package contract

import (
	"context"
	"time"

	"github.com/xraph/forge/extensions/dashboard/contract"

	"github.com/xraph/vault/audit"
	audithook "github.com/xraph/vault/audit_hook"
	"github.com/xraph/vault/secret"
)

// overviewRecentActivityLimit is how many audit rows the overview shows.
const overviewRecentActivityLimit = 10

// expiringSoonDays is how far ahead the overview counts secrets as expiring.
const expiringSoonDays = 30

// rotationFailureWindow is how far back the overview counts failed rotations.
const rotationFailureWindow = 24 * time.Hour

// overviewStatsRequest is the wire request for overview.stats: nothing.
type overviewStatsRequest struct{}

// overviewStatsResponse is the wire response for overview.stats.
//
// EncryptionEnabled and EncryptionAlgorithm describe how this process
// encrypts NEW secrets. They say nothing about rows already stored, which
// is why UnencryptedSecrets rides along: a page must never call the vault
// encrypted while it is above zero. ConfigOverrides counts config tenant
// overrides only, not flag tenant overrides. RotationPolicies counts every
// policy, disabled ones included.
type overviewStatsResponse struct {
	Secrets            int64 `json:"secrets"`
	UnencryptedSecrets int64 `json:"unencryptedSecrets"`
	Flags              int64 `json:"flags"`
	ConfigEntries      int64 `json:"configEntries"`
	ConfigOverrides    int64 `json:"configOverrides"`
	RotationPolicies   int64 `json:"rotationPolicies"`
	// RotationEnabled counts enabled policies.
	RotationEnabled int64 `json:"rotationEnabled"`
	// RotationOverdue counts enabled policies with a rotator whose next
	// rotation is in the past.
	RotationOverdue int64 `json:"rotationOverdue"`
	// RotationWithoutRotator counts enabled policies no application has
	// registered a rotator for on this process. They can never rotate.
	RotationWithoutRotator int64 `json:"rotationWithoutRotator"`
	// RotationFailures24h counts failed rotation attempts, manual or
	// scheduled, in the last 24 hours.
	RotationFailures24h int64 `json:"rotationFailures24h"`
	// PlaintextVersions counts earlier version rows (never a secret's
	// current one, which UnencryptedSecrets covers) recorded as stored
	// without encryption. UnrecordedVersions counts earlier rows from before
	// versions recorded an algorithm that the backfill has not classified.
	PlaintextVersions  int64 `json:"plaintextVersions"`
	UnrecordedVersions int64 `json:"unrecordedVersions"`
	// ExpiredSecrets counts secrets whose expiry is at or before now.
	// ExpiringSecrets counts those expiring after now and within 30 days.
	ExpiredSecrets      int64          `json:"expiredSecrets"`
	ExpiringSecrets     int64          `json:"expiringSecrets"`
	EncryptionEnabled   bool           `json:"encryptionEnabled"`
	EncryptionAlgorithm string         `json:"encryptionAlgorithm"`
	RecentActivity      []AuditSummary `json:"recentActivity"`
}

// overviewStatsHandler answers overview.stats for deps.Vault.AppID() alone.
// Any read that fails fails the whole query: a count that could not be read
// must never reach the page as a 0, because a 0 reads as "nothing wrong".
func overviewStatsHandler(deps Deps) func(ctx context.Context, in overviewStatsRequest, p contract.Principal) (overviewStatsResponse, error) {
	return func(ctx context.Context, _ overviewStatsRequest, _ contract.Principal) (overviewStatsResponse, error) {
		const intent = "overview.stats"
		appID := deps.Vault.AppID()
		st := deps.Vault.Store()
		now := time.Now().UTC()
		var out overviewStatsResponse
		var err error

		if out.Secrets, err = st.CountSecrets(ctx, appID); err != nil {
			return overviewStatsResponse{}, deps.mapError(intent, err)
		}
		if out.UnencryptedSecrets, err = st.CountSecretsUnencrypted(ctx, appID); err != nil {
			return overviewStatsResponse{}, deps.mapError(intent, err)
		}
		if out.Flags, err = st.CountFlagDefinitions(ctx, appID); err != nil {
			return overviewStatsResponse{}, deps.mapError(intent, err)
		}
		if out.ConfigEntries, err = st.CountConfig(ctx, appID); err != nil {
			return overviewStatsResponse{}, deps.mapError(intent, err)
		}
		if out.ConfigOverrides, err = st.CountOverrides(ctx, appID); err != nil {
			return overviewStatsResponse{}, deps.mapError(intent, err)
		}

		versions, err := st.CountVersionEncryption(ctx, appID)
		if err != nil {
			return overviewStatsResponse{}, deps.mapError(intent, err)
		}
		out.PlaintextVersions = versions.Plaintext
		out.UnrecordedVersions = versions.Unrecorded

		soon := now.AddDate(0, 0, expiringSoonDays)
		if out.ExpiredSecrets, err = st.CountSecretsMatching(ctx, appID, secret.ListOpts{ExpiresBefore: &now}); err != nil {
			return overviewStatsResponse{}, deps.mapError(intent, err)
		}
		if out.ExpiringSecrets, err = st.CountSecretsMatching(ctx, appID, secret.ListOpts{ExpiresAfter: &now, ExpiresBefore: &soon}); err != nil {
			return overviewStatsResponse{}, deps.mapError(intent, err)
		}

		// The policy list is small and unpaged, and every rotation figure
		// comes from this one read, so the total and its subsets agree.
		policies, err := st.ListRotationPolicies(ctx, appID)
		if err != nil {
			return overviewStatsResponse{}, deps.mapError(intent, err)
		}
		out.RotationPolicies = int64(len(policies))
		rotatorKeys := deps.Vault.Rotation().RotatorKeys()
		for _, p := range policies {
			if !p.Enabled {
				continue
			}
			out.RotationEnabled++
			if !isRotatable(rotatorKeys, p.SecretKey) {
				out.RotationWithoutRotator++
				continue
			}
			if p.NextRotationAt != nil && p.NextRotationAt.Before(now) {
				out.RotationOverdue++
			}
		}

		if out.RotationFailures24h, err = st.CountAuditMatching(ctx, appID, audit.ListOpts{
			Action:  audithook.ActionSecretRotated,
			Outcome: audithook.OutcomeFailure,
			Since:   now.Add(-rotationFailureWindow),
		}); err != nil {
			return overviewStatsResponse{}, deps.mapError(intent, err)
		}

		rows, err := st.ListAudit(ctx, appID, audit.ListOpts{Limit: overviewRecentActivityLimit, ExcludeActions: readActions})
		if err != nil {
			return overviewStatsResponse{}, deps.mapError(intent, err)
		}
		out.RecentActivity = make([]AuditSummary, 0, len(rows))
		for _, r := range rows {
			out.RecentActivity = append(out.RecentActivity, projectAuditSummary(r))
		}

		out.EncryptionEnabled = deps.Vault.EncryptionEnabled()
		out.EncryptionAlgorithm = deps.Vault.EncryptionAlgorithm()
		return out, nil
	}
}
