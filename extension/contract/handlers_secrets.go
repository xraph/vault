package contract

import (
	"context"
	"errors"
	"sort"

	"github.com/xraph/forge/extensions/dashboard/contract"

	"github.com/xraph/vault"
	"github.com/xraph/vault/audit"
	"github.com/xraph/vault/secret"
)

// defaultListLimit and maxListLimit bound secrets.list paging. A request
// that omits limit gets defaultListLimit; one that asks for more than
// maxListLimit is capped rather than rejected, since a page size is a
// preference, not a contract the client must get exactly right.
const (
	defaultListLimit = 25
	maxListLimit     = 200
)

// recentAuditLimit bounds how many audit entries secrets.detail returns
// alongside a secret. The full history lives behind its own paged read,
// which is out of scope for this slice.
const recentAuditLimit = 10

// secretsListRequest is the wire request for secrets.list.
type secretsListRequest struct {
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

// secretsListResponse is the wire response for secrets.list.
type secretsListResponse struct {
	Secrets []SecretSummary `json:"secrets"`
	Total   int64           `json:"total"`
}

// secretsListHandler answers secrets.list for deps.Vault.AppID() alone; no
// request field ever names a different app.
func secretsListHandler(deps Deps) func(ctx context.Context, in secretsListRequest, p contract.Principal) (secretsListResponse, error) {
	return func(ctx context.Context, in secretsListRequest, _ contract.Principal) (secretsListResponse, error) {
		appID := deps.Vault.AppID()

		limit := in.Limit
		if limit <= 0 {
			limit = defaultListLimit
		}
		if limit > maxListLimit {
			limit = maxListLimit
		}
		offset := in.Offset
		if offset < 0 {
			offset = 0
		}

		metas, err := deps.Vault.Secrets().List(ctx, appID, secret.ListOpts{Limit: limit, Offset: offset})
		if err != nil {
			return secretsListResponse{}, mapError(err)
		}
		total, err := deps.Vault.Store().CountSecrets(ctx, appID)
		if err != nil {
			return secretsListResponse{}, mapError(err)
		}

		summaries := make([]SecretSummary, 0, len(metas))
		for _, m := range metas {
			summaries = append(summaries, projectSecretSummary(m))
		}
		return secretsListResponse{Secrets: summaries, Total: total}, nil
	}
}

// secretsDetailRequest is the wire request for secrets.detail.
type secretsDetailRequest struct {
	Key string `json:"key"`
}

// secretsDetailResponse is the wire response for secrets.detail. Rotation
// has no omitempty: it must reach the client as an explicit null when the
// secret has no policy, not be dropped, so one page can both show and
// create a policy.
type secretsDetailResponse struct {
	Secret      SecretSummary          `json:"secret"`
	Rotation    *RotationPolicySummary `json:"rotation"`
	RecentAudit []AuditSummary         `json:"recentAudit"`
}

// secretsDetailHandler answers secrets.detail for deps.Vault.AppID() alone.
func secretsDetailHandler(deps Deps) func(ctx context.Context, in secretsDetailRequest, p contract.Principal) (secretsDetailResponse, error) {
	return func(ctx context.Context, in secretsDetailRequest, _ contract.Principal) (secretsDetailResponse, error) {
		appID := deps.Vault.AppID()
		key, err := requireKey(in.Key)
		if err != nil {
			return secretsDetailResponse{}, err
		}

		meta, err := deps.Vault.Secrets().GetMeta(ctx, key, appID)
		if err != nil {
			return secretsDetailResponse{}, mapError(err)
		}

		var rotationSummary *RotationPolicySummary
		policy, err := deps.Vault.Store().GetRotationPolicy(ctx, key, appID)
		switch {
		case err == nil:
			rs := projectRotationPolicy(policy, isRotatable(deps.Vault.Rotation().RotatorKeys(), key))
			rotationSummary = &rs
		case errors.Is(err, vault.ErrRotationNotFound):
			// No policy for this secret: rotation stays nil, not an error.
		default:
			return secretsDetailResponse{}, mapError(err)
		}

		entries, err := deps.Vault.Store().ListAuditByKey(ctx, key, appID, audit.ListOpts{Limit: recentAuditLimit})
		if err != nil {
			return secretsDetailResponse{}, mapError(err)
		}
		recentAudit := make([]AuditSummary, 0, len(entries))
		for _, e := range entries {
			recentAudit = append(recentAudit, projectAuditSummary(e))
		}

		return secretsDetailResponse{
			Secret:      projectSecretSummary(meta),
			Rotation:    rotationSummary,
			RecentAudit: recentAudit,
		}, nil
	}
}

// secretsVersionsRequest is the wire request for secrets.versions.
type secretsVersionsRequest struct {
	Key string `json:"key"`
}

// secretsVersionsResponse is the wire response for secrets.versions.
type secretsVersionsResponse struct {
	Versions []SecretVersionSummary `json:"versions"`
}

// secretsVersionsHandler answers secrets.versions for deps.Vault.AppID()
// alone. It checks the secret itself exists before listing, so an orphan
// version row left behind by a deleted secret can never make this answer
// as if the secret were still there.
func secretsVersionsHandler(deps Deps) func(ctx context.Context, in secretsVersionsRequest, p contract.Principal) (secretsVersionsResponse, error) {
	return func(ctx context.Context, in secretsVersionsRequest, _ contract.Principal) (secretsVersionsResponse, error) {
		appID := deps.Vault.AppID()
		key, err := requireKey(in.Key)
		if err != nil {
			return secretsVersionsResponse{}, err
		}

		if _, metaErr := deps.Vault.Secrets().GetMeta(ctx, key, appID); metaErr != nil {
			return secretsVersionsResponse{}, mapError(metaErr)
		}

		versions, err := deps.Vault.Secrets().ListVersions(ctx, key, appID)
		if err != nil {
			return secretsVersionsResponse{}, mapError(err)
		}
		sort.Slice(versions, func(i, j int) bool { return versions[i].Version > versions[j].Version })

		out := make([]SecretVersionSummary, 0, len(versions))
		for _, v := range versions {
			out = append(out, projectSecretVersionSummary(v))
		}
		return secretsVersionsResponse{Versions: out}, nil
	}
}
