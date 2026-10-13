package secret

import (
	"context"

	"github.com/xraph/vault/id"
)

// Store defines the persistence interface for secrets.
//
// A secret is identified by its key, app ID and tenant ID together. An empty
// tenant ID is the app-level secret, not a wildcard: every tenant-scoped
// method below matches the tenant exactly, so a read under one tenant can
// never return, overwrite or delete a secret of another tenant or of the app.
//
// The operator-level methods (CountSecrets, CountSecretsMatching,
// CountSecretsUnencrypted, CountVersionEncryption, ListUnrecordedVersions and
// SetVersionEncryption) take no tenant and work across every tenant of the
// app. They serve statistics and maintenance, and none of them returns a
// secret value: ListUnrecordedVersions hands back stored bytes only so the
// backfill can test them against the key.
type Store interface {
	// GetSecret retrieves the latest version of the secret with this key in
	// this app and tenant.
	GetSecret(ctx context.Context, key, appID, tenantID string) (*Secret, error)

	// SetSecret creates or updates a secret. The secret's own AppID and
	// TenantID say whose it is. If the key already exists for that app and
	// tenant, a new version is created; the same key under another tenant
	// is a different secret.
	SetSecret(ctx context.Context, s *Secret) error

	// DeleteSecret removes the secret with this key in this app and tenant,
	// and all its versions. Other tenants' secrets under the same key stay.
	DeleteSecret(ctx context.Context, key, appID, tenantID string) error

	// ListSecrets returns secret metadata (never values) for an app, limited
	// to the tenant in opts.TenantID by exact match ("" is the app-level
	// secrets only). Without an expiry bound in opts the result is ordered
	// by key. With one, only secrets that expire within the bounds are
	// returned, ordered by expiry and then key.
	ListSecrets(ctx context.Context, appID string, opts ListOpts) ([]*Meta, error)

	// GetSecretVersion retrieves a specific version of the secret with this
	// key in this app and tenant. The returned secret's EncryptionAlg is the
	// version's own recorded algorithm when it has one, and the secret's
	// current algorithm otherwise (a row written before versions recorded
	// theirs).
	GetSecretVersion(ctx context.Context, key, appID, tenantID string, version int64) (*Secret, error)

	// ListSecretVersions returns all versions of the secret with this key in
	// this app and tenant.
	ListSecretVersions(ctx context.Context, key, appID, tenantID string) ([]*Version, error)

	// CountSecrets returns the total number of secrets for an app, across
	// every tenant and the app-level ones, independent of any paging.
	CountSecrets(ctx context.Context, appID string) (int64, error)

	// CountSecretsMatching returns the number of secrets for an app, across
	// every tenant and the app-level ones, that pass the expiry bounds in
	// opts, the same bounds ListSecrets applies. TenantID, Limit and Offset
	// are ignored.
	CountSecretsMatching(ctx context.Context, appID string, opts ListOpts) (int64, error)

	// CountSecretsUnencrypted returns the number of secrets for an app,
	// across every tenant and the app-level ones, whose stored value carries
	// no encryption algorithm, that is, rows written while no encryption key
	// was configured. It counts in the store and never loads a value.
	CountSecretsUnencrypted(ctx context.Context, appID string) (int64, error)

	// ListUnrecordedVersions returns up to limit version rows of an app,
	// across every tenant and the app-level ones, whose encryption algorithm
	// was never recorded, in ascending version id order, starting after the
	// id after (empty means from the start). Callers page by passing the
	// last id of the previous page, so rows they decline to classify are
	// not fetched again.
	ListUnrecordedVersions(ctx context.Context, appID, after string, limit int) ([]*Version, error)

	// SetVersionEncryption records the algorithm of one version row,
	// whichever tenant it belongs to: version ids are unique across the
	// store. An empty alg records "stored without encryption". An unknown
	// id returns nil: the row was already set or has been removed.
	SetVersionEncryption(ctx context.Context, versionID id.ID, alg string) error

	// CountVersionEncryption tallies an app's earlier version rows, across
	// every tenant and the app-level ones, by recorded algorithm, without
	// loading any value. A secret's current version row is not counted:
	// SetSecret writes one for the current value too, and
	// CountSecretsUnencrypted already covers current values, so a row
	// counted here is history only. A version row is matched to its current
	// secret by key, app and tenant together.
	CountVersionEncryption(ctx context.Context, appID string) (VersionEncryptionCounts, error)
}
