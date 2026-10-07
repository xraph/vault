package secret

import (
	"context"

	"github.com/xraph/vault/id"
)

// Store defines the persistence interface for secrets.
type Store interface {
	// GetSecret retrieves the latest version of a secret by key and app ID.
	GetSecret(ctx context.Context, key, appID string) (*Secret, error)

	// SetSecret creates or updates a secret. If the key already exists, a new version is created.
	SetSecret(ctx context.Context, s *Secret) error

	// DeleteSecret removes a secret and all its versions.
	DeleteSecret(ctx context.Context, key, appID string) error

	// ListSecrets returns secret metadata (never values) for an app. Without
	// an expiry bound in opts the result is ordered by key. With one, only
	// secrets that expire within the bounds are returned, ordered by expiry
	// and then key.
	ListSecrets(ctx context.Context, appID string, opts ListOpts) ([]*Meta, error)

	// GetSecretVersion retrieves a specific version of a secret. The returned
	// secret's EncryptionAlg is the version's own recorded algorithm when it
	// has one, and the secret's current algorithm otherwise (a row written
	// before versions recorded theirs).
	GetSecretVersion(ctx context.Context, key, appID string, version int64) (*Secret, error)

	// ListSecretVersions returns all versions of a secret.
	ListSecretVersions(ctx context.Context, key, appID string) ([]*Version, error)

	// CountSecrets returns the total number of secrets for an app,
	// independent of any paging.
	CountSecrets(ctx context.Context, appID string) (int64, error)

	// CountSecretsMatching returns the number of secrets for an app that
	// match opts, applying the same expiry bounds as ListSecrets. Limit and
	// Offset are ignored.
	CountSecretsMatching(ctx context.Context, appID string, opts ListOpts) (int64, error)

	// CountSecretsUnencrypted returns the number of secrets for an app whose
	// stored value carries no encryption algorithm, that is, rows written
	// while no encryption key was configured. It counts in the store and
	// never loads a value.
	CountSecretsUnencrypted(ctx context.Context, appID string) (int64, error)

	// ListUnrecordedVersions returns up to limit version rows of an app whose
	// encryption algorithm was never recorded, in ascending version id order,
	// starting after the id after (empty means from the start). Callers page
	// by passing the last id of the previous page, so rows they decline to
	// classify are not fetched again.
	ListUnrecordedVersions(ctx context.Context, appID, after string, limit int) ([]*Version, error)

	// SetVersionEncryption records the algorithm of one version row. An empty
	// alg records "stored without encryption". An unknown id returns nil: the
	// row was already set or has been removed.
	SetVersionEncryption(ctx context.Context, versionID id.ID, alg string) error

	// CountVersionEncryption tallies an app's earlier version rows by
	// recorded algorithm, without loading any value. A secret's current
	// version row is not counted: SetSecret writes one for the current value
	// too, and CountSecretsUnencrypted already covers current values, so a
	// row counted here is history only.
	CountVersionEncryption(ctx context.Context, appID string) (VersionEncryptionCounts, error)
}
