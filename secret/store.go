package secret

import "context"

// Store defines the persistence interface for secrets.
type Store interface {
	// GetSecret retrieves the latest version of a secret by key and app ID.
	GetSecret(ctx context.Context, key, appID string) (*Secret, error)

	// SetSecret creates or updates a secret. If the key already exists, a new version is created.
	SetSecret(ctx context.Context, s *Secret) error

	// DeleteSecret removes a secret and all its versions.
	DeleteSecret(ctx context.Context, key, appID string) error

	// ListSecrets returns secret metadata (never values) for an app.
	ListSecrets(ctx context.Context, appID string, opts ListOpts) ([]*Meta, error)

	// GetSecretVersion retrieves a specific version of a secret.
	GetSecretVersion(ctx context.Context, key, appID string, version int64) (*Secret, error)

	// ListSecretVersions returns all versions of a secret.
	ListSecretVersions(ctx context.Context, key, appID string) ([]*Version, error)
}
