package crypto

import "context"

// KeyStore manages per-entity encryption keys (for GDPR-style per-tenant key isolation).
type KeyStore interface {
	// GetOrCreate retrieves the key for the given ID, creating one if it doesn't exist.
	GetOrCreate(ctx context.Context, id string) ([]byte, error)

	// Get retrieves the key for the given ID.
	Get(ctx context.Context, id string) ([]byte, error)

	// Delete removes the key for the given ID (crypto-shredding).
	Delete(ctx context.Context, id string) error
}
