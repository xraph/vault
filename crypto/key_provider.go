package crypto

import "context"

// EncryptionKeyProvider retrieves and rotates encryption keys.
type EncryptionKeyProvider interface {
	// GetKey returns the current encryption key.
	GetKey(ctx context.Context) ([]byte, error)

	// RotateKey generates and stores a new key, returning it.
	RotateKey(ctx context.Context) ([]byte, error)
}
