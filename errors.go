package vault

import "errors"

// Sentinel errors for Vault operations.
var (
	// Store errors.
	ErrNoStore = errors.New("vault: no store configured")

	// Key/entity not found errors.
	ErrKeyNotFound      = errors.New("vault: key not found")
	ErrSecretNotFound   = errors.New("vault: secret not found")
	ErrFlagNotFound     = errors.New("vault: flag not found")
	ErrConfigNotFound   = errors.New("vault: config entry not found")
	ErrOverrideNotFound = errors.New("vault: override not found")
	ErrRotationNotFound = errors.New("vault: rotation policy not found")
	ErrAuditNotFound    = errors.New("vault: audit entry not found")
	ErrRunNotFound      = errors.New("vault: workflow run not found")
	ErrDLQNotFound      = errors.New("vault: DLQ entry not found")
	ErrCronNotFound     = errors.New("vault: cron entry not found")
	ErrEventNotFound    = errors.New("vault: event not found")
	ErrWorkflowNotFound = errors.New("vault: workflow not found")

	// Crypto errors.
	ErrDecryptionFailed = errors.New("vault: decryption failed")
	ErrEncryptionFailed = errors.New("vault: encryption failed")
	ErrInvalidKey       = errors.New("vault: invalid encryption key")

	// Feature flag errors.
	ErrFlagDisabled   = errors.New("vault: flag is disabled")
	ErrFlagExists     = errors.New("vault: flag already exists")
	ErrInvalidFlagKey = errors.New("vault: invalid flag key")

	// Rotation errors.
	ErrRotationFailed = errors.New("vault: rotation failed")

	// Auth errors.
	ErrUnauthorized = errors.New("vault: unauthorized")

	// Secret errors.
	ErrSecretExists = errors.New("vault: secret already exists")

	// Config errors.
	ErrConfigExists = errors.New("vault: config entry already exists")
)
