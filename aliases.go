package vault

import "github.com/xraph/vault/core"

// Entity is the base type embedded by all Vault entities.
//
// This is a type alias, not a defined type: callers embed vault.Entity and
// pass it where core.Entity is expected, and both must keep working.
type Entity = core.Entity

// NewEntity creates a new Entity with both timestamps set to now (UTC).
func NewEntity() Entity { return core.NewEntity() }

// Sentinel errors for Vault operations.
//
// These are the same values as their core counterparts, not copies, so
// errors.Is keeps matching for every caller that wrapped one.
var (
	// Store errors.
	ErrNoStore = core.ErrNoStore

	// Key/entity not found errors.
	ErrKeyNotFound      = core.ErrKeyNotFound
	ErrSecretNotFound   = core.ErrSecretNotFound
	ErrFlagNotFound     = core.ErrFlagNotFound
	ErrConfigNotFound   = core.ErrConfigNotFound
	ErrOverrideNotFound = core.ErrOverrideNotFound
	ErrRotationNotFound = core.ErrRotationNotFound
	ErrAuditNotFound    = core.ErrAuditNotFound
	ErrRunNotFound      = core.ErrRunNotFound
	ErrDLQNotFound      = core.ErrDLQNotFound
	ErrCronNotFound     = core.ErrCronNotFound
	ErrEventNotFound    = core.ErrEventNotFound
	ErrWorkflowNotFound = core.ErrWorkflowNotFound

	// Crypto errors.
	ErrDecryptionFailed = core.ErrDecryptionFailed
	ErrEncryptionFailed = core.ErrEncryptionFailed
	ErrInvalidKey       = core.ErrInvalidKey

	// Feature flag errors.
	ErrFlagDisabled   = core.ErrFlagDisabled
	ErrFlagExists     = core.ErrFlagExists
	ErrInvalidFlagKey = core.ErrInvalidFlagKey

	// Rotation errors.
	ErrRotationFailed = core.ErrRotationFailed

	// Auth errors.
	ErrUnauthorized = core.ErrUnauthorized

	// Secret errors.
	ErrSecretExists = core.ErrSecretExists

	// Config errors.
	ErrConfigExists = core.ErrConfigExists

	// ErrConfigVersionNotFound is returned when a config entry has no
	// version with the requested number.
	ErrConfigVersionNotFound = core.ErrConfigVersionNotFound
)
