package override

import "context"

// Store defines the persistence interface for per-tenant overrides.
type Store interface {
	// GetOverride retrieves a tenant override by key, app ID, and tenant ID.
	GetOverride(ctx context.Context, key, appID, tenantID string) (*Override, error)

	// SetOverride creates or updates a tenant override.
	SetOverride(ctx context.Context, o *Override) error

	// DeleteOverride removes a tenant override.
	DeleteOverride(ctx context.Context, key, appID, tenantID string) error

	// ListOverridesByTenant returns all overrides for a specific tenant.
	ListOverridesByTenant(ctx context.Context, appID, tenantID string) ([]*Override, error)

	// ListOverridesByKey returns all tenant overrides for a specific config key.
	ListOverridesByKey(ctx context.Context, key, appID string) ([]*Override, error)
}
