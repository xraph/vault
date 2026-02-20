package flag

import "context"

// Store defines the persistence interface for feature flags.
type Store interface {
	// DefineFlag creates or updates a flag definition.
	DefineFlag(ctx context.Context, f *Definition) error

	// GetFlagDefinition retrieves a flag definition by key and app ID.
	GetFlagDefinition(ctx context.Context, key, appID string) (*Definition, error)

	// ListFlagDefinitions returns all flag definitions for an app.
	ListFlagDefinitions(ctx context.Context, appID string, opts ListOpts) ([]*Definition, error)

	// DeleteFlagDefinition removes a flag definition and its rules.
	DeleteFlagDefinition(ctx context.Context, key, appID string) error

	// SetFlagRules replaces all targeting rules for a flag.
	SetFlagRules(ctx context.Context, key, appID string, rules []*Rule) error

	// GetFlagRules returns targeting rules for a flag, ordered by priority.
	GetFlagRules(ctx context.Context, key, appID string) ([]*Rule, error)

	// SetFlagTenantOverride sets a direct per-tenant override value.
	SetFlagTenantOverride(ctx context.Context, key, appID, tenantID string, value any) error

	// GetFlagTenantOverride retrieves a tenant override for a flag.
	GetFlagTenantOverride(ctx context.Context, key, appID, tenantID string) (any, error)

	// DeleteFlagTenantOverride removes a tenant override.
	DeleteFlagTenantOverride(ctx context.Context, key, appID, tenantID string) error

	// ListFlagTenantOverrides returns all tenant overrides for a flag.
	ListFlagTenantOverrides(ctx context.Context, key, appID string) ([]*TenantOverride, error)
}
