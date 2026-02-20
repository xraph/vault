// Package scope provides context-based request scoping for Vault operations.
// It extracts and injects identifiers (app ID, tenant ID, user ID, IP)
// used across secrets, flags, config, and audit.
package scope

import "context"

// ContextKey is the type for context value keys used by scope.
type ContextKey string

// Standard scope context keys.
// These intentionally match the keys used by flag.ContextKeyTenantID ("vault.tenant_id")
// and flag.ContextKeyUserID ("vault.user_id") so that values set by scope helpers
// are automatically visible to the flag engine and override resolver.
const (
	KeyAppID    ContextKey = "vault.app_id"
	KeyTenantID ContextKey = "vault.tenant_id"
	KeyUserID   ContextKey = "vault.user_id"
	KeyIP       ContextKey = "vault.ip"
)

// FromContext extracts all scope values from the context.
// Missing values are returned as empty strings.
func FromContext(ctx context.Context) (appID, tenantID, userID, ip string) {
	appID = getString(ctx, KeyAppID)
	tenantID = getString(ctx, KeyTenantID)
	userID = getString(ctx, KeyUserID)
	ip = getString(ctx, KeyIP)
	return
}

// WithAppID returns a new context with the given app ID.
func WithAppID(ctx context.Context, appID string) context.Context {
	return context.WithValue(ctx, KeyAppID, appID)
}

// WithTenantID returns a new context with the given tenant ID.
func WithTenantID(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, KeyTenantID, tenantID)
}

// WithUserID returns a new context with the given user ID.
func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, KeyUserID, userID)
}

// WithIP returns a new context with the given client IP.
func WithIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, KeyIP, ip)
}

// WithScope returns a context with all scope values set.
func WithScope(ctx context.Context, appID, tenantID, userID, ip string) context.Context {
	ctx = WithAppID(ctx, appID)
	ctx = WithTenantID(ctx, tenantID)
	ctx = WithUserID(ctx, userID)
	ctx = WithIP(ctx, ip)
	return ctx
}

// getString extracts a string value from the context.
func getString(ctx context.Context, key ContextKey) string {
	v, ok := ctx.Value(key).(string)
	if !ok {
		return ""
	}
	return v
}
