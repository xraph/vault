package override

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/xraph/vault"
	"github.com/xraph/vault/config"
)

// contextKey is the type for context value keys used by the resolver.
type contextKey string

const (
	// ContextKeyTenantID is the context key for tenant ID (matches flag.ContextKeyTenantID).
	ContextKeyTenantID contextKey = "vault.tenant_id"
)

// ResolverOption configures the Resolver.
type ResolverOption func(*Resolver)

// WithLogger sets the logger for the resolver.
func WithLogger(l *slog.Logger) ResolverOption {
	return func(r *Resolver) { r.logger = l }
}

// WithCacheTTL enables result caching with the given TTL.
func WithCacheTTL(ttl time.Duration) ResolverOption {
	return func(r *Resolver) { r.cache = newResolverCache(ttl) }
}

// Resolver resolves config values with per-tenant override support.
//
// Resolution order:
//  1. If tenant ID is present in context, look up tenant override → use if found.
//  2. Fall back to app-level config value.
//  3. Cache results when a cache TTL is configured.
type Resolver struct {
	configStore   config.Store
	overrideStore Store
	cache         *resolverCache
	logger        *slog.Logger
}

// NewResolver creates a config resolver with override support.
func NewResolver(configStore config.Store, overrideStore Store, opts ...ResolverOption) *Resolver {
	r := &Resolver{
		configStore:   configStore,
		overrideStore: overrideStore,
		logger:        slog.Default(),
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Resolve returns the effective value for a config key and app ID.
//
// It extracts the tenant ID from the context and checks for a tenant override first.
// If no override is found or there is no tenant context, it returns the app-level config value.
func (r *Resolver) Resolve(ctx context.Context, key, appID string) (any, error) {
	tenantID := contextString(ctx, ContextKeyTenantID)

	// Check cache.
	if r.cache != nil {
		if val, ok := r.cache.get(key, appID, tenantID); ok {
			return val, nil
		}
	}

	// Try tenant override if tenant context is present.
	if tenantID != "" {
		ov, err := r.overrideStore.GetOverride(ctx, key, appID, tenantID)
		if err == nil {
			r.cacheSet(key, appID, tenantID, ov.Value)
			return ov.Value, nil
		}
		// Ignore "not found" — fall through to app default.
		if !errors.Is(err, vault.ErrOverrideNotFound) {
			return nil, err
		}
	}

	// Fall back to app-level config.
	entry, err := r.configStore.GetConfig(ctx, key, appID)
	if err != nil {
		return nil, err
	}

	r.cacheSet(key, appID, tenantID, entry.Value)
	return entry.Value, nil
}

// Invalidate removes cached entries for a specific config key and app ID.
func (r *Resolver) Invalidate(key, appID string) {
	if r.cache != nil {
		r.cache.invalidate(key, appID)
	}
}

// InvalidateAll removes all cached entries.
func (r *Resolver) InvalidateAll() {
	if r.cache != nil {
		r.cache.invalidateAll()
	}
}

func (r *Resolver) cacheSet(key, appID, tenantID string, val any) {
	if r.cache != nil {
		r.cache.set(key, appID, tenantID, val)
	}
}

// contextString extracts a string value from the context, returning "" if absent.
func contextString(ctx context.Context, key contextKey) string {
	v, ok := ctx.Value(key).(string)
	if !ok {
		return ""
	}
	return v
}

// ──────────────────────────────────────────────────
// Resolver Cache
// ──────────────────────────────────────────────────

// resolverCacheEntry holds a cached resolution result with expiry.
type resolverCacheEntry struct {
	value     any
	expiresAt time.Time
}

// resolverCache is a simple TTL-based cache for resolved config values.
type resolverCache struct {
	mu      sync.RWMutex
	entries map[string]resolverCacheEntry
	ttl     time.Duration
}

// newResolverCache creates a resolver cache with the given TTL.
func newResolverCache(ttl time.Duration) *resolverCache {
	return &resolverCache{
		entries: make(map[string]resolverCacheEntry),
		ttl:     ttl,
	}
}

// resolverCacheKey builds a composite cache key.
func resolverCacheKey(key, appID, tenantID string) string {
	return key + "\x00" + appID + "\x00" + tenantID
}

// get retrieves a cached value. Returns (value, true) on hit, (nil, false) on miss/expired.
func (c *resolverCache) get(key, appID, tenantID string) (any, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[resolverCacheKey(key, appID, tenantID)]
	if !ok {
		return nil, false
	}
	if time.Now().After(entry.expiresAt) {
		return nil, false
	}
	return entry.value, true
}

// set stores a value in the cache with the configured TTL.
func (c *resolverCache) set(key, appID, tenantID string, value any) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[resolverCacheKey(key, appID, tenantID)] = resolverCacheEntry{
		value:     value,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// invalidate removes all entries matching a specific key and appID.
func (c *resolverCache) invalidate(key, appID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	prefix := key + "\x00" + appID + "\x00"
	for k := range c.entries {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			delete(c.entries, k)
		}
	}
}

// invalidateAll removes all cached entries.
func (c *resolverCache) invalidateAll() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]resolverCacheEntry)
}
