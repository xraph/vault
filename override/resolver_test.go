package override_test

import (
	"context"
	"testing"
	"time"

	"github.com/xraph/vault"
	"github.com/xraph/vault/config"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/override"
	"github.com/xraph/vault/store/memory"
)

const testApp = "app1"

func bg() context.Context { return context.Background() }

func withTenant(tenantID string) context.Context {
	return context.WithValue(bg(), override.ContextKeyTenantID, tenantID)
}

func setConfig(t *testing.T, s *memory.Store, key string, value any) {
	t.Helper()
	err := s.SetConfig(bg(), &config.Entry{
		Entity: vault.NewEntity(),
		ID:     id.NewConfigID(),
		Key:    key,
		Value:  value,
		AppID:  testApp,
	})
	if err != nil {
		t.Fatalf("SetConfig(%q): %v", key, err)
	}
}

func setOverride(t *testing.T, s *memory.Store, key, tenantID string, value any) {
	t.Helper()
	err := s.SetOverride(bg(), &override.Override{
		Entity:   vault.NewEntity(),
		ID:       id.NewOverrideID(),
		Key:      key,
		Value:    value,
		AppID:    testApp,
		TenantID: tenantID,
	})
	if err != nil {
		t.Fatalf("SetOverride(%q, %q): %v", key, tenantID, err)
	}
}

func TestResolveAppDefault(t *testing.T) {
	s := memory.New()
	setConfig(t, s, "db.pool_size", float64(10))

	r := override.NewResolver(s, s)

	// No tenant in context → app default.
	val, err := r.Resolve(bg(), "db.pool_size", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if val != float64(10) {
		t.Errorf("got %v, want 10", val)
	}
}

func TestResolveTenantOverrideWins(t *testing.T) {
	s := memory.New()
	setConfig(t, s, "db.pool_size", float64(10))
	setOverride(t, s, "db.pool_size", "t-1", float64(50))

	r := override.NewResolver(s, s)

	// Tenant t-1 → override.
	val, err := r.Resolve(withTenant("t-1"), "db.pool_size", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if val != float64(50) {
		t.Errorf("got %v, want 50", val)
	}
}

func TestResolveFallsBackOnOverrideNotFound(t *testing.T) {
	s := memory.New()
	setConfig(t, s, "db.pool_size", float64(10))

	r := override.NewResolver(s, s)

	// Tenant t-2 has no override → falls back to app default.
	val, err := r.Resolve(withTenant("t-2"), "db.pool_size", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if val != float64(10) {
		t.Errorf("got %v, want 10 (app default)", val)
	}
}

func TestResolveNoTenantContext(t *testing.T) {
	s := memory.New()
	setConfig(t, s, "feature.enabled", true)
	setOverride(t, s, "feature.enabled", "t-1", false)

	r := override.NewResolver(s, s)

	// No tenant → app default even though override exists.
	val, err := r.Resolve(bg(), "feature.enabled", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if val != true {
		t.Errorf("got %v, want true (no tenant context)", val)
	}
}

func TestResolveConfigNotFound(t *testing.T) {
	s := memory.New()
	r := override.NewResolver(s, s)

	_, err := r.Resolve(bg(), "nonexistent", testApp)
	if err == nil {
		t.Fatal("expected error for nonexistent config")
	}
}

func TestResolveWithCacheTTL(t *testing.T) {
	s := memory.New()
	setConfig(t, s, "cached.key", "original")

	r := override.NewResolver(s, s, override.WithCacheTTL(1*time.Minute))

	// First call populates cache.
	val1, err := r.Resolve(bg(), "cached.key", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if val1 != "original" {
		t.Errorf("got %v, want %q", val1, "original")
	}

	// Second call hits cache.
	val2, err := r.Resolve(bg(), "cached.key", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if val2 != "original" {
		t.Errorf("cached: got %v, want %q", val2, "original")
	}
}

func TestResolveCacheWithTenantOverride(t *testing.T) {
	s := memory.New()
	setConfig(t, s, "limit", float64(100))
	setOverride(t, s, "limit", "t-1", float64(200))

	r := override.NewResolver(s, s, override.WithCacheTTL(1*time.Minute))

	// Resolve for tenant t-1.
	val1, err := r.Resolve(withTenant("t-1"), "limit", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if val1 != float64(200) {
		t.Errorf("got %v, want 200 (override)", val1)
	}

	// Resolve without tenant → different cache entry.
	val2, err := r.Resolve(bg(), "limit", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if val2 != float64(100) {
		t.Errorf("got %v, want 100 (app default)", val2)
	}
}

func TestResolveInvalidateCache(t *testing.T) {
	s := memory.New()
	setConfig(t, s, "inv.key", "v1")

	r := override.NewResolver(s, s, override.WithCacheTTL(1*time.Minute))

	// Populate cache.
	val, _ := r.Resolve(bg(), "inv.key", testApp)
	if val != "v1" {
		t.Fatalf("got %v, want v1", val)
	}

	// Update config directly in the store.
	_ = s.SetConfig(bg(), &config.Entry{
		Entity: vault.NewEntity(),
		ID:     id.NewConfigID(),
		Key:    "inv.key",
		Value:  "v2",
		AppID:  testApp,
	})

	// Before invalidation, cache returns old value.
	cached, _ := r.Resolve(bg(), "inv.key", testApp)
	if cached != "v1" {
		t.Errorf("got %v, want v1 (cached)", cached)
	}

	// Invalidate.
	r.Invalidate("inv.key", testApp)

	// After invalidation, returns new value.
	fresh, err := r.Resolve(bg(), "inv.key", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if fresh != "v2" {
		t.Errorf("got %v, want v2 (after invalidation)", fresh)
	}
}

func TestResolveInvalidateAll(t *testing.T) {
	s := memory.New()
	setConfig(t, s, "k1", "a")
	setConfig(t, s, "k2", "b")

	r := override.NewResolver(s, s, override.WithCacheTTL(1*time.Minute))

	// Populate both in cache.
	_, _ = r.Resolve(bg(), "k1", testApp)
	_, _ = r.Resolve(bg(), "k2", testApp)

	// Update both in store.
	_ = s.SetConfig(bg(), &config.Entry{
		Entity: vault.NewEntity(), ID: id.NewConfigID(),
		Key: "k1", Value: "aa", AppID: testApp,
	})
	_ = s.SetConfig(bg(), &config.Entry{
		Entity: vault.NewEntity(), ID: id.NewConfigID(),
		Key: "k2", Value: "bb", AppID: testApp,
	})

	// InvalidateAll.
	r.InvalidateAll()

	v1, _ := r.Resolve(bg(), "k1", testApp)
	v2, _ := r.Resolve(bg(), "k2", testApp)

	if v1 != "aa" {
		t.Errorf("k1: got %v, want aa", v1)
	}
	if v2 != "bb" {
		t.Errorf("k2: got %v, want bb", v2)
	}
}

func TestResolverSatisfiesValueResolver(_ *testing.T) {
	s := memory.New()
	r := override.NewResolver(s, s)

	// Verify override.Resolver satisfies config.ValueResolver at compile time.
	var _ config.ValueResolver = r
}
