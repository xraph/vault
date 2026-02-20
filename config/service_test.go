package config_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xraph/vault"
	cfgpkg "github.com/xraph/vault/config"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/override"
	"github.com/xraph/vault/store/memory"
)

const testApp = "app1"

func bg() context.Context { return context.Background() }

func withTenant(tenantID string) context.Context {
	return context.WithValue(bg(), override.ContextKeyTenantID, tenantID)
}

func seedConfig(t *testing.T, s *memory.Store, key string, value any) {
	t.Helper()
	err := s.SetConfig(bg(), &cfgpkg.Entry{
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

func seedOverride(t *testing.T, s *memory.Store, key, tenantID string, value any) {
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

// ──────────────────────────────────────────────────
// Type-safe accessor tests (no resolver)
// ──────────────────────────────────────────────────

func TestServiceStringValue(t *testing.T) {
	s := memory.New()
	seedConfig(t, s, "app.name", "myapp")

	svc := cfgpkg.NewService(s, cfgpkg.WithAppID(testApp))
	got := svc.String(bg(), "app.name", "default")
	if got != "myapp" {
		t.Errorf("got %q, want %q", got, "myapp")
	}
}

func TestServiceStringDefault(t *testing.T) {
	s := memory.New()
	svc := cfgpkg.NewService(s, cfgpkg.WithAppID(testApp))

	got := svc.String(bg(), "missing", "fallback")
	if got != "fallback" {
		t.Errorf("got %q, want %q", got, "fallback")
	}
}

func TestServiceStringTypeMismatch(t *testing.T) {
	s := memory.New()
	seedConfig(t, s, "not.string", float64(42))

	svc := cfgpkg.NewService(s, cfgpkg.WithAppID(testApp))
	got := svc.String(bg(), "not.string", "default")
	if got != "default" {
		t.Errorf("got %q, want %q (type mismatch)", got, "default")
	}
}

func TestServiceBoolValue(t *testing.T) {
	s := memory.New()
	seedConfig(t, s, "feature.on", true)

	svc := cfgpkg.NewService(s, cfgpkg.WithAppID(testApp))
	got := svc.Bool(bg(), "feature.on", false)
	if got != true {
		t.Errorf("got %v, want true", got)
	}
}

func TestServiceBoolDefault(t *testing.T) {
	s := memory.New()
	svc := cfgpkg.NewService(s, cfgpkg.WithAppID(testApp))

	got := svc.Bool(bg(), "missing.bool", true)
	if got != true {
		t.Errorf("got %v, want true (default)", got)
	}
}

func TestServiceIntValue(t *testing.T) {
	s := memory.New()
	seedConfig(t, s, "pool.size", float64(25)) // JSON numbers are float64

	svc := cfgpkg.NewService(s, cfgpkg.WithAppID(testApp))
	got := svc.Int(bg(), "pool.size", 10)
	if got != 25 {
		t.Errorf("got %d, want 25", got)
	}
}

func TestServiceIntTypeMismatch(t *testing.T) {
	s := memory.New()
	seedConfig(t, s, "not.int", "hello")

	svc := cfgpkg.NewService(s, cfgpkg.WithAppID(testApp))
	got := svc.Int(bg(), "not.int", 99)
	if got != 99 {
		t.Errorf("got %d, want 99 (type mismatch)", got)
	}
}

func TestServiceFloatValue(t *testing.T) {
	s := memory.New()
	seedConfig(t, s, "threshold", float64(0.75))

	svc := cfgpkg.NewService(s, cfgpkg.WithAppID(testApp))
	got := svc.Float(bg(), "threshold", 0.5)
	if got != 0.75 {
		t.Errorf("got %f, want 0.75", got)
	}
}

func TestServiceDurationValue(t *testing.T) {
	s := memory.New()
	seedConfig(t, s, "timeout", "5s")

	svc := cfgpkg.NewService(s, cfgpkg.WithAppID(testApp))
	got := svc.Duration(bg(), "timeout", 1*time.Second)
	if got != 5*time.Second {
		t.Errorf("got %v, want 5s", got)
	}
}

func TestServiceDurationDefault(t *testing.T) {
	s := memory.New()
	svc := cfgpkg.NewService(s, cfgpkg.WithAppID(testApp))

	got := svc.Duration(bg(), "missing.dur", 10*time.Second)
	if got != 10*time.Second {
		t.Errorf("got %v, want 10s", got)
	}
}

func TestServiceDurationInvalidString(t *testing.T) {
	s := memory.New()
	seedConfig(t, s, "bad.dur", "not-a-duration")

	svc := cfgpkg.NewService(s, cfgpkg.WithAppID(testApp))
	got := svc.Duration(bg(), "bad.dur", 3*time.Second)
	if got != 3*time.Second {
		t.Errorf("got %v, want 3s (default on invalid)", got)
	}
}

func TestServiceJSONValue(t *testing.T) {
	s := memory.New()
	seedConfig(t, s, "limits", map[string]any{"max": float64(100), "min": float64(1)})

	svc := cfgpkg.NewService(s, cfgpkg.WithAppID(testApp))

	var result map[string]float64
	err := svc.JSON(bg(), "limits", &result)
	if err != nil {
		t.Fatal(err)
	}
	if result["max"] != 100 || result["min"] != 1 {
		t.Errorf("got %v, want {max:100, min:1}", result)
	}
}

func TestServiceJSONNotFound(t *testing.T) {
	s := memory.New()
	svc := cfgpkg.NewService(s, cfgpkg.WithAppID(testApp))

	var result map[string]any
	err := svc.JSON(bg(), "missing.json", &result)
	if err == nil {
		t.Fatal("expected error for missing config")
	}
}

// ──────────────────────────────────────────────────
// CRUD tests
// ──────────────────────────────────────────────────

func TestServiceSetAndGet(t *testing.T) {
	s := memory.New()
	svc := cfgpkg.NewService(s, cfgpkg.WithAppID(testApp))

	err := svc.Set(bg(), "new.key", "new-value", "")
	if err != nil {
		t.Fatal(err)
	}

	entry, err := svc.Get(bg(), "new.key", "")
	if err != nil {
		t.Fatal(err)
	}
	if entry.Key != "new.key" {
		t.Errorf("key: got %q, want %q", entry.Key, "new.key")
	}
	if entry.Value != "new-value" {
		t.Errorf("value: got %v, want %q", entry.Value, "new-value")
	}
	if entry.Version != 1 {
		t.Errorf("version: got %d, want 1", entry.Version)
	}
}

func TestServiceSetAutoVersioning(t *testing.T) {
	s := memory.New()
	svc := cfgpkg.NewService(s, cfgpkg.WithAppID(testApp))

	_ = svc.Set(bg(), "ver.key", "v1", "")
	_ = svc.Set(bg(), "ver.key", "v2", "")

	entry, err := svc.Get(bg(), "ver.key", "")
	if err != nil {
		t.Fatal(err)
	}
	if entry.Version != 2 {
		t.Errorf("version: got %d, want 2", entry.Version)
	}
	if entry.Value != "v2" {
		t.Errorf("value: got %v, want %q", entry.Value, "v2")
	}
}

func TestServiceSetInfersValueType(t *testing.T) {
	s := memory.New()
	svc := cfgpkg.NewService(s, cfgpkg.WithAppID(testApp))

	_ = svc.Set(bg(), "str.key", "hello", "")
	entry, _ := svc.Get(bg(), "str.key", "")
	if entry.ValueType != "string" {
		t.Errorf("got type %q, want %q", entry.ValueType, "string")
	}

	_ = svc.Set(bg(), "bool.key", true, "")
	entry2, _ := svc.Get(bg(), "bool.key", "")
	if entry2.ValueType != "bool" {
		t.Errorf("got type %q, want %q", entry2.ValueType, "bool")
	}

	_ = svc.Set(bg(), "float.key", float64(3.14), "")
	entry3, _ := svc.Get(bg(), "float.key", "")
	if entry3.ValueType != "float" {
		t.Errorf("got type %q, want %q", entry3.ValueType, "float")
	}
}

func TestServiceSetWithOptions(t *testing.T) {
	s := memory.New()
	svc := cfgpkg.NewService(s, cfgpkg.WithAppID(testApp))

	err := svc.Set(bg(), "opt.key", "val", "",
		cfgpkg.WithDescription("A config entry"),
		cfgpkg.WithValueType("string"),
		cfgpkg.WithMetadata(map[string]string{"env": "prod"}),
	)
	if err != nil {
		t.Fatal(err)
	}

	entry, _ := svc.Get(bg(), "opt.key", "")
	if entry.Description != "A config entry" {
		t.Errorf("description: got %q, want %q", entry.Description, "A config entry")
	}
	if entry.ValueType != "string" {
		t.Errorf("valueType: got %q, want %q", entry.ValueType, "string")
	}
	if entry.Metadata["env"] != "prod" {
		t.Errorf("metadata: got %v", entry.Metadata)
	}
}

func TestServiceDeleteAndGet(t *testing.T) {
	s := memory.New()
	svc := cfgpkg.NewService(s, cfgpkg.WithAppID(testApp))

	_ = svc.Set(bg(), "del.key", "value", "")
	err := svc.Delete(bg(), "del.key", "")
	if err != nil {
		t.Fatal(err)
	}

	_, err = svc.Get(bg(), "del.key", "")
	if err == nil {
		t.Fatal("expected error after delete")
	}
}

func TestServiceList(t *testing.T) {
	s := memory.New()
	svc := cfgpkg.NewService(s, cfgpkg.WithAppID(testApp))

	_ = svc.Set(bg(), "list.a", "a", "")
	_ = svc.Set(bg(), "list.b", "b", "")
	_ = svc.Set(bg(), "list.c", "c", "")

	entries, err := svc.List(bg(), "", cfgpkg.ListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Errorf("got %d entries, want 3", len(entries))
	}
}

// ──────────────────────────────────────────────────
// Watch tests
// ──────────────────────────────────────────────────

func TestServiceWatchFires(t *testing.T) {
	s := memory.New()
	svc := cfgpkg.NewService(s, cfgpkg.WithAppID(testApp))

	var callCount atomic.Int32
	var gotOld, gotNew any

	svc.Watch("watch.key", func(_ context.Context, _ string, oldValue, newValue any) {
		callCount.Add(1)
		gotOld = oldValue
		gotNew = newValue
	})

	// First set (no old value).
	_ = svc.Set(bg(), "watch.key", "first", "")
	if callCount.Load() != 1 {
		t.Errorf("call count: got %d, want 1", callCount.Load())
	}
	if gotOld != nil {
		t.Errorf("old: got %v, want nil", gotOld)
	}
	if gotNew != "first" {
		t.Errorf("new: got %v, want %q", gotNew, "first")
	}

	// Second set (has old value).
	_ = svc.Set(bg(), "watch.key", "second", "")
	if callCount.Load() != 2 {
		t.Errorf("call count: got %d, want 2", callCount.Load())
	}
	if gotOld != "first" {
		t.Errorf("old: got %v, want %q", gotOld, "first")
	}
	if gotNew != "second" {
		t.Errorf("new: got %v, want %q", gotNew, "second")
	}
}

func TestServiceWatchDoesNotFireForOtherKey(t *testing.T) {
	s := memory.New()
	svc := cfgpkg.NewService(s, cfgpkg.WithAppID(testApp))

	var callCount atomic.Int32
	svc.Watch("watched.key", func(_ context.Context, _ string, _, _ any) {
		callCount.Add(1)
	})

	_ = svc.Set(bg(), "other.key", "val", "")
	if callCount.Load() != 0 {
		t.Errorf("watch fired for wrong key: count=%d", callCount.Load())
	}
}

// ──────────────────────────────────────────────────
// Resolver integration tests
// ──────────────────────────────────────────────────

func TestServiceWithResolverTenantOverride(t *testing.T) {
	s := memory.New()
	seedConfig(t, s, "db.pool", float64(10))
	seedOverride(t, s, "db.pool", "t-1", float64(50))

	resolver := override.NewResolver(s, s)
	svc := cfgpkg.NewService(s,
		cfgpkg.WithAppID(testApp),
		cfgpkg.WithResolver(resolver),
	)

	// Tenant t-1 → override value.
	got := svc.Int(withTenant("t-1"), "db.pool", 0)
	if got != 50 {
		t.Errorf("got %d, want 50 (tenant override)", got)
	}

	// No tenant → app default.
	got2 := svc.Int(bg(), "db.pool", 0)
	if got2 != 10 {
		t.Errorf("got %d, want 10 (app default)", got2)
	}
}

func TestServiceWithResolverNoOverride(t *testing.T) {
	s := memory.New()
	seedConfig(t, s, "feature.limit", float64(100))

	resolver := override.NewResolver(s, s)
	svc := cfgpkg.NewService(s,
		cfgpkg.WithAppID(testApp),
		cfgpkg.WithResolver(resolver),
	)

	// Tenant with no override → app default.
	got := svc.Int(withTenant("t-2"), "feature.limit", 0)
	if got != 100 {
		t.Errorf("got %d, want 100 (fall back to app default)", got)
	}
}

func TestServiceSetInvalidatesResolverCache(t *testing.T) {
	s := memory.New()
	seedConfig(t, s, "cached.cfg", "original")

	resolver := override.NewResolver(s, s, override.WithCacheTTL(1*time.Minute))
	svc := cfgpkg.NewService(s,
		cfgpkg.WithAppID(testApp),
		cfgpkg.WithResolver(resolver),
	)

	// Read to populate cache.
	got := svc.String(bg(), "cached.cfg", "")
	if got != "original" {
		t.Fatalf("got %q, want %q", got, "original")
	}

	// Update through service (should invalidate cache).
	_ = svc.Set(bg(), "cached.cfg", "updated", "")

	// Read again → should see updated value.
	got2 := svc.String(bg(), "cached.cfg", "")
	if got2 != "updated" {
		t.Errorf("got %q, want %q (after cache invalidation)", got2, "updated")
	}
}
