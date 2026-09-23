package flag

import (
	"fmt"
	"testing"
	"time"
)

func TestCacheSetGet(t *testing.T) {
	c := newEvaluationCache(5*time.Minute, 0)
	c.set("flag1", "app", "tenant-a", "", "value1")

	val, ok := c.get("flag1", "app", "tenant-a", "")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if val != "value1" {
		t.Errorf("got %v, want %q", val, "value1")
	}
}

func TestCacheMiss(t *testing.T) {
	c := newEvaluationCache(5*time.Minute, 0)

	_, ok := c.get("flag1", "app", "tenant-a", "")
	if ok {
		t.Error("expected cache miss")
	}
}

func TestCacheDifferentTenants(t *testing.T) {
	c := newEvaluationCache(5*time.Minute, 0)
	c.set("flag1", "app", "tenant-a", "", "val-a")
	c.set("flag1", "app", "tenant-b", "", "val-b")

	valA, ok := c.get("flag1", "app", "tenant-a", "")
	if !ok || valA != "val-a" {
		t.Errorf("tenant-a: got %v, want val-a", valA)
	}
	valB, ok := c.get("flag1", "app", "tenant-b", "")
	if !ok || valB != "val-b" {
		t.Errorf("tenant-b: got %v, want val-b", valB)
	}
}

func TestCacheDifferentApps(t *testing.T) {
	c := newEvaluationCache(5*time.Minute, 0)
	c.set("flag1", "app-a", "t", "", "val-a")

	if val, ok := c.get("flag1", "app-b", "t", ""); ok {
		t.Errorf("app-b hit app-a's entry: got %v", val)
	}

	c.set("flag1", "app-b", "t", "", "val-b")
	valA, ok := c.get("flag1", "app-a", "t", "")
	if !ok || valA != "val-a" {
		t.Errorf("app-a: got %v, want val-a", valA)
	}
	valB, ok := c.get("flag1", "app-b", "t", "")
	if !ok || valB != "val-b" {
		t.Errorf("app-b: got %v, want val-b", valB)
	}
}

func TestCacheDifferentUsers(t *testing.T) {
	c := newEvaluationCache(5*time.Minute, 0)
	c.set("flag1", "app", "t", "u-1", "val-1")

	if val, ok := c.get("flag1", "app", "t", "u-2"); ok {
		t.Errorf("u-2 hit u-1's entry: got %v", val)
	}
	if val, ok := c.get("flag1", "app", "t", ""); ok {
		t.Errorf("no user hit u-1's entry: got %v", val)
	}
}

// The separator must keep fields apart, so that shifting characters from
// one field into the next cannot collide.
func TestCacheKeyFieldsDoNotRunTogether(t *testing.T) {
	c := newEvaluationCache(5*time.Minute, 0)
	c.set("flag1", "ab", "c", "", "v")

	if _, ok := c.get("flag1", "a", "bc", ""); ok {
		t.Error("(app ab, tenant c) and (app a, tenant bc) share a key")
	}
}

func TestCacheEmptyTenantID(t *testing.T) {
	c := newEvaluationCache(5*time.Minute, 0)
	c.set("flag1", "app", "", "", "global-val")

	val, ok := c.get("flag1", "app", "", "")
	if !ok || val != "global-val" {
		t.Errorf("got %v, want global-val", val)
	}
}

func TestCacheTTLExpiry(t *testing.T) {
	c := newEvaluationCache(1*time.Millisecond, 0)
	c.set("flag1", "app", "t", "", "val")

	// Wait for expiry.
	time.Sleep(5 * time.Millisecond)

	_, ok := c.get("flag1", "app", "t", "")
	if ok {
		t.Error("expected cache miss after TTL expiry")
	}
}

func TestCacheInvalidateFlag(t *testing.T) {
	c := newEvaluationCache(5*time.Minute, 0)
	c.set("flag1", "app", "t-1", "", "v1")
	c.set("flag1", "app", "t-2", "", "v2")
	c.set("flag1", "other-app", "t-1", "u-1", "v4")
	c.set("flag2", "app", "t-1", "", "v3")
	c.set("flag10", "app", "t-1", "", "v5")

	// Invalidate all entries for flag1, across every app, tenant and user.
	c.invalidate("flag1")

	_, ok1 := c.get("flag1", "app", "t-1", "")
	_, ok2 := c.get("flag1", "app", "t-2", "")
	_, ok4 := c.get("flag1", "other-app", "t-1", "u-1")
	if ok1 || ok2 || ok4 {
		t.Error("expected flag1 entries to be invalidated")
	}

	// flag2 should still be cached.
	val, ok := c.get("flag2", "app", "t-1", "")
	if !ok || val != "v3" {
		t.Errorf("flag2 should still be cached: %v, %v", val, ok)
	}

	// flag10 shares flag1's leading characters and must survive too.
	val, ok = c.get("flag10", "app", "t-1", "")
	if !ok || val != "v5" {
		t.Errorf("flag10 should still be cached: %v, %v", val, ok)
	}
}

func TestCacheInvalidateAll(t *testing.T) {
	c := newEvaluationCache(5*time.Minute, 0)
	c.set("flag1", "app", "t-1", "", "v1")
	c.set("flag2", "app", "t-2", "", "v2")

	c.invalidateAll()

	_, ok1 := c.get("flag1", "app", "t-1", "")
	_, ok2 := c.get("flag2", "app", "t-2", "")
	if ok1 || ok2 {
		t.Error("expected all entries to be invalidated")
	}
}

func TestCacheOverwrite(t *testing.T) {
	c := newEvaluationCache(5*time.Minute, 0)
	c.set("flag1", "app", "t", "", "old")
	c.set("flag1", "app", "t", "", "new")

	val, ok := c.get("flag1", "app", "t", "")
	if !ok || val != "new" {
		t.Errorf("got %v, want %q (overwritten)", val, "new")
	}
}

// The cache is never allowed to grow past its cap, no matter how many
// distinct keys come through: since the key includes the user, an
// unbounded cache grows by one entry per user forever.
func TestCacheNeverExceedsItsCap(t *testing.T) {
	c := newEvaluationCache(5*time.Minute, 100)

	for i := 0; i < 1000; i++ {
		c.set("flag1", "app", "t", fmt.Sprintf("u-%d", i), i)
		if len(c.entries) > 100 {
			t.Fatalf("after %d sets: len(entries) = %d, want <= 100", i+1, len(c.entries))
		}
	}
}

// When set hits the cap, it sweeps expired entries first, and only clears
// the whole map if that sweep was not enough. The population here is
// deliberately mixed (half expired, half still live) so that sweep-then-
// clear and always-clear give different, distinguishable results: if the
// test only checked that the map ended up small with the fresh entry
// present, an implementation that dropped the sweep and always cleared on
// cap would pass it too.
func TestCacheSweepsExpiredBeforeClearing(t *testing.T) {
	c := newEvaluationCache(time.Minute, 10)

	// Seed the map directly, with no sleeping: five entries that expired an
	// hour ago and five that stay live for another hour. Together they fill
	// the cache to its cap exactly.
	now := time.Now()
	for i := 0; i < 5; i++ {
		c.entries[cacheKey("flag1", "app", "t", fmt.Sprintf("expired-%d", i))] = cacheEntry{
			value:     i,
			expiresAt: now.Add(-time.Hour),
		}
		c.entries[cacheKey("flag1", "app", "t", fmt.Sprintf("live-%d", i))] = cacheEntry{
			value:     i,
			expiresAt: now.Add(time.Hour),
		}
	}
	if len(c.entries) != 10 {
		t.Fatalf("len(entries) = %d, want 10 (5 expired + 5 live) before the triggering set", len(c.entries))
	}

	// This set finds the cache at cap (10 entries, 5 expired). Sweep-then-
	// clear removes only the 5 expired ones, which is enough, so the 5 live
	// ones survive. Always-clear would drop them too.
	c.set("flag1", "app", "t", "fresh", "fresh-val")

	for i := 0; i < 5; i++ {
		if _, ok := c.entries[cacheKey("flag1", "app", "t", fmt.Sprintf("expired-%d", i))]; ok {
			t.Errorf("expired-%d should have been swept", i)
		}
	}
	for i := 0; i < 5; i++ {
		if _, ok := c.entries[cacheKey("flag1", "app", "t", fmt.Sprintf("live-%d", i))]; !ok {
			t.Errorf("live-%d should have survived: only expired entries are dropped by a sweep", i)
		}
	}
	entry, ok := c.entries[cacheKey("flag1", "app", "t", "fresh")]
	if !ok || entry.value != "fresh-val" {
		t.Fatalf("fresh entry missing or wrong: %+v, ok=%v", entry, ok)
	}
	if len(c.entries) != 6 {
		t.Fatalf("len(entries) = %d, want 6 (5 live + fresh, 5 expired swept)", len(c.entries))
	}
}

// WithCacheMaxEntries must take effect whether it is applied before or
// after WithCacheTTL: options must not silently overwrite each other's work.
func TestCacheMaxEntriesOptionOrderIndependent(t *testing.T) {
	maxFirst := NewEngine(nil, WithCacheMaxEntries(50), WithCacheTTL(time.Minute))
	if maxFirst.cache == nil {
		t.Fatal("maxEntries-then-TTL: expected a cache to be configured")
	}
	if maxFirst.cache.maxEntries != 50 {
		t.Errorf("maxEntries-then-TTL: got maxEntries %d, want 50", maxFirst.cache.maxEntries)
	}

	ttlFirst := NewEngine(nil, WithCacheTTL(time.Minute), WithCacheMaxEntries(50))
	if ttlFirst.cache == nil {
		t.Fatal("TTL-then-maxEntries: expected a cache to be configured")
	}
	if ttlFirst.cache.maxEntries != 50 {
		t.Errorf("TTL-then-maxEntries: got maxEntries %d, want 50", ttlFirst.cache.maxEntries)
	}
}

// An evaluation reads the generation before it reads the store. If an
// invalidate lands before it writes its result back, that result came from
// a store read the invalidate has overtaken, so setIfGen must drop it. The
// generation is driven directly here, so the interleaving is exact and the
// test cannot pass or fail on timing.
func TestInvalidateWinsAgainstAnInFlightEvaluate(t *testing.T) {
	c := newEvaluationCache(time.Hour, 10)

	// invalidate: a stale generation stores nothing.
	stale := c.generation()
	c.invalidate("flag1")
	c.setIfGen("flag1", "app", "t", "u", "old", stale)
	if _, ok := c.entries[cacheKey("flag1", "app", "t", "u")]; ok {
		t.Fatal("setIfGen stored a value read before invalidate ran")
	}
	if _, ok := c.get("flag1", "app", "t", "u"); ok {
		t.Fatal("get hit on a value read before invalidate ran")
	}

	// invalidateAll moves the generation too.
	stale = c.generation()
	c.invalidateAll()
	c.setIfGen("flag1", "app", "t", "u", "old", stale)
	if len(c.entries) != 0 {
		t.Fatalf("setIfGen stored a value read before invalidateAll ran: %d entries", len(c.entries))
	}

	// With nothing in between, the same call stores the value. Without
	// this, a setIfGen that never stored anything would pass the checks
	// above.
	current := c.generation()
	c.setIfGen("flag1", "app", "t", "u", "new", current)
	if val, ok := c.get("flag1", "app", "t", "u"); !ok || val != "new" {
		t.Fatalf("get = %v, %v; want %q, true for a generation nothing overtook", val, ok, "new")
	}
}
