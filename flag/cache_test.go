package flag

import (
	"testing"
	"time"
)

func TestCacheSetGet(t *testing.T) {
	c := newEvaluationCache(5 * time.Minute)
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
	c := newEvaluationCache(5 * time.Minute)

	_, ok := c.get("flag1", "app", "tenant-a", "")
	if ok {
		t.Error("expected cache miss")
	}
}

func TestCacheDifferentTenants(t *testing.T) {
	c := newEvaluationCache(5 * time.Minute)
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
	c := newEvaluationCache(5 * time.Minute)
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
	c := newEvaluationCache(5 * time.Minute)
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
	c := newEvaluationCache(5 * time.Minute)
	c.set("flag1", "ab", "c", "", "v")

	if _, ok := c.get("flag1", "a", "bc", ""); ok {
		t.Error("(app ab, tenant c) and (app a, tenant bc) share a key")
	}
}

func TestCacheEmptyTenantID(t *testing.T) {
	c := newEvaluationCache(5 * time.Minute)
	c.set("flag1", "app", "", "", "global-val")

	val, ok := c.get("flag1", "app", "", "")
	if !ok || val != "global-val" {
		t.Errorf("got %v, want global-val", val)
	}
}

func TestCacheTTLExpiry(t *testing.T) {
	c := newEvaluationCache(1 * time.Millisecond)
	c.set("flag1", "app", "t", "", "val")

	// Wait for expiry.
	time.Sleep(5 * time.Millisecond)

	_, ok := c.get("flag1", "app", "t", "")
	if ok {
		t.Error("expected cache miss after TTL expiry")
	}
}

func TestCacheInvalidateFlag(t *testing.T) {
	c := newEvaluationCache(5 * time.Minute)
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
	c := newEvaluationCache(5 * time.Minute)
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
	c := newEvaluationCache(5 * time.Minute)
	c.set("flag1", "app", "t", "", "old")
	c.set("flag1", "app", "t", "", "new")

	val, ok := c.get("flag1", "app", "t", "")
	if !ok || val != "new" {
		t.Errorf("got %v, want %q (overwritten)", val, "new")
	}
}
