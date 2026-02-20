package flag

import (
	"testing"
	"time"
)

func TestCacheSetGet(t *testing.T) {
	c := newEvaluationCache(5 * time.Minute)
	c.set("flag1", "tenant-a", "value1")

	val, ok := c.get("flag1", "tenant-a")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if val != "value1" {
		t.Errorf("got %v, want %q", val, "value1")
	}
}

func TestCacheMiss(t *testing.T) {
	c := newEvaluationCache(5 * time.Minute)

	_, ok := c.get("flag1", "tenant-a")
	if ok {
		t.Error("expected cache miss")
	}
}

func TestCacheDifferentTenants(t *testing.T) {
	c := newEvaluationCache(5 * time.Minute)
	c.set("flag1", "tenant-a", "val-a")
	c.set("flag1", "tenant-b", "val-b")

	valA, ok := c.get("flag1", "tenant-a")
	if !ok || valA != "val-a" {
		t.Errorf("tenant-a: got %v, want val-a", valA)
	}
	valB, ok := c.get("flag1", "tenant-b")
	if !ok || valB != "val-b" {
		t.Errorf("tenant-b: got %v, want val-b", valB)
	}
}

func TestCacheEmptyTenantID(t *testing.T) {
	c := newEvaluationCache(5 * time.Minute)
	c.set("flag1", "", "global-val")

	val, ok := c.get("flag1", "")
	if !ok || val != "global-val" {
		t.Errorf("got %v, want global-val", val)
	}
}

func TestCacheTTLExpiry(t *testing.T) {
	c := newEvaluationCache(1 * time.Millisecond)
	c.set("flag1", "t", "val")

	// Wait for expiry.
	time.Sleep(5 * time.Millisecond)

	_, ok := c.get("flag1", "t")
	if ok {
		t.Error("expected cache miss after TTL expiry")
	}
}

func TestCacheInvalidateFlag(t *testing.T) {
	c := newEvaluationCache(5 * time.Minute)
	c.set("flag1", "t-1", "v1")
	c.set("flag1", "t-2", "v2")
	c.set("flag2", "t-1", "v3")

	// Invalidate all entries for flag1.
	c.invalidate("flag1")

	_, ok1 := c.get("flag1", "t-1")
	_, ok2 := c.get("flag1", "t-2")
	if ok1 || ok2 {
		t.Error("expected flag1 entries to be invalidated")
	}

	// flag2 should still be cached.
	val, ok := c.get("flag2", "t-1")
	if !ok || val != "v3" {
		t.Errorf("flag2 should still be cached: %v, %v", val, ok)
	}
}

func TestCacheInvalidateAll(t *testing.T) {
	c := newEvaluationCache(5 * time.Minute)
	c.set("flag1", "t-1", "v1")
	c.set("flag2", "t-2", "v2")

	c.invalidateAll()

	_, ok1 := c.get("flag1", "t-1")
	_, ok2 := c.get("flag2", "t-2")
	if ok1 || ok2 {
		t.Error("expected all entries to be invalidated")
	}
}

func TestCacheOverwrite(t *testing.T) {
	c := newEvaluationCache(5 * time.Minute)
	c.set("flag1", "t", "old")
	c.set("flag1", "t", "new")

	val, ok := c.get("flag1", "t")
	if !ok || val != "new" {
		t.Errorf("got %v, want %q (overwritten)", val, "new")
	}
}
