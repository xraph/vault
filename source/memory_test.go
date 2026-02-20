package source_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/xraph/vault/source"
)

func TestMemorySetGet(t *testing.T) {
	m := source.NewMemory()
	m.Set(bg(), "key1", "value1")

	val, err := m.Get(bg(), "key1")
	if err != nil {
		t.Fatal(err)
	}
	if val.Raw != "value1" {
		t.Errorf("Raw = %q", val.Raw)
	}
	if val.Source != "memory" {
		t.Errorf("Source = %q", val.Source)
	}
}

func TestMemoryGetMissing(t *testing.T) {
	m := source.NewMemory()
	_, err := m.Get(bg(), "missing")
	if !errors.Is(err, source.ErrKeyNotFound) {
		t.Errorf("got %v, want ErrKeyNotFound", err)
	}
}

func TestMemoryList(t *testing.T) {
	m := source.NewMemory()
	m.Set(bg(), "app.host", "localhost")
	m.Set(bg(), "app.port", "8080")
	m.Set(bg(), "db.host", "dbhost")

	// List with prefix.
	vals, err := m.List(bg(), "app.")
	if err != nil {
		t.Fatal(err)
	}
	if len(vals) != 2 {
		t.Errorf("len = %d, want 2", len(vals))
	}

	// List all.
	all, err := m.List(bg(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Errorf("len = %d, want 3", len(all))
	}
}

func TestMemoryWatch(t *testing.T) {
	m := source.NewMemory()

	var called atomic.Int32
	err := m.Watch(bg(), "watched-key", func(_ context.Context, _ string, _ *source.Value) {
		called.Add(1)
	})
	if err != nil {
		t.Fatal(err)
	}

	m.Set(bg(), "watched-key", "new-value")

	if called.Load() != 1 {
		t.Errorf("watch called %d times, want 1", called.Load())
	}

	// Setting a different key should NOT trigger the watcher.
	m.Set(bg(), "other-key", "val")
	if called.Load() != 1 {
		t.Errorf("watch called %d times, want still 1", called.Load())
	}
}

func TestMemoryGetReturnsCopy(t *testing.T) {
	m := source.NewMemory()
	m.Set(bg(), "k", "original")

	v1, _ := m.Get(bg(), "k")
	v1.Raw = "mutated"

	v2, _ := m.Get(bg(), "k")
	if v2.Raw != "original" {
		t.Error("Get should return a copy, not a reference")
	}
}
