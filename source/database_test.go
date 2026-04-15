package source_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xraph/vault"
	"github.com/xraph/vault/config"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/source"
	"github.com/xraph/vault/store/memory"
)

func TestDatabaseGet(t *testing.T) {
	store := memory.New()
	_ = store.SetConfig(bg(), &config.Entry{
		Entity: vault.NewEntity(),
		ID:     id.NewConfigID(),
		Key:    "timeout",
		Value:  "30",
		AppID:  "app1",
	})

	db := source.NewDatabase(store, "app1")
	val, err := db.Get(bg(), "timeout")
	if err != nil {
		t.Fatal(err)
	}
	if val.Raw != "30" {
		t.Errorf("Raw = %q, want %q", val.Raw, "30")
	}
	if val.Source != "database" {
		t.Errorf("Source = %q", val.Source)
	}
	if val.Version != 1 {
		t.Errorf("Version = %d, want 1", val.Version)
	}
}

func TestDatabaseGetMissing(t *testing.T) {
	store := memory.New()
	db := source.NewDatabase(store, "app1")

	_, err := db.Get(bg(), "missing")
	if !errors.Is(err, source.ErrKeyNotFound) {
		t.Errorf("got %v, want ErrKeyNotFound", err)
	}
}

func TestDatabaseList(t *testing.T) {
	store := memory.New()
	for _, key := range []string{"db.host", "db.port", "app.name"} {
		_ = store.SetConfig(bg(), &config.Entry{
			Entity: vault.NewEntity(),
			ID:     id.NewConfigID(),
			Key:    key,
			Value:  "val",
			AppID:  "app1",
		})
	}

	db := source.NewDatabase(store, "app1")

	// List with prefix.
	vals, err := db.List(bg(), "db.")
	if err != nil {
		t.Fatal(err)
	}
	if len(vals) != 2 {
		t.Errorf("len = %d, want 2", len(vals))
	}

	// List all.
	all, err := db.List(bg(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Errorf("len = %d, want 3", len(all))
	}
}

func TestDatabaseName(t *testing.T) {
	db := source.NewDatabase(memory.New(), "app1")
	if db.Name() != "database" {
		t.Errorf("Name = %q", db.Name())
	}
}

func TestDatabaseWatchDetectsChange(t *testing.T) {
	store := memory.New()
	_ = store.SetConfig(bg(), &config.Entry{
		Entity: vault.NewEntity(),
		ID:     id.NewConfigID(),
		Key:    "watch.key",
		Value:  "original",
		AppID:  "app1",
	})

	db := source.NewDatabase(store, "app1", source.WithPollInterval(50*time.Millisecond))
	defer db.Close()

	var called atomic.Int32
	var lastRaw atomic.Value

	err := db.Watch(bg(), "watch.key", func(_ context.Context, _ string, val *source.Value) {
		called.Add(1)
		if val != nil {
			lastRaw.Store(val.Raw)
		}
	})
	if err != nil {
		t.Fatal(err)
	}

	// Update the config entry — version bumps from 1 to 2.
	_ = store.SetConfig(bg(), &config.Entry{
		Entity: vault.NewEntity(),
		ID:     id.NewConfigID(),
		Key:    "watch.key",
		Value:  "updated",
		AppID:  "app1",
	})

	// Wait for poll to detect the change.
	time.Sleep(200 * time.Millisecond)

	if called.Load() < 1 {
		t.Errorf("watch called %d times, want >= 1", called.Load())
	}
	if raw, ok := lastRaw.Load().(string); !ok || raw != "updated" {
		t.Errorf("last raw = %v, want %q", lastRaw.Load(), "updated")
	}
}

func TestDatabaseWatchDetectsDelete(t *testing.T) {
	store := memory.New()
	_ = store.SetConfig(bg(), &config.Entry{
		Entity: vault.NewEntity(),
		ID:     id.NewConfigID(),
		Key:    "del.key",
		Value:  "exists",
		AppID:  "app1",
	})

	db := source.NewDatabase(store, "app1", source.WithPollInterval(50*time.Millisecond))
	defer db.Close()

	var gotNil atomic.Bool
	err := db.Watch(bg(), "del.key", func(_ context.Context, _ string, val *source.Value) {
		if val == nil {
			gotNil.Store(true)
		}
	})
	if err != nil {
		t.Fatal(err)
	}

	_ = store.DeleteConfig(bg(), "del.key", "app1")

	time.Sleep(200 * time.Millisecond)

	if !gotNil.Load() {
		t.Error("expected watcher to fire with nil value after delete")
	}
}

func TestDatabaseWatchNoFalsePositive(t *testing.T) {
	store := memory.New()
	_ = store.SetConfig(bg(), &config.Entry{
		Entity: vault.NewEntity(),
		ID:     id.NewConfigID(),
		Key:    "stable.key",
		Value:  "unchanged",
		AppID:  "app1",
	})

	db := source.NewDatabase(store, "app1", source.WithPollInterval(50*time.Millisecond))
	defer db.Close()

	var called atomic.Int32
	err := db.Watch(bg(), "stable.key", func(_ context.Context, _ string, _ *source.Value) {
		called.Add(1)
	})
	if err != nil {
		t.Fatal(err)
	}

	// Don't change anything — wait several poll intervals.
	time.Sleep(200 * time.Millisecond)

	if called.Load() != 0 {
		t.Errorf("watch called %d times, want 0", called.Load())
	}
}

func TestDatabaseWatchMultipleKeys(t *testing.T) {
	store := memory.New()
	for _, key := range []string{"key.a", "key.b"} {
		_ = store.SetConfig(bg(), &config.Entry{
			Entity: vault.NewEntity(),
			ID:     id.NewConfigID(),
			Key:    key,
			Value:  "v1",
			AppID:  "app1",
		})
	}

	db := source.NewDatabase(store, "app1", source.WithPollInterval(50*time.Millisecond))
	defer db.Close()

	var calledA, calledB atomic.Int32
	_ = db.Watch(bg(), "key.a", func(_ context.Context, _ string, _ *source.Value) {
		calledA.Add(1)
	})
	_ = db.Watch(bg(), "key.b", func(_ context.Context, _ string, _ *source.Value) {
		calledB.Add(1)
	})

	// Only change key.a.
	_ = store.SetConfig(bg(), &config.Entry{
		Entity: vault.NewEntity(),
		ID:     id.NewConfigID(),
		Key:    "key.a",
		Value:  "v2",
		AppID:  "app1",
	})

	time.Sleep(200 * time.Millisecond)

	if calledA.Load() < 1 {
		t.Errorf("key.a watcher called %d times, want >= 1", calledA.Load())
	}
	if calledB.Load() != 0 {
		t.Errorf("key.b watcher called %d times, want 0", calledB.Load())
	}
}

func TestDatabaseClose(t *testing.T) {
	store := memory.New()
	_ = store.SetConfig(bg(), &config.Entry{
		Entity: vault.NewEntity(),
		ID:     id.NewConfigID(),
		Key:    "close.key",
		Value:  "v",
		AppID:  "app1",
	})

	db := source.NewDatabase(store, "app1", source.WithPollInterval(50*time.Millisecond))

	_ = db.Watch(bg(), "close.key", func(_ context.Context, _ string, _ *source.Value) {})

	// Close should return without hanging.
	done := make(chan struct{})
	go func() {
		_ = db.Close()
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("Close() did not return in time")
	}
}
