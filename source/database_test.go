package source_test

import (
	"errors"
	"testing"

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
