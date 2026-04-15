package confy_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xraph/vault"
	"github.com/xraph/vault/config"
	vaultconfy "github.com/xraph/vault/confy"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/secret"
	"github.com/xraph/vault/store/memory"
)

func bg() context.Context { return context.Background() }

func TestVaultConfigSourceLoad(t *testing.T) {
	store := memory.New()
	for _, kv := range []struct{ k, v string }{
		{"db.host", "localhost"},
		{"db.port", "5432"},
		{"app.name", "myapp"},
	} {
		_ = store.SetConfig(bg(), &config.Entry{
			Entity: vault.NewEntity(),
			ID:     id.NewConfigID(),
			Key:    kv.k,
			Value:  kv.v,
			AppID:  "app1",
		})
	}

	src := vaultconfy.NewVaultConfigSource(store, store, "app1")
	data, err := src.Load(bg())
	if err != nil {
		t.Fatal(err)
	}

	if len(data) != 3 {
		t.Errorf("len = %d, want 3", len(data))
	}
	if data["db.host"] != "localhost" {
		t.Errorf("db.host = %v", data["db.host"])
	}
}

func TestVaultConfigSourceWatch(t *testing.T) {
	store := memory.New()
	_ = store.SetConfig(bg(), &config.Entry{
		Entity: vault.NewEntity(),
		ID:     id.NewConfigID(),
		Key:    "watched",
		Value:  "original",
		AppID:  "app1",
	})

	src := vaultconfy.NewVaultConfigSource(store, store, "app1",
		vaultconfy.WithSourcePollInterval(50*time.Millisecond),
	)

	// Load initial state so lastSnapshot is seeded.
	_, _ = src.Load(bg())

	var callCount atomic.Int32
	err := src.Watch(bg(), func(_ map[string]any) {
		callCount.Add(1)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer src.StopWatch()

	// Update config.
	_ = store.SetConfig(bg(), &config.Entry{
		Entity: vault.NewEntity(),
		ID:     id.NewConfigID(),
		Key:    "watched",
		Value:  "updated",
		AppID:  "app1",
	})

	time.Sleep(200 * time.Millisecond)

	if callCount.Load() < 1 {
		t.Errorf("watch callback called %d times, want >= 1", callCount.Load())
	}
}

func TestVaultConfigSourceStopWatch(t *testing.T) {
	store := memory.New()
	src := vaultconfy.NewVaultConfigSource(store, store, "app1",
		vaultconfy.WithSourcePollInterval(50*time.Millisecond),
	)

	watchErr := src.Watch(bg(), func(_ map[string]any) {})
	if watchErr != nil {
		t.Fatal(watchErr)
	}

	if stopErr := src.StopWatch(); stopErr != nil {
		t.Fatal(stopErr)
	}

	// Watching again after stop should succeed.
	watchErr = src.Watch(bg(), func(_ map[string]any) {})
	if watchErr != nil {
		t.Errorf("Watch after StopWatch failed: %v", watchErr)
	}
	_ = src.StopWatch()
}

func TestVaultConfigSourceGetSecret(t *testing.T) {
	store := memory.New()
	_ = store.SetSecret(bg(), &secret.Secret{
		Entity: vault.NewEntity(),
		ID:     id.NewSecretID(),
		Key:    "db_password",
		Value:  []byte("s3cret"),
		AppID:  "app1",
	})

	src := vaultconfy.NewVaultConfigSource(store, store, "app1")
	val, err := src.GetSecret(bg(), "db_password")
	if err != nil {
		t.Fatal(err)
	}
	if val != "s3cret" {
		t.Errorf("secret = %q, want %q", val, "s3cret")
	}
}

func TestVaultConfigSourceReload(t *testing.T) {
	store := memory.New()
	src := vaultconfy.NewVaultConfigSource(store, store, "app1")

	// Reload on empty store should work.
	if err := src.Reload(bg()); err != nil {
		t.Fatal(err)
	}
}

func TestVaultConfigSourceMetadata(t *testing.T) {
	store := memory.New()
	src := vaultconfy.NewVaultConfigSource(store, store, "app1",
		vaultconfy.WithSourceName("vault:config"),
		vaultconfy.WithSourcePriority(200),
	)

	if src.Name() != "vault:config" {
		t.Errorf("Name = %q", src.Name())
	}
	if src.GetName() != "vault:config" {
		t.Errorf("GetName = %q", src.GetName())
	}
	if src.GetType() != "vault" {
		t.Errorf("GetType = %q", src.GetType())
	}
	if src.Priority() != 200 {
		t.Errorf("Priority = %d", src.Priority())
	}
	if !src.IsWatchable() {
		t.Error("IsWatchable = false")
	}
	if !src.SupportsSecrets() {
		t.Error("SupportsSecrets = false")
	}
}

func TestVaultConfigSourceIsAvailable(t *testing.T) {
	store := memory.New()
	src := vaultconfy.NewVaultConfigSource(store, store, "app1")
	if !src.IsAvailable(bg()) {
		t.Error("IsAvailable = false, want true")
	}
}

func seedConfigs(t *testing.T, store *memory.Store, keys []string) {
	t.Helper()
	for _, k := range keys {
		_ = store.SetConfig(bg(), &config.Entry{
			Entity: vault.NewEntity(),
			ID:     id.NewConfigID(),
			Key:    k,
			Value:  "val:" + k,
			AppID:  "app1",
		})
	}
}

func TestVaultConfigSourceKeyPrefix(t *testing.T) {
	store := memory.New()
	seedConfigs(t, store, []string{"db.host", "db.port"})

	src := vaultconfy.NewVaultConfigSource(store, store, "app1",
		vaultconfy.WithKeyPrefix("vault."),
	)
	data, err := src.Load(bg())
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := data["vault.db.host"]; !ok {
		t.Error("expected key 'vault.db.host', not found")
	}
	if _, ok := data["db.host"]; ok {
		t.Error("key 'db.host' should not exist when prefix is set")
	}
	if len(data) != 2 {
		t.Errorf("len = %d, want 2", len(data))
	}
}

func TestVaultConfigSourceWithKeys(t *testing.T) {
	store := memory.New()
	seedConfigs(t, store, []string{"db.host", "db.port", "app.name", "app.version"})

	src := vaultconfy.NewVaultConfigSource(store, store, "app1",
		vaultconfy.WithKeys("db.host", "app.name"),
	)
	data, err := src.Load(bg())
	if err != nil {
		t.Fatal(err)
	}

	if len(data) != 2 {
		t.Errorf("len = %d, want 2", len(data))
	}
	if _, ok := data["db.host"]; !ok {
		t.Error("expected 'db.host'")
	}
	if _, ok := data["app.name"]; !ok {
		t.Error("expected 'app.name'")
	}
	if _, ok := data["db.port"]; ok {
		t.Error("'db.port' should be filtered out")
	}
}

func TestVaultConfigSourceWithPatterns(t *testing.T) {
	store := memory.New()
	seedConfigs(t, store, []string{"db.host", "db.port", "app.name", "cache.ttl"})

	src := vaultconfy.NewVaultConfigSource(store, store, "app1",
		vaultconfy.WithKeyPatterns("db.*"),
	)
	data, err := src.Load(bg())
	if err != nil {
		t.Fatal(err)
	}

	if len(data) != 2 {
		t.Errorf("len = %d, want 2", len(data))
	}
	if _, ok := data["db.host"]; !ok {
		t.Error("expected 'db.host'")
	}
	if _, ok := data["app.name"]; ok {
		t.Error("'app.name' should be filtered out")
	}
}

func TestVaultConfigSourceKeysAndPatternsCombined(t *testing.T) {
	store := memory.New()
	seedConfigs(t, store, []string{"db.host", "db.port", "app.name", "cache.ttl", "auth.token"})

	// Whitelist "cache.ttl" explicitly + pattern "db.*" — should include both.
	src := vaultconfy.NewVaultConfigSource(store, store, "app1",
		vaultconfy.WithKeys("cache.ttl"),
		vaultconfy.WithKeyPatterns("db.*"),
	)
	data, err := src.Load(bg())
	if err != nil {
		t.Fatal(err)
	}

	if len(data) != 3 {
		t.Errorf("len = %d, want 3 (db.host, db.port, cache.ttl)", len(data))
	}
	for _, k := range []string{"db.host", "db.port", "cache.ttl"} {
		if _, ok := data[k]; !ok {
			t.Errorf("expected key %q", k)
		}
	}
	if _, ok := data["app.name"]; ok {
		t.Error("'app.name' should be filtered out")
	}
}

func TestVaultConfigSourcePrefixWithFilters(t *testing.T) {
	store := memory.New()
	seedConfigs(t, store, []string{"db.host", "db.port", "app.name"})

	src := vaultconfy.NewVaultConfigSource(store, store, "app1",
		vaultconfy.WithKeyPrefix("secrets."),
		vaultconfy.WithKeys("db.host"),
	)
	data, err := src.Load(bg())
	if err != nil {
		t.Fatal(err)
	}

	if len(data) != 1 {
		t.Errorf("len = %d, want 1", len(data))
	}
	if _, ok := data["secrets.db.host"]; !ok {
		t.Error("expected 'secrets.db.host'")
	}
}
