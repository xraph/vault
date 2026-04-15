package confy_test

import (
	"testing"

	"github.com/xraph/vault"
	vaultconfy "github.com/xraph/vault/confy"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/secret"
	"github.com/xraph/vault/store/memory"
)

func TestVaultSecretProviderGetSet(t *testing.T) {
	store := memory.New()
	p := vaultconfy.NewVaultSecretProvider(store, "app1")

	if err := p.SetSecret(bg(), "api_key", "abc123"); err != nil {
		t.Fatal(err)
	}

	val, err := p.GetSecret(bg(), "api_key")
	if err != nil {
		t.Fatal(err)
	}
	if val != "abc123" {
		t.Errorf("secret = %q, want %q", val, "abc123")
	}
}

func TestVaultSecretProviderDelete(t *testing.T) {
	store := memory.New()
	_ = store.SetSecret(bg(), &secret.Secret{
		Entity: vault.NewEntity(),
		ID:     id.NewSecretID(),
		Key:    "temp_key",
		Value:  []byte("temp"),
		AppID:  "app1",
	})

	p := vaultconfy.NewVaultSecretProvider(store, "app1")

	if err := p.DeleteSecret(bg(), "temp_key"); err != nil {
		t.Fatal(err)
	}

	_, err := p.GetSecret(bg(), "temp_key")
	if err == nil {
		t.Error("expected error after delete, got nil")
	}
}

func TestVaultSecretProviderList(t *testing.T) {
	store := memory.New()
	for _, key := range []string{"key1", "key2", "key3"} {
		_ = store.SetSecret(bg(), &secret.Secret{
			Entity: vault.NewEntity(),
			ID:     id.NewSecretID(),
			Key:    key,
			Value:  []byte("val"),
			AppID:  "app1",
		})
	}

	p := vaultconfy.NewVaultSecretProvider(store, "app1")
	keys, err := p.ListSecrets(bg())
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 3 {
		t.Errorf("len = %d, want 3", len(keys))
	}
}

func TestVaultSecretProviderHealthCheck(t *testing.T) {
	store := memory.New()
	p := vaultconfy.NewVaultSecretProvider(store, "app1")

	if err := p.HealthCheck(bg()); err != nil {
		t.Fatal(err)
	}
}

func TestVaultSecretProviderName(t *testing.T) {
	p := vaultconfy.NewVaultSecretProvider(memory.New(), "app1")
	if p.Name() != "vault" {
		t.Errorf("Name = %q", p.Name())
	}
}

func TestVaultSecretProviderCapabilities(t *testing.T) {
	p := vaultconfy.NewVaultSecretProvider(memory.New(), "app1")
	if p.SupportsRotation() {
		t.Error("SupportsRotation should be false")
	}
	if p.SupportsCaching() {
		t.Error("SupportsCaching should be false")
	}
}

func TestVaultSecretProviderInitializeAndClose(t *testing.T) {
	p := vaultconfy.NewVaultSecretProvider(memory.New(), "app1")

	if err := p.Initialize(bg(), nil); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(bg()); err != nil {
		t.Fatal(err)
	}
}
