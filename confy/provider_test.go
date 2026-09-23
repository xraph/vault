package confy_test

import (
	"crypto/rand"
	"testing"

	vaultconfy "github.com/xraph/vault/confy"
	"github.com/xraph/vault/crypto"
	"github.com/xraph/vault/secret"
	"github.com/xraph/vault/store/memory"
)

// *secret.Service is the value callers pass to NewVaultSecretProvider, so it
// must satisfy the full SecretService surface. This fails to compile if a
// signature on either side drifts.
var _ vaultconfy.SecretService = (*secret.Service)(nil)

// testEncryptor returns an Encryptor over a fresh random key, for tests that
// need a real (as opposed to keyless) secret.Service.
func testEncryptor(t *testing.T) *crypto.Encryptor {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	enc, err := crypto.NewEncryptor(key)
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

func TestVaultSecretProviderGetSet(t *testing.T) {
	svc := secret.NewService(memory.New(), nil)
	p := vaultconfy.NewVaultSecretProvider(svc, "app1")

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
	svc := secret.NewService(memory.New(), nil)
	if _, err := svc.Set(bg(), "temp_key", []byte("temp"), "app1"); err != nil {
		t.Fatal(err)
	}

	p := vaultconfy.NewVaultSecretProvider(svc, "app1")

	if err := p.DeleteSecret(bg(), "temp_key"); err != nil {
		t.Fatal(err)
	}

	_, err := p.GetSecret(bg(), "temp_key")
	if err == nil {
		t.Error("expected error after delete, got nil")
	}
}

func TestVaultSecretProviderList(t *testing.T) {
	svc := secret.NewService(memory.New(), nil)
	for _, key := range []string{"key1", "key2", "key3"} {
		if _, err := svc.Set(bg(), key, []byte("val"), "app1"); err != nil {
			t.Fatal(err)
		}
	}

	p := vaultconfy.NewVaultSecretProvider(svc, "app1")
	keys, err := p.ListSecrets(bg())
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 3 {
		t.Errorf("len = %d, want 3", len(keys))
	}
}

func TestVaultSecretProviderHealthCheck(t *testing.T) {
	svc := secret.NewService(memory.New(), nil)
	p := vaultconfy.NewVaultSecretProvider(svc, "app1")

	if err := p.HealthCheck(bg()); err != nil {
		t.Fatal(err)
	}
}

func TestVaultSecretProviderName(t *testing.T) {
	p := vaultconfy.NewVaultSecretProvider(secret.NewService(memory.New(), nil), "app1")
	if p.Name() != "vault" {
		t.Errorf("Name = %q", p.Name())
	}
}

func TestVaultSecretProviderCapabilities(t *testing.T) {
	p := vaultconfy.NewVaultSecretProvider(secret.NewService(memory.New(), nil), "app1")
	if p.SupportsRotation() {
		t.Error("SupportsRotation should be false")
	}
	if p.SupportsCaching() {
		t.Error("SupportsCaching should be false")
	}
}

func TestVaultSecretProviderInitializeAndClose(t *testing.T) {
	p := vaultconfy.NewVaultSecretProvider(secret.NewService(memory.New(), nil), "app1")

	if err := p.Initialize(bg(), nil); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(bg()); err != nil {
		t.Fatal(err)
	}
}

// TestProviderReturnsPlaintextForAnEncryptedSecret pins the fix this task
// makes: confy reads a secret through the service, which decrypts it, not
// through the raw store, which never held a decrypted value to begin with.
func TestProviderReturnsPlaintextForAnEncryptedSecret(t *testing.T) {
	svc := secret.NewService(memory.New(), testEncryptor(t))
	p := vaultconfy.NewVaultSecretProvider(svc, "app1")

	if err := p.SetSecret(bg(), "db_password", "s3cret"); err != nil {
		t.Fatal(err)
	}

	val, err := p.GetSecret(bg(), "db_password")
	if err != nil {
		t.Fatal(err)
	}
	if val != "s3cret" {
		t.Errorf("secret = %q, want %q", val, "s3cret")
	}
}

// TestProviderReturnsPlaintextWithNoKey covers the keyless fallback: with no
// encryption key configured, the service stores the value as given and
// still returns it through GetSecret, rather than the empty string a raw
// store read produces.
func TestProviderReturnsPlaintextWithNoKey(t *testing.T) {
	svc := secret.NewService(memory.New(), nil)
	p := vaultconfy.NewVaultSecretProvider(svc, "app1")

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
