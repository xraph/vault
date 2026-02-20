package secret_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/xraph/vault"
	"github.com/xraph/vault/crypto"
	"github.com/xraph/vault/secret"
	"github.com/xraph/vault/store/memory"
)

func bg() context.Context { return context.Background() }

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

func TestSetGetRoundTrip(t *testing.T) {
	store := memory.New()
	svc := secret.NewService(store, testEncryptor(t), secret.WithAppID("app1"))

	meta, err := svc.Set(bg(), "db-password", []byte("s3cret"), "")
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if meta.Key != "db-password" {
		t.Errorf("Key = %q", meta.Key)
	}
	if meta.Version != 1 {
		t.Errorf("Version = %d, want 1", meta.Version)
	}

	got, err := svc.Get(bg(), "db-password", "")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got.Value, []byte("s3cret")) {
		t.Errorf("Value = %q, want %q", got.Value, "s3cret")
	}

	// EncryptedValue should NOT be plaintext.
	raw, _ := store.GetSecret(bg(), "db-password", "app1")
	if bytes.Equal(raw.EncryptedValue, []byte("s3cret")) {
		t.Error("EncryptedValue should not be plaintext")
	}
}

func TestAutoVersioning(t *testing.T) {
	svc := secret.NewService(memory.New(), testEncryptor(t), secret.WithAppID("app1"))

	_, err := svc.Set(bg(), "key1", []byte("value-v1"), "")
	if err != nil {
		t.Fatal(err)
	}
	meta2, err := svc.Set(bg(), "key1", []byte("value-v2"), "")
	if err != nil {
		t.Fatal(err)
	}
	if meta2.Version != 2 {
		t.Errorf("Version = %d, want 2", meta2.Version)
	}

	// Get returns latest.
	latest, _ := svc.Get(bg(), "key1", "")
	if !bytes.Equal(latest.Value, []byte("value-v2")) {
		t.Errorf("latest Value = %q", latest.Value)
	}

	// GetVersion returns v1.
	v1, err := svc.GetVersion(bg(), "key1", "", 1)
	if err != nil {
		t.Fatalf("GetVersion(1): %v", err)
	}
	if v1.Version != 1 {
		t.Errorf("v1.Version = %d, want 1", v1.Version)
	}

	// ListVersions returns both.
	versions, err := svc.ListVersions(bg(), "key1", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 2 {
		t.Errorf("len(versions) = %d, want 2", len(versions))
	}
}

func TestDeleteThenGetReturnsNotFound(t *testing.T) {
	svc := secret.NewService(memory.New(), testEncryptor(t), secret.WithAppID("app1"))

	_, _ = svc.Set(bg(), "to-delete", []byte("value"), "")

	if err := svc.Delete(bg(), "to-delete", ""); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err := svc.Get(bg(), "to-delete", "")
	if !errors.Is(err, vault.ErrSecretNotFound) {
		t.Errorf("Get after delete: got %v, want ErrSecretNotFound", err)
	}
}

func TestListReturnsMetadataOnly(t *testing.T) {
	svc := secret.NewService(memory.New(), testEncryptor(t), secret.WithAppID("app1"))

	_, _ = svc.Set(bg(), "s1", []byte("v1"), "")
	_, _ = svc.Set(bg(), "s2", []byte("v2"), "")

	list, err := svc.List(bg(), "", secret.ListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("len = %d, want 2", len(list))
	}
	// Meta should not expose the key value itself.
	for _, m := range list {
		if m.Key == "" {
			t.Error("Key should be populated in Meta")
		}
	}
}

func TestGetMeta(t *testing.T) {
	svc := secret.NewService(memory.New(), testEncryptor(t), secret.WithAppID("app1"))

	_, _ = svc.Set(bg(), "meta-test", []byte("value"), "")

	meta, err := svc.GetMeta(bg(), "meta-test", "")
	if err != nil {
		t.Fatalf("GetMeta: %v", err)
	}
	if meta.Key != "meta-test" {
		t.Errorf("Key = %q", meta.Key)
	}
}

func TestSetWithMetadata(t *testing.T) {
	svc := secret.NewService(memory.New(), testEncryptor(t), secret.WithAppID("app1"))

	md := map[string]string{"env": "prod", "team": "platform"}
	meta, err := svc.Set(bg(), "with-md", []byte("val"), "", secret.WithMetadata(md))
	if err != nil {
		t.Fatal(err)
	}
	if meta.Metadata["env"] != "prod" {
		t.Errorf("metadata env = %q", meta.Metadata["env"])
	}
}

func TestSetWithExpiresAt(t *testing.T) {
	svc := secret.NewService(memory.New(), testEncryptor(t), secret.WithAppID("app1"))

	exp := time.Now().Add(24 * time.Hour)
	meta, err := svc.Set(bg(), "with-exp", []byte("val"), "", secret.WithExpiresAt(exp))
	if err != nil {
		t.Fatal(err)
	}
	if meta.ExpiresAt == nil {
		t.Fatal("ExpiresAt should not be nil")
	}
}

func TestAuditCallbacks(t *testing.T) {
	var accessCalls, mutateCalls int
	var lastAction string

	svc := secret.NewService(
		memory.New(),
		testEncryptor(t),
		secret.WithAppID("app1"),
		secret.WithOnAccess(func(_ context.Context, _, _ string) {
			accessCalls++
		}),
		secret.WithOnMutate(func(_ context.Context, action, _, _ string) {
			mutateCalls++
			lastAction = action
		}),
	)

	_, _ = svc.Set(bg(), "k1", []byte("v"), "")
	if mutateCalls != 1 || lastAction != "secret.set" {
		t.Errorf("mutateCalls=%d lastAction=%q", mutateCalls, lastAction)
	}

	_, _ = svc.Get(bg(), "k1", "")
	if accessCalls != 1 {
		t.Errorf("accessCalls=%d, want 1", accessCalls)
	}

	_ = svc.Delete(bg(), "k1", "")
	if mutateCalls != 2 || lastAction != "secret.delete" {
		t.Errorf("mutateCalls=%d lastAction=%q", mutateCalls, lastAction)
	}
}

func TestServiceWithoutEncryptor(t *testing.T) {
	svc := secret.NewService(memory.New(), nil, secret.WithAppID("app1"))

	_, err := svc.Set(bg(), "plain", []byte("plain-value"), "")
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := svc.Get(bg(), "plain", "")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got.Value, []byte("plain-value")) {
		t.Errorf("Value = %q", got.Value)
	}
}

func TestExplicitAppIDOverridesDefault(t *testing.T) {
	svc := secret.NewService(memory.New(), testEncryptor(t), secret.WithAppID("default-app"))

	_, err := svc.Set(bg(), "key1", []byte("val"), "custom-app")
	if err != nil {
		t.Fatal(err)
	}

	// Should NOT find it under default app.
	_, err = svc.Get(bg(), "key1", "default-app")
	if !errors.Is(err, vault.ErrSecretNotFound) {
		t.Error("expected not found under default-app")
	}

	// Should find it under custom-app.
	got, err := svc.Get(bg(), "key1", "custom-app")
	if err != nil {
		t.Fatalf("Get custom-app: %v", err)
	}
	if got.AppID != "custom-app" {
		t.Errorf("AppID = %q", got.AppID)
	}
}
