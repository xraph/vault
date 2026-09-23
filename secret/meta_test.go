package secret_test

import (
	"context"
	"testing"

	"github.com/xraph/vault/crypto"
	"github.com/xraph/vault/secret"
	"github.com/xraph/vault/store/memory"
)

// A secret written with no encryptor is plaintext in EncryptedValue, and the
// metadata must say so. Anything less lets a page call it encrypted.
func TestMetaReportsNoAlgorithmWhenNothingEncrypted(t *testing.T) {
	s := memory.New()
	svc := secret.NewService(s, nil, secret.WithAppID("app1"))

	meta, err := svc.Set(context.Background(), "k", []byte("plain"), "app1")
	if err != nil {
		t.Fatal(err)
	}
	if meta.EncryptionAlg != "" {
		t.Errorf("Set returned alg %q, want empty", meta.EncryptionAlg)
	}

	list, err := svc.List(context.Background(), "app1", secret.ListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("list: got %d, want 1", len(list))
	}
	if list[0].EncryptionAlg != "" {
		t.Errorf("listed alg %q, want empty; an unencrypted row must not look encrypted", list[0].EncryptionAlg)
	}
}

func TestMetaReportsTheAlgorithmWhenEncrypted(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	enc, err := crypto.NewEncryptor(key)
	if err != nil {
		t.Fatal(err)
	}
	s := memory.New()
	svc := secret.NewService(s, enc, secret.WithAppID("app1"))

	if _, errSet := svc.Set(context.Background(), "k", []byte("secret"), "app1"); errSet != nil {
		t.Fatal(errSet)
	}
	list, err := svc.List(context.Background(), "app1", secret.ListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if list[0].EncryptionAlg != "AES-256-GCM" {
		t.Errorf("listed alg %q, want AES-256-GCM", list[0].EncryptionAlg)
	}
}

// The two can coexist: a key added later does not re-encrypt what is already
// stored, so one app can hold rows of both kinds. This is why the field has
// to be per row and EncryptionEnabled() on the Vault is not enough.
func TestMetaDistinguishesRowsWrittenUnderDifferentConfig(t *testing.T) {
	s := memory.New()

	plain := secret.NewService(s, nil, secret.WithAppID("app1"))
	if _, err := plain.Set(context.Background(), "before", []byte("v"), "app1"); err != nil {
		t.Fatal(err)
	}

	key := make([]byte, 32)
	enc, err := crypto.NewEncryptor(key)
	if err != nil {
		t.Fatal(err)
	}
	encrypted := secret.NewService(s, enc, secret.WithAppID("app1"))
	if _, errSet := encrypted.Set(context.Background(), "after", []byte("v"), "app1"); errSet != nil {
		t.Fatal(errSet)
	}

	list, err := encrypted.List(context.Background(), "app1", secret.ListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]string{}
	for _, m := range list {
		byKey[m.Key] = m.EncryptionAlg
	}
	if byKey["before"] != "" {
		t.Errorf("before: got %q, want empty", byKey["before"])
	}
	if byKey["after"] != "AES-256-GCM" {
		t.Errorf("after: got %q, want AES-256-GCM", byKey["after"])
	}
}
