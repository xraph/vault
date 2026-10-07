package secret_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/xraph/vault/core"
	"github.com/xraph/vault/crypto"
	"github.com/xraph/vault/secret"
	"github.com/xraph/vault/store/memory"
)

func encryptorWithKey(t *testing.T, fill byte) *crypto.Encryptor {
	t.Helper()
	enc, err := crypto.NewEncryptor(bytes.Repeat([]byte{fill}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

// The scenario the version column exists for, through the service and the
// memory store.
func TestGetVersionAcrossAChangeOfKeyConfiguration(t *testing.T) {
	store := memory.New()
	enc := encryptorWithKey(t, 1)
	open := func(e *crypto.Encryptor) *secret.Service {
		return secret.NewService(store, e, secret.WithAppID("app1"))
	}

	// v1 is written with no key, v2 after a key is configured.
	if _, err := open(nil).Set(t.Context(), "k", []byte("plain-v1"), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := open(enc).Set(t.Context(), "k", []byte("sealed-v2"), ""); err != nil {
		t.Fatal(err)
	}

	withKey := open(enc)
	v1, err := withKey.GetVersion(t.Context(), "k", "", 1)
	if err != nil {
		t.Fatalf("GetVersion(1) with a key: %v", err)
	}
	if string(v1.Value) != "plain-v1" {
		t.Errorf("v1 = %q, want plain-v1", v1.Value)
	}
	v2, err := withKey.GetVersion(t.Context(), "k", "", 2)
	if err != nil {
		t.Fatalf("GetVersion(2) with a key: %v", err)
	}
	if string(v2.Value) != "sealed-v2" {
		t.Errorf("v2 = %q, want sealed-v2", v2.Value)
	}

	// The key is removed from config: v2 must refuse, v1 is still plaintext.
	noKey := open(nil)
	got, err := noKey.GetVersion(t.Context(), "k", "", 2)
	if !errors.Is(err, core.ErrDecryptionFailed) {
		t.Fatalf("GetVersion(2) without a key: err = %v, want one wrapping ErrDecryptionFailed", err)
	}
	if got != nil && len(got.Value) != 0 {
		t.Errorf("GetVersion(2) without a key returned a value %q", got.Value)
	}
	if v1, err = noKey.GetVersion(t.Context(), "k", "", 1); err != nil || string(v1.Value) != "plain-v1" {
		t.Errorf("v1 without a key = %q, %v; want plain-v1", v1.Value, err)
	}
}

// The silent direction: an encrypted v1 under a current row written with no
// key used to come back as ciphertext with a nil error.
func TestGetVersionNeverReturnsCiphertextAsAValue(t *testing.T) {
	store := memory.New()
	enc := encryptorWithKey(t, 1)
	if _, err := secret.NewService(store, enc, secret.WithAppID("app1")).Set(t.Context(), "k", []byte("sealed-v1"), ""); err != nil {
		t.Fatal(err)
	}
	noKey := secret.NewService(store, nil, secret.WithAppID("app1"))
	if _, err := noKey.Set(t.Context(), "k", []byte("plain-v2"), ""); err != nil {
		t.Fatal(err)
	}

	got, err := noKey.GetVersion(t.Context(), "k", "", 1)
	if !errors.Is(err, core.ErrDecryptionFailed) {
		t.Fatalf("err = %v, want one wrapping ErrDecryptionFailed", err)
	}
	if got != nil && len(got.Value) != 0 {
		t.Errorf("returned a value %q", got.Value)
	}
	v2, err := noKey.GetVersion(t.Context(), "k", "", 2)
	if err != nil || string(v2.Value) != "plain-v2" {
		t.Errorf("v2 = %q, %v; want plain-v2", v2.Value, err)
	}
}
