package crypto_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/xraph/vault/crypto"
)

func TestEnvKeyProviderHex(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	encoded := hex.EncodeToString(key)

	t.Setenv("TEST_VAULT_KEY_HEX", encoded)

	p := crypto.NewEnvKeyProvider("TEST_VAULT_KEY_HEX")
	got, err := p.GetKey(context.Background())
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if len(got) != 32 {
		t.Errorf("key length = %d, want 32", len(got))
	}
	for i := range got {
		if got[i] != byte(i) {
			t.Fatalf("key[%d] = %d, want %d", i, got[i], i)
		}
	}
}

func TestEnvKeyProviderBase64(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 100)
	}
	encoded := base64.StdEncoding.EncodeToString(key)

	t.Setenv("TEST_VAULT_KEY_B64", encoded)

	p := crypto.NewEnvKeyProvider("TEST_VAULT_KEY_B64")
	got, err := p.GetKey(context.Background())
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if len(got) != 32 {
		t.Errorf("key length = %d, want 32", len(got))
	}
	for i := range got {
		if got[i] != byte(i+100) {
			t.Fatalf("key[%d] = %d, want %d", i, got[i], i+100)
		}
	}
}

func TestEnvKeyProviderEmpty(t *testing.T) {
	t.Setenv("TEST_VAULT_KEY_EMPTY", "")

	p := crypto.NewEnvKeyProvider("TEST_VAULT_KEY_EMPTY")
	_, err := p.GetKey(context.Background())
	if err == nil {
		t.Error("expected error for empty env var")
	}
}

func TestEnvKeyProviderNotSet(t *testing.T) {
	p := crypto.NewEnvKeyProvider("TEST_VAULT_KEY_DEFINITELY_NOT_SET_XYZ")
	_, err := p.GetKey(context.Background())
	if err == nil {
		t.Error("expected error for unset env var")
	}
}

func TestEnvKeyProviderRotateNotSupported(t *testing.T) {
	p := crypto.NewEnvKeyProvider("TEST_VAULT_KEY")
	_, err := p.RotateKey(context.Background())
	if err == nil {
		t.Error("expected error: env provider does not support rotation")
	}
}
