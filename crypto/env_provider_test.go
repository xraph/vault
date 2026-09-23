package crypto_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"strings"
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

// A malformed key must not leak into the error, because vault.New returns
// this error from the extension's Register and it lands in startup logs.
// Any fragment of a near-valid key narrows the search for the real one.
func TestEnvKeyProviderErrorDoesNotEchoTheKey(t *testing.T) {
	cases := map[string]string{
		// 64 characters, so the hex branch is tried, with one bad digit.
		"near-valid hex": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1bZ",
		"not a key":      "Kx9#Wq2@Pz5&Lm3*Rv8!",
	}
	for name, raw := range cases {
		t.Setenv("TEST_VAULT_KEY_BAD", raw)
		_, err := crypto.NewEnvKeyProvider("TEST_VAULT_KEY_BAD").GetKey(context.Background())
		if err == nil {
			t.Fatalf("%s: expected an error", name)
		}
		msg := err.Error()
		for i := 0; i+3 <= len(raw); i++ {
			if frag := raw[i : i+3]; strings.Contains(msg, frag) {
				t.Errorf("%s: error %q contains %q from the input", name, msg, frag)
				break
			}
		}
	}
}
