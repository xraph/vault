//go:build integration

package postgres_test

import (
	"testing"

	"github.com/xraph/vault/core"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/secret"
)

// CountSecretsUnencrypted counts the rows stored without an encryption
// algorithm, per app, and follows a secret when it is rewritten encrypted.
func TestCountSecretsUnencrypted(t *testing.T) {
	s := testStore(t)
	put := func(app, key, alg string) {
		t.Helper()
		if err := s.SetSecret(t.Context(), &secret.Secret{
			Entity: core.NewEntity(), ID: id.NewSecretID(),
			Key: key, AppID: app, EncryptedValue: []byte("x"), EncryptionAlg: alg,
		}); err != nil {
			t.Fatal(err)
		}
	}
	count := func(app string, want int64) {
		t.Helper()
		got, err := s.CountSecretsUnencrypted(t.Context(), app)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("app %s: got %d, want %d", app, got, want)
		}
	}

	count("a", 0)
	put("a", "plain-1", "")
	put("a", "plain-2", "")
	put("a", "sealed", "AES-256-GCM")
	put("b", "other-plain", "")
	count("a", 2)
	count("b", 1)
	count("nobody", 0)

	// Rewriting a plain secret with an algorithm takes it out of the count.
	put("a", "plain-1", "AES-256-GCM")
	count("a", 1)
}
