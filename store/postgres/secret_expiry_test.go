//go:build integration

package postgres_test

import (
	"testing"

	"github.com/xraph/vault/internal/storetest"
	"github.com/xraph/vault/secret"
)

// TestSecretExpiry skips unless VAULT_TEST_PG_URL is set (see versionStore).
func TestSecretExpiry(t *testing.T) {
	storetest.RunSecretExpiry(t, func(t *testing.T) secret.Store {
		s, _ := versionStore(t)
		return s
	})
}
