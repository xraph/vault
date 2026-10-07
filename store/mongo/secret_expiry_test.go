package mongo_test

import (
	"testing"

	"github.com/xraph/vault/internal/storetest"
	"github.com/xraph/vault/secret"
)

// TestSecretExpiry skips unless VAULT_TEST_MONGO_URL is set (see testStore).
func TestSecretExpiry(t *testing.T) {
	storetest.RunSecretExpiry(t, func(t *testing.T) secret.Store { return testStore(t) })
}
