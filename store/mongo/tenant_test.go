package mongo_test

import (
	"testing"

	"github.com/xraph/vault/internal/storetest"
	"github.com/xraph/vault/secret"
)

// TestTenantIsolation skips unless VAULT_TEST_MONGO_URL is set (see testStore).
func TestTenantIsolation(t *testing.T) {
	storetest.RunTenantIsolation(t, func(t *testing.T) secret.Store { return testStore(t) })
}
