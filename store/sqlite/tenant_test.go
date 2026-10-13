package sqlite_test

import (
	"testing"

	"github.com/xraph/vault/internal/storetest"
	"github.com/xraph/vault/secret"
)

func TestTenantIsolation(t *testing.T) {
	storetest.RunTenantIsolation(t, func(t *testing.T) secret.Store { return testStore(t) })
}
