package memory

import (
	"testing"

	"github.com/xraph/vault/internal/storetest"
	"github.com/xraph/vault/secret"
)

func TestTenantIsolation(t *testing.T) {
	storetest.RunTenantIsolation(t, func(*testing.T) secret.Store { return New() })
}
