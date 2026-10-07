package sqlite_test

import (
	"testing"

	"github.com/xraph/vault/internal/storetest"
	"github.com/xraph/vault/secret"
)

func TestSecretExpiry(t *testing.T) {
	storetest.RunSecretExpiry(t, func(t *testing.T) secret.Store { return testStore(t) })
}
