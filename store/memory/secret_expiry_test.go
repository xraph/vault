package memory

import (
	"testing"

	"github.com/xraph/vault/internal/storetest"
	"github.com/xraph/vault/secret"
)

func TestSecretExpiry(t *testing.T) {
	storetest.RunSecretExpiry(t, func(*testing.T) secret.Store { return New() })
}
