package vault_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/xraph/vault"
	"github.com/xraph/vault/core"
	"github.com/xraph/vault/secret"
)

// The alias must be a true alias, not a defined type: external callers embed
// vault.Entity and pass it where core.Entity is expected, and a defined type
// would break both.
func TestEntityAliasIsIdentical(t *testing.T) {
	// The explicit types below are the point of the test: if vault.Entity
	// were a defined type instead of an alias, core.NewEntity() would not
	// be assignable to a vault.Entity-typed variable, and vice versa.
	var fromRoot vault.Entity = core.NewEntity() //nolint:staticcheck // explicit type verifies cross-package assignability
	var fromCore core.Entity = vault.NewEntity() //nolint:staticcheck // explicit type verifies cross-package assignability
	_ = fromRoot
	_ = fromCore

	// Embedding through the alias still promotes the fields.
	s := secret.Secret{Entity: vault.NewEntity(), Key: "k"}
	if s.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero; NewEntity did not populate through the alias")
	}
	if s.Key != "k" {
		t.Error("Key was not set through the composite literal")
	}
}

// The sentinels must be the same values, or errors.Is stops matching for
// every caller that wrapped the old ones.
func TestErrorSentinelsAreTheSameValues(t *testing.T) {
	cases := []struct {
		name       string
		root, leaf error
	}{
		{"ErrSecretNotFound", vault.ErrSecretNotFound, core.ErrSecretNotFound},
		{"ErrOverrideNotFound", vault.ErrOverrideNotFound, core.ErrOverrideNotFound},
		{"ErrFlagNotFound", vault.ErrFlagNotFound, core.ErrFlagNotFound},
		{"ErrConfigNotFound", vault.ErrConfigNotFound, core.ErrConfigNotFound},
	}
	for _, tc := range cases {
		if tc.root != tc.leaf { //nolint:errorlint // intentional identity check: these must be the same sentinel value, not merely errors.Is-compatible
			t.Errorf("%s: root and core are different values", tc.name)
		}
		wrapped := fmt.Errorf("wrapped: %w", tc.leaf)
		if !errors.Is(wrapped, tc.root) {
			t.Errorf("%s: errors.Is failed against the root alias", tc.name)
		}
	}
}
