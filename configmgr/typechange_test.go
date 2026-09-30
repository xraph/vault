package configmgr_test

import (
	"errors"
	"testing"

	"github.com/xraph/vault"
	"github.com/xraph/vault/config"
	"github.com/xraph/vault/configmgr"
)

// A type change must not leave an override that is no longer a value of the
// entry's type: that tenant would silently read the caller's fallback.
func TestUpdateRefusesATypeChangeThatStrandsAnOverride(t *testing.T) {
	backends(t, func(t *testing.T, v *vault.Vault) {
		m := v.ConfigManager()
		mustCreate(t, v, configmgr.CreateInput{Key: "s", ValueType: config.TypeString, Value: "app", Description: "d"})
		if _, err := m.SetOverride(bg(), "s", "acme", "abc"); err != nil {
			t.Fatal(err)
		}
		if _, err := m.SetOverride(bg(), "s", "zed", "def"); err != nil {
			t.Fatal(err)
		}
		auditBefore := len(auditRows(t, v, "config"))

		_, err := m.Update(bg(), "s", configmgr.UpdateInput{ValueType: strp(config.TypeInt), Value: anyp(5.0)})
		wantValidation(t, err, "valueType")
		var ve *config.ValidationError
		if !errors.As(err, &ve) {
			t.Fatalf("err = %v", err)
		}
		want := "tenant acme has an override of a string, which is not a valid int; change or revert it first"
		if ve.Message != want {
			t.Errorf("message = %q, want %q", ve.Message, want)
		}

		got, err := v.Store().GetConfig(bg(), "s", mgrApp)
		if err != nil || got.ValueType != config.TypeString || got.Value != "app" || got.Version != 1 {
			t.Errorf("a refused type change altered the entry: %+v, %v", got, err)
		}
		if n := len(auditRows(t, v, "config")); n != auditBefore {
			t.Errorf("a refused type change wrote %d audit rows", n-auditBefore)
		}
	})
}

// An override that is already valid for the new type does not block the
// change, and neither does a key with no overrides. This test covers
// behaviour that was already correct, so it cannot fail first.
func TestUpdateTypeChangeAllowedWhenOverridesStillFit(t *testing.T) {
	backends(t, func(t *testing.T, v *vault.Vault) {
		m := v.ConfigManager()
		mustCreate(t, v, configmgr.CreateInput{Key: "j", ValueType: config.TypeJSON, Value: map[string]any{"a": 1.0}})
		if _, err := m.SetOverride(bg(), "j", "acme", "abc"); err != nil {
			t.Fatal(err)
		}
		got, err := m.Update(bg(), "j", configmgr.UpdateInput{ValueType: strp(config.TypeString), Value: anyp("x")})
		if err != nil || got.ValueType != config.TypeString || got.Value != "x" {
			t.Fatalf("retype with a fitting override = %+v, %v", got, err)
		}

		mustCreate(t, v, configmgr.CreateInput{Key: "bare", ValueType: config.TypeString, Value: "a"})
		got, err = m.Update(bg(), "bare", configmgr.UpdateInput{ValueType: strp(config.TypeInt), Value: anyp(5.0)})
		if err != nil || got.ValueType != config.TypeInt || got.Value != 5.0 {
			t.Fatalf("retype with no overrides = %+v, %v", got, err)
		}
	})
}
