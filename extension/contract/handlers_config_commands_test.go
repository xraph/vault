package contract

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"

	"github.com/xraph/vault"
	"github.com/xraph/vault/config"
	"github.com/xraph/vault/configmgr"
	"github.com/xraph/vault/store/memory"
)

// --- helpers ---

// decodeCommand decodes a wire payload into a request the way the transport
// does, so a test can tell an absent field from a null one.
func decodeCommand[T any](t *testing.T, payload string) T {
	t.Helper()
	var in T
	if err := json.Unmarshal([]byte(payload), &in); err != nil {
		t.Fatalf("decode %s: %v", payload, err)
	}
	return in
}

func versionCount(t *testing.T, v *vault.Vault, key string) int {
	t.Helper()
	vers, err := configVersionsHandler(Deps{Vault: v})(context.Background(), configVersionsRequest{Key: key}, configPrincipal)
	if err != nil {
		t.Fatalf("versions %q: %v", key, err)
	}
	return len(vers.Versions)
}

func configEntryOf(t *testing.T, v *vault.Vault, key string) ConfigEntrySummary {
	t.Helper()
	det, err := configDetailHandler(Deps{Vault: v})(context.Background(), configDetailRequest{Key: key}, configPrincipal)
	if err != nil {
		t.Fatalf("detail %q: %v", key, err)
	}
	return det.Entry
}

// --- config.create ---

func TestConfigCreate_HappyPath(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	deps := Deps{Vault: v}

	in := decodeCommand[configCreateRequest](t, `{"key":"db.port","valueType":"int","value":5432,"description":"the port"}`)
	out, err := configCreateHandler(deps)(ctx, in, configPrincipal)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	e := out.Entry
	if e.Key != "db.port" || e.ValueType != "int" || e.Value != float64(5432) || e.Description != "the port" || e.Version != 1 || !e.ValueMatchesType || !e.KnownType {
		t.Errorf("entry = %+v", e)
	}
	if got := configEntryOf(t, v, "db.port"); !reflect.DeepEqual(got, e) {
		t.Errorf("stored entry = %+v, response = %+v", got, e)
	}

	// A json entry may be created holding null.
	out, err = configCreateHandler(deps)(ctx, decodeCommand[configCreateRequest](t, `{"key":"blob","valueType":"json","value":null}`), configPrincipal)
	if err != nil || out.Entry.Value != nil || !out.Entry.ValueMatchesType {
		t.Errorf("json null create = %+v, %v", out, err)
	}
}

func TestConfigCreate_Refusals(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	deps := Deps{Vault: v}

	_, err := configCreateHandler(deps)(ctx, decodeCommand[configCreateRequest](t, `{"key":"k","value":"x"}`), configPrincipal)
	wantCode(t, err, dashcontract.CodeBadRequest, "valueType is required")
	_, err = configCreateHandler(deps)(ctx, decodeCommand[configCreateRequest](t, `{"key":"k","valueType":"  ","value":"x"}`), configPrincipal)
	wantCode(t, err, dashcontract.CodeBadRequest, "valueType is required")
	_, err = configCreateHandler(deps)(ctx, decodeCommand[configCreateRequest](t, `{"valueType":"string","value":"x"}`), configPrincipal)
	wantCode(t, err, dashcontract.CodeBadRequest, "key is required")
	_, err = configCreateHandler(deps)(ctx, decodeCommand[configCreateRequest](t, `{"key":"k","valueType":"yaml","value":"x"}`), configPrincipal)
	wantCode(t, err, dashcontract.CodeBadRequest, "valueType")
	_, err = configCreateHandler(deps)(ctx, decodeCommand[configCreateRequest](t, `{"key":"k","valueType":"int","value":"abc"}`), configPrincipal)
	wantCode(t, err, dashcontract.CodeBadRequest, "value")
	_, err = configCreateHandler(deps)(ctx, decodeCommand[configCreateRequest](t, `{"key":"k","valueType":"string"}`), configPrincipal)
	wantCode(t, err, dashcontract.CodeBadRequest, "value")
	if _, gerr := configDetailHandler(deps)(ctx, configDetailRequest{Key: "k"}, configPrincipal); codeOf(gerr) != dashcontract.CodeNotFound {
		t.Errorf("a refused create stored an entry: %v", gerr)
	}
}

func TestConfigCreate_ConflictLeavesTheEntryUnchanged(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	deps := Deps{Vault: v}
	seedConfig(t, v, "taken", "string", "original")
	before := configEntryOf(t, v, "taken")

	_, err := configCreateHandler(deps)(ctx, decodeCommand[configCreateRequest](t, `{"key":"taken","valueType":"int","value":1,"description":"new"}`), configPrincipal)
	wantCode(t, err, dashcontract.CodeConflict, "already exists")
	if after := configEntryOf(t, v, "taken"); !reflect.DeepEqual(after, before) {
		t.Errorf("entry changed by a conflicting create: %+v -> %+v", before, after)
	}
}

// --- config.update ---

func TestConfigUpdate_ValueKeepsDescription(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	deps := Deps{Vault: v}
	if _, err := v.ConfigManager().Create(ctx, configmgr.CreateInput{Key: "k", ValueType: "string", Description: "keep me", Value: "a"}); err != nil {
		t.Fatal(err)
	}

	out, err := configUpdateHandler(deps)(ctx, decodeCommand[configUpdateRequest](t, `{"key":"k","value":"b"}`), configPrincipal)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if out.Entry.Value != "b" || out.Entry.Description != "keep me" || out.Entry.Version != 2 || out.Entry.ValueType != "string" {
		t.Errorf("entry = %+v", out.Entry)
	}

	// Description alone leaves the value, and an empty description is a
	// present value that clears it.
	out, err = configUpdateHandler(deps)(ctx, decodeCommand[configUpdateRequest](t, `{"key":"k","description":""}`), configPrincipal)
	if err != nil || out.Entry.Value != "b" || out.Entry.Description != "" {
		t.Errorf("description-only update = %+v, %v", out, err)
	}

	// A type change needs a value of the new type.
	out, err = configUpdateHandler(deps)(ctx, decodeCommand[configUpdateRequest](t, `{"key":"k","valueType":"int","value":3}`), configPrincipal)
	if err != nil || out.Entry.ValueType != "int" || out.Entry.Value != float64(3) {
		t.Errorf("retype = %+v, %v", out, err)
	}
	_, err = configUpdateHandler(deps)(ctx, decodeCommand[configUpdateRequest](t, `{"key":"k","valueType":"bool"}`), configPrincipal)
	wantCode(t, err, dashcontract.CodeBadRequest, "valueType")
}

func TestConfigUpdate_AbsentVersusNull(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	deps := Deps{Vault: v}
	seedConfig(t, v, "s", "string", "text")
	seedConfig(t, v, "j", "json", map[string]any{"a": float64(1)})

	// null on a string entry is a refusal and changes nothing.
	_, err := configUpdateHandler(deps)(ctx, decodeCommand[configUpdateRequest](t, `{"key":"s","value":null}`), configPrincipal)
	wantCode(t, err, dashcontract.CodeBadRequest, "value")
	if e := configEntryOf(t, v, "s"); e.Value != "text" || e.Version != 1 {
		t.Errorf("a refused null changed the entry: %+v", e)
	}

	// null on a json entry stores null.
	out, err := configUpdateHandler(deps)(ctx, decodeCommand[configUpdateRequest](t, `{"key":"j","value":null}`), configPrincipal)
	if err != nil || out.Entry.Value != nil || out.Entry.Version != 2 || !out.Entry.ValueMatchesType {
		t.Errorf("json null update = %+v, %v", out, err)
	}

	// Absent leaves the value: a description-only update on the same entry.
	out, err = configUpdateHandler(deps)(ctx, decodeCommand[configUpdateRequest](t, `{"key":"j","description":"now null"}`), configPrincipal)
	if err != nil || out.Entry.Value != nil || out.Entry.Description != "now null" {
		t.Errorf("absent value = %+v, %v", out, err)
	}
	// Absent, on a string entry, did not become null.
	out, err = configUpdateHandler(deps)(ctx, decodeCommand[configUpdateRequest](t, `{"key":"s","description":"d"}`), configPrincipal)
	if err != nil || out.Entry.Value != "text" {
		t.Errorf("absent value on a string entry = %+v, %v", out, err)
	}
}

func TestConfigUpdate_NoOpReturnsTheEntryAndAddsNoVersion(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	deps := Deps{Vault: v}
	seedConfig(t, v, "k", "int", float64(5))

	out, err := configUpdateHandler(deps)(ctx, decodeCommand[configUpdateRequest](t, `{"key":"k","value":5}`), configPrincipal)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if out.Entry.Key != "k" || out.Entry.Value != float64(5) || out.Entry.Version != 1 {
		t.Errorf("entry = %+v", out.Entry)
	}
	if n := versionCount(t, v, "k"); n != 1 {
		t.Errorf("versions = %d after a no-op update, want 1", n)
	}
}

func TestConfigUpdate_Refusals(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	deps := Deps{Vault: v}
	seedConfig(t, v, "n", "int", float64(5))

	_, err := configUpdateHandler(deps)(ctx, decodeCommand[configUpdateRequest](t, `{"key":"n","value":"abc"}`), configPrincipal)
	wantCode(t, err, dashcontract.CodeBadRequest, "value")
	_, err = configUpdateHandler(deps)(ctx, decodeCommand[configUpdateRequest](t, `{"key":"ghost","value":1}`), configPrincipal)
	wantCode(t, err, dashcontract.CodeNotFound, "config entry not found")
	_, err = configUpdateHandler(deps)(ctx, decodeCommand[configUpdateRequest](t, `{"value":1}`), configPrincipal)
	wantCode(t, err, dashcontract.CodeBadRequest, "key is required")
	if e := configEntryOf(t, v, "n"); e.Value != float64(5) || e.Version != 1 {
		t.Errorf("a refused update changed the entry: %+v", e)
	}
}

// --- config.delete ---

func TestConfigDelete_RemovesTheEntryAndItsOverrides(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	deps := Deps{Vault: v}
	seedConfig(t, v, "gone", "string", "x")
	seedOverride(t, v, "gone", "acme", "y")

	out, err := configDeleteHandler(deps)(ctx, configDeleteRequest{Key: " gone "}, configPrincipal)
	if err != nil || !out.OK || out.Key != "gone" {
		t.Fatalf("delete = %+v, %v", out, err)
	}
	_, err = configDetailHandler(deps)(ctx, configDetailRequest{Key: "gone"}, configPrincipal)
	wantCode(t, err, dashcontract.CodeNotFound, "")
	list, err := overridesListHandler(deps)(ctx, overridesListRequest{Key: "gone"}, configPrincipal)
	if err != nil || list.Total != 0 {
		t.Errorf("overrides after delete = %+v, %v", list, err)
	}

	_, err = configDeleteHandler(deps)(ctx, configDeleteRequest{Key: "gone"}, configPrincipal)
	wantCode(t, err, dashcontract.CodeNotFound, "config entry not found")
	_, err = configDeleteHandler(deps)(ctx, configDeleteRequest{}, configPrincipal)
	wantCode(t, err, dashcontract.CodeBadRequest, "key is required")
}

// --- config.rollback ---

func TestConfigRollback_HappyPathAndRefusals(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	deps := Deps{Vault: v}
	if _, err := v.ConfigManager().Create(ctx, configmgr.CreateInput{Key: "k", ValueType: "int", Description: "desc", Value: float64(1)}); err != nil {
		t.Fatal(err)
	}
	for _, n := range []float64{2, 3} {
		val := any(n)
		if _, err := v.ConfigManager().Update(ctx, "k", configmgr.UpdateInput{Value: &val}); err != nil {
			t.Fatal(err)
		}
	}

	out, err := configRollbackHandler(deps)(ctx, configRollbackRequest{Key: "k", Version: 1}, configPrincipal)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if out.Entry.Value != float64(1) || out.Entry.Version != 4 || out.Entry.Description != "desc" || out.Entry.ValueType != "int" {
		t.Errorf("entry = %+v", out.Entry)
	}
	if n := versionCount(t, v, "k"); n != 4 {
		t.Errorf("versions = %d, want 4 (a rollback is a new version)", n)
	}

	_, err = configRollbackHandler(deps)(ctx, configRollbackRequest{Key: "k", Version: 99}, configPrincipal)
	wantCode(t, err, dashcontract.CodeNotFound, "config version not found")
	_, err = configRollbackHandler(deps)(ctx, configRollbackRequest{Key: "ghost", Version: 1}, configPrincipal)
	wantCode(t, err, dashcontract.CodeNotFound, "config entry not found")
	_, err = configRollbackHandler(deps)(ctx, configRollbackRequest{Version: 1}, configPrincipal)
	wantCode(t, err, dashcontract.CodeBadRequest, "key is required")
	if e := configEntryOf(t, v, "k"); e.Version != 4 || e.Value != float64(1) {
		t.Errorf("a refused rollback changed the entry: %+v", e)
	}
}

// A version whose value does not fit the entry's current type is refused,
// naming the version.
func TestConfigRollback_RefusesAValueOfTheOldType(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	deps := Deps{Vault: v}
	seedConfig(t, v, "k", "string", "text")
	val := any(float64(7))
	ty := "int"
	if _, err := v.ConfigManager().Update(ctx, "k", configmgr.UpdateInput{Value: &val, ValueType: &ty}); err != nil {
		t.Fatal(err)
	}

	_, err := configRollbackHandler(deps)(ctx, configRollbackRequest{Key: "k", Version: 1}, configPrincipal)
	wantCode(t, err, dashcontract.CodeBadRequest, "version")
	if e := configEntryOf(t, v, "k"); e.Value != float64(7) || e.ValueType != "int" || e.Version != 2 {
		t.Errorf("a refused rollback changed the entry: %+v", e)
	}
}

// --- overrides.set ---

func TestOverridesSet_HappyPath(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	deps := Deps{Vault: v}
	seedConfig(t, v, "k", "string", "app")

	out, err := overridesSetHandler(deps)(ctx, decodeCommand[overridesSetRequest](t, `{"key":"k","tenantId":" acme ","value":"tenant"}`), configPrincipal)
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	o := out.Override
	if o.Key != "k" || o.TenantID != "acme" || o.Value != "tenant" || !o.KeyExists || !o.ValueMatchesType {
		t.Errorf("override = %+v", o)
	}
	res, err := configResolveHandler(deps)(ctx, configResolveRequest{Key: "k", TenantID: "acme"}, configPrincipal)
	if err != nil || res.Source != sourceOverride || res.Value != "tenant" || res.AppValue != "app" {
		t.Errorf("resolve = %+v, %v", res, err)
	}

	// The empty string is a value, not an unset: it is stored and resolves
	// from the override.
	out, err = overridesSetHandler(deps)(ctx, decodeCommand[overridesSetRequest](t, `{"key":"k","tenantId":"acme","value":""}`), configPrincipal)
	if err != nil || out.Override.Value != "" {
		t.Fatalf("set empty = %+v, %v", out, err)
	}
	res, err = configResolveHandler(deps)(ctx, configResolveRequest{Key: "k", TenantID: "acme"}, configPrincipal)
	if err != nil || res.Source != sourceOverride || res.Value != "" || res.OverrideValue == nil {
		t.Errorf("resolve after empty = %+v, %v", res, err)
	}
}

func TestOverridesSet_Refusals(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	deps := Deps{Vault: v}
	seedConfig(t, v, "n", "int", float64(5))
	seedConfig(t, v, "j", "json", map[string]any{})

	_, err := overridesSetHandler(deps)(ctx, decodeCommand[overridesSetRequest](t, `{"key":"ghost","tenantId":"acme","value":1}`), configPrincipal)
	wantCode(t, err, dashcontract.CodeNotFound, "config entry not found")
	_, err = overridesSetHandler(deps)(ctx, decodeCommand[overridesSetRequest](t, `{"key":"n","tenantId":"acme","value":"abc"}`), configPrincipal)
	wantCode(t, err, dashcontract.CodeBadRequest, "value")
	// Absent is not null: it is refused before the value is judged.
	_, err = overridesSetHandler(deps)(ctx, decodeCommand[overridesSetRequest](t, `{"key":"j","tenantId":"acme"}`), configPrincipal)
	wantCode(t, err, dashcontract.CodeBadRequest, "value is required")
	// Null is a value: refused for an int, stored for a json entry.
	_, err = overridesSetHandler(deps)(ctx, decodeCommand[overridesSetRequest](t, `{"key":"n","tenantId":"acme","value":null}`), configPrincipal)
	wantCode(t, err, dashcontract.CodeBadRequest, "value")
	out, err := overridesSetHandler(deps)(ctx, decodeCommand[overridesSetRequest](t, `{"key":"j","tenantId":"acme","value":null}`), configPrincipal)
	if err != nil || out.Override.Value != nil {
		t.Errorf("json null override = %+v, %v", out, err)
	}
	_, err = overridesSetHandler(deps)(ctx, decodeCommand[overridesSetRequest](t, `{"key":"n","tenantId":" ","value":1}`), configPrincipal)
	wantCode(t, err, dashcontract.CodeBadRequest, "tenantId")
	_, err = overridesSetHandler(deps)(ctx, decodeCommand[overridesSetRequest](t, `{"tenantId":"acme","value":1}`), configPrincipal)
	wantCode(t, err, dashcontract.CodeBadRequest, "key is required")

	list, err := overridesListHandler(deps)(ctx, overridesListRequest{Key: "n"}, configPrincipal)
	if err != nil || list.Total != 0 {
		t.Errorf("a refused set stored an override: %+v, %v", list, err)
	}
}

// --- overrides.delete ---

func TestOverridesDelete_ExplicitUnsetFallsBackToTheAppDefault(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	deps := Deps{Vault: v}
	seedConfig(t, v, "k", "string", "app")
	seedOverride(t, v, "k", "acme", "tenant")
	seedOverride(t, v, "k", "other", "keep")

	out, err := overridesDeleteHandler(deps)(ctx, overridesDeleteRequest{Key: "k", TenantID: " acme "}, configPrincipal)
	if err != nil || !out.OK || out.Key != "k" || out.TenantID != "acme" {
		t.Fatalf("delete = %+v, %v", out, err)
	}
	res, err := configResolveHandler(deps)(ctx, configResolveRequest{Key: "k", TenantID: "acme"}, configPrincipal)
	if err != nil || res.Source != sourceAppDefault || res.Value != "app" || res.OverrideValue != nil {
		t.Errorf("resolve after unset = %+v, %v", res, err)
	}
	list, err := overridesListHandler(deps)(ctx, overridesListRequest{Key: "k"}, configPrincipal)
	if err != nil || !reflect.DeepEqual(overrideRefs(list.Overrides), []string{"k@other"}) {
		t.Errorf("overrides after unset = %+v, %v", list, err)
	}
}

func TestOverridesDelete_Refusals(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	deps := Deps{Vault: v}
	seedConfig(t, v, "k", "string", "app")

	_, err := overridesDeleteHandler(deps)(ctx, overridesDeleteRequest{Key: "k", TenantID: "nobody"}, configPrincipal)
	wantCode(t, err, dashcontract.CodeNotFound, "")
	var ce *dashcontract.Error
	if !errors.As(err, &ce) || ce.Message != "tenant override not found" {
		t.Errorf("message = %v, want exactly %q", err, "tenant override not found")
	}
	// The entry is not read, so a missing key with no override is the same
	// answer as a present key with none.
	_, err = overridesDeleteHandler(deps)(ctx, overridesDeleteRequest{Key: "ghost", TenantID: "nobody"}, configPrincipal)
	if !errors.As(err, &ce) || ce.Code != dashcontract.CodeNotFound || ce.Message != "tenant override not found" {
		t.Errorf("missing key err = %v, want NOT_FOUND %q", err, "tenant override not found")
	}
	_, err = overridesDeleteHandler(deps)(ctx, overridesDeleteRequest{Key: "k", TenantID: " "}, configPrincipal)
	wantCode(t, err, dashcontract.CodeBadRequest, "tenantId")
	_, err = overridesDeleteHandler(deps)(ctx, overridesDeleteRequest{TenantID: "x"}, configPrincipal)
	wantCode(t, err, dashcontract.CodeBadRequest, "key is required")
}

// An override whose entry is gone still resolves for its tenant, so
// overrides.delete must remove it.
func TestOverridesDelete_RemovesAnOrphan(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	deps := Deps{Vault: v}
	seedConfig(t, v, "gone", "string", "app")
	seedOverride(t, v, "gone", "acme", "tenant")
	if err := v.Store().DeleteConfig(ctx, "gone", testAppID); err != nil {
		t.Fatalf("delete entry: %v", err)
	}

	out, err := overridesDeleteHandler(deps)(ctx, overridesDeleteRequest{Key: "gone", TenantID: "acme"}, configPrincipal)
	if err != nil || !out.OK || out.Key != "gone" || out.TenantID != "acme" {
		t.Fatalf("delete of an orphan = %+v, %v", out, err)
	}
	list, err := overridesListHandler(deps)(ctx, overridesListRequest{Key: "gone"}, configPrincipal)
	if err != nil || list.Total != 0 {
		t.Errorf("orphan still listed: %+v, %v", list, err)
	}
}

// flakyReadStore refuses every GetConfig after the first for its key, the way
// a concurrent delete would.
type flakyReadStore struct {
	armed bool
	*memory.Store
	reads int
}

func (s *flakyReadStore) GetConfig(ctx context.Context, key, appID string) (*config.Entry, error) {
	s.reads++
	if s.armed && s.reads > 1 {
		return nil, vault.ErrConfigNotFound
	}
	return s.Store.GetConfig(ctx, key, appID)
}

// overrides.set answers from the entry the manager already read, so an entry
// deleted between the write and the response cannot turn a stored override
// into an error.
func TestOverridesSet_DoesNotReadTheEntryASecondTime(t *testing.T) {
	st := &flakyReadStore{Store: memory.New()}
	v, err := vault.New(vault.WithStore(st), vault.WithAppID(testAppID), vault.WithEncryptionKey(testEncryptionKey))
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	seedConfig(t, v, "k", "string", "app")
	st.reads, st.armed = 0, true

	out, err := overridesSetHandler(Deps{Vault: v})(context.Background(),
		decodeCommand[overridesSetRequest](t, `{"key":"k","tenantId":"acme","value":"tenant"}`), configPrincipal)
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	if o := out.Override; o.Key != "k" || o.TenantID != "acme" || o.Value != "tenant" || !o.KeyExists || !o.ValueMatchesType {
		t.Errorf("override = %+v", o)
	}
	if st.reads != 1 {
		t.Errorf("the entry was read %d times, want once", st.reads)
	}
}
