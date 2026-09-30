package contract

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"

	"github.com/xraph/vault"
	audithook "github.com/xraph/vault/audit_hook"
	"github.com/xraph/vault/config"
	"github.com/xraph/vault/configmgr"
	"github.com/xraph/vault/core"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/override"
	"github.com/xraph/vault/scope"
)

var configPrincipal = dashcontract.Principal{}

// seedConfig creates an entry through the manager, the path the write
// intents use.
func seedConfig(t *testing.T, v *vault.Vault, key, typ string, value any) {
	t.Helper()
	if _, err := v.ConfigManager().Create(context.Background(), configmgr.CreateInput{Key: key, ValueType: typ, Value: value}); err != nil {
		t.Fatalf("seed config %q: %v", key, err)
	}
}

// seedOverride sets a tenant override through the manager.
func seedOverride(t *testing.T, v *vault.Vault, key, tenant string, value any) {
	t.Helper()
	if _, err := v.ConfigManager().SetOverride(context.Background(), key, tenant, value); err != nil {
		t.Fatalf("seed override %q/%q: %v", key, tenant, err)
	}
}

// seedRawConfig writes an entry straight to the store, bypassing the
// manager's validation, the way an older page or another program could have.
func seedRawConfig(t *testing.T, v *vault.Vault, key, typ string, value any) {
	t.Helper()
	if err := v.Store().SetConfig(context.Background(), &config.Entry{
		Entity: core.NewEntity(), ID: id.NewConfigID(), Key: key, Value: value, ValueType: typ, AppID: testAppID,
	}); err != nil {
		t.Fatalf("seed raw config %q: %v", key, err)
	}
}

// seedRawOverride writes an override straight to the store.
func seedRawOverride(t *testing.T, v *vault.Vault, key, tenant string, value any) {
	t.Helper()
	if err := v.Store().SetOverride(context.Background(), &override.Override{
		Entity: core.NewEntity(), ID: id.NewOverrideID(), Key: key, Value: value, AppID: testAppID, TenantID: tenant,
	}); err != nil {
		t.Fatalf("seed raw override %q/%q: %v", key, tenant, err)
	}
}

func configKeys(es []ConfigEntrySummary) []string {
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, e.Key)
	}
	return out
}

func overrideRefs(os []OverrideSummary) []string {
	out := make([]string, 0, len(os))
	for _, o := range os {
		out = append(out, o.Key+"@"+o.TenantID)
	}
	return out
}

// --- config.list ---

func TestConfigList_PrefixFilterAndTotal(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	for _, k := range []string{"db.host", "db.port", "db.user", "cache.ttl", "dbx"} {
		seedConfig(t, v, k, "string", "x")
	}
	deps := Deps{Vault: v}

	out, err := configListHandler(deps)(ctx, configListRequest{KeyPrefix: "db.", Limit: 2}, configPrincipal)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if out.Total != 3 || !reflect.DeepEqual(configKeys(out.Entries), []string{"db.host", "db.port"}) {
		t.Errorf("page 1 = %v total %d, want [db.host db.port] total 3", configKeys(out.Entries), out.Total)
	}
	out, err = configListHandler(deps)(ctx, configListRequest{KeyPrefix: "db.", Limit: 2, Offset: 2}, configPrincipal)
	if err != nil {
		t.Fatalf("list page 2: %v", err)
	}
	if out.Total != 3 || !reflect.DeepEqual(configKeys(out.Entries), []string{"db.user"}) {
		t.Errorf("page 2 = %v total %d, want [db.user] total 3", configKeys(out.Entries), out.Total)
	}

	all, err := configListHandler(deps)(ctx, configListRequest{}, configPrincipal)
	if err != nil || all.Total != 5 || len(all.Entries) != 5 {
		t.Errorf("unfiltered = %+v, %v", all, err)
	}
	none, err := configListHandler(deps)(ctx, configListRequest{KeyPrefix: "zzz"}, configPrincipal)
	if err != nil {
		t.Fatalf("list none: %v", err)
	}
	if none.Total != 0 || none.Entries == nil {
		t.Errorf("no match = %+v, want total 0 and a non-nil entries slice", none)
	}
	raw, _ := json.Marshal(none)
	if !strings.Contains(string(raw), `"entries":[]`) {
		t.Errorf("wire form = %s, want an empty array", raw)
	}
}

func TestConfigList_LimitDefaultsAndCap(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	for i := 0; i < 130; i++ {
		seedConfig(t, v, "k"+itoa(1000+i), "int", float64(i))
	}
	deps := Deps{Vault: v}

	def, err := configListHandler(deps)(ctx, configListRequest{}, configPrincipal)
	if err != nil || len(def.Entries) != 25 || def.Total != 130 {
		t.Errorf("default limit: %d entries total %d, %v", len(def.Entries), def.Total, err)
	}
	big, err := configListHandler(deps)(ctx, configListRequest{Limit: 500}, configPrincipal)
	if err != nil || len(big.Entries) != 100 {
		t.Errorf("capped limit: %d entries, %v", len(big.Entries), err)
	}
	neg, err := configListHandler(deps)(ctx, configListRequest{Limit: -3, Offset: -9}, configPrincipal)
	if err != nil || len(neg.Entries) != 25 {
		t.Errorf("negative limit and offset: %d entries, %v", len(neg.Entries), err)
	}
}

func TestConfigList_OtherAppsEntriesAreInvisible(t *testing.T) {
	v, st := newTestVault(t)
	ctx := context.Background()
	seedConfig(t, v, "mine", "string", "x")
	if err := st.SetConfig(ctx, &config.Entry{Entity: core.NewEntity(), ID: id.NewConfigID(), Key: "theirs", Value: "x", ValueType: "string", AppID: "other"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	out, err := configListHandler(Deps{Vault: v})(ctx, configListRequest{}, configPrincipal)
	if err != nil || out.Total != 1 || !reflect.DeepEqual(configKeys(out.Entries), []string{"mine"}) {
		t.Errorf("list = %+v, %v", out, err)
	}
}

func TestConfigList_ReportsTypeMismatchAndUnknownType(t *testing.T) {
	v, _ := newTestVault(t)
	seedRawConfig(t, v, "count", "int", "abc")
	seedRawConfig(t, v, "page", "yaml", "a: 1")
	seedConfig(t, v, "fine", "int", float64(3))

	out, err := configListHandler(Deps{Vault: v})(context.Background(), configListRequest{}, configPrincipal)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	by := map[string]ConfigEntrySummary{}
	for _, e := range out.Entries {
		by[e.Key] = e
	}
	if e := by["count"]; !e.KnownType || e.ValueMatchesType {
		t.Errorf("string on an int entry: knownType=%v valueMatchesType=%v, want true and false", e.KnownType, e.ValueMatchesType)
	}
	if e := by["page"]; e.KnownType || e.ValueMatchesType {
		t.Errorf("yaml entry: knownType=%v valueMatchesType=%v, want false and false", e.KnownType, e.ValueMatchesType)
	}
	if e := by["fine"]; !e.KnownType || !e.ValueMatchesType {
		t.Errorf("int 3 on an int entry: knownType=%v valueMatchesType=%v", e.KnownType, e.ValueMatchesType)
	}
}

// --- config.detail ---

func TestConfigDetail_ProjectsEveryField(t *testing.T) {
	v, st := newTestVault(t)
	ctx := context.Background()
	if _, err := v.ConfigManager().Create(ctx, configmgr.CreateInput{
		Key: "limits", ValueType: "json", Value: map[string]any{"max": float64(5)}, Description: "request limits",
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	// Metadata has no write path; seed it the way a program that defines
	// entries in code does.
	e, err := st.GetConfig(ctx, "limits", testAppID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	e.Metadata = map[string]string{"owner": "growth"}
	if err = st.SetConfig(ctx, e); err != nil {
		t.Fatalf("seed metadata: %v", err)
	}
	seedOverride(t, v, "limits", "zed", map[string]any{"max": float64(9)})
	seedOverride(t, v, "limits", "acme", map[string]any{"max": float64(7)})

	out, err := configDetailHandler(Deps{Vault: v})(ctx, configDetailRequest{Key: "limits"}, configPrincipal)
	if err != nil {
		t.Fatalf("detail: %v", err)
	}
	got := out.Entry
	if got.ID == "" || got.Key != "limits" || got.ValueType != "json" || !got.KnownType || !got.ValueMatchesType {
		t.Errorf("entry identity = %+v", got)
	}
	if !reflect.DeepEqual(got.Value, map[string]any{"max": float64(5)}) {
		t.Errorf("value = %#v", got.Value)
	}
	if got.Version != 2 || got.Description != "request limits" || !reflect.DeepEqual(got.Metadata, map[string]string{"owner": "growth"}) {
		t.Errorf("version=%d description=%q metadata=%v", got.Version, got.Description, got.Metadata)
	}
	if _, err = time.Parse(time.RFC3339, got.CreatedAt); err != nil {
		t.Errorf("createdAt = %q", got.CreatedAt)
	}
	if _, err = time.Parse(time.RFC3339, got.UpdatedAt); err != nil {
		t.Errorf("updatedAt = %q", got.UpdatedAt)
	}
	if !reflect.DeepEqual(overrideRefs(out.Overrides), []string{"limits@acme", "limits@zed"}) {
		t.Errorf("overrides = %v, want tenant order", overrideRefs(out.Overrides))
	}
	for _, o := range out.Overrides {
		if !o.KeyExists || !o.ValueMatchesType {
			t.Errorf("override %+v: keyExists and valueMatchesType must be true", o)
		}
	}
	if out.Overrides[0].Value == nil {
		t.Errorf("override value missing: %+v", out.Overrides[0])
	}
}

func TestConfigDetail_EmptyMetadataIsAnObjectAndListsAreArrays(t *testing.T) {
	v, _ := newTestVault(t)
	seedConfig(t, v, "plain", "string", "x")
	// Round-trip through the wire: a nil map or slice would print as null.
	out, err := configDetailHandler(Deps{Vault: v})(context.Background(), configDetailRequest{Key: "plain"}, configPrincipal)
	if err != nil {
		t.Fatalf("detail: %v", err)
	}
	raw, _ := json.Marshal(out)
	s := string(raw)
	for _, want := range []string{`"metadata":{}`, `"overrides":[]`} {
		if !strings.Contains(s, want) {
			t.Errorf("wire form %s lacks %s", s, want)
		}
	}
	if strings.Contains(s, "null") {
		t.Errorf("wire form carries a null: %s", s)
	}
}

func TestConfigDetail_Errors(t *testing.T) {
	v, _ := newTestVault(t)
	h := configDetailHandler(Deps{Vault: v})
	_, err := h(context.Background(), configDetailRequest{Key: "  "}, configPrincipal)
	wantCode(t, err, dashcontract.CodeBadRequest, "key is required")
	_, err = h(context.Background(), configDetailRequest{Key: "ghost"}, configPrincipal)
	wantCode(t, err, dashcontract.CodeNotFound, "config entry not found")
}

// A stored "yaml" entry is the templ page's doing. It must come back, say it
// is a type the vault does not validate, and not claim the value is wrong.
func TestConfigDetail_StoredYamlEntryReportsUnknownType(t *testing.T) {
	v, _ := newTestVault(t)
	seedRawConfig(t, v, "page", "yaml", "a: 1")
	out, err := configDetailHandler(Deps{Vault: v})(context.Background(), configDetailRequest{Key: "page"}, configPrincipal)
	if err != nil {
		t.Fatalf("detail: %v", err)
	}
	if out.Entry.KnownType || out.Entry.ValueType != "yaml" || out.Entry.Value != "a: 1" {
		t.Errorf("entry = %+v", out.Entry)
	}
}

// Rows for the key on two resources, plus newer rows on the same key that
// belong to a flag and a secret: only config and override rows come back,
// newest first, at most ten.
func TestConfigDetail_RecentAuditMergesConfigAndOverrideRowsNewestFirst(t *testing.T) {
	v, st := newTestVault(t)
	ctx := context.Background()
	seedConfig(t, v, "shared", "string", "x")

	base := time.Now().UTC().Add(time.Hour)
	// Interleaved by time: config at +0s +1s +2s, override at +0.5s +1.5s.
	recordAuditRows(t, st, "shared", audithook.ResourceConfig, base, audithook.ActionConfigSet, audithook.ActionConfigSet, audithook.ActionConfigDeleted)
	recordAuditRows(t, st, "shared", audithook.ResourceOverride, base.Add(500*time.Millisecond), audithook.ActionOverrideSet, audithook.ActionOverrideDeleted)
	recordAuditRows(t, st, "shared", audithook.ResourceFlag, base.Add(time.Hour), repeatAction(audithook.ActionFlagUpdated, 12)...)
	recordAuditRows(t, st, "shared", audithook.ResourceSecret, base.Add(2*time.Hour), repeatAction(audithook.ActionSecretAccessed, 12)...)

	out, err := configDetailHandler(Deps{Vault: v})(ctx, configDetailRequest{Key: "shared"}, configPrincipal)
	if err != nil {
		t.Fatalf("detail: %v", err)
	}
	for _, e := range out.RecentAudit {
		if !strings.HasPrefix(e.Action, "config.") && !strings.HasPrefix(e.Action, "override.") {
			t.Errorf("recentAudit carries a foreign row: %+v", e)
		}
	}
	// Times are newest first and the two resources are interleaved, not
	// concatenated.
	times := make([]string, 0, len(out.RecentAudit))
	for _, e := range out.RecentAudit {
		times = append(times, e.CreatedAt)
	}
	for i := 1; i < len(times); i++ {
		if times[i-1] < times[i] {
			t.Errorf("recentAudit is not newest first: %v", times)
		}
	}
	first5 := make([]string, 0, 5)
	for _, e := range out.RecentAudit[:5] {
		first5 = append(first5, e.Action)
	}
	want := []string{audithook.ActionConfigDeleted, audithook.ActionOverrideDeleted, audithook.ActionConfigSet, audithook.ActionOverrideSet, audithook.ActionConfigSet}
	if !reflect.DeepEqual(first5, want) {
		t.Errorf("first five actions = %v, want %v", first5, want)
	}
}

func TestConfigDetail_RecentAuditIsBoundedAtTen(t *testing.T) {
	v, st := newTestVault(t)
	seedConfig(t, v, "busy", "string", "x")
	base := time.Now().UTC().Add(time.Hour)
	recordAuditRows(t, st, "busy", audithook.ResourceConfig, base, repeatAction(audithook.ActionConfigSet, 14)...)
	recordAuditRows(t, st, "busy", audithook.ResourceOverride, base.Add(time.Minute), repeatAction(audithook.ActionOverrideSet, 14)...)
	out, err := configDetailHandler(Deps{Vault: v})(context.Background(), configDetailRequest{Key: "busy"}, configPrincipal)
	if err != nil {
		t.Fatalf("detail: %v", err)
	}
	if len(out.RecentAudit) != 10 {
		t.Fatalf("recentAudit = %d rows, want 10", len(out.RecentAudit))
	}
	for _, e := range out.RecentAudit {
		if e.Action != audithook.ActionOverrideSet {
			t.Errorf("row %+v: the ten newest are all override rows", e)
		}
	}
}

// The manager writes its own audit rows: an override write must show up in
// the key's recent audit.
func TestConfigDetail_RecentAuditShowsOverrideRowsWrittenByTheManager(t *testing.T) {
	v, _ := newTestVault(t)
	seedConfig(t, v, "flagged", "int", float64(1))
	seedOverride(t, v, "flagged", "acme", float64(2))
	if err := v.ConfigManager().DeleteOverride(context.Background(), "flagged", "acme"); err != nil {
		t.Fatalf("delete override: %v", err)
	}
	out, err := configDetailHandler(Deps{Vault: v})(context.Background(), configDetailRequest{Key: "flagged"}, configPrincipal)
	if err != nil {
		t.Fatalf("detail: %v", err)
	}
	seen := map[string]bool{}
	for _, e := range out.RecentAudit {
		seen[e.Action] = true
	}
	for _, want := range []string{audithook.ActionConfigSet, audithook.ActionOverrideSet, audithook.ActionOverrideDeleted} {
		if !seen[want] {
			t.Errorf("recentAudit lacks %s: %+v", want, out.RecentAudit)
		}
	}
}

// --- config.versions ---

func TestConfigVersions_NewestFirstWithCurrent(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	seedConfig(t, v, "n", "int", float64(1))
	for _, val := range []any{float64(2), float64(3)} {
		val := val
		if _, err := v.ConfigManager().Update(ctx, "n", configmgr.UpdateInput{Value: &val}); err != nil {
			t.Fatalf("update: %v", err)
		}
	}
	out, err := configVersionsHandler(Deps{Vault: v})(ctx, configVersionsRequest{Key: "n"}, configPrincipal)
	if err != nil {
		t.Fatalf("versions: %v", err)
	}
	if len(out.Versions) != 3 {
		t.Fatalf("versions = %+v", out.Versions)
	}
	for i, wantVersion := range []int64{3, 2, 1} {
		got := out.Versions[i]
		if got.Version != wantVersion || got.Value != float64(wantVersion) || !got.ValueMatchesType || got.Current != (wantVersion == 3) {
			t.Errorf("versions[%d] = %+v, want version %d current=%v", i, got, wantVersion, wantVersion == 3)
		}
		if _, err = time.Parse(time.RFC3339, got.CreatedAt); err != nil {
			t.Errorf("versions[%d].createdAt = %q", i, got.CreatedAt)
		}
	}
}

func TestConfigVersions_MatchesTypeAgainstTheCurrentType(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	// Version 1 was a string, then the entry was retyped to int.
	seedRawConfig(t, v, "n", "string", "abc")
	seedRawConfig(t, v, "n", "int", float64(2))
	out, err := configVersionsHandler(Deps{Vault: v})(ctx, configVersionsRequest{Key: "n"}, configPrincipal)
	if err != nil {
		t.Fatalf("versions: %v", err)
	}
	if len(out.Versions) != 2 || out.Versions[0].Value != float64(2) || !out.Versions[0].ValueMatchesType ||
		out.Versions[1].Value != "abc" || out.Versions[1].ValueMatchesType {
		t.Errorf("versions = %+v, want [2 ok, abc mismatched]", out.Versions)
	}
}

func TestConfigVersions_Errors(t *testing.T) {
	v, _ := newTestVault(t)
	h := configVersionsHandler(Deps{Vault: v})
	_, err := h(context.Background(), configVersionsRequest{Key: ""}, configPrincipal)
	wantCode(t, err, dashcontract.CodeBadRequest, "key is required")
	// The store answers an unknown key with an empty list; the handler must
	// still say not found.
	_, err = h(context.Background(), configVersionsRequest{Key: "ghost"}, configPrincipal)
	wantCode(t, err, dashcontract.CodeNotFound, "config entry not found")
}

// --- config.resolve ---

func TestConfigResolve_SourceForOverrideAndAppDefault(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	seedConfig(t, v, "limit", "int", float64(10))
	seedOverride(t, v, "limit", "acme", float64(50))
	h := configResolveHandler(Deps{Vault: v})

	out, err := h(ctx, configResolveRequest{Key: "limit", TenantID: "acme"}, configPrincipal)
	if err != nil {
		t.Fatalf("resolve acme: %v", err)
	}
	if out.Source != "override" || out.Value != float64(50) || out.AppValue != float64(10) || !out.ValueMatchesType ||
		out.OverrideValue == nil || *out.OverrideValue != float64(50) || out.TenantID != "acme" {
		t.Errorf("acme = %+v", out)
	}

	out, err = h(ctx, configResolveRequest{Key: "limit", TenantID: "nobody"}, configPrincipal)
	if err != nil {
		t.Fatalf("resolve nobody: %v", err)
	}
	if out.Source != "appDefault" || out.Value != float64(10) || out.AppValue != float64(10) || out.OverrideValue != nil || out.TenantID != "nobody" {
		t.Errorf("nobody = %+v", out)
	}

	out, err = h(ctx, configResolveRequest{Key: "limit"}, configPrincipal)
	if err != nil {
		t.Fatalf("resolve no tenant: %v", err)
	}
	if out.Source != "appDefault" || out.Value != float64(10) || out.TenantID != "" {
		t.Errorf("no tenant = %+v", out)
	}
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), "overrideValue") || strings.Contains(string(raw), "tenantId") {
		t.Errorf("wire form %s must omit overrideValue and tenantId when there are none", raw)
	}
}

// An empty-string override is an override, not "no override": the source is
// override and the value is "".
func TestConfigResolve_EmptyStringOverrideStillAnswers(t *testing.T) {
	v, _ := newTestVault(t)
	seedConfig(t, v, "banner", "string", "hello")
	seedOverride(t, v, "banner", "acme", "")
	out, err := configResolveHandler(Deps{Vault: v})(context.Background(), configResolveRequest{Key: "banner", TenantID: "acme"}, configPrincipal)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	raw, _ := json.Marshal(out)
	if out.Source != "override" || out.Value != "" || out.AppValue != "hello" || !strings.Contains(string(raw), `"overrideValue":""`) {
		t.Errorf("resolve = %+v, wire %s", out, raw)
	}
}

func TestConfigResolve_NullJSONOverrideStillReachesTheWire(t *testing.T) {
	v, _ := newTestVault(t)
	seedConfig(t, v, "blob", "json", map[string]any{"a": float64(1)})
	seedOverride(t, v, "blob", "acme", nil)
	out, err := configResolveHandler(Deps{Vault: v})(context.Background(), configResolveRequest{Key: "blob", TenantID: "acme"}, configPrincipal)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	raw, _ := json.Marshal(out)
	if out.Source != "override" || out.Value != nil || !strings.Contains(string(raw), `"overrideValue":null`) {
		t.Errorf("resolve = %+v, wire %s", out, raw)
	}
}

func TestConfigResolve_MissingKeyIsNotFoundEvenWithAnOrphanOverride(t *testing.T) {
	v, _ := newTestVault(t)
	seedRawOverride(t, v, "ghost", "acme", float64(1))
	_, err := configResolveHandler(Deps{Vault: v})(context.Background(), configResolveRequest{Key: "ghost", TenantID: "acme"}, configPrincipal)
	wantCode(t, err, dashcontract.CodeNotFound, "config entry not found")
	_, err = configResolveHandler(Deps{Vault: v})(context.Background(), configResolveRequest{Key: ""}, configPrincipal)
	wantCode(t, err, dashcontract.CodeBadRequest, "key is required")
}

func TestConfigResolve_NeverInheritsTheTenantFromTheRequestContext(t *testing.T) {
	v, _ := newTestVault(t)
	seedConfig(t, v, "limit", "int", float64(10))
	seedOverride(t, v, "limit", "acme", float64(50))
	leaky := scope.WithTenantID(context.Background(), "acme")
	out, err := configResolveHandler(Deps{Vault: v})(leaky, configResolveRequest{Key: "limit"}, configPrincipal)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if out.Source != "appDefault" || out.Value != float64(10) {
		t.Errorf("resolve with a tenant in ctx and none requested = %+v, want the app default", out)
	}
}

func TestConfigResolve_ReportsAMismatchedOverride(t *testing.T) {
	v, _ := newTestVault(t)
	seedConfig(t, v, "limit", "int", float64(10))
	seedRawOverride(t, v, "limit", "acme", "abc")
	out, err := configResolveHandler(Deps{Vault: v})(context.Background(), configResolveRequest{Key: "limit", TenantID: "acme"}, configPrincipal)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if out.Source != "override" || out.Value != "abc" || out.ValueMatchesType {
		t.Errorf("resolve = %+v, want the override, flagged as not an int", out)
	}
}

// --- overrides.list ---

func TestOverridesList_ByTenantByKeyAndBoth(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	for _, k := range []string{"a", "b", "c"} {
		seedConfig(t, v, k, "int", float64(1))
	}
	seedOverride(t, v, "a", "acme", float64(2))
	seedOverride(t, v, "b", "acme", float64(3))
	seedOverride(t, v, "a", "zed", float64(4))
	h := overridesListHandler(Deps{Vault: v})

	out, err := h(ctx, overridesListRequest{TenantID: "acme"}, configPrincipal)
	if err != nil {
		t.Fatalf("by tenant: %v", err)
	}
	if out.Total != 2 || !reflect.DeepEqual(overrideRefs(out.Overrides), []string{"a@acme", "b@acme"}) {
		t.Errorf("by tenant = %v total %d", overrideRefs(out.Overrides), out.Total)
	}
	out, err = h(ctx, overridesListRequest{Key: "a"}, configPrincipal)
	if err != nil {
		t.Fatalf("by key: %v", err)
	}
	if out.Total != 2 || !reflect.DeepEqual(overrideRefs(out.Overrides), []string{"a@acme", "a@zed"}) {
		t.Errorf("by key = %v total %d", overrideRefs(out.Overrides), out.Total)
	}
	for _, o := range out.Overrides {
		if !o.KeyExists || !o.ValueMatchesType || o.Value == nil {
			t.Errorf("override = %+v", o)
		}
	}
	out, err = h(ctx, overridesListRequest{Key: "a", TenantID: "zed"}, configPrincipal)
	if err != nil || out.Total != 1 || out.Overrides[0].TenantID != "zed" || out.Overrides[0].Value != float64(4) {
		t.Errorf("both = %+v, %v", out, err)
	}
	out, err = h(ctx, overridesListRequest{Key: "c", TenantID: "zed"}, configPrincipal)
	if err != nil || out.Total != 0 || out.Overrides == nil {
		t.Errorf("both, none stored = %+v, %v", out, err)
	}
	out, err = h(ctx, overridesListRequest{TenantID: "nobody"}, configPrincipal)
	raw, _ := json.Marshal(out)
	if err != nil || out.Total != 0 || !strings.Contains(string(raw), `"overrides":[]`) {
		t.Errorf("empty tenant = %s, %v", raw, err)
	}
}

func TestOverridesList_NeitherIsBadRequest(t *testing.T) {
	v, _ := newTestVault(t)
	_, err := overridesListHandler(Deps{Vault: v})(context.Background(), overridesListRequest{Limit: 10}, configPrincipal)
	wantCode(t, err, dashcontract.CodeBadRequest, "give a tenantId or a key")
	_, err = overridesListHandler(Deps{Vault: v})(context.Background(), overridesListRequest{TenantID: "  ", Key: " "}, configPrincipal)
	wantCode(t, err, dashcontract.CodeBadRequest, "give a tenantId or a key")
}

func TestOverridesList_ExactPagingTotal(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	for i := 0; i < 7; i++ {
		k := "k" + itoa(10+i)
		seedConfig(t, v, k, "int", float64(i))
		seedOverride(t, v, k, "acme", float64(i))
	}
	h := overridesListHandler(Deps{Vault: v})

	p1, err := h(ctx, overridesListRequest{TenantID: "acme", Limit: 3}, configPrincipal)
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	p2, _ := h(ctx, overridesListRequest{TenantID: "acme", Limit: 3, Offset: 3}, configPrincipal)
	p3, _ := h(ctx, overridesListRequest{TenantID: "acme", Limit: 3, Offset: 6}, configPrincipal)
	past, _ := h(ctx, overridesListRequest{TenantID: "acme", Limit: 3, Offset: 60}, configPrincipal)
	if p1.Total != 7 || p2.Total != 7 || p3.Total != 7 || past.Total != 7 {
		t.Errorf("totals = %d %d %d %d, want 7 throughout", p1.Total, p2.Total, p3.Total, past.Total)
	}
	got := append(append(overrideRefs(p1.Overrides), overrideRefs(p2.Overrides)...), overrideRefs(p3.Overrides)...)
	want := []string{"k10@acme", "k11@acme", "k12@acme", "k13@acme", "k14@acme", "k15@acme", "k16@acme"}
	if !reflect.DeepEqual(got, want) || len(past.Overrides) != 0 || past.Overrides == nil {
		t.Errorf("pages joined = %v, past = %+v", got, past.Overrides)
	}

	def, err := h(ctx, overridesListRequest{TenantID: "acme"}, configPrincipal)
	if err != nil || len(def.Overrides) != 7 {
		t.Errorf("default limit: %d rows, %v", len(def.Overrides), err)
	}
}

func TestOverridesList_OrphanAndMismatchedRows(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	seedConfig(t, v, "live", "int", float64(1))
	seedOverride(t, v, "live", "acme", float64(2))
	seedRawOverride(t, v, "gone", "acme", float64(3)) // key never existed
	seedRawOverride(t, v, "live", "zed", "abc")       // wrong type

	byTenant, err := overridesListHandler(Deps{Vault: v})(ctx, overridesListRequest{TenantID: "acme"}, configPrincipal)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	by := map[string]OverrideSummary{}
	for _, o := range byTenant.Overrides {
		by[o.Key] = o
	}
	if o := by["live"]; !o.KeyExists || !o.ValueMatchesType {
		t.Errorf("live = %+v", o)
	}
	if o := by["gone"]; o.KeyExists || o.ValueMatchesType || o.Value != float64(3) {
		t.Errorf("orphan = %+v, want keyExists=false valueMatchesType=false and its value kept", o)
	}

	byKey, err := overridesListHandler(Deps{Vault: v})(ctx, overridesListRequest{Key: "gone"}, configPrincipal)
	if err != nil || byKey.Total != 1 || byKey.Overrides[0].KeyExists {
		t.Errorf("orphan by key = %+v, %v", byKey, err)
	}
	mis, err := overridesListHandler(Deps{Vault: v})(ctx, overridesListRequest{TenantID: "zed"}, configPrincipal)
	if err != nil || len(mis.Overrides) != 1 || !mis.Overrides[0].KeyExists || mis.Overrides[0].ValueMatchesType {
		t.Errorf("mismatched = %+v, %v", mis, err)
	}
}

func TestOverridesList_OtherAppsOverridesAreInvisible(t *testing.T) {
	v, st := newTestVault(t)
	seedConfig(t, v, "k", "int", float64(1))
	if err := st.SetOverride(context.Background(), &override.Override{Entity: core.NewEntity(), ID: id.NewOverrideID(), Key: "k", Value: float64(9), AppID: "other", TenantID: "acme"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	out, err := overridesListHandler(Deps{Vault: v})(context.Background(), overridesListRequest{TenantID: "acme"}, configPrincipal)
	if err != nil || out.Total != 0 {
		t.Errorf("list = %+v, %v", out, err)
	}
}
