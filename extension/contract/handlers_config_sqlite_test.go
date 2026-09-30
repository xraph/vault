package contract

import (
	"context"
	"reflect"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/xraph/vault/config"
	"github.com/xraph/vault/configmgr"
	"github.com/xraph/vault/core"
	"github.com/xraph/vault/id"
)

// The config and override queries against a real backend. Memory hands a
// value back as the Go value it was given; sqlite writes JSON text and reads
// it back as float64, map[string]any and []any, and refuses an offset with no
// limit, which is what these tests need to see.

func TestConfig_SQLite_ListDetailVersionsResolve(t *testing.T) {
	v := newSQLiteTestVault(t)
	ctx := context.Background()
	deps := Deps{Vault: v}

	for _, k := range []string{"app.a", "app.b", "app.c", "other"} {
		seedConfig(t, v, k, "int", float64(1))
	}
	seedConfig(t, v, "app.blob", "json", map[string]any{"a": []any{float64(1)}})
	seedRawConfig(t, v, "page", "yaml", "a: 1")
	val := any(float64(2))
	if _, err := v.ConfigManager().Update(ctx, "app.a", configmgr.UpdateInput{Value: &val}); err != nil {
		t.Fatalf("update: %v", err)
	}
	seedOverride(t, v, "app.a", "acme", float64(9))
	seedOverride(t, v, "app.b", "acme", float64(8))
	seedRawOverride(t, v, "ghost", "acme", float64(7))

	// An offset on a filtered list must reach sqlite with a limit.
	page, err := configListHandler(deps)(ctx, configListRequest{KeyPrefix: "app.", Limit: 2, Offset: 2}, configPrincipal)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if page.Total != 4 || !reflect.DeepEqual(configKeys(page.Entries), []string{"app.blob", "app.c"}) {
		t.Errorf("list page = %v total %d", configKeys(page.Entries), page.Total)
	}
	unbounded, err := configListHandler(deps)(ctx, configListRequest{Offset: 1}, configPrincipal)
	if err != nil || len(unbounded.Entries) != 5 || unbounded.Total != 6 {
		t.Errorf("list offset with no limit: %d entries total %d, %v", len(unbounded.Entries), unbounded.Total, err)
	}
	for _, e := range page.Entries {
		if e.Key == "app.blob" && (!reflect.DeepEqual(e.Value, map[string]any{"a": []any{float64(1)}}) || !e.ValueMatchesType) {
			t.Errorf("blob = %+v", e)
		}
	}

	det, err := configDetailHandler(deps)(ctx, configDetailRequest{Key: "app.a"}, configPrincipal)
	if err != nil {
		t.Fatalf("detail: %v", err)
	}
	if det.Entry.Value != float64(2) || det.Entry.Version != 2 || len(det.Overrides) != 1 || det.Overrides[0].Value != float64(9) || !det.Overrides[0].KeyExists {
		t.Errorf("detail = %+v", det)
	}
	seen := map[string]bool{}
	for _, e := range det.RecentAudit {
		seen[e.Action] = true
	}
	if !seen["config.set"] || !seen["override.set"] {
		t.Errorf("recentAudit = %+v, want config and override rows", det.RecentAudit)
	}

	vers, err := configVersionsHandler(deps)(ctx, configVersionsRequest{Key: "app.a"}, configPrincipal)
	if err != nil || len(vers.Versions) != 2 || vers.Versions[0].Version != 2 || !vers.Versions[0].Current ||
		vers.Versions[1].Value != float64(1) || vers.Versions[1].Current {
		t.Errorf("versions = %+v, %v", vers, err)
	}

	res, err := configResolveHandler(deps)(ctx, configResolveRequest{Key: "app.a", TenantID: "acme"}, configPrincipal)
	if err != nil || res.Source != "override" || res.Value != float64(9) || res.AppValue != float64(2) {
		t.Errorf("resolve = %+v, %v", res, err)
	}

	byTenant, err := overridesListHandler(deps)(ctx, overridesListRequest{TenantID: "acme", Limit: 2, Offset: 1}, configPrincipal)
	if err != nil {
		t.Fatalf("overrides: %v", err)
	}
	if byTenant.Total != 3 || !reflect.DeepEqual(overrideRefs(byTenant.Overrides), []string{"app.b@acme", "ghost@acme"}) || byTenant.Overrides[1].KeyExists {
		t.Errorf("overrides = %+v", byTenant)
	}
	empty, err := overridesListHandler(deps)(ctx, overridesListRequest{TenantID: "nobody"}, configPrincipal)
	if err != nil || empty.Overrides == nil || empty.Total != 0 {
		t.Errorf("empty overrides = %+v, %v", empty, err)
	}
	none, err := configListHandler(deps)(ctx, configListRequest{KeyPrefix: "zzz"}, configPrincipal)
	if err != nil || none.Entries == nil {
		t.Errorf("empty list = %+v, %v", none, err)
	}
}

// A mongo read gives bson.D and int32: they must leave as plain JSON shapes
// and still be judged against the entry's type.
func TestConfig_MongoShapedValuesProjectAsPlainJSON(t *testing.T) {
	v, st := newTestVault(t)
	ctx := context.Background()
	if err := st.SetConfig(ctx, &config.Entry{
		Entity: core.NewEntity(), ID: id.NewConfigID(), Key: "cfg", ValueType: "json", AppID: testAppID,
		Value: bson.D{{Key: "limit", Value: int32(5)}, {Key: "tags", Value: bson.A{"a"}}},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := st.SetConfig(ctx, &config.Entry{Entity: core.NewEntity(), ID: id.NewConfigID(), Key: "n", ValueType: "int", AppID: testAppID, Value: int32(7)}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	seedRawOverride(t, v, "n", "acme", int32(8))

	list, err := configListHandler(Deps{Vault: v})(ctx, configListRequest{}, configPrincipal)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	by := map[string]ConfigEntrySummary{}
	for _, e := range list.Entries {
		by[e.Key] = e
	}
	if want := map[string]any{"limit": float64(5), "tags": []any{"a"}}; !reflect.DeepEqual(by["cfg"].Value, want) || !by["cfg"].ValueMatchesType {
		t.Errorf("cfg = %+v", by["cfg"])
	}
	if by["n"].Value != float64(7) || !by["n"].ValueMatchesType {
		t.Errorf("n = %+v", by["n"])
	}
	res, err := configResolveHandler(Deps{Vault: v})(ctx, configResolveRequest{Key: "n", TenantID: "acme"}, configPrincipal)
	if err != nil || res.Value != float64(8) || res.OverrideValue == nil || *res.OverrideValue != float64(8) || !res.ValueMatchesType {
		t.Errorf("resolve = %+v, %v", res, err)
	}
}
