package contract

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"

	"github.com/xraph/vault"
	"github.com/xraph/vault/audit"
	audithook "github.com/xraph/vault/audit_hook"
	"github.com/xraph/vault/core"
	"github.com/xraph/vault/flag"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/scope"
	"github.com/xraph/vault/store"
	"github.com/xraph/vault/store/memory"
)

var flagPrincipal = dashcontract.Principal{}

// seedFlag creates a flag through the manager, the same path the write
// intents use.
func seedFlag(t *testing.T, v *vault.Vault, key string, typ flag.Type, def any, enabled bool) {
	t.Helper()
	if _, err := v.FlagManager().Create(context.Background(), flag.CreateInput{
		Key: key, Type: typ, DefaultValue: def, Enabled: enabled,
	}); err != nil {
		t.Fatalf("seed flag %q: %v", key, err)
	}
}

// seedRules sets a flag's rules through the manager.
func seedRules(t *testing.T, v *vault.Vault, key string, rules ...flag.RuleInput) {
	t.Helper()
	if _, err := v.FlagManager().SetRules(context.Background(), key, rules); err != nil {
		t.Fatalf("seed rules for %q: %v", key, err)
	}
}

// --- wireValue ---

func TestWireValue(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want any
	}{
		{"nil", nil, nil},
		{"bool", true, true},
		{"string", "x", "x"},
		{"float", 1.5, 1.5},
		{"go int becomes float64", 5, float64(5)},
		{"int32 from mongo becomes float64", int32(7), float64(7)},
		{"bson.D becomes a plain map", bson.D{{Key: "a", Value: int32(1)}, {Key: "b", Value: "x"}}, map[string]any{"a": float64(1), "b": "x"}},
		{"bson.A becomes a plain slice", bson.A{int32(1), "two", bson.D{{Key: "k", Value: true}}}, []any{float64(1), "two", map[string]any{"k": true}}},
		{"nested bson.D in bson.D", bson.D{{Key: "o", Value: bson.D{{Key: "n", Value: int64(3)}}}}, map[string]any{"o": map[string]any{"n": float64(3)}}},
		{"map[string]any", map[string]any{"a": []string{"x"}}, map[string]any{"a": []any{"x"}}},
		{"slice", []int{1, 2}, []any{float64(1), float64(2)}},
		{"unmarshalable projects as nil", make(chan int), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := wireValue(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("wireValue(%#v) = %#v, want %#v", tt.in, got, tt.want)
			}
		})
	}
}

// --- flags.list ---

func TestFlagsList_PagingTypeFilterAndTotals(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	seedFlag(t, v, "a-bool", flag.TypeBool, true, true)
	seedFlag(t, v, "b-string", flag.TypeString, "x", true)
	seedFlag(t, v, "c-bool", flag.TypeBool, false, false)
	seedFlag(t, v, "d-int", flag.TypeInt, float64(3), true)
	seedFlag(t, v, "e-bool", flag.TypeBool, true, true)

	h := flagsListHandler(Deps{Vault: v})

	all, err := h(ctx, flagsListRequest{}, flagPrincipal)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if all.Total != 5 || len(all.Flags) != 5 {
		t.Fatalf("all: total=%d len=%d, want 5 and 5", all.Total, len(all.Flags))
	}
	if all.Flags[0].Key != "a-bool" || all.Flags[4].Key != "e-bool" {
		t.Errorf("flags are not in key order: %v", flagKeys(all.Flags))
	}

	bools, err := h(ctx, flagsListRequest{Type: "bool"}, flagPrincipal)
	if err != nil {
		t.Fatalf("list bool: %v", err)
	}
	if bools.Total != 3 || !reflect.DeepEqual(flagKeys(bools.Flags), []string{"a-bool", "c-bool", "e-bool"}) {
		t.Errorf("bool filter: total=%d keys=%v", bools.Total, flagKeys(bools.Flags))
	}

	// A page of a filtered list: the total is the filtered total, not the
	// page and not the unfiltered count.
	page, err := h(ctx, flagsListRequest{Type: "bool", Limit: 2, Offset: 2}, flagPrincipal)
	if err != nil {
		t.Fatalf("list bool page: %v", err)
	}
	if page.Total != 3 || !reflect.DeepEqual(flagKeys(page.Flags), []string{"e-bool"}) {
		t.Errorf("bool page 2: total=%d keys=%v, want total 3 and [e-bool]", page.Total, flagKeys(page.Flags))
	}

	// Offset past the end is an empty page, still with the right total.
	past, err := h(ctx, flagsListRequest{Type: "bool", Offset: 10}, flagPrincipal)
	if err != nil {
		t.Fatalf("list past end: %v", err)
	}
	if past.Total != 3 || len(past.Flags) != 0 {
		t.Errorf("past end: total=%d len=%d", past.Total, len(past.Flags))
	}
}

func TestFlagsList_LimitDefaultsAndCap(t *testing.T) {
	v, st := newTestVault(t)
	ctx := context.Background()
	for i := 0; i < 110; i++ {
		key := "flag-" + strings.Repeat("0", 3-len(itoa(i))) + itoa(i)
		if err := st.DefineFlag(ctx, &flag.Definition{
			Entity: core.NewEntity(), ID: id.NewFlagID(), Key: key, Type: flag.TypeBool,
			DefaultValue: true, Enabled: true, AppID: testAppID,
		}); err != nil {
			t.Fatalf("define: %v", err)
		}
	}
	h := flagsListHandler(Deps{Vault: v})

	def, err := h(ctx, flagsListRequest{}, flagPrincipal)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(def.Flags) != 25 || def.Total != 110 {
		t.Errorf("default limit: len=%d total=%d, want 25 and 110", len(def.Flags), def.Total)
	}
	huge, err := h(ctx, flagsListRequest{Limit: 5000}, flagPrincipal)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(huge.Flags) != 100 {
		t.Errorf("capped limit: len=%d, want 100", len(huge.Flags))
	}
	neg, err := h(ctx, flagsListRequest{Limit: -3, Offset: -4}, flagPrincipal)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(neg.Flags) != 25 || neg.Flags[0].Key != "flag-000" {
		t.Errorf("negative limit/offset: keys=%v", flagKeys(neg.Flags))
	}
}

func TestFlagsList_UnknownTypeIsBadRequest(t *testing.T) {
	v, _ := newTestVault(t)
	for _, typ := range []string{"yaml", "BOOL", "boolean", " bool"} {
		_, err := flagsListHandler(Deps{Vault: v})(context.Background(), flagsListRequest{Type: typ}, flagPrincipal)
		if codeOf(err) != dashcontract.CodeBadRequest {
			t.Errorf("type %q: code = %q (%v), want BAD_REQUEST", typ, codeOf(err), err)
		}
	}
}

func TestFlagsList_EmptyIsAnEmptyArray(t *testing.T) {
	v, _ := newTestVault(t)
	out, err := flagsListHandler(Deps{Vault: v})(context.Background(), flagsListRequest{}, flagPrincipal)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	raw, _ := json.Marshal(out)
	if string(raw) != `{"flags":[],"total":0}` {
		t.Errorf("empty list JSON = %s", raw)
	}
}

func TestFlagsList_OtherAppsFlagsAreInvisible(t *testing.T) {
	v, st := newTestVault(t)
	ctx := context.Background()
	seedFlag(t, v, "mine", flag.TypeBool, true, true)
	if err := st.DefineFlag(ctx, &flag.Definition{
		Entity: core.NewEntity(), ID: id.NewFlagID(), Key: "theirs", Type: flag.TypeBool,
		DefaultValue: true, Enabled: true, AppID: "other-app",
	}); err != nil {
		t.Fatalf("define: %v", err)
	}
	out, err := flagsListHandler(Deps{Vault: v})(ctx, flagsListRequest{}, flagPrincipal)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if out.Total != 1 || !reflect.DeepEqual(flagKeys(out.Flags), []string{"mine"}) {
		t.Errorf("total=%d keys=%v, want only mine", out.Total, flagKeys(out.Flags))
	}
}

func TestFlagsList_StoredStringOnBoolFlagReportsMismatch(t *testing.T) {
	v, st := newTestVault(t)
	ctx := context.Background()
	// The templ create page wrote the raw form string for every type.
	if err := st.DefineFlag(ctx, &flag.Definition{
		Entity: core.NewEntity(), ID: id.NewFlagID(), Key: "templ-made", Type: flag.TypeBool,
		DefaultValue: "true", Enabled: true, AppID: testAppID,
	}); err != nil {
		t.Fatalf("define: %v", err)
	}
	seedFlag(t, v, "fine", flag.TypeBool, true, true)

	out, err := flagsListHandler(Deps{Vault: v})(ctx, flagsListRequest{}, flagPrincipal)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	byKey := map[string]FlagSummary{}
	for _, f := range out.Flags {
		byKey[f.Key] = f
	}
	if byKey["templ-made"].DefaultMatchesType {
		t.Errorf(`string "true" on a bool flag: defaultMatchesType = true, want false`)
	}
	if byKey["templ-made"].DefaultValue != "true" {
		t.Errorf("defaultValue = %#v, want the stored string", byKey["templ-made"].DefaultValue)
	}
	if !byKey["fine"].DefaultMatchesType {
		t.Errorf("bool true on a bool flag: defaultMatchesType = false, want true")
	}
}

func TestFlagsList_MongoShapedDefaultProjectsAsPlainObject(t *testing.T) {
	v, st := newTestVault(t)
	ctx := context.Background()
	if err := st.DefineFlag(ctx, &flag.Definition{
		Entity: core.NewEntity(), ID: id.NewFlagID(), Key: "cfg", Type: flag.TypeJSON,
		DefaultValue: bson.D{{Key: "limit", Value: int32(5)}, {Key: "tags", Value: bson.A{"a"}}},
		Enabled:      true, AppID: testAppID,
	}); err != nil {
		t.Fatalf("define: %v", err)
	}
	out, err := flagsListHandler(Deps{Vault: v})(ctx, flagsListRequest{}, flagPrincipal)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	want := map[string]any{"limit": float64(5), "tags": []any{"a"}}
	if !reflect.DeepEqual(out.Flags[0].DefaultValue, want) {
		t.Errorf("defaultValue = %#v, want %#v", out.Flags[0].DefaultValue, want)
	}
	if !out.Flags[0].DefaultMatchesType {
		t.Errorf("a json flag with an object default: defaultMatchesType = false")
	}
}

// --- flags.detail ---

func TestFlagsDetail_ProjectsEveryField(t *testing.T) {
	v, st := newTestVault(t)
	ctx := context.Background()

	start := time.Date(2030, 1, 2, 3, 4, 5, 0, time.FixedZone("x", 2*3600))
	end := start.Add(24 * time.Hour)
	if _, err := v.FlagManager().Create(ctx, flag.CreateInput{
		Key: "checkout", Type: flag.TypeString, DefaultValue: "old", Description: "the new checkout",
		Tags: []string{"web", "beta"}, Enabled: true,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	// Variants and metadata have no write path in this slice; put them on
	// the row the way another writer would.
	def, err := st.GetFlagDefinition(ctx, "checkout", testAppID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	def.Variants = []flag.Variant{{Value: "new", Description: "the new one"}, {Value: bson.D{{Key: "k", Value: int32(1)}}, Description: "obj"}}
	def.Metadata = map[string]string{"owner": "growth"}
	if err = st.DefineFlag(ctx, def); err != nil {
		t.Fatalf("redefine: %v", err)
	}

	seedRules(t, v, "checkout",
		flag.RuleInput{Type: flag.RuleWhenTenant, Config: flag.RuleConfig{TenantIDs: []string{"t1", "t2"}}, ReturnValue: "new"},
		flag.RuleInput{Type: flag.RuleWhenUser, Config: flag.RuleConfig{UserIDs: []string{"u1"}}, ReturnValue: "new"},
		flag.RuleInput{Type: flag.RuleRollout, Config: flag.RuleConfig{Percentage: 25}, ReturnValue: "new"},
		flag.RuleInput{Type: flag.RuleSchedule, Config: flag.RuleConfig{StartAt: &start, EndAt: &end}, ReturnValue: "new"},
		flag.RuleInput{Type: flag.RuleWhenTenantTag, Config: flag.RuleConfig{TagKey: "plan", TagValue: "pro"}, ReturnValue: "new"},
		flag.RuleInput{Type: flag.RuleCustom, Config: flag.RuleConfig{Evaluator: "geo", Params: map[string]any{"region": "eu", "n": 3}}, ReturnValue: "new"},
	)
	// "mid" is written past the manager: a number on a string flag.
	if _, err = v.FlagManager().SetTenantOverride(ctx, "checkout", "zeta", "z"); err != nil {
		t.Fatalf("override: %v", err)
	}
	if _, err = v.FlagManager().SetTenantOverride(ctx, "checkout", "alpha", "a"); err != nil {
		t.Fatalf("override: %v", err)
	}
	if err = st.SetFlagTenantOverride(ctx, "checkout", testAppID, "mid", float64(9)); err != nil {
		t.Fatalf("override: %v", err)
	}

	out, err := flagsDetailHandler(Deps{Vault: v})(ctx, flagsDetailRequest{Key: " checkout "}, flagPrincipal)
	if err != nil {
		t.Fatalf("detail: %v", err)
	}

	f := out.Flag
	if f.ID == "" || f.Key != "checkout" || f.Type != "string" || f.DefaultValue != "old" || !f.DefaultMatchesType ||
		f.Description != "the new checkout" || !f.Enabled || !reflect.DeepEqual(f.Tags, []string{"web", "beta"}) {
		t.Errorf("flag = %+v", f)
	}
	if !strings.HasSuffix(f.CreatedAt, "Z") || !strings.HasSuffix(f.UpdatedAt, "Z") {
		t.Errorf("times are not UTC RFC3339: %q %q", f.CreatedAt, f.UpdatedAt)
	}

	wantVariants := []FlagVariantSummary{{Value: "new", Description: "the new one"}, {Value: map[string]any{"k": float64(1)}, Description: "obj"}}
	if !reflect.DeepEqual(out.Variants, wantVariants) {
		t.Errorf("variants = %#v, want %#v", out.Variants, wantVariants)
	}
	if !reflect.DeepEqual(out.Metadata, map[string]string{"owner": "growth"}) {
		t.Errorf("metadata = %#v", out.Metadata)
	}

	if len(out.Rules) != 6 {
		t.Fatalf("rules = %d, want 6: %+v", len(out.Rules), out.Rules)
	}
	for i, r := range out.Rules {
		if r.Priority != i || r.ID == "" || r.ReturnValue != "new" || !r.ReturnMatchesType {
			t.Errorf("rule %d = %+v", i, r)
		}
	}
	if r := out.Rules[0]; r.Type != "when_tenant" || !r.Implemented || !reflect.DeepEqual(r.TenantIDs, []string{"t1", "t2"}) || len(r.UserIDs) != 0 || r.UserIDs == nil {
		t.Errorf("when_tenant rule = %+v", r)
	}
	if r := out.Rules[1]; r.Type != "when_user" || !r.Implemented || !reflect.DeepEqual(r.UserIDs, []string{"u1"}) || r.TenantIDs == nil {
		t.Errorf("when_user rule = %+v", r)
	}
	if r := out.Rules[2]; r.Type != "rollout" || !r.Implemented || r.Percentage != 25 {
		t.Errorf("rollout rule = %+v", r)
	}
	if r := out.Rules[3]; r.Type != "schedule" || !r.Implemented || r.StartAt == nil || r.EndAt == nil ||
		*r.StartAt != "2030-01-02T01:04:05Z" || *r.EndAt != "2030-01-03T01:04:05Z" {
		t.Errorf("schedule rule = %+v (start %v end %v)", r, deref(r.StartAt), deref(r.EndAt))
	}
	if r := out.Rules[4]; r.Type != "when_tenant_tag" || r.Implemented || r.TagKey != "plan" || r.TagValue != "pro" {
		t.Errorf("when_tenant_tag rule = %+v", r)
	}
	if r := out.Rules[5]; r.Type != "custom" || r.Implemented || r.Evaluator != "geo" ||
		!reflect.DeepEqual(r.Params, map[string]any{"region": "eu", "n": float64(3)}) {
		t.Errorf("custom rule = %+v", r)
	}

	// Overrides in tenantId order, with the mismatch reported per row.
	if got := []string{out.Overrides[0].TenantID, out.Overrides[1].TenantID, out.Overrides[2].TenantID}; !reflect.DeepEqual(got, []string{"alpha", "mid", "zeta"}) {
		t.Fatalf("override order = %v", got)
	}
	if o := out.Overrides[0]; o.Value != "a" || !o.ValueMatchesType || !strings.HasSuffix(o.UpdatedAt, "Z") {
		t.Errorf("override alpha = %+v", o)
	}
	if o := out.Overrides[1]; o.Value != float64(9) || o.ValueMatchesType {
		t.Errorf("override mid = %+v, want a number that does not match string", o)
	}

	if out.CacheTTLSeconds != 30 {
		t.Errorf("cacheTtlSeconds = %d, want the 30s default", out.CacheTTLSeconds)
	}
	if out.RecentAudit == nil {
		t.Errorf("recentAudit is nil, want a list")
	}
}

func TestFlagsDetail_EmptyListsAreArraysAndMetadataAnObject(t *testing.T) {
	v, _ := newTestVault(t)
	seedFlag(t, v, "bare", flag.TypeBool, true, true)
	out, err := flagsDetailHandler(Deps{Vault: v})(context.Background(), flagsDetailRequest{Key: "bare"}, flagPrincipal)
	if err != nil {
		t.Fatalf("detail: %v", err)
	}
	raw, _ := json.Marshal(out)
	s := string(raw)
	for _, want := range []string{`"variants":[]`, `"metadata":{}`, `"rules":[]`, `"overrides":[]`, `"tags":[]`} {
		if !strings.Contains(s, want) {
			t.Errorf("JSON lacks %s: %s", want, s)
		}
	}
	if strings.Contains(s, "null") {
		t.Errorf("JSON carries a null: %s", s)
	}
}

func TestFlagsDetail_Errors(t *testing.T) {
	v, _ := newTestVault(t)
	h := flagsDetailHandler(Deps{Vault: v})
	if _, err := h(context.Background(), flagsDetailRequest{Key: "  "}, flagPrincipal); codeOf(err) != dashcontract.CodeBadRequest {
		t.Errorf("blank key: code = %q, want BAD_REQUEST", codeOf(err))
	}
	if _, err := h(context.Background(), flagsDetailRequest{Key: "nope"}, flagPrincipal); codeOf(err) != dashcontract.CodeNotFound {
		t.Errorf("missing flag: code = %q (%v), want NOT_FOUND", codeOf(err), err)
	}
}

// The order the engine walks is the order the page shows. The handler must
// not sort: this store hands the rules back in a deliberately odd order.
type shuffledRulesStore struct{ store.Store }

func (s shuffledRulesStore) GetFlagRules(ctx context.Context, key, appID string) ([]*flag.Rule, error) {
	rules, err := s.Store.GetFlagRules(ctx, key, appID)
	if err != nil {
		return nil, err
	}
	for i, j := 0, len(rules)-1; i < j; i, j = i+1, j-1 {
		rules[i], rules[j] = rules[j], rules[i]
	}
	return rules, nil
}

func TestFlagsDetail_RulesKeepTheOrderGetFlagRulesReturns(t *testing.T) {
	v, err := vault.New(vault.WithStore(shuffledRulesStore{memory.New()}), vault.WithAppID(testAppID))
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	seedFlag(t, v, "ordered", flag.TypeBool, false, true)
	seedRules(t, v, "ordered",
		flag.RuleInput{Type: flag.RuleWhenTenant, Config: flag.RuleConfig{TenantIDs: []string{"a"}}, ReturnValue: true},
		flag.RuleInput{Type: flag.RuleWhenTenant, Config: flag.RuleConfig{TenantIDs: []string{"b"}}, ReturnValue: true},
		flag.RuleInput{Type: flag.RuleWhenTenant, Config: flag.RuleConfig{TenantIDs: []string{"c"}}, ReturnValue: true},
	)
	out, err := flagsDetailHandler(Deps{Vault: v})(context.Background(), flagsDetailRequest{Key: "ordered"}, flagPrincipal)
	if err != nil {
		t.Fatalf("detail: %v", err)
	}
	got := make([]int, 0, len(out.Rules))
	for _, r := range out.Rules {
		got = append(got, r.Priority)
	}
	if !reflect.DeepEqual(got, []int{2, 1, 0}) {
		t.Errorf("priorities = %v, want [2 1 0] (the store's order, unsorted)", got)
	}
}

func TestFlagsDetail_RecentAuditIsFlagRowsOnlyAndBounded(t *testing.T) {
	v, st := newTestVault(t)
	ctx := context.Background()
	const key = "shared-key"
	seedFlag(t, v, key, flag.TypeBool, true, true)
	if _, err := v.Secrets().Set(ctx, key, []byte("value"), testAppID); err != nil {
		t.Fatalf("seed secret: %v", err)
	}
	base := time.Now().UTC()
	type auditRow struct{ resource, action string }
	rows := make([]auditRow, 0, 16)
	rows = append(rows,
		auditRow{audithook.ResourceSecret, audithook.ActionSecretSet},
		auditRow{audithook.ResourceSecret, audithook.ActionSecretAccessed},
	)
	for range 14 {
		rows = append(rows, auditRow{audithook.ResourceFlag, audithook.ActionFlagUpdated})
	}
	for i, r := range rows {
		if err := st.RecordAudit(ctx, &audit.Entry{
			ID: id.NewAuditID(), Action: r.action, Resource: r.resource, Key: key, AppID: testAppID,
			Outcome: "success", CreatedAt: base.Add(time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatalf("RecordAudit: %v", err)
		}
	}

	out, err := flagsDetailHandler(Deps{Vault: v})(ctx, flagsDetailRequest{Key: key}, flagPrincipal)
	if err != nil {
		t.Fatalf("detail: %v", err)
	}
	if len(out.RecentAudit) != 10 {
		t.Errorf("recentAudit = %d rows, want the limit of 10", len(out.RecentAudit))
	}
	for _, e := range out.RecentAudit {
		if strings.HasPrefix(e.Action, "secret") {
			t.Errorf("recentAudit carries a secret row: %+v", e)
		}
	}
}

func TestFlagsDetail_CacheTTLComesFromTheVaultConfig(t *testing.T) {
	st := memory.New()
	v, err := vault.New(vault.WithStore(st), vault.WithAppID(testAppID), vault.WithConfig(vault.Config{FlagCacheTTL: 90 * time.Second}))
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	seedFlag(t, v, "f", flag.TypeBool, true, true)
	out, err := flagsDetailHandler(Deps{Vault: v})(context.Background(), flagsDetailRequest{Key: "f"}, flagPrincipal)
	if err != nil {
		t.Fatalf("detail: %v", err)
	}
	if out.CacheTTLSeconds != 90 {
		t.Errorf("cacheTtlSeconds = %d, want 90", out.CacheTTLSeconds)
	}
	if v.FlagCacheTTL() != 90*time.Second {
		t.Errorf("FlagCacheTTL = %v", v.FlagCacheTTL())
	}
}

// --- flags.evaluate ---

// The request context may carry a tenant (or user) of its own. It must not
// reach the engine: the operator asked about the tenant they typed, or none.
func TestFlagsEvaluate_NeverInheritsTenantOrUserFromTheRequestContext(t *testing.T) {
	v, _ := newTestVault(t)
	seedFlag(t, v, "leaky", flag.TypeBool, false, true)
	seedRules(t, v, "leaky",
		flag.RuleInput{Type: flag.RuleWhenTenant, Config: flag.RuleConfig{TenantIDs: []string{"leak"}}, ReturnValue: true},
		flag.RuleInput{Type: flag.RuleWhenUser, Config: flag.RuleConfig{UserIDs: []string{"leaky-user"}}, ReturnValue: true},
	)
	if _, err := v.FlagManager().SetTenantOverride(context.Background(), "leaky", "leak", true); err != nil {
		t.Fatalf("override: %v", err)
	}

	ctx := scope.WithUserID(scope.WithTenantID(context.Background(), "leak"), "leaky-user")
	out, err := flagsEvaluateHandler(Deps{Vault: v})(ctx, flagsEvaluateRequest{Key: "leaky"}, flagPrincipal)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if out.Value != false || out.Reason != flag.ReasonDefault {
		t.Errorf("value=%v reason=%q, want the default false: the context's tenant/user leaked in", out.Value, out.Reason)
	}
	if out.Bucket != nil {
		t.Errorf("bucket = %d with no tenant in the request, want none", *out.Bucket)
	}
	for _, s := range out.Trace {
		if s.Matched {
			t.Errorf("trace step matched with no tenant or user asked: %+v", s)
		}
	}

	// And the request's own tenant does count.
	got, err := flagsEvaluateHandler(Deps{Vault: v})(ctx, flagsEvaluateRequest{Key: "leaky", TenantID: "leak"}, flagPrincipal)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if got.Value != true || got.Reason != flag.ReasonTenantOverride {
		t.Errorf("explicit tenant: value=%v reason=%q, want the override", got.Value, got.Reason)
	}
}

func TestFlagsEvaluate_RuleMatchTraceAndBucket(t *testing.T) {
	v, _ := newTestVault(t)
	seedFlag(t, v, "roll", flag.TypeBool, false, true)
	seedRules(t, v, "roll",
		flag.RuleInput{Type: flag.RuleWhenTenant, Config: flag.RuleConfig{TenantIDs: []string{"nobody"}}, ReturnValue: true},
		flag.RuleInput{Type: flag.RuleRollout, Config: flag.RuleConfig{Percentage: 100}, ReturnValue: true},
		flag.RuleInput{Type: flag.RuleWhenUser, Config: flag.RuleConfig{UserIDs: []string{"u"}}, ReturnValue: true},
	)

	out, err := flagsEvaluateHandler(Deps{Vault: v})(context.Background(), flagsEvaluateRequest{Key: "roll", TenantID: " t-42 "}, flagPrincipal)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if out.Value != true || !out.ValueMatchesType || out.Reason != flag.ReasonRule {
		t.Errorf("value=%v matches=%v reason=%q", out.Value, out.ValueMatchesType, out.Reason)
	}
	if out.MatchedRulePriority == nil || *out.MatchedRulePriority != 1 {
		t.Errorf("matchedRulePriority = %v, want 1", out.MatchedRulePriority)
	}
	want := int(flag.RolloutBucket("t-42", "roll"))
	if out.Bucket == nil || *out.Bucket != want {
		t.Errorf("bucket = %v, want %d", out.Bucket, want)
	}
	if len(out.Trace) != 3 {
		t.Fatalf("trace = %+v, want 3 steps", out.Trace)
	}
	if s := out.Trace[0]; s.Priority != 0 || s.Type != "when_tenant" || s.Matched || !s.Reached || s.Note == "" {
		t.Errorf("trace[0] = %+v", s)
	}
	if s := out.Trace[1]; s.Priority != 1 || s.Type != "rollout" || !s.Matched || !s.Reached {
		t.Errorf("trace[1] = %+v", s)
	}
	if s := out.Trace[2]; s.Priority != 2 || s.Matched || s.Reached {
		t.Errorf("trace[2] = %+v, want unreached", s)
	}
	if _, err := time.Parse(time.RFC3339, out.EvaluatedAt); err != nil || !strings.HasSuffix(out.EvaluatedAt, "Z") {
		t.Errorf("evaluatedAt = %q", out.EvaluatedAt)
	}
}

func TestFlagsEvaluate_BucketZeroIsStillReported(t *testing.T) {
	v, _ := newTestVault(t)
	seedFlag(t, v, "b0", flag.TypeBool, false, true)
	tenant := ""
	for i := 0; i < 10000; i++ {
		cand := "tenant-" + itoa(i)
		if flag.RolloutBucket(cand, "b0") == 0 {
			tenant = cand
			break
		}
	}
	if tenant == "" {
		t.Fatal("no tenant found in bucket 0")
	}
	out, err := flagsEvaluateHandler(Deps{Vault: v})(context.Background(), flagsEvaluateRequest{Key: "b0", TenantID: tenant}, flagPrincipal)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if out.Bucket == nil || *out.Bucket != 0 {
		t.Errorf("bucket = %v, want a present 0", out.Bucket)
	}
	raw, _ := json.Marshal(out)
	if !strings.Contains(string(raw), `"bucket":0`) {
		t.Errorf("JSON lacks bucket 0: %s", raw)
	}
}

func TestFlagsEvaluate_OmittedFieldsAndEmptyTrace(t *testing.T) {
	v, _ := newTestVault(t)
	seedFlag(t, v, "plain", flag.TypeString, "dflt", true)
	out, err := flagsEvaluateHandler(Deps{Vault: v})(context.Background(), flagsEvaluateRequest{Key: "plain"}, flagPrincipal)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	raw, _ := json.Marshal(out)
	s := string(raw)
	if !strings.Contains(s, `"trace":[]`) || strings.Contains(s, "matchedRulePriority") || strings.Contains(s, `"bucket"`) {
		t.Errorf("JSON = %s", s)
	}
	if out.Value != "dflt" || out.Reason != flag.ReasonDefault || !out.ValueMatchesType {
		t.Errorf("out = %+v", out)
	}
}

func TestFlagsEvaluate_DisabledAndOverrideReasons(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	seedFlag(t, v, "off", flag.TypeBool, false, false)
	seedFlag(t, v, "on", flag.TypeInt, float64(1), true)
	if _, err := v.FlagManager().SetTenantOverride(ctx, "on", "big", float64(50)); err != nil {
		t.Fatalf("override: %v", err)
	}
	h := flagsEvaluateHandler(Deps{Vault: v})

	off, err := h(ctx, flagsEvaluateRequest{Key: "off"}, flagPrincipal)
	if err != nil || off.Reason != flag.ReasonDisabled || off.Value != false {
		t.Errorf("disabled: %+v, %v", off, err)
	}
	ov, err := h(ctx, flagsEvaluateRequest{Key: "on", TenantID: "big"}, flagPrincipal)
	if err != nil || ov.Reason != flag.ReasonTenantOverride || ov.Value != float64(50) || !ov.ValueMatchesType {
		t.Errorf("override: %+v, %v", ov, err)
	}
	if ov.Trace == nil || len(ov.Trace) != 0 {
		t.Errorf("override trace = %#v, want an empty non-nil slice", ov.Trace)
	}
}

func TestFlagsEvaluate_MismatchedValueIsReported(t *testing.T) {
	v, st := newTestVault(t)
	ctx := context.Background()
	if err := st.DefineFlag(ctx, &flag.Definition{
		Entity: core.NewEntity(), ID: id.NewFlagID(), Key: "templ", Type: flag.TypeBool,
		DefaultValue: "true", Enabled: true, AppID: testAppID,
	}); err != nil {
		t.Fatalf("define: %v", err)
	}
	out, err := flagsEvaluateHandler(Deps{Vault: v})(ctx, flagsEvaluateRequest{Key: "templ"}, flagPrincipal)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if out.Value != "true" || out.ValueMatchesType {
		t.Errorf("value=%#v matches=%v, want the string and false", out.Value, out.ValueMatchesType)
	}
}

func TestFlagsEvaluate_Errors(t *testing.T) {
	v, _ := newTestVault(t)
	h := flagsEvaluateHandler(Deps{Vault: v})
	if _, err := h(context.Background(), flagsEvaluateRequest{}, flagPrincipal); codeOf(err) != dashcontract.CodeBadRequest {
		t.Errorf("blank key: code = %q, want BAD_REQUEST", codeOf(err))
	}
	if _, err := h(context.Background(), flagsEvaluateRequest{Key: "nope"}, flagPrincipal); codeOf(err) != dashcontract.CodeNotFound {
		t.Errorf("missing flag: code = %q (%v), want NOT_FOUND", codeOf(err), err)
	}
}

// --- helpers ---

func flagKeys(fs []FlagSummary) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Key)
	}
	return out
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

// --- sqlite ---

// The same queries against a real backend: values come back through JSON
// text, schedule times keep the caller's offset, and the type filter runs in
// SQL.
func TestFlags_SQLite_ListDetailEvaluate(t *testing.T) {
	v := newSQLiteTestVault(t)
	ctx := context.Background()

	seedFlag(t, v, "limit", flag.TypeInt, float64(5), true)
	seedFlag(t, v, "on", flag.TypeBool, true, true)
	seedFlag(t, v, "cfg", flag.TypeJSON, map[string]any{"a": []any{float64(1)}}, true)

	start := time.Date(2030, 6, 1, 12, 0, 0, 0, time.FixedZone("x", -5*3600))
	seedRules(t, v, "limit",
		flag.RuleInput{Type: flag.RuleWhenTenant, Config: flag.RuleConfig{TenantIDs: []string{"acme"}}, ReturnValue: float64(50)},
		flag.RuleInput{Type: flag.RuleSchedule, Config: flag.RuleConfig{StartAt: &start}, ReturnValue: float64(7)},
	)
	if _, err := v.FlagManager().SetTenantOverride(ctx, "limit", "zed", float64(99)); err != nil {
		t.Fatalf("override: %v", err)
	}

	deps := Deps{Vault: v}
	list, err := flagsListHandler(deps)(ctx, flagsListRequest{Type: "int"}, flagPrincipal)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if list.Total != 1 || len(list.Flags) != 1 || list.Flags[0].Key != "limit" || list.Flags[0].DefaultValue != float64(5) || !list.Flags[0].DefaultMatchesType {
		t.Errorf("list int = %+v", list)
	}
	all, err := flagsListHandler(deps)(ctx, flagsListRequest{Limit: 2}, flagPrincipal)
	if err != nil || all.Total != 3 || len(all.Flags) != 2 {
		t.Errorf("list page: %+v, %v", all, err)
	}

	cfg, err := flagsDetailHandler(deps)(ctx, flagsDetailRequest{Key: "cfg"}, flagPrincipal)
	if err != nil {
		t.Fatalf("detail cfg: %v", err)
	}
	if !reflect.DeepEqual(cfg.Flag.DefaultValue, map[string]any{"a": []any{float64(1)}}) || !cfg.Flag.DefaultMatchesType {
		t.Errorf("cfg default = %#v matches=%v", cfg.Flag.DefaultValue, cfg.Flag.DefaultMatchesType)
	}

	det, err := flagsDetailHandler(deps)(ctx, flagsDetailRequest{Key: "limit"}, flagPrincipal)
	if err != nil {
		t.Fatalf("detail: %v", err)
	}
	if len(det.Rules) != 2 || det.Rules[0].Priority != 0 || det.Rules[1].Priority != 1 {
		t.Fatalf("rules = %+v", det.Rules)
	}
	if s := det.Rules[1]; s.StartAt == nil || *s.StartAt != "2030-06-01T17:00:00Z" || s.EndAt != nil {
		t.Errorf("schedule rule start=%v end=%v, want UTC start and no end", deref(s.StartAt), deref(s.EndAt))
	}
	if len(det.Overrides) != 1 || det.Overrides[0].TenantID != "zed" || det.Overrides[0].Value != float64(99) || !det.Overrides[0].ValueMatchesType {
		t.Errorf("overrides = %+v", det.Overrides)
	}
	if len(det.RecentAudit) == 0 {
		t.Errorf("recentAudit is empty, want the manager's flag rows")
	}

	// Scope the request context to a tenant that has a rule: the explicit
	// (empty) tenant still wins.
	leak := scope.WithTenantID(ctx, "acme")
	ev, err := flagsEvaluateHandler(deps)(leak, flagsEvaluateRequest{Key: "limit"}, flagPrincipal)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if ev.Reason != flag.ReasonDefault || ev.Value != float64(5) {
		t.Errorf("evaluate with leaked ctx tenant: %+v", ev)
	}
	ev, err = flagsEvaluateHandler(deps)(leak, flagsEvaluateRequest{Key: "limit", TenantID: "acme"}, flagPrincipal)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if ev.Reason != flag.ReasonRule || ev.Value != float64(50) || ev.MatchedRulePriority == nil || *ev.MatchedRulePriority != 0 || !ev.ValueMatchesType {
		t.Errorf("evaluate acme: %+v", ev)
	}
}
