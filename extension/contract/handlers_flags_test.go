package contract

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
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

// recordAuditRows writes one audit row per action for key, oldest first,
// starting at first and one second apart. Every row is a success in testAppID.
func recordAuditRows(t *testing.T, st store.Store, key, resource string, first time.Time, actions ...string) {
	t.Helper()
	for i, action := range actions {
		if err := st.RecordAudit(context.Background(), &audit.Entry{
			ID: id.NewAuditID(), Action: action, Resource: resource, Key: key, AppID: testAppID,
			Outcome: "success", CreatedAt: first.Add(time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatalf("RecordAudit: %v", err)
		}
	}
}

func repeatAction(action string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = action
	}
	return out
}

// assertNoSecretActions fails for any recent-audit row whose action is a
// secret one.
func assertNoSecretActions(t *testing.T, rows []AuditSummary) {
	t.Helper()
	for _, e := range rows {
		if strings.HasPrefix(e.Action, "secret.") {
			t.Errorf("recentAudit carries a secret row: %+v", e)
		}
	}
}

// The secret rows are the NEWEST on the key, so a handler that lost its
// Resource filter would fill the page with them and this test would fail.
func TestFlagsDetail_RecentAuditIsFlagRowsOnlyAndBounded(t *testing.T) {
	v, st := newTestVault(t)
	ctx := context.Background()
	const key = "shared-key"
	seedFlag(t, v, key, flag.TypeBool, true, true)

	// Well after anything the seeding above recorded.
	base := time.Now().UTC().Add(time.Hour)
	recordAuditRows(t, st, key, audithook.ResourceFlag, base, repeatAction(audithook.ActionFlagUpdated, 14)...)
	recordAuditRows(t, st, key, audithook.ResourceSecret, base.Add(time.Minute), audithook.ActionSecretSet, audithook.ActionSecretAccessed)

	out, err := flagsDetailHandler(Deps{Vault: v})(ctx, flagsDetailRequest{Key: key}, flagPrincipal)
	if err != nil {
		t.Fatalf("detail: %v", err)
	}
	if len(out.RecentAudit) != 10 {
		t.Errorf("recentAudit = %d rows, want the limit of 10", len(out.RecentAudit))
	}
	assertNoSecretActions(t, out.RecentAudit)
	for _, e := range out.RecentAudit {
		if e.Action != audithook.ActionFlagUpdated {
			t.Errorf("recentAudit row %+v is not one of the 14 newest flag rows", e)
		}
	}
}

// Fewer flag rows than the limit, and newer secret rows to fill the page if
// the filter were gone: the flag rows must all come back and nothing else.
func TestFlagsDetail_RecentAuditIsNotFilledWithNewerSecretRows(t *testing.T) {
	v, st := newTestVault(t)
	ctx := context.Background()
	const key = "shared-key"
	seedFlag(t, v, key, flag.TypeBool, true, true)

	base := time.Now().UTC().Add(time.Hour)
	recordAuditRows(t, st, key, audithook.ResourceFlag, base, audithook.ActionFlagToggled, audithook.ActionFlagRulesSet)
	recordAuditRows(t, st, key, audithook.ResourceSecret, base.Add(time.Minute), repeatAction(audithook.ActionSecretAccessed, 12)...)

	out, err := flagsDetailHandler(Deps{Vault: v})(ctx, flagsDetailRequest{Key: key}, flagPrincipal)
	if err != nil {
		t.Fatalf("detail: %v", err)
	}
	assertNoSecretActions(t, out.RecentAudit)
	seen := map[string]bool{}
	for _, e := range out.RecentAudit {
		seen[e.Action] = true
	}
	for _, want := range []string{audithook.ActionFlagToggled, audithook.ActionFlagRulesSet, audithook.ActionFlagCreated} {
		if !seen[want] {
			t.Errorf("recentAudit lacks a %s row: %+v", want, out.RecentAudit)
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
	// The manager wrote a created, a rules_set and an override_set row for
	// this flag. A newer secret row on the same key must not displace or join
	// them.
	recordAuditRows(t, v.Store(), "limit", audithook.ResourceSecret, time.Now().UTC().Add(time.Hour),
		audithook.ActionSecretSet, audithook.ActionSecretAccessed)
	det, err = flagsDetailHandler(deps)(ctx, flagsDetailRequest{Key: "limit"}, flagPrincipal)
	if err != nil {
		t.Fatalf("detail after secret rows: %v", err)
	}
	assertNoSecretActions(t, det.RecentAudit)
	actions := make([]string, 0, len(det.RecentAudit))
	for _, e := range det.RecentAudit {
		actions = append(actions, e.Action)
	}
	sort.Strings(actions)
	wantActions := []string{audithook.ActionFlagCreated, audithook.ActionFlagOverrideSet, audithook.ActionFlagRulesSet}
	if !reflect.DeepEqual(actions, wantActions) {
		t.Errorf("recentAudit actions = %v, want %v", actions, wantActions)
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

// --- flag commands ---

// decodeReq builds a request the way the dispatcher does: json.Unmarshal of
// the raw payload. Tests that care about absent versus null go through it.
func decodeReq[T any](t *testing.T, raw string) T {
	t.Helper()
	var in T
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	return in
}

func flagDetail(t *testing.T, v *vault.Vault, key string) flagsDetailResponse {
	t.Helper()
	out, err := flagsDetailHandler(Deps{Vault: v})(context.Background(), flagsDetailRequest{Key: key}, flagPrincipal)
	if err != nil {
		t.Fatalf("detail %q: %v", key, err)
	}
	return out
}

func wantCode(t *testing.T, err error, code dashcontract.ErrorCode, msg string) {
	t.Helper()
	if codeOf(err) != code {
		t.Fatalf("code = %q (err %v), want %q", codeOf(err), err, code)
	}
	if msg == "" {
		return
	}
	var ce *dashcontract.Error
	if !errors.As(err, &ce) || !strings.Contains(ce.Message, msg) {
		t.Errorf("message = %v, want it to contain %q", err, msg)
	}
}

func ptr[T any](v T) *T { return &v }

func TestOptionalValue(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		present bool
		want    any
	}{
		{"absent", "", false, nil},
		{"null is a value", "null", true, nil},
		{"false", "false", true, false},
		{"zero", "0", true, float64(0)},
		{"empty string", `""`, true, ""},
		{"object", `{"a":[1]}`, true, map[string]any{"a": []any{float64(1)}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := optionalValue("defaultValue", json.RawMessage(tt.raw))
			if err != nil {
				t.Fatalf("optionalValue: %v", err)
			}
			if (got != nil) != tt.present {
				t.Fatalf("present = %v, want %v", got != nil, tt.present)
			}
			if got != nil && !reflect.DeepEqual(*got, tt.want) {
				t.Errorf("value = %#v, want %#v", *got, tt.want)
			}
		})
	}
	_, err := optionalValue("defaultValue", json.RawMessage(`{`))
	wantCode(t, err, dashcontract.CodeBadRequest, "defaultValue is not valid JSON")
	_, err = optionalValue("value", json.RawMessage(`{`))
	wantCode(t, err, dashcontract.CodeBadRequest, "value is not valid JSON")
}

// --- flags.create ---

func TestFlagsCreate_HappyPath(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	deps := Deps{Vault: v}

	out, err := flagsCreateHandler(deps)(ctx, decodeReq[flagsCreateRequest](t,
		`{"key":"checkout","type":"int","defaultValue":5,"description":"cart size","tags":["a","b"],"enabled":true}`), flagPrincipal)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	f := out.Flag
	if f.Key != "checkout" || f.Type != "int" || f.DefaultValue != float64(5) || !f.DefaultMatchesType ||
		f.Description != "cart size" || !reflect.DeepEqual(f.Tags, []string{"a", "b"}) || !f.Enabled || f.ID == "" {
		t.Errorf("created flag = %+v", f)
	}
	if det := flagDetail(t, v, "checkout"); det.Flag.Key != "checkout" || len(det.Rules) != 0 {
		t.Errorf("detail after create = %+v", det)
	}
	// A disabled flag with no tags marshals tags as [] and stays disabled.
	off, err := flagsCreateHandler(deps)(ctx, flagsCreateRequest{Key: "off", Type: "bool", DefaultValue: false}, flagPrincipal)
	if err != nil || off.Flag.Enabled || off.Flag.Tags == nil {
		t.Errorf("create disabled: %+v, %v", off, err)
	}
	// A json flag takes null.
	js, err := flagsCreateHandler(deps)(ctx, decodeReq[flagsCreateRequest](t, `{"key":"cfg","type":"json","defaultValue":null,"enabled":true}`), flagPrincipal)
	if err != nil || js.Flag.DefaultValue != nil || !js.Flag.DefaultMatchesType {
		t.Errorf("create json null: %+v, %v", js, err)
	}
}

func TestFlagsCreate_ConflictLeavesTheFlagUnchanged(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	seedFlag(t, v, "taken", flag.TypeInt, float64(5), true)
	seedRules(t, v, "taken", flag.RuleInput{Type: flag.RuleRollout, Config: flag.RuleConfig{Percentage: 10}, ReturnValue: float64(9)})

	_, err := flagsCreateHandler(Deps{Vault: v})(ctx, flagsCreateRequest{Key: "taken", Type: "string", DefaultValue: "x", Enabled: false}, flagPrincipal)
	wantCode(t, err, dashcontract.CodeConflict, "already exists")

	det := flagDetail(t, v, "taken")
	if det.Flag.Type != "int" || det.Flag.DefaultValue != float64(5) || !det.Flag.Enabled || len(det.Rules) != 1 {
		t.Errorf("flag changed by a refused create: %+v rules=%d", det.Flag, len(det.Rules))
	}
}

func TestFlagsCreate_InvalidInputIsBadRequestAndCreatesNothing(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	deps := Deps{Vault: v}
	tests := []struct {
		name string
		in   flagsCreateRequest
		msg  string
	}{
		{"blank key", flagsCreateRequest{Key: "  ", Type: "bool", DefaultValue: true}, "key is required"},
		{"unknown type", flagsCreateRequest{Key: "k", Type: "yaml", DefaultValue: "x"}, "type"},
		{"no type", flagsCreateRequest{Key: "k", DefaultValue: true}, "type"},
		{"string default on a bool flag", flagsCreateRequest{Key: "k", Type: "bool", DefaultValue: "true"}, "defaultValue"},
		{"absent default on a bool flag", flagsCreateRequest{Key: "k", Type: "bool"}, "defaultValue"},
		{"fractional int", flagsCreateRequest{Key: "k", Type: "int", DefaultValue: 1.5}, "defaultValue"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := flagsCreateHandler(deps)(ctx, tt.in, flagPrincipal)
			wantCode(t, err, dashcontract.CodeBadRequest, tt.msg)
		})
	}
	out, err := flagsListHandler(deps)(ctx, flagsListRequest{}, flagPrincipal)
	if err != nil || out.Total != 0 {
		t.Errorf("flags after refused creates: %+v, %v", out, err)
	}
}

// --- flags.update ---

func TestFlagsUpdate_AbsentDefaultKeepsItAndDescriptionAloneChanges(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	deps := Deps{Vault: v}
	if _, err := v.FlagManager().Create(ctx, flag.CreateInput{
		Key: "u", Type: flag.TypeInt, DefaultValue: float64(7), Description: "old", Tags: []string{"x"}, Enabled: true,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	out, err := flagsUpdateHandler(deps)(ctx, decodeReq[flagsUpdateRequest](t, `{"key":"u","description":"new"}`), flagPrincipal)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	f := out.Flag
	if f.Description != "new" || f.DefaultValue != float64(7) || !reflect.DeepEqual(f.Tags, []string{"x"}) || !f.Enabled {
		t.Errorf("after description-only update: %+v", f)
	}

	// Tags present replace, and an empty list clears; description "" clears.
	out, err = flagsUpdateHandler(deps)(ctx, decodeReq[flagsUpdateRequest](t, `{"key":"u","tags":[],"description":""}`), flagPrincipal)
	if err != nil || len(out.Flag.Tags) != 0 || out.Flag.Tags == nil || out.Flag.Description != "" || out.Flag.DefaultValue != float64(7) {
		t.Errorf("clear tags and description: %+v, %v", out, err)
	}

	// A new default is validated against the stored type and applied.
	out, err = flagsUpdateHandler(deps)(ctx, decodeReq[flagsUpdateRequest](t, `{"key":"u","defaultValue":0}`), flagPrincipal)
	if err != nil || out.Flag.DefaultValue != float64(0) {
		t.Errorf("update default to zero: %+v, %v", out, err)
	}
	_, err = flagsUpdateHandler(deps)(ctx, decodeReq[flagsUpdateRequest](t, `{"key":"u","defaultValue":"seven"}`), flagPrincipal)
	wantCode(t, err, dashcontract.CodeBadRequest, "defaultValue")
}

func TestFlagsUpdate_NullDefault(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	deps := Deps{Vault: v}
	seedFlag(t, v, "b", flag.TypeBool, true, true)
	seedFlag(t, v, "j", flag.TypeJSON, map[string]any{"a": float64(1)}, true)

	// null on a bool flag is refused and the default stays.
	_, err := flagsUpdateHandler(deps)(ctx, decodeReq[flagsUpdateRequest](t, `{"key":"b","defaultValue":null}`), flagPrincipal)
	wantCode(t, err, dashcontract.CodeBadRequest, "defaultValue")
	if got := flagDetail(t, v, "b").Flag.DefaultValue; got != true {
		t.Errorf("bool default after refused null = %v, want true", got)
	}

	// null on a json flag is stored: it is not "absent".
	out, err := flagsUpdateHandler(deps)(ctx, decodeReq[flagsUpdateRequest](t, `{"key":"j","defaultValue":null}`), flagPrincipal)
	if err != nil {
		t.Fatalf("update json to null: %v", err)
	}
	if out.Flag.DefaultValue != nil || !out.Flag.DefaultMatchesType {
		t.Errorf("json default = %#v matches=%v, want null", out.Flag.DefaultValue, out.Flag.DefaultMatchesType)
	}
	if got := flagDetail(t, v, "j").Flag.DefaultValue; got != nil {
		t.Errorf("stored json default = %#v, want nil", got)
	}

	// Absent leaves the (now null) default alone while changing something else.
	out, err = flagsUpdateHandler(deps)(ctx, decodeReq[flagsUpdateRequest](t, `{"key":"j","description":"d"}`), flagPrincipal)
	if err != nil || out.Flag.DefaultValue != nil || out.Flag.Description != "d" {
		t.Errorf("absent default: %+v, %v", out, err)
	}
}

func TestFlagsUpdate_KeepsVariantsMetadataAndRules(t *testing.T) {
	v, st := newTestVault(t)
	ctx := context.Background()
	seedFlag(t, v, "keep", flag.TypeString, "a", true)
	seedRules(t, v, "keep", flag.RuleInput{Type: flag.RuleWhenTenant, Config: flag.RuleConfig{TenantIDs: []string{"t"}}, ReturnValue: "b"})
	def, err := st.GetFlagDefinition(ctx, "keep", testAppID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	def.Variants = []flag.Variant{{Value: "a", Description: "control"}}
	def.Metadata = map[string]string{"owner": "growth"}
	if err := st.DefineFlag(ctx, def); err != nil {
		t.Fatalf("define: %v", err)
	}

	if _, err := flagsUpdateHandler(Deps{Vault: v})(ctx, flagsUpdateRequest{Key: "keep", Description: ptr("changed")}, flagPrincipal); err != nil {
		t.Fatalf("update: %v", err)
	}
	det := flagDetail(t, v, "keep")
	if len(det.Variants) != 1 || det.Variants[0].Description != "control" || det.Metadata["owner"] != "growth" || len(det.Rules) != 1 {
		t.Errorf("variants=%+v metadata=%v rules=%d after update", det.Variants, det.Metadata, len(det.Rules))
	}
}

func TestFlagsUpdate_Errors(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	deps := Deps{Vault: v}
	_, err := flagsUpdateHandler(deps)(ctx, flagsUpdateRequest{Key: "ghost", Description: ptr("x")}, flagPrincipal)
	wantCode(t, err, dashcontract.CodeNotFound, "flag not found")
	_, err = flagsUpdateHandler(deps)(ctx, flagsUpdateRequest{Key: " "}, flagPrincipal)
	wantCode(t, err, dashcontract.CodeBadRequest, "key is required")
}

// --- flags.setEnabled ---

func TestFlagsSetEnabled_DisablingIsVisibleToEvaluateAtOnce(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	deps := Deps{Vault: v}
	seedFlag(t, v, "kill", flag.TypeBool, false, true)
	seedRules(t, v, "kill", flag.RuleInput{Type: flag.RuleWhenTenant, Config: flag.RuleConfig{TenantIDs: []string{"acme"}}, ReturnValue: true})

	// Warm the engine's cache on the hot path first: a disable that does
	// not drop it would keep serving true for the cache TTL.
	tctx := scope.WithTenantID(scope.WithAppID(ctx, testAppID), "acme")
	if got, err := v.FlagEngine().Evaluate(tctx, "kill", testAppID); err != nil || got != true {
		t.Fatalf("warm evaluate = %v, %v, want true", got, err)
	}

	out, err := flagsSetEnabledHandler(deps)(ctx, flagsSetEnabledRequest{Key: "kill", Enabled: false}, flagPrincipal)
	if err != nil {
		t.Fatalf("disable: %v", err)
	}
	if out.Flag.Enabled {
		t.Errorf("response still enabled: %+v", out.Flag)
	}
	if got, evErr := v.FlagEngine().Evaluate(tctx, "kill", testAppID); evErr != nil || got != false {
		t.Errorf("hot path after disable = %v, %v, want the default false at once", got, evErr)
	}
	ev, err := flagsEvaluateHandler(deps)(ctx, flagsEvaluateRequest{Key: "kill", TenantID: "acme"}, flagPrincipal)
	if err != nil || ev.Reason != flag.ReasonDisabled || ev.Value != false {
		t.Errorf("flags.evaluate after disable = %+v, %v", ev, err)
	}

	// And on again.
	out, err = flagsSetEnabledHandler(deps)(ctx, flagsSetEnabledRequest{Key: "kill", Enabled: true}, flagPrincipal)
	if err != nil || !out.Flag.Enabled {
		t.Fatalf("enable: %+v, %v", out, err)
	}
	ev, err = flagsEvaluateHandler(deps)(ctx, flagsEvaluateRequest{Key: "kill", TenantID: "acme"}, flagPrincipal)
	if err != nil || ev.Reason != flag.ReasonRule || ev.Value != true {
		t.Errorf("flags.evaluate after enable = %+v, %v", ev, err)
	}
}

func TestFlagsSetEnabled_Errors(t *testing.T) {
	v, _ := newTestVault(t)
	deps := Deps{Vault: v}
	_, err := flagsSetEnabledHandler(deps)(context.Background(), flagsSetEnabledRequest{Key: "ghost", Enabled: true}, flagPrincipal)
	wantCode(t, err, dashcontract.CodeNotFound, "flag not found")
	_, err = flagsSetEnabledHandler(deps)(context.Background(), flagsSetEnabledRequest{Enabled: true}, flagPrincipal)
	wantCode(t, err, dashcontract.CodeBadRequest, "key is required")
}

// --- flags.delete ---

func TestFlagsDelete_RemovesTheFlagItsRulesAndOverrides(t *testing.T) {
	v, st := newTestVault(t)
	ctx := context.Background()
	deps := Deps{Vault: v}
	seedFlag(t, v, "gone", flag.TypeBool, false, true)
	seedFlag(t, v, "stays", flag.TypeBool, false, true)
	seedRules(t, v, "gone", flag.RuleInput{Type: flag.RuleRollout, Config: flag.RuleConfig{Percentage: 50}, ReturnValue: true})
	if _, err := v.FlagManager().SetTenantOverride(ctx, "gone", "acme", true); err != nil {
		t.Fatalf("override: %v", err)
	}

	out, err := flagsDeleteHandler(deps)(ctx, flagsDeleteRequest{Key: "gone"}, flagPrincipal)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if !out.OK || out.Key != "gone" {
		t.Errorf("response = %+v", out)
	}
	_, err = flagsDetailHandler(deps)(ctx, flagsDetailRequest{Key: "gone"}, flagPrincipal)
	wantCode(t, err, dashcontract.CodeNotFound, "flag not found")
	if rules, _ := st.GetFlagRules(ctx, "gone", testAppID); len(rules) != 0 {
		t.Errorf("rules survived the delete: %d", len(rules))
	}
	if ovs, _ := st.ListFlagTenantOverrides(ctx, "gone", testAppID); len(ovs) != 0 {
		t.Errorf("overrides survived the delete: %d", len(ovs))
	}
	if got := flagDetail(t, v, "stays"); got.Flag.Key != "stays" {
		t.Errorf("the other flag was touched: %+v", got)
	}
	// The row is gone, so a second delete is not found.
	_, err = flagsDeleteHandler(deps)(ctx, flagsDeleteRequest{Key: "gone"}, flagPrincipal)
	wantCode(t, err, dashcontract.CodeNotFound, "flag not found")
	_, err = flagsDeleteHandler(deps)(ctx, flagsDeleteRequest{}, flagPrincipal)
	wantCode(t, err, dashcontract.CodeBadRequest, "key is required")
}

// --- flags.setRules ---

func TestFlagsSetRules_HappyPathKeepsDisplayOrderAndUTC(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	deps := Deps{Vault: v}
	seedFlag(t, v, "r", flag.TypeInt, float64(1), true)

	in := decodeReq[flagsSetRulesRequest](t, `{"key":"r","rules":[
		{"type":"when_tenant","tenantIds":["acme","zed"],"returnValue":10},
		{"type":"when_user","userIds":["u1"],"returnValue":20},
		{"type":"rollout","percentage":25,"returnValue":30},
		{"type":"schedule","startAt":"2030-06-01T12:00:00-05:00","endAt":"2030-07-01T00:00:00Z","returnValue":40}
	]}`)
	out, err := flagsSetRulesHandler(deps)(ctx, in, flagPrincipal)
	if err != nil {
		t.Fatalf("setRules: %v", err)
	}
	if len(out.Rules) != 4 {
		t.Fatalf("rules = %+v", out.Rules)
	}
	wantTypes := []string{"when_tenant", "when_user", "rollout", "schedule"}
	for i, r := range out.Rules {
		if r.Priority != i || r.Type != wantTypes[i] || !r.Implemented || !r.ReturnMatchesType || r.ReturnValue != float64((i+1)*10) || r.ID == "" {
			t.Errorf("rule %d = %+v", i, r)
		}
	}
	if !reflect.DeepEqual(out.Rules[0].TenantIDs, []string{"acme", "zed"}) || out.Rules[0].UserIDs == nil {
		t.Errorf("tenant rule = %+v", out.Rules[0])
	}
	if out.Rules[2].Percentage != 25 {
		t.Errorf("rollout = %+v", out.Rules[2])
	}
	if s := out.Rules[3]; s.StartAt == nil || *s.StartAt != "2030-06-01T17:00:00Z" || s.EndAt == nil || *s.EndAt != "2030-07-01T00:00:00Z" {
		t.Errorf("schedule = start %v end %v", deref(s.StartAt), deref(s.EndAt))
	}
	if det := flagDetail(t, v, "r"); len(det.Rules) != 4 || det.Rules[3].Type != "schedule" {
		t.Errorf("detail rules = %+v", det.Rules)
	}
	// Open-ended schedule: only a start.
	out, err = flagsSetRulesHandler(deps)(ctx, decodeReq[flagsSetRulesRequest](t,
		`{"key":"r","rules":[{"type":"schedule","startAt":"2030-01-01T00:00:00Z","returnValue":2}]}`), flagPrincipal)
	if err != nil || len(out.Rules) != 1 || out.Rules[0].EndAt != nil {
		t.Errorf("open schedule: %+v, %v", out, err)
	}
}

func TestFlagsSetRules_EmptyListClearsAndAbsentListIsRefused(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	deps := Deps{Vault: v}
	seedFlag(t, v, "r", flag.TypeBool, false, true)
	seedRules(t, v, "r", flag.RuleInput{Type: flag.RuleRollout, Config: flag.RuleConfig{Percentage: 50}, ReturnValue: true})

	// A request that lost its rules field must not wipe the list.
	for _, raw := range []string{`{"key":"r"}`, `{"key":"r","rules":null}`} {
		_, err := flagsSetRulesHandler(deps)(ctx, decodeReq[flagsSetRulesRequest](t, raw), flagPrincipal)
		wantCode(t, err, dashcontract.CodeBadRequest, "rules")
	}
	if n := len(flagDetail(t, v, "r").Rules); n != 1 {
		t.Fatalf("rules after refused requests = %d, want 1", n)
	}

	out, err := flagsSetRulesHandler(deps)(ctx, decodeReq[flagsSetRulesRequest](t, `{"key":"r","rules":[]}`), flagPrincipal)
	if err != nil {
		t.Fatalf("clear: %v", err)
	}
	if out.Rules == nil || len(out.Rules) != 0 {
		t.Errorf("cleared rules = %#v, want an empty non-nil list", out.Rules)
	}
	raw, _ := json.Marshal(out)
	if string(raw) != `{"rules":[]}` {
		t.Errorf("wire = %s", raw)
	}
	if n := len(flagDetail(t, v, "r").Rules); n != 0 {
		t.Errorf("rules after clear = %d", n)
	}
}

func TestFlagsSetRules_BadTimesNameTheField(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	deps := Deps{Vault: v}
	seedFlag(t, v, "r", flag.TypeBool, false, true)
	seedRules(t, v, "r", flag.RuleInput{Type: flag.RuleRollout, Config: flag.RuleConfig{Percentage: 50}, ReturnValue: true})

	tests := []struct{ name, raw, field string }{
		{"startAt", `{"key":"r","rules":[{"type":"rollout","percentage":5,"returnValue":true},{"type":"schedule","startAt":"tomorrow","returnValue":true}]}`, "rules[1].startAt"},
		{"endAt", `{"key":"r","rules":[{"type":"schedule","startAt":"2030-01-01T00:00:00Z","endAt":"2030-13-01","returnValue":true}]}`, "rules[0].endAt"},
		{"date without a zone", `{"key":"r","rules":[{"type":"schedule","startAt":"2030-01-01T00:00:00","returnValue":true}]}`, "rules[0].startAt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := flagsSetRulesHandler(deps)(ctx, decodeReq[flagsSetRulesRequest](t, tt.raw), flagPrincipal)
			wantCode(t, err, dashcontract.CodeBadRequest, tt.field)
		})
	}
	// Nothing was written: the earlier rule is still there.
	if det := flagDetail(t, v, "r"); len(det.Rules) != 1 || det.Rules[0].Type != "rollout" || det.Rules[0].Percentage != 50 {
		t.Errorf("rules after refused writes = %+v", det.Rules)
	}
}

func TestFlagsSetRules_ManagerRefusalsAreBadRequestAndWriteNothing(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	deps := Deps{Vault: v}
	seedFlag(t, v, "r", flag.TypeBool, false, true)
	seedRules(t, v, "r", flag.RuleInput{Type: flag.RuleWhenUser, Config: flag.RuleConfig{UserIDs: []string{"u"}}, ReturnValue: true})

	tests := []struct{ name, raw, msg string }{
		{"percentage out of range", `{"key":"r","rules":[{"type":"rollout","percentage":150,"returnValue":true}]}`, "rules[0].percentage"},
		{"return value of the wrong type", `{"key":"r","rules":[{"type":"when_user","userIds":["u"],"returnValue":"yes"}]}`, "rules[0].returnValue"},
		{"empty id list", `{"key":"r","rules":[{"type":"when_tenant","returnValue":true}]}`, "rules[0].tenantIds"},
		{"unknown type", `{"key":"r","rules":[{"type":"astrology","returnValue":true}]}`, "rules[0].type"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := flagsSetRulesHandler(deps)(ctx, decodeReq[flagsSetRulesRequest](t, tt.raw), flagPrincipal)
			wantCode(t, err, dashcontract.CodeBadRequest, tt.msg)
		})
	}
	if det := flagDetail(t, v, "r"); len(det.Rules) != 1 || det.Rules[0].Type != "when_user" {
		t.Errorf("rules after refused writes = %+v", det.Rules)
	}
	_, err := flagsSetRulesHandler(deps)(ctx, decodeReq[flagsSetRulesRequest](t, `{"key":"ghost","rules":[]}`), flagPrincipal)
	wantCode(t, err, dashcontract.CodeNotFound, "flag not found")
	_, err = flagsSetRulesHandler(deps)(ctx, decodeReq[flagsSetRulesRequest](t, `{"rules":[]}`), flagPrincipal)
	wantCode(t, err, dashcontract.CodeBadRequest, "key is required")
}

func TestFlagsSetRules_RoundTripsACustomRule(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	deps := Deps{Vault: v}
	seedFlag(t, v, "c", flag.TypeString, "d", true)

	out, err := flagsSetRulesHandler(deps)(ctx, decodeReq[flagsSetRulesRequest](t, `{"key":"c","rules":[
		{"type":"custom","evaluator":"beta-cohort","params":{"n":3,"nested":{"a":[1,"x"]}},"returnValue":"custom"},
		{"type":"when_tenant_tag","tagKey":"plan","tagValue":"pro","returnValue":"tagged"}
	]}`), flagPrincipal)
	if err != nil {
		t.Fatalf("setRules: %v", err)
	}
	c, tag := out.Rules[0], out.Rules[1]
	wantParams := map[string]any{"n": float64(3), "nested": map[string]any{"a": []any{float64(1), "x"}}}
	if c.Type != "custom" || c.Implemented || c.Evaluator != "beta-cohort" || !reflect.DeepEqual(c.Params, wantParams) || c.ReturnValue != "custom" {
		t.Errorf("custom rule = %+v", c)
	}
	if tag.Type != "when_tenant_tag" || tag.Implemented || tag.TagKey != "plan" || tag.TagValue != "pro" {
		t.Errorf("tag rule = %+v", tag)
	}
	det := flagDetail(t, v, "c")
	if !reflect.DeepEqual(det.Rules[0].Params, wantParams) || det.Rules[1].TagKey != "plan" {
		t.Errorf("detail rules = %+v", det.Rules)
	}
}

// --- flags.setTenantOverride / flags.deleteTenantOverride ---

func TestFlagsTenantOverride_SetReplaceAndDelete(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	deps := Deps{Vault: v}
	seedFlag(t, v, "o", flag.TypeInt, float64(1), true)

	out, err := flagsSetTenantOverrideHandler(deps)(ctx, decodeReq[flagsSetTenantOverrideRequest](t, `{"key":"o","tenantId":"acme","value":50}`), flagPrincipal)
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	if o := out.Override; o.TenantID != "acme" || o.Value != float64(50) || !o.ValueMatchesType || o.UpdatedAt == "" {
		t.Errorf("override = %+v", o)
	}
	// A second set for the same tenant replaces the value.
	out, err = flagsSetTenantOverrideHandler(deps)(ctx, decodeReq[flagsSetTenantOverrideRequest](t, `{"key":"o","tenantId":"acme","value":60}`), flagPrincipal)
	if err != nil || out.Override.Value != float64(60) {
		t.Fatalf("replace: %+v, %v", out, err)
	}
	if det := flagDetail(t, v, "o"); len(det.Overrides) != 1 || det.Overrides[0].Value != float64(60) {
		t.Errorf("detail overrides = %+v", det.Overrides)
	}
	ev, err := flagsEvaluateHandler(deps)(ctx, flagsEvaluateRequest{Key: "o", TenantID: "acme"}, flagPrincipal)
	if err != nil || ev.Reason != flag.ReasonTenantOverride || ev.Value != float64(60) {
		t.Errorf("evaluate = %+v, %v", ev, err)
	}

	del, err := flagsDeleteTenantOverrideHandler(deps)(ctx, flagsDeleteTenantOverrideRequest{Key: "o", TenantID: "acme"}, flagPrincipal)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if !del.OK || del.Key != "o" || del.TenantID != "acme" {
		t.Errorf("delete response = %+v", del)
	}
	if det := flagDetail(t, v, "o"); len(det.Overrides) != 0 {
		t.Errorf("overrides after delete = %+v", det.Overrides)
	}
	ev, err = flagsEvaluateHandler(deps)(ctx, flagsEvaluateRequest{Key: "o", TenantID: "acme"}, flagPrincipal)
	if err != nil || ev.Reason != flag.ReasonDefault {
		t.Errorf("evaluate after delete = %+v, %v", ev, err)
	}
}

func TestFlagsSetTenantOverride_Refusals(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	deps := Deps{Vault: v}
	seedFlag(t, v, "o", flag.TypeBool, false, true)

	_, err := flagsSetTenantOverrideHandler(deps)(ctx, flagsSetTenantOverrideRequest{Key: "o", TenantID: "acme", Value: "true"}, flagPrincipal)
	wantCode(t, err, dashcontract.CodeBadRequest, "value")
	_, err = flagsSetTenantOverrideHandler(deps)(ctx, flagsSetTenantOverrideRequest{Key: "o", TenantID: "  ", Value: true}, flagPrincipal)
	wantCode(t, err, dashcontract.CodeBadRequest, "tenantId")
	_, err = flagsSetTenantOverrideHandler(deps)(ctx, flagsSetTenantOverrideRequest{Key: "ghost", TenantID: "acme", Value: true}, flagPrincipal)
	wantCode(t, err, dashcontract.CodeNotFound, "flag not found")
	_, err = flagsSetTenantOverrideHandler(deps)(ctx, flagsSetTenantOverrideRequest{TenantID: "acme", Value: true}, flagPrincipal)
	wantCode(t, err, dashcontract.CodeBadRequest, "key is required")
	if det := flagDetail(t, v, "o"); len(det.Overrides) != 0 {
		t.Errorf("a refused set left overrides: %+v", det.Overrides)
	}
}

func TestFlagsDeleteTenantOverride_MissingTenantIsNotFound(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	deps := Deps{Vault: v}
	seedFlag(t, v, "o", flag.TypeBool, false, true)

	_, err := flagsDeleteTenantOverrideHandler(deps)(ctx, flagsDeleteTenantOverrideRequest{Key: "o", TenantID: "nobody"}, flagPrincipal)
	wantCode(t, err, dashcontract.CodeNotFound, "")
	var ce *dashcontract.Error
	if !errors.As(err, &ce) || ce.Message != "tenant override not found" {
		t.Errorf("message = %v, want exactly %q", err, "tenant override not found")
	}
	// A missing flag stays a flag not found, not an override not found.
	_, err = flagsDeleteTenantOverrideHandler(deps)(ctx, flagsDeleteTenantOverrideRequest{Key: "ghost", TenantID: "nobody"}, flagPrincipal)
	wantCode(t, err, dashcontract.CodeNotFound, "flag not found")
	_, err = flagsDeleteTenantOverrideHandler(deps)(ctx, flagsDeleteTenantOverrideRequest{Key: "o", TenantID: " "}, flagPrincipal)
	wantCode(t, err, dashcontract.CodeBadRequest, "tenantId")
	_, err = flagsDeleteTenantOverrideHandler(deps)(ctx, flagsDeleteTenantOverrideRequest{TenantID: "x"}, flagPrincipal)
	wantCode(t, err, dashcontract.CodeBadRequest, "key is required")
}

// --- shared properties of every flag command ---

// Every command goes through the manager: it drops the engine cache and
// records an audit row per change, which a store write would not.
func TestFlagCommands_GoThroughTheManagerAndAreAudited(t *testing.T) {
	v, st := newTestVault(t)
	ctx := context.Background()
	deps := Deps{Vault: v}

	steps := []func() error{
		func() error {
			_, err := flagsCreateHandler(deps)(ctx, flagsCreateRequest{Key: "a", Type: "bool", DefaultValue: false, Enabled: true}, flagPrincipal)
			return err
		},
		func() error {
			_, err := flagsUpdateHandler(deps)(ctx, flagsUpdateRequest{Key: "a", Description: ptr("d")}, flagPrincipal)
			return err
		},
		func() error {
			_, err := flagsSetEnabledHandler(deps)(ctx, flagsSetEnabledRequest{Key: "a", Enabled: false}, flagPrincipal)
			return err
		},
		func() error {
			_, err := flagsSetRulesHandler(deps)(ctx, decodeReq[flagsSetRulesRequest](t, `{"key":"a","rules":[]}`), flagPrincipal)
			return err
		},
		func() error {
			_, err := flagsSetTenantOverrideHandler(deps)(ctx, flagsSetTenantOverrideRequest{Key: "a", TenantID: "t", Value: true}, flagPrincipal)
			return err
		},
		func() error {
			_, err := flagsDeleteTenantOverrideHandler(deps)(ctx, flagsDeleteTenantOverrideRequest{Key: "a", TenantID: "t"}, flagPrincipal)
			return err
		},
		func() error {
			_, err := flagsDeleteHandler(deps)(ctx, flagsDeleteRequest{Key: "a"}, flagPrincipal)
			return err
		},
	}
	for i, step := range steps {
		if err := step(); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
	entries, err := st.ListAuditByKey(ctx, "a", testAppID, audit.ListOpts{Limit: 50, Resource: audithook.ResourceFlag})
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	got := make([]string, 0, len(entries))
	for _, e := range entries {
		got = append(got, e.Action)
	}
	sort.Strings(got)
	want := []string{
		audithook.ActionFlagCreated, audithook.ActionFlagDeleted, audithook.ActionFlagOverrideDeleted,
		audithook.ActionFlagOverrideSet, audithook.ActionFlagRulesSet, audithook.ActionFlagToggled, audithook.ActionFlagUpdated,
	}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("audit actions = %v, want %v", got, want)
	}
}

// Every command operates on deps.Vault.AppID() alone: a flag another app
// owns under the same key is neither visible nor changed.
func TestFlagCommands_OtherAppsFlagsAreUntouched(t *testing.T) {
	v, st := newTestVault(t)
	ctx := context.Background()
	deps := Deps{Vault: v}
	if err := st.DefineFlag(ctx, &flag.Definition{
		Entity: core.NewEntity(), ID: id.NewFlagID(), Key: "shared", Type: flag.TypeBool,
		DefaultValue: true, Enabled: true, AppID: "other-app",
	}); err != nil {
		t.Fatalf("define: %v", err)
	}

	_, err := flagsSetEnabledHandler(deps)(ctx, flagsSetEnabledRequest{Key: "shared", Enabled: false}, flagPrincipal)
	wantCode(t, err, dashcontract.CodeNotFound, "flag not found")
	_, err = flagsDeleteHandler(deps)(ctx, flagsDeleteRequest{Key: "shared"}, flagPrincipal)
	wantCode(t, err, dashcontract.CodeNotFound, "flag not found")
	_, err = flagsSetRulesHandler(deps)(ctx, decodeReq[flagsSetRulesRequest](t, `{"key":"shared","rules":[]}`), flagPrincipal)
	wantCode(t, err, dashcontract.CodeNotFound, "flag not found")

	// Creating "shared" here is allowed (different app) and leaves theirs be.
	if _, err = flagsCreateHandler(deps)(ctx, flagsCreateRequest{Key: "shared", Type: "string", DefaultValue: "mine", Enabled: true}, flagPrincipal); err != nil {
		t.Fatalf("create in own app: %v", err)
	}
	theirs, err := st.GetFlagDefinition(ctx, "shared", "other-app")
	if err != nil || theirs.Type != flag.TypeBool || theirs.DefaultValue != true || !theirs.Enabled {
		t.Errorf("the other app's flag = %+v, %v", theirs, err)
	}
}

// The wire: a command answers with exactly the documented shape.
func TestFlagCommands_WireShapes(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	deps := Deps{Vault: v}
	seedFlag(t, v, "w", flag.TypeBool, false, true)

	if _, err := flagsSetTenantOverrideHandler(deps)(ctx, flagsSetTenantOverrideRequest{Key: "w", TenantID: "t", Value: true}, flagPrincipal); err != nil {
		t.Fatalf("set: %v", err)
	}
	del, err := flagsDeleteTenantOverrideHandler(deps)(ctx, flagsDeleteTenantOverrideRequest{Key: "w", TenantID: "t"}, flagPrincipal)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	raw, _ := json.Marshal(del)
	if string(raw) != `{"ok":true,"key":"w","tenantId":"t"}` {
		t.Errorf("deleteTenantOverride wire = %s", raw)
	}
	fd, err := flagsDeleteHandler(deps)(ctx, flagsDeleteRequest{Key: "w"}, flagPrincipal)
	if err != nil {
		t.Fatalf("delete flag: %v", err)
	}
	raw, _ = json.Marshal(fd)
	if string(raw) != `{"ok":true,"key":"w"}` {
		t.Errorf("delete wire = %s", raw)
	}
}

// A rule read from flags.detail carries tenantIds and userIds as [] when it
// has none. A custom or when_tenant_tag rule keeps its config as given, so
// those empty lists must not end up stored as empty (non-nil) slices: the
// stored config has to equal the one that was read, not merely marshal like
// it.
func TestFlagsSetRules_EmptyIdListsOnAKeptConfigStayUnset(t *testing.T) {
	v, st := newTestVault(t)
	ctx := context.Background()
	seedFlag(t, v, "c", flag.TypeString, "d", true)

	_, err := flagsSetRulesHandler(Deps{Vault: v})(ctx, decodeReq[flagsSetRulesRequest](t, `{"key":"c","rules":[
		{"type":"custom","tenantIds":[],"userIds":[],"evaluator":"x","returnValue":"a"},
		{"type":"when_tenant_tag","tenantIds":[],"userIds":[],"tagKey":"k","tagValue":"v","returnValue":"b"}
	]}`), flagPrincipal)
	if err != nil {
		t.Fatalf("setRules: %v", err)
	}
	rules, err := st.GetFlagRules(ctx, "c", testAppID)
	if err != nil || len(rules) != 2 {
		t.Fatalf("stored rules = %v, %v", rules, err)
	}
	for i, r := range rules {
		if r.Config.TenantIDs != nil || r.Config.UserIDs != nil {
			t.Errorf("rule %d stored tenantIds=%#v userIds=%#v, want both unset", i, r.Config.TenantIDs, r.Config.UserIDs)
		}
	}
}

// The evaluation names the rules by id: each trace step carries the id of the
// rule it describes and matchedRuleId is the id of the one that decided.
func TestFlagsEvaluate_TraceCarriesRuleIDsAndMatchedRuleID(t *testing.T) {
	v, _ := newTestVault(t)
	seedFlag(t, v, "ids", flag.TypeBool, false, true)
	stored, err := v.FlagManager().SetRules(context.Background(), "ids", []flag.RuleInput{
		{Type: flag.RuleWhenTenant, Config: flag.RuleConfig{TenantIDs: []string{"nobody"}}, ReturnValue: true},
		{Type: flag.RuleRollout, Config: flag.RuleConfig{Percentage: 100}, ReturnValue: true},
		{Type: flag.RuleWhenUser, Config: flag.RuleConfig{UserIDs: []string{"u"}}, ReturnValue: true},
	})
	if err != nil {
		t.Fatalf("rules: %v", err)
	}

	out, err := flagsEvaluateHandler(Deps{Vault: v})(context.Background(), flagsEvaluateRequest{Key: "ids", TenantID: "t-1"}, flagPrincipal)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if len(out.Trace) != 3 {
		t.Fatalf("trace = %+v, want 3 steps", out.Trace)
	}
	for i, r := range stored {
		if out.Trace[i].RuleID == "" || out.Trace[i].RuleID != r.ID.String() {
			t.Errorf("trace[%d].ruleId = %q, want %q", i, out.Trace[i].RuleID, r.ID.String())
		}
	}
	if out.MatchedRuleID != stored[1].ID.String() {
		t.Errorf("matchedRuleId = %q, want %q", out.MatchedRuleID, stored[1].ID.String())
	}
	raw, _ := json.Marshal(out)
	s := string(raw)
	if !strings.Contains(s, `"matchedRuleId":"`+stored[1].ID.String()+`"`) || !strings.Contains(s, `"ruleId":"`+stored[0].ID.String()+`"`) {
		t.Errorf("JSON lacks the rule ids: %s", s)
	}
}

// matchedRuleId is present exactly when the reason is "rule".
func TestFlagsEvaluate_MatchedRuleIDAbsentUnlessARuleMatched(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	seedFlag(t, v, "off", flag.TypeBool, false, false)
	seedFlag(t, v, "ov", flag.TypeBool, false, true)
	seedFlag(t, v, "dflt", flag.TypeBool, false, true)
	seedRules(t, v, "off", flag.RuleInput{Type: flag.RuleRollout, Config: flag.RuleConfig{Percentage: 100}, ReturnValue: true})
	seedRules(t, v, "dflt", flag.RuleInput{Type: flag.RuleWhenTenant, Config: flag.RuleConfig{TenantIDs: []string{"nobody"}}, ReturnValue: true})
	if _, err := v.FlagManager().SetTenantOverride(ctx, "ov", "big", true); err != nil {
		t.Fatalf("override: %v", err)
	}
	h := flagsEvaluateHandler(Deps{Vault: v})

	for _, tc := range []struct {
		name string
		in   flagsEvaluateRequest
		want string
	}{
		{"disabled", flagsEvaluateRequest{Key: "off", TenantID: "t"}, flag.ReasonDisabled},
		{"tenant override", flagsEvaluateRequest{Key: "ov", TenantID: "big"}, flag.ReasonTenantOverride},
		{"default", flagsEvaluateRequest{Key: "dflt", TenantID: "t"}, flag.ReasonDefault},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := h(ctx, tc.in, flagPrincipal)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if out.Reason != tc.want {
				t.Fatalf("reason = %q, want %q", out.Reason, tc.want)
			}
			if out.MatchedRuleID != "" {
				t.Errorf("matchedRuleId = %q, want none", out.MatchedRuleID)
			}
			raw, _ := json.Marshal(out)
			if strings.Contains(string(raw), "matchedRuleId") {
				t.Errorf("JSON carries matchedRuleId: %s", raw)
			}
		})
	}
}
