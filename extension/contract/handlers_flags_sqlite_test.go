package contract

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/xraph/vault/flag"
)

// The flag commands against a real backend. A memory store hands a value
// back as the Go value it was given; sqlite writes JSON text and reads it
// back as float64, map[string]any and []any, which is what these tests need
// to see.

func TestFlags_SQLite_CreateUpdateAndReadBack(t *testing.T) {
	v := newSQLiteTestVault(t)
	ctx := context.Background()
	deps := Deps{Vault: v}

	created, err := flagsCreateHandler(deps)(ctx, decodeReq[flagsCreateRequest](t,
		`{"key":"limit","type":"int","defaultValue":5,"description":"old","tags":["team-a"],"enabled":true}`), flagPrincipal)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.Flag.DefaultValue != float64(5) || !created.Flag.DefaultMatchesType {
		t.Errorf("created = %+v", created.Flag)
	}

	// Variants and metadata have no write path: seed them through the store,
	// the way a program that defines flags in code does.
	st := v.Store()
	def, err := st.GetFlagDefinition(ctx, "limit", testAppID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	def.Variants = []flag.Variant{{Value: float64(5), Description: "control"}, {Value: float64(50), Description: "big"}}
	def.Metadata = map[string]string{"owner": "growth", "ticket": "GRO-1"}
	if err = st.DefineFlag(ctx, def); err != nil {
		t.Fatalf("seed variants: %v", err)
	}
	before := flagDetail(t, v, "limit")

	// A description-only update: everything else must come back as it was.
	out, err := flagsUpdateHandler(deps)(ctx, decodeReq[flagsUpdateRequest](t, `{"key":"limit","description":"new"}`), flagPrincipal)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if out.Flag.Description != "new" {
		t.Errorf("description = %q", out.Flag.Description)
	}

	after := flagDetail(t, v, "limit")
	if after.Flag.Description != "new" || after.Flag.DefaultValue != float64(5) || !after.Flag.Enabled ||
		!reflect.DeepEqual(after.Flag.Tags, []string{"team-a"}) || after.Flag.ID != before.Flag.ID {
		t.Errorf("flag after update = %+v, before = %+v", after.Flag, before.Flag)
	}
	if !reflect.DeepEqual(after.Variants, before.Variants) || len(after.Variants) != 2 || after.Variants[1].Description != "big" {
		t.Errorf("variants after update = %+v, want %+v", after.Variants, before.Variants)
	}
	if !reflect.DeepEqual(after.Metadata, before.Metadata) || after.Metadata["ticket"] != "GRO-1" {
		t.Errorf("metadata after update = %v, want %v", after.Metadata, before.Metadata)
	}
	if after.Flag.CreatedAt != before.Flag.CreatedAt {
		t.Errorf("createdAt moved: %s -> %s", before.Flag.CreatedAt, after.Flag.CreatedAt)
	}

	// setEnabled and a new default keep them too.
	if _, err = flagsSetEnabledHandler(deps)(ctx, flagsSetEnabledRequest{Key: "limit", Enabled: false}, flagPrincipal); err != nil {
		t.Fatalf("setEnabled: %v", err)
	}
	if _, err = flagsUpdateHandler(deps)(ctx, decodeReq[flagsUpdateRequest](t, `{"key":"limit","defaultValue":9}`), flagPrincipal); err != nil {
		t.Fatalf("update default: %v", err)
	}
	last := flagDetail(t, v, "limit")
	if last.Flag.Enabled || last.Flag.DefaultValue != float64(9) || len(last.Variants) != 2 || last.Metadata["owner"] != "growth" {
		t.Errorf("after setEnabled and default update: %+v variants=%+v metadata=%v", last.Flag, last.Variants, last.Metadata)
	}

	// A refused create leaves the stored flag exactly as it was.
	_, err = flagsCreateHandler(deps)(ctx, flagsCreateRequest{Key: "limit", Type: "string", DefaultValue: "x", Enabled: true}, flagPrincipal)
	wantCode(t, err, "CONFLICT", "")
	if got := flagDetail(t, v, "limit"); got.Flag.Type != "int" || got.Flag.DefaultValue != float64(9) || len(got.Variants) != 2 {
		t.Errorf("flag after a refused create: %+v", got)
	}
}

// The "keep it byte for byte" scenario: rules read back from sqlite through
// flags.detail, sent unchanged through flags.setRules, must be stored
// exactly as they were. A custom rule's params come back as float64 and
// nested maps, a when_tenant_tag rule keeps its tag, and neither engine
// evaluates them, so a rewrite that lost anything would go unnoticed.
func TestFlags_SQLite_DetailRulesGoBackThroughSetRulesUnchanged(t *testing.T) {
	v := newSQLiteTestVault(t)
	ctx := context.Background()
	deps := Deps{Vault: v}
	st := v.Store()
	seedFlag(t, v, "beta", flag.TypeString, "off", true)

	start := time.Date(2030, 6, 1, 12, 0, 0, 0, time.FixedZone("x", -5*3600))
	end := time.Date(2030, 9, 1, 0, 0, 0, 0, time.UTC)
	seedRules(t, v, "beta",
		flag.RuleInput{Type: flag.RuleWhenTenant, Config: flag.RuleConfig{TenantIDs: []string{"acme", "zed"}}, ReturnValue: "tenant"},
		flag.RuleInput{
			Type: flag.RuleCustom,
			Config: flag.RuleConfig{
				Evaluator: "beta-cohort",
				Params: map[string]any{
					"n":      3,
					"ratio":  0.25,
					"on":     true,
					"nested": map[string]any{"a": []any{1, "x", map[string]any{"deep": nil}}},
				},
			},
			ReturnValue: "custom",
		},
		flag.RuleInput{Type: flag.RuleWhenTenantTag, Config: flag.RuleConfig{TagKey: "plan", TagValue: "pro"}, ReturnValue: "tagged"},
		flag.RuleInput{Type: flag.RuleRollout, Config: flag.RuleConfig{Percentage: 25}, ReturnValue: "rollout"},
		flag.RuleInput{Type: flag.RuleWhenUser, Config: flag.RuleConfig{UserIDs: []string{"u1"}}, ReturnValue: "user"},
		flag.RuleInput{Type: flag.RuleSchedule, Config: flag.RuleConfig{StartAt: &start, EndAt: &end}, ReturnValue: "scheduled"},
	)

	stored := func() []*flag.Rule {
		t.Helper()
		rules, err := st.GetFlagRules(ctx, "beta", testAppID)
		if err != nil {
			t.Fatalf("GetFlagRules: %v", err)
		}
		return rules
	}
	original := stored()
	if len(original) != 6 {
		t.Fatalf("stored %d rules, want 6", len(original))
	}

	// Read the rules back the way the page does, and send them on the wire
	// exactly as it would: the projection's own JSON.
	det := flagDetail(t, v, "beta")
	custom := det.Rules[1]
	if custom.Type != "custom" || custom.Params["n"] != float64(3) || custom.Params["nested"] == nil {
		t.Fatalf("custom rule read back as %+v", custom)
	}
	rawRules, err := json.Marshal(det.Rules)
	if err != nil {
		t.Fatalf("marshal rules: %v", err)
	}
	in := decodeReq[flagsSetRulesRequest](t, `{"key":"beta","rules":`+string(rawRules)+`}`)

	out, err := flagsSetRulesHandler(deps)(ctx, in, flagPrincipal)
	if err != nil {
		t.Fatalf("setRules with the rules just read: %v", err)
	}
	if len(out.Rules) != 6 {
		t.Fatalf("setRules returned %d rules", len(out.Rules))
	}

	rewritten := stored()
	if len(rewritten) != len(original) {
		t.Fatalf("stored %d rules after, %d before", len(rewritten), len(original))
	}
	for i := range original {
		a, b := original[i], rewritten[i]
		if a.Type != b.Type || a.Priority != b.Priority {
			t.Errorf("rule %d: type/priority %s/%d -> %s/%d", i, a.Type, a.Priority, b.Type, b.Priority)
		}
		if !reflect.DeepEqual(a.Config, b.Config) {
			t.Errorf("rule %d (%s): config changed\n before: %#v\n after:  %#v", i, a.Type, a.Config, b.Config)
		}
		if !reflect.DeepEqual(a.ReturnValue, b.ReturnValue) {
			t.Errorf("rule %d (%s): return value %#v -> %#v", i, a.Type, a.ReturnValue, b.ReturnValue)
		}
	}

	// The stored JSON itself, byte for byte, for the two rule types nothing
	// validates.
	for _, i := range []int{1, 2} {
		want, err := json.Marshal(original[i].Config)
		if err != nil {
			t.Fatal(err)
		}
		got, err := json.Marshal(rewritten[i].Config)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Errorf("rule %d config JSON = %s, want %s", i, got, want)
		}
	}

	// And what the page reads afterwards is what it read before.
	again := flagDetail(t, v, "beta")
	for i := range det.Rules {
		a, b := det.Rules[i], again.Rules[i]
		a.ID, b.ID = "", ""
		if !reflect.DeepEqual(a, b) {
			t.Errorf("rule %d read back differently:\n before: %+v\n after:  %+v", i, a, b)
		}
	}
}
