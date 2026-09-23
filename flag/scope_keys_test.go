package flag_test

import (
	"testing"

	"github.com/xraph/vault"
	"github.com/xraph/vault/flag"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/scope"
	"github.com/xraph/vault/store/memory"
)

// These tests exercise the public contract: a tenant or user placed on the
// context with the scope package's own helpers must be visible to flag
// evaluation. scope.ContextKey, flag.ContextKey and override.contextKey used
// to be three distinct defined types with the same string value, so a
// context.WithValue keyed by one type was invisible to code reading it with
// another, even though the values printed the same.
func TestScopeTenantReachesTheEngine(t *testing.T) {
	s := memory.New()
	if err := s.DefineFlag(bg(), &flag.Definition{
		Entity:       vault.NewEntity(),
		ID:           id.NewFlagID(),
		Key:          "feat-scope-tenant",
		Type:         flag.TypeBool,
		DefaultValue: false,
		Enabled:      true,
		AppID:        testApp,
	}); err != nil {
		t.Fatalf("DefineFlag: %v", err)
	}
	if err := s.SetFlagTenantOverride(bg(), "feat-scope-tenant", testApp, "t-1", true); err != nil {
		t.Fatalf("SetFlagTenantOverride: %v", err)
	}

	engine := flag.NewEngine(s)
	ctx := scope.WithTenantID(bg(), "t-1")

	val, err := engine.Evaluate(ctx, "feat-scope-tenant", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if val != true {
		t.Errorf("Evaluate: got %v, want true (tenant override reached via scope.WithTenantID)", val)
	}

	detail, err := engine.EvaluateDetail(ctx, "feat-scope-tenant", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if detail.Reason != flag.ReasonTenantOverride {
		t.Errorf("EvaluateDetail: got reason %q, want %q", detail.Reason, flag.ReasonTenantOverride)
	}
}

func TestScopeUserReachesTheEngine(t *testing.T) {
	s := memory.New()
	if err := s.DefineFlag(bg(), &flag.Definition{
		Entity:       vault.NewEntity(),
		ID:           id.NewFlagID(),
		Key:          "feat-scope-user",
		Type:         flag.TypeBool,
		DefaultValue: false,
		Enabled:      true,
		AppID:        testApp,
	}); err != nil {
		t.Fatalf("DefineFlag: %v", err)
	}

	rule := flag.WhenUser("u-1").Return(true)
	rule.FlagKey = "feat-scope-user"
	rule.AppID = testApp
	rule.Priority = 1
	if err := s.SetFlagRules(bg(), "feat-scope-user", testApp, []*flag.Rule{rule}); err != nil {
		t.Fatalf("SetFlagRules: %v", err)
	}

	engine := flag.NewEngine(s)
	ctx := scope.WithUserID(bg(), "u-1")

	detail, err := engine.EvaluateDetail(ctx, "feat-scope-user", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if detail.Reason != flag.ReasonRule {
		t.Fatalf("EvaluateDetail: got reason %q, want %q (when_user rule reached via scope.WithUserID)", detail.Reason, flag.ReasonRule)
	}
	if detail.Value != true {
		t.Errorf("EvaluateDetail: got value %v, want true", detail.Value)
	}
}
