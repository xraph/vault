package flag_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/xraph/vault"
	"github.com/xraph/vault/flag"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/store/memory"
)

const testApp = "app1"

func bg() context.Context { return context.Background() }

func withTenant(tenantID string) context.Context {
	return context.WithValue(bg(), flag.ContextKeyTenantID, tenantID)
}

func withUser(userID string) context.Context {
	return context.WithValue(bg(), flag.ContextKeyUserID, userID)
}

func withTenantAndUser(tenantID, userID string) context.Context {
	ctx := context.WithValue(bg(), flag.ContextKeyTenantID, tenantID)
	return context.WithValue(ctx, flag.ContextKeyUserID, userID)
}

func defineFlag(t *testing.T, s *memory.Store, key string, defaultVal any, enabled bool) {
	t.Helper()
	err := s.DefineFlag(bg(), &flag.Definition{
		Entity:       vault.NewEntity(),
		ID:           id.NewFlagID(),
		Key:          key,
		Type:         flag.TypeBool,
		DefaultValue: defaultVal,
		Enabled:      enabled,
		AppID:        testApp,
	})
	if err != nil {
		t.Fatalf("DefineFlag(%q): %v", key, err)
	}
}

func TestEvaluateDefault(t *testing.T) {
	s := memory.New()
	defineFlag(t, s, "feat-x", false, true)

	engine := flag.NewEngine(s)
	val, err := engine.Evaluate(bg(), "feat-x", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if val != false {
		t.Errorf("got %v, want false (default)", val)
	}
}

func TestEvaluateDisabledFlag(t *testing.T) {
	s := memory.New()
	defineFlag(t, s, "feat-disabled", "on", false)

	engine := flag.NewEngine(s)
	val, err := engine.Evaluate(bg(), "feat-disabled", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if val != "on" {
		t.Errorf("got %v, want %q (default for disabled flag)", val, "on")
	}
}

func TestEvaluateFlagNotFound(t *testing.T) {
	s := memory.New()
	engine := flag.NewEngine(s)

	_, err := engine.Evaluate(bg(), "nonexistent", testApp)
	if err == nil {
		t.Fatal("expected error for nonexistent flag")
	}
}

func TestEvaluateTenantOverride(t *testing.T) {
	s := memory.New()
	defineFlag(t, s, "feat-o", false, true)
	_ = s.SetFlagTenantOverride(bg(), "feat-o", testApp, "t-1", true)

	engine := flag.NewEngine(s)

	// With matching tenant context.
	val, err := engine.Evaluate(withTenant("t-1"), "feat-o", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if val != true {
		t.Errorf("got %v, want true (tenant override)", val)
	}

	// Without tenant context -> default.
	val2, err := engine.Evaluate(bg(), "feat-o", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if val2 != false {
		t.Errorf("got %v, want false (default, no tenant)", val2)
	}

	// With different tenant -> default.
	val3, err := engine.Evaluate(withTenant("t-other"), "feat-o", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if val3 != false {
		t.Errorf("got %v, want false (default, other tenant)", val3)
	}
}

func TestEvaluateWhenTenantRule(t *testing.T) {
	s := memory.New()
	defineFlag(t, s, "feat-t", "off", true)

	rules := []*flag.Rule{
		flag.WhenTenant("t-alpha", "t-beta").Return("on"),
	}
	rules[0].FlagKey = "feat-t"
	rules[0].AppID = testApp
	rules[0].Priority = 1
	_ = s.SetFlagRules(bg(), "feat-t", testApp, rules)

	engine := flag.NewEngine(s)

	// Matching tenant.
	val, err := engine.Evaluate(withTenant("t-alpha"), "feat-t", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if val != "on" {
		t.Errorf("got %v, want %q", val, "on")
	}

	// Non-matching tenant.
	val2, err := engine.Evaluate(withTenant("t-gamma"), "feat-t", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if val2 != "off" {
		t.Errorf("got %v, want %q (default)", val2, "off")
	}
}

func TestEvaluateWhenUserRule(t *testing.T) {
	s := memory.New()
	defineFlag(t, s, "feat-u", false, true)

	rules := []*flag.Rule{
		flag.WhenUser("user-1", "user-2").Return(true),
	}
	rules[0].FlagKey = "feat-u"
	rules[0].AppID = testApp
	rules[0].Priority = 1
	_ = s.SetFlagRules(bg(), "feat-u", testApp, rules)

	engine := flag.NewEngine(s)

	// Matching user.
	val, err := engine.Evaluate(withUser("user-1"), "feat-u", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if val != true {
		t.Errorf("got %v, want true", val)
	}

	// Non-matching user.
	val2, err := engine.Evaluate(withUser("user-3"), "feat-u", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if val2 != false {
		t.Errorf("got %v, want false (default)", val2)
	}
}

func TestEvaluateRollout(t *testing.T) {
	s := memory.New()
	defineFlag(t, s, "feat-roll", false, true)

	rules := []*flag.Rule{
		flag.Rollout(50).Return(true),
	}
	rules[0].FlagKey = "feat-roll"
	rules[0].AppID = testApp
	rules[0].Priority = 1
	_ = s.SetFlagRules(bg(), "feat-roll", testApp, rules)

	engine := flag.NewEngine(s)

	// Deterministic: same tenant + key = same result.
	val1, _ := engine.Evaluate(withTenant("tenant-a"), "feat-roll", testApp)
	val2, _ := engine.Evaluate(withTenant("tenant-a"), "feat-roll", testApp)
	if val1 != val2 {
		t.Errorf("rollout not deterministic: %v != %v", val1, val2)
	}

	// No tenant -> default (rollout requires tenantID).
	val3, _ := engine.Evaluate(bg(), "feat-roll", testApp)
	if val3 != false {
		t.Errorf("got %v, want false (no tenant for rollout)", val3)
	}
}

func TestEvaluateRolloutZeroPercent(t *testing.T) {
	s := memory.New()
	defineFlag(t, s, "feat-r0", "default", true)

	rules := []*flag.Rule{
		flag.Rollout(0).Return("rolled-out"),
	}
	rules[0].FlagKey = "feat-r0"
	rules[0].AppID = testApp
	rules[0].Priority = 1
	_ = s.SetFlagRules(bg(), "feat-r0", testApp, rules)

	engine := flag.NewEngine(s)

	// 0% rollout -> nobody gets it.
	for i := range 20 {
		val, _ := engine.Evaluate(withTenant(fmt.Sprintf("t-%d", i)), "feat-r0", testApp)
		if val != "default" {
			t.Errorf("tenant t-%d got %v, want default (0%% rollout)", i, val)
		}
	}
}

func TestEvaluateRollout100Percent(t *testing.T) {
	s := memory.New()
	defineFlag(t, s, "feat-r100", "default", true)

	rules := []*flag.Rule{
		flag.Rollout(100).Return("rolled-out"),
	}
	rules[0].FlagKey = "feat-r100"
	rules[0].AppID = testApp
	rules[0].Priority = 1
	_ = s.SetFlagRules(bg(), "feat-r100", testApp, rules)

	engine := flag.NewEngine(s)

	// 100% rollout -> everyone gets it.
	for i := range 20 {
		val, _ := engine.Evaluate(withTenant(fmt.Sprintf("t-%d", i)), "feat-r100", testApp)
		if val != "rolled-out" {
			t.Errorf("tenant t-%d got %v, want rolled-out (100%% rollout)", i, val)
		}
	}
}

func TestEvaluateSchedule(t *testing.T) {
	s := memory.New()
	defineFlag(t, s, "feat-sched", "off", true)

	now := time.Now().UTC()
	pastStart := now.Add(-1 * time.Hour)
	futureEnd := now.Add(1 * time.Hour)

	// Active schedule (now is between start and end).
	rules := []*flag.Rule{
		flag.Schedule(pastStart, futureEnd).Return("scheduled"),
	}
	rules[0].FlagKey = "feat-sched"
	rules[0].AppID = testApp
	rules[0].Priority = 1
	_ = s.SetFlagRules(bg(), "feat-sched", testApp, rules)

	engine := flag.NewEngine(s)
	val, err := engine.Evaluate(bg(), "feat-sched", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if val != "scheduled" {
		t.Errorf("got %v, want %q (schedule active)", val, "scheduled")
	}
}

func TestEvaluateScheduleFuture(t *testing.T) {
	s := memory.New()
	defineFlag(t, s, "feat-future", "off", true)

	futureStart := time.Now().UTC().Add(1 * time.Hour)
	futureEnd := time.Now().UTC().Add(2 * time.Hour)

	rules := []*flag.Rule{
		flag.Schedule(futureStart, futureEnd).Return("scheduled"),
	}
	rules[0].FlagKey = "feat-future"
	rules[0].AppID = testApp
	rules[0].Priority = 1
	_ = s.SetFlagRules(bg(), "feat-future", testApp, rules)

	engine := flag.NewEngine(s)
	val, _ := engine.Evaluate(bg(), "feat-future", testApp)
	if val != "off" {
		t.Errorf("got %v, want %q (schedule not yet active)", val, "off")
	}
}

func TestEvaluateSchedulePast(t *testing.T) {
	s := memory.New()
	defineFlag(t, s, "feat-past", "off", true)

	pastStart := time.Now().UTC().Add(-2 * time.Hour)
	pastEnd := time.Now().UTC().Add(-1 * time.Hour)

	rules := []*flag.Rule{
		flag.Schedule(pastStart, pastEnd).Return("scheduled"),
	}
	rules[0].FlagKey = "feat-past"
	rules[0].AppID = testApp
	rules[0].Priority = 1
	_ = s.SetFlagRules(bg(), "feat-past", testApp, rules)

	engine := flag.NewEngine(s)
	val, _ := engine.Evaluate(bg(), "feat-past", testApp)
	if val != "off" {
		t.Errorf("got %v, want %q (schedule expired)", val, "off")
	}
}

func TestEvaluatePriorityOrdering(t *testing.T) {
	s := memory.New()
	defineFlag(t, s, "feat-pri", "default", true)

	r1 := flag.WhenTenant("t-1").Return("low-priority")
	r1.FlagKey = "feat-pri"
	r1.AppID = testApp
	r1.Priority = 10 // lower priority

	r2 := flag.WhenUser("u-1").Return("high-priority")
	r2.FlagKey = "feat-pri"
	r2.AppID = testApp
	r2.Priority = 1 // higher priority

	_ = s.SetFlagRules(bg(), "feat-pri", testApp, []*flag.Rule{r1, r2})

	engine := flag.NewEngine(s)

	// With both tenant and user matching: higher priority (user rule) wins.
	ctx := withTenantAndUser("t-1", "u-1")
	val, err := engine.Evaluate(ctx, "feat-pri", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if val != "high-priority" {
		t.Errorf("got %v, want %q (higher priority wins)", val, "high-priority")
	}
}

func TestEvaluateTenantOverrideSupersedesRules(t *testing.T) {
	s := memory.New()
	defineFlag(t, s, "feat-sup", "default", true)

	// Set a tenant override.
	_ = s.SetFlagTenantOverride(bg(), "feat-sup", testApp, "t-1", "override-val")

	// Set a rule that also matches.
	r := flag.WhenTenant("t-1").Return("rule-val")
	r.FlagKey = "feat-sup"
	r.AppID = testApp
	r.Priority = 1
	_ = s.SetFlagRules(bg(), "feat-sup", testApp, []*flag.Rule{r})

	engine := flag.NewEngine(s)

	val, err := engine.Evaluate(withTenant("t-1"), "feat-sup", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if val != "override-val" {
		t.Errorf("got %v, want %q (tenant override supersedes rules)", val, "override-val")
	}
}

func TestEvaluateMultipleRulesFirstMatchWins(t *testing.T) {
	s := memory.New()
	defineFlag(t, s, "feat-multi", "default", true)

	r1 := flag.WhenTenant("t-1").Return("first-match")
	r1.FlagKey = "feat-multi"
	r1.AppID = testApp
	r1.Priority = 1

	r2 := flag.WhenTenant("t-1", "t-2").Return("second-match")
	r2.FlagKey = "feat-multi"
	r2.AppID = testApp
	r2.Priority = 2

	_ = s.SetFlagRules(bg(), "feat-multi", testApp, []*flag.Rule{r1, r2})

	engine := flag.NewEngine(s)

	// t-1 matches both rules; first (priority 1) wins.
	val, _ := engine.Evaluate(withTenant("t-1"), "feat-multi", testApp)
	if val != "first-match" {
		t.Errorf("got %v, want %q (first match by priority)", val, "first-match")
	}
}

func TestEvaluateWithCache(t *testing.T) {
	s := memory.New()
	defineFlag(t, s, "feat-cache", "default", true)

	engine := flag.NewEngine(s, flag.WithCacheTTL(1*time.Minute))

	// First call populates cache.
	val1, err := engine.Evaluate(bg(), "feat-cache", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if val1 != "default" {
		t.Errorf("got %v, want %q", val1, "default")
	}

	// Second call should hit cache (same result).
	val2, err := engine.Evaluate(bg(), "feat-cache", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if val2 != "default" {
		t.Errorf("cached: got %v, want %q", val2, "default")
	}
}
