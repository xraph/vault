package flag_test

import (
	"strconv"
	"testing"
	"time"

	"github.com/xraph/vault/flag"
	"github.com/xraph/vault/store/memory"
)

// setRules is a local helper; engine_test.go's helpers are in the same
// package so defineFlag/bg/withTenant are already available.
func setRules(t *testing.T, s *memory.Store, key string, rules ...*flag.Rule) {
	t.Helper()
	for _, r := range rules {
		r.FlagKey = key
		r.AppID = testApp
	}
	if err := s.SetFlagRules(bg(), key, testApp, rules); err != nil {
		t.Fatalf("SetFlagRules(%q): %v", key, err)
	}
}

func TestDetailReasonDefaultNoRules(t *testing.T) {
	s := memory.New()
	defineFlag(t, s, "f", false, true)
	e := flag.NewEngine(s)

	d, err := e.EvaluateDetail(bg(), "f", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if d.Reason != flag.ReasonDefault {
		t.Errorf("reason: got %q, want %q", d.Reason, flag.ReasonDefault)
	}
	if d.Value != false {
		t.Errorf("value: got %v, want false", d.Value)
	}
	if d.MatchedRule != nil {
		t.Errorf("MatchedRule: got %v, want nil", d.MatchedRule)
	}
	if len(d.Trace) != 0 {
		t.Errorf("trace: got %d steps, want 0", len(d.Trace))
	}
}

func TestDetailReasonDisabledIgnoresTenantOverride(t *testing.T) {
	s := memory.New()
	defineFlag(t, s, "f", false, false) // disabled, default false
	if err := s.SetFlagTenantOverride(bg(), "f", testApp, "t-1", true); err != nil {
		t.Fatal(err)
	}
	e := flag.NewEngine(s)

	d, err := e.EvaluateDetail(withTenant("t-1"), "f", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if d.Reason != flag.ReasonDisabled {
		t.Errorf("reason: got %q, want %q", d.Reason, flag.ReasonDisabled)
	}
	if d.Value != false {
		t.Errorf("value: got %v, want false (the default, not the override)", d.Value)
	}
	if len(d.Trace) != 0 {
		t.Errorf("trace: got %d steps, want 0; a disabled flag consults nothing", len(d.Trace))
	}
}

func TestDetailReasonTenantOverride(t *testing.T) {
	s := memory.New()
	defineFlag(t, s, "f", false, true)
	if err := s.SetFlagTenantOverride(bg(), "f", testApp, "t-1", true); err != nil {
		t.Fatal(err)
	}
	e := flag.NewEngine(s)

	d, err := e.EvaluateDetail(withTenant("t-1"), "f", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if d.Reason != flag.ReasonTenantOverride {
		t.Errorf("reason: got %q, want %q", d.Reason, flag.ReasonTenantOverride)
	}
	if d.Value != true {
		t.Errorf("value: got %v, want true", d.Value)
	}
}

func TestDetailReasonRuleMarksLaterRulesUnreached(t *testing.T) {
	s := memory.New()
	defineFlag(t, s, "f", false, true)
	// WhenTenant and Rollout already assign Entity and ID.
	first := flag.WhenTenant("t-1").Return(true)
	first.Priority = 0
	second := flag.Rollout(100).Return(true)
	second.Priority = 1
	setRules(t, s, "f", first, second)
	e := flag.NewEngine(s)

	d, err := e.EvaluateDetail(withTenant("t-1"), "f", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if d.Reason != flag.ReasonRule {
		t.Fatalf("reason: got %q, want %q", d.Reason, flag.ReasonRule)
	}
	if d.MatchedRule == nil || d.MatchedRule.Type != flag.RuleWhenTenant {
		t.Fatalf("MatchedRule: got %v, want the when_tenant rule", d.MatchedRule)
	}
	if len(d.Trace) != 2 {
		t.Fatalf("trace: got %d steps, want 2", len(d.Trace))
	}
	if !d.Trace[0].Reached || !d.Trace[0].Matched {
		t.Errorf("trace[0]: got reached=%v matched=%v, want both true", d.Trace[0].Reached, d.Trace[0].Matched)
	}
	if d.Trace[1].Reached {
		t.Errorf("trace[1]: got reached=true, want false; the engine stopped at the first match")
	}
}

func TestDetailRolloutNoteReportsBucket(t *testing.T) {
	s := memory.New()
	defineFlag(t, s, "f", false, true)
	r := flag.Rollout(0).Return(true) // 0% so it never matches and we reach the note
	r.Priority = 0
	setRules(t, s, "f", r)
	e := flag.NewEngine(s)

	d, err := e.EvaluateDetail(withTenant("t-acme"), "f", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Trace) != 1 {
		t.Fatalf("trace: got %d steps, want 1", len(d.Trace))
	}
	// The note must quote the same bucket the verdict used, so the page
	// cannot disagree with the engine.
	want := "bucket " + itoa(int(flag.RolloutBucket("t-acme", "f"))) + " of 100, threshold 0"
	if d.Trace[0].Note != want {
		t.Errorf("note: got %q, want %q", d.Trace[0].Note, want)
	}
}

func TestDetailBypassesCacheWhileEvaluateUsesIt(t *testing.T) {
	s := memory.New()
	defineFlag(t, s, "f", false, true)
	e := flag.NewEngine(s, flag.WithCacheTTL(time.Hour))

	// Prime the cache through the hot path.
	if _, err := e.Evaluate(bg(), "f", testApp); err != nil {
		t.Fatal(err)
	}
	// Change the default underneath it.
	defineFlag(t, s, "f", true, true)

	cached, err := e.Evaluate(bg(), "f", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if cached != false {
		t.Errorf("Evaluate: got %v, want false (still cached)", cached)
	}

	d, err := e.EvaluateDetail(bg(), "f", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if d.Value != true {
		t.Errorf("EvaluateDetail: got %v, want true (cache bypassed)", d.Value)
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

// TestDetailTraceFollowsPriorityOrder proves that EvaluateDetail builds its
// trace in the order the engine evaluates rules, and that a priority-0 rule
// wins in the returned Detail. The rules are inserted worst-priority first
// so the assertion is meaningful; this does not test the store in isolation
// (m.flagRules is unexported, so an external test package cannot do that),
// it only tests EvaluateDetail's own trace and verdict.
func TestDetailTraceFollowsPriorityOrder(t *testing.T) {
	s := memory.New()
	defineFlag(t, s, "f", "default", true)

	// Inserted worst-priority first, on purpose.
	low := flag.WhenTenant("t-1").Return("low")
	low.Priority = 10
	high := flag.WhenTenant("t-1").Return("high")
	high.Priority = 0
	setRules(t, s, "f", low, high)

	e := flag.NewEngine(s)
	d, err := e.EvaluateDetail(withTenant("t-1"), "f", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if d.Value != "high" {
		t.Errorf("got %v, want \"high\"; priority 0 must win over priority 10 regardless of insertion order", d.Value)
	}
	if len(d.Trace) == 0 || d.Trace[0].Priority != 0 {
		t.Errorf("trace starts at priority %v, want 0", d.Trace)
	}
}
