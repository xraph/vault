package flag_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.opentelemetry.io/otel/codes"

	"github.com/xraph/vault"
	"github.com/xraph/vault/flag"
	"github.com/xraph/vault/internal/telemetry"
	"github.com/xraph/vault/internal/telemetrytest"
	"github.com/xraph/vault/store/memory"
)

func evals(source, result string) map[string]string {
	return map[string]string{"source": source, "result": result}
}

// A store read gets a span and counts as source=store; a cache hit gets
// neither a span nor a store count. Keys, tenants and users stay off both.
func TestEvaluateSpansAndMetrics(t *testing.T) {
	const (
		flagKey = "checkout-redesign-4c2d"
		tenant  = "tenant-acme-81f0"
		user    = "alice@example.com"
	)
	s := memory.New()
	defineFlag(t, s, flagKey, false, true)
	if err := s.SetFlagTenantOverride(bg(), flagKey, testApp, tenant, true); err != nil {
		t.Fatal(err)
	}

	rec := telemetrytest.Spans(t)
	sink := telemetrytest.NewSink()
	engine := flag.NewEngine(s, flag.WithCacheTTL(time.Minute), flag.WithMetrics(sink))

	ctx, parent := telemetry.Start(withTenantAndUser(tenant, user), "handle request")
	for range 2 {
		if v, err := engine.Evaluate(ctx, flagKey, testApp); err != nil || v != true {
			t.Fatalf("Evaluate = %v, %v", v, err)
		}
	}
	if _, err := engine.EvaluateDetail(ctx, flagKey, testApp); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Evaluate(ctx, "no-such-flag", testApp); !errors.Is(err, vault.ErrFlagNotFound) {
		t.Fatalf("Evaluate missing flag: %v", err)
	}
	parent.End()

	spans := telemetrytest.Named(rec, "evaluate flag")
	if len(spans) != 3 {
		t.Fatalf("got %d evaluate spans, want 3 (miss, detail, missing; the hit has none)", len(spans))
	}
	wants := []map[string]string{
		{"vault.flag.explain": "false", "vault.flag.found": "true", "vault.flag.reason": flag.ReasonTenantOverride},
		{"vault.flag.explain": "true", "vault.flag.found": "true", "vault.flag.reason": flag.ReasonTenantOverride},
		{"vault.flag.explain": "false", "vault.flag.found": "false"},
	}
	for i, want := range wants {
		sp := spans[i]
		if sp.Parent().SpanID() != parent.SpanContext().SpanID() {
			t.Errorf("span %d is not a child of the caller's span", i)
		}
		if sp.Status().Code == codes.Error {
			t.Errorf("span %d marked failed: %+v", i, sp.Status())
		}
		for k, v := range want {
			if got, _ := telemetrytest.Attr(sp, k); got != v {
				t.Errorf("span %d %s = %q, want %q", i, k, got, v)
			}
		}
	}

	for _, c := range []struct {
		labels map[string]string
		want   float64
	}{
		{evals("store", "ok"), 2},
		{evals("cache", "ok"), 1},
		{evals("store", "not_found"), 1},
	} {
		if got := sink.Count(telemetry.MetricFlagEvaluations, c.labels); got != c.want {
			t.Errorf("%v = %v, want %v", c.labels, got, c.want)
		}
	}

	telemetrytest.AssertNoLeak(t, rec, flagKey, tenant, user, testApp)
	sink.AssertNoLeak(t, flagKey, tenant, user, testApp)
}

type failingFlagStore struct{ *memory.Store }

var errFlagStoreDown = errors.New("flag store down: key checkout-redesign-4c2d")

func (failingFlagStore) GetFlagDefinition(context.Context, string, string) (*flag.Definition, error) {
	return nil, errFlagStoreDown
}

func TestEvaluateStoreFailureSpan(t *testing.T) {
	rec := telemetrytest.Spans(t)
	sink := telemetrytest.NewSink()
	engine := flag.NewEngine(failingFlagStore{memory.New()}, flag.WithMetrics(sink))

	if _, err := engine.Evaluate(bg(), "checkout-redesign-4c2d", testApp); err == nil {
		t.Fatal("Evaluate succeeded against a failing store")
	}
	spans := telemetrytest.Named(rec, "evaluate flag")
	if len(spans) != 1 {
		t.Fatalf("got %d evaluate spans, want 1", len(spans))
	}
	if st := spans[0].Status(); st.Code != codes.Error || st.Description != "*errors.errorString" {
		t.Errorf("status = %+v, want error \"*errors.errorString\"", st)
	}
	if sink.Count(telemetry.MetricFlagEvaluations, evals("store", "error")) != 1 {
		t.Error("the failed evaluation was not counted")
	}
	telemetrytest.AssertNoLeak(t, rec, "checkout-redesign-4c2d", "store down")
}

// Every reason the engine can reach shows up on the span as the same string
// Detail.Reason carries.
func TestEvaluateSpanReasons(t *testing.T) {
	const tenant = "tenant-initech-5c1a"
	s := memory.New()
	defineFlag(t, s, "flag-off", true, false)
	defineFlag(t, s, "flag-override", false, true)
	if err := s.SetFlagTenantOverride(bg(), "flag-override", testApp, tenant, true); err != nil {
		t.Fatal(err)
	}
	defineFlag(t, s, "flag-rule", false, true)
	rule := flag.WhenTenant(tenant).Return(true)
	rule.FlagKey, rule.AppID, rule.Priority = "flag-rule", testApp, 1
	if err := s.SetFlagRules(bg(), "flag-rule", testApp, []*flag.Rule{rule}); err != nil {
		t.Fatal(err)
	}
	defineFlag(t, s, "flag-default", false, true)

	rec := telemetrytest.Spans(t)
	sink := telemetrytest.NewSink()
	engine := flag.NewEngine(s, flag.WithMetrics(sink))
	ctx := withTenant(tenant)

	cases := []struct{ key, reason string }{
		{"flag-off", flag.ReasonDisabled},
		{"flag-override", flag.ReasonTenantOverride},
		{"flag-rule", flag.ReasonRule},
		{"flag-default", flag.ReasonDefault},
	}
	for _, c := range cases {
		if _, err := engine.Evaluate(ctx, c.key, testApp); err != nil {
			t.Fatalf("Evaluate(%s): %v", c.key, err)
		}
	}

	spans := telemetrytest.Named(rec, "evaluate flag")
	if len(spans) != len(cases) {
		t.Fatalf("got %d evaluate spans, want %d", len(spans), len(cases))
	}
	for i, c := range cases {
		if got, _ := telemetrytest.Attr(spans[i], "vault.flag.reason"); got != c.reason {
			t.Errorf("%s: vault.flag.reason = %q, want %q", c.key, got, c.reason)
		}
	}
	if got := sink.Count(telemetry.MetricFlagEvaluations, evals("store", "ok")); got != float64(len(cases)) {
		t.Errorf("store/ok = %v, want %d", got, len(cases))
	}
	telemetrytest.AssertNoLeak(t, rec, tenant, "flag-off", "flag-override", "flag-rule", "flag-default")
}
