package rotation_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/xraph/vault/internal/telemetry"
	"github.com/xraph/vault/internal/telemetrytest"
	"github.com/xraph/vault/rotation"
	"github.com/xraph/vault/store/memory"
)

const (
	leakKey      = "stripe-live-key-5d81"
	leakValue    = "rk_live_51HxQ-old-value-a7c3"
	leakNewValue = "rk_live_51HxQ-new-value-e4b9"
)

func rotations(trigger, result string) map[string]string {
	return map[string]string{"trigger": trigger, "result": result}
}

func TestRotateNowSpanAndMetrics(t *testing.T) {
	s := memory.New()
	svc := setupSecretService(t, s)
	seedSecret(t, svc, leakKey, []byte(leakValue))

	rec := telemetrytest.Spans(t)
	sink := telemetrytest.NewSink()
	mgr := rotation.NewManager(s, svc, rotation.WithAppID(testApp), rotation.WithMetrics(sink))
	mgr.RegisterRotator(leakKey, func(_ context.Context, _ []byte) ([]byte, error) {
		return []byte(leakNewValue), nil
	})

	ctx, parent := telemetry.Start(t.Context(), "handle request")
	if err := mgr.RotateNow(ctx, leakKey, ""); err != nil {
		t.Fatalf("RotateNow: %v", err)
	}
	parent.End()

	rot := telemetrytest.Named(rec, "rotate secret")
	if len(rot) != 1 {
		t.Fatalf("got %d rotate spans", len(rot))
	}
	if rot[0].Parent().SpanID() != parent.SpanContext().SpanID() {
		t.Error("a manual rotation is not a child of the caller's span")
	}
	if v, _ := telemetrytest.Attr(rot[0], "vault.rotation.trigger"); v != "manual" {
		t.Errorf("trigger = %q, want manual", v)
	}
	if rot[0].Status().Code == codes.Error {
		t.Errorf("successful rotation marked failed: %+v", rot[0].Status())
	}
	// The secret read and write nest inside the rotation.
	for _, name := range []string{"get secret", "set secret"} {
		got := telemetrytest.Named(rec, name)
		if len(got) != 1 || got[0].Parent().SpanID() != rot[0].SpanContext().SpanID() {
			t.Errorf("%s is not a child of the rotation span", name)
		}
	}

	if got := sink.Count(telemetry.MetricRotations, rotations("manual", "ok")); got != 1 {
		t.Errorf("manual/ok = %v, want 1", got)
	}
	if got := sink.Observations(telemetry.MetricRotationDuration, rotations("manual", "ok")); got != 1 {
		t.Errorf("duration observations = %d, want 1", got)
	}

	telemetrytest.AssertNoLeak(t, rec, leakKey, leakValue, leakNewValue)
	sink.AssertNoLeak(t, leakKey, leakValue, leakNewValue)
}

// A careless rotator puts the secret value and key in its error. The span
// names the failed step and the error's type, and nothing else.
func TestRotateNowFailureKeepsTheErrorOffTheSpan(t *testing.T) {
	s := memory.New()
	svc := setupSecretService(t, s)
	seedSecret(t, svc, leakKey, []byte(leakValue))

	rec := telemetrytest.Spans(t)
	sink := telemetrytest.NewSink()
	mgr := rotation.NewManager(s, svc, rotation.WithAppID(testApp), rotation.WithMetrics(sink))
	mgr.RegisterRotator(leakKey, func(_ context.Context, current []byte) ([]byte, error) {
		return nil, errors.New("provider refused " + leakKey + " old value " + string(current))
	})

	if err := mgr.RotateNow(t.Context(), leakKey, ""); err == nil {
		t.Fatal("RotateNow succeeded with a failing rotator")
	}
	if err := mgr.RotateNow(t.Context(), "no-rotator-"+leakKey, ""); err == nil {
		t.Fatal("RotateNow succeeded without a rotator")
	}

	rot := telemetrytest.Named(rec, "rotate secret")
	if len(rot) != 2 {
		t.Fatalf("got %d rotate spans, want 2", len(rot))
	}
	for i, want := range []string{"rotator failed", "no rotator registered"} {
		if st := rot[i].Status(); st.Code != codes.Error || st.Description != want {
			t.Errorf("span %d status = %+v, want error %q", i, st, want)
		}
	}
	if got := sink.Count(telemetry.MetricRotations, rotations("manual", "error")); got != 2 {
		t.Errorf("manual/error = %v, want 2", got)
	}

	telemetrytest.AssertNoLeak(t, rec, leakKey, leakValue, "provider refused")
	sink.AssertNoLeak(t, leakKey, leakValue)
}

// A pass that rotates gets its own root span, even when the loop's ctx
// carries a span; a pass with nothing due starts no span at all.
func TestScheduledPassSpans(t *testing.T) {
	s := memory.New()
	svc := setupSecretService(t, s)
	seedSecret(t, svc, leakKey, []byte(leakValue))

	rec := telemetrytest.Spans(t)
	sink := telemetrytest.NewSink()
	mgr := rotation.NewManager(s, svc, rotation.WithAppID(testApp), rotation.WithMetrics(sink))
	mgr.RegisterRotator(leakKey, func(_ context.Context, _ []byte) ([]byte, error) {
		return []byte(leakNewValue), nil
	})

	ctx, boot := telemetry.Start(t.Context(), "start vault")
	defer boot.End()

	// Nothing due yet.
	seedPolicy(t, s, leakKey, time.Hour, time.Now().Add(time.Hour))
	mgr.CheckDuePoliciesForTest(ctx)
	if n := len(rec.Ended()); n != 0 {
		t.Fatalf("an idle pass started %d spans", n)
	}

	seedPolicy(t, s, leakKey, time.Hour, time.Now().Add(-time.Minute))
	mgr.CheckDuePoliciesForTest(ctx)

	pass := telemetrytest.Named(rec, "rotate due secrets")
	if len(pass) != 1 {
		t.Fatalf("got %d pass spans, want 1", len(pass))
	}
	if pass[0].Parent().IsValid() {
		t.Error("the pass span hangs off the loop's ctx; it must be a root")
	}
	for k, want := range map[string]string{"vault.rotation.due": "1", "vault.rotation.claimed": "1", "vault.rotation.failed": "0"} {
		if v, _ := telemetrytest.Attr(pass[0], k); v != want {
			t.Errorf("%s = %q, want %q", k, v, want)
		}
	}
	rot := telemetrytest.Named(rec, "rotate secret")
	if len(rot) != 1 || rot[0].Parent().SpanID() != pass[0].SpanContext().SpanID() {
		t.Fatal("the rotation is not a child of the pass span")
	}
	if v, _ := telemetrytest.Attr(rot[0], "vault.rotation.trigger"); v != "scheduled" {
		t.Errorf("trigger = %q, want scheduled", v)
	}
	if got := sink.Count(telemetry.MetricRotations, rotations("scheduled", "ok")); got != 1 {
		t.Errorf("scheduled/ok = %v, want 1", got)
	}

	telemetrytest.AssertNoLeak(t, rec, leakKey, leakValue, leakNewValue)
}

// probeStore reports, for every policy list, whether the ctx it got carries a
// valid span: grove would start a db.client span under one.
type probeStore struct {
	*memory.Store
	listed chan bool
}

func (p probeStore) ListRotationPolicies(ctx context.Context, appID string) ([]*rotation.Policy, error) {
	select {
	case p.listed <- trace.SpanContextFromContext(ctx).IsValid():
	default:
	}
	return p.Store.ListRotationPolicies(ctx, appID)
}

// The loop outlives Start, so its idle list reads must not carry the span of
// whoever called Start (forge's "start vault" span, or a request's).
func TestLoopDropsTheCallersSpan(t *testing.T) {
	s := memory.New()
	probe := probeStore{Store: s, listed: make(chan bool, 1)}
	mgr := rotation.NewManager(probe, setupSecretService(t, s),
		rotation.WithAppID(testApp), rotation.WithCheckInterval(5*time.Millisecond))

	telemetrytest.Spans(t)
	ctx, boot := telemetry.Start(t.Context(), "start vault")
	if err := mgr.Start(ctx); err != nil {
		t.Fatal(err)
	}
	boot.End()
	defer func() {
		if err := mgr.Stop(t.Context()); err != nil {
			t.Error(err)
		}
	}()

	select {
	case valid := <-probe.listed:
		if valid {
			t.Error("the loop's policy list ran under the caller's span")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the loop never listed policies")
	}
}
