package telemetry_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/xraph/vault/core"
	"github.com/xraph/vault/internal/telemetry"
	"github.com/xraph/vault/internal/telemetrytest"
)

type driverError struct{ msg string }

func (e *driverError) Error() string { return e.msg }

func TestErrorTypeNamesWithoutQuoting(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ""},
		{"sentinel", core.ErrSecretNotFound, "ErrSecretNotFound"},
		{"wrapped sentinel", fmt.Errorf("secret: decrypt %q: %w", "db-password", core.ErrDecryptionFailed), "ErrDecryptionFailed"},
		{"context", fmt.Errorf("list: %w", context.DeadlineExceeded), "context.DeadlineExceeded"},
		{"innermost type", fmt.Errorf("outer %q: %w", "db-password", &driverError{"value s3cr3t rejected"}), "*telemetry_test.driverError"},
		{"plain", errors.New("value s3cr3t rejected"), "*errors.errorString"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := telemetry.ErrorType(tc.err); got != tc.want {
				t.Errorf("ErrorType = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFailRecordsOnlyTheType(t *testing.T) {
	rec := telemetrytest.Spans(t)

	_, span := telemetry.Start(t.Context(), "do thing")
	telemetry.Fail(span, fmt.Errorf("store %q: %w", "db-password", &driverError{"value s3cr3t rejected"}))
	span.End()

	_, span = telemetry.Start(t.Context(), "do other thing")
	telemetry.FailAs(span, "rotator failed", errors.New("s3cr3t"))
	span.End()

	spans := rec.Ended()
	if len(spans) != 2 {
		t.Fatalf("got %d spans, want 2", len(spans))
	}
	first := spans[0]
	if first.SpanKind() != trace.SpanKindInternal {
		t.Errorf("kind = %v, want internal", first.SpanKind())
	}
	if first.InstrumentationScope().Name != telemetry.ScopeName {
		t.Errorf("scope = %q, want %q", first.InstrumentationScope().Name, telemetry.ScopeName)
	}
	if first.Status().Code != codes.Error || first.Status().Description != "*telemetry_test.driverError" {
		t.Errorf("status = %+v", first.Status())
	}
	if len(first.Events()) != 1 || first.Events()[0].Name != "exception" {
		t.Fatalf("events = %+v", first.Events())
	}
	if attrs := first.Events()[0].Attributes; len(attrs) != 1 || attrs[0].Key != "exception.type" {
		t.Errorf("exception attributes = %+v, want exception.type alone", attrs)
	}
	if spans[1].Status().Description != "rotator failed" {
		t.Errorf("FailAs status = %q", spans[1].Status().Description)
	}
	telemetrytest.AssertNoLeak(t, rec, "db-password", "s3cr3t")
}

func TestStartRootIgnoresTheParent(t *testing.T) {
	rec := telemetrytest.Spans(t)

	ctx, parent := telemetry.Start(t.Context(), "boot")
	_, child := telemetry.StartRoot(ctx, "poll")
	child.End()
	parent.End()

	poll := telemetrytest.Named(rec, "poll")
	if len(poll) != 1 {
		t.Fatalf("got %d poll spans", len(poll))
	}
	if poll[0].Parent().IsValid() {
		t.Error("a root span has a parent")
	}
	if poll[0].SpanContext().TraceID() == parent.SpanContext().TraceID() {
		t.Error("a root span joined its caller's trace")
	}
}

func TestNilInstrumentsRecordNothing(t *testing.T) {
	c := telemetry.NewCounter(nil, "x_total", "", "result")
	h := telemetry.NewHistogram(nil, "x_seconds", "", nil, "result")
	if c != nil || h != nil {
		t.Fatal("a nil sink built instruments")
	}
	c.Inc("ok")
	h.Observe(1, "ok")
}

func TestCounterAndHistogramLabels(t *testing.T) {
	sink := telemetrytest.NewSink()
	c := telemetry.NewCounter(sink, "vault_things_done_total", "help", "op", "result")
	h := telemetry.NewHistogram(sink, "vault_thing_duration_seconds", "help", []float64{1}, "op")

	c.Inc("get", "ok")
	c.Inc("get", "ok")
	c.Inc("get", "error")
	c.Inc("wrong arity")
	h.Observe(0.5, "get")

	if got := sink.Count("vault_things_done_total", map[string]string{"op": "get", "result": "ok"}); got != 2 {
		t.Errorf("get/ok = %v, want 2", got)
	}
	if got := sink.Count("vault_things_done_total", map[string]string{"op": "get", "result": "error"}); got != 1 {
		t.Errorf("get/error = %v, want 1", got)
	}
	if got := len(sink.LabelSets("vault_things_done_total")); got != 2 {
		t.Errorf("series = %d, want 2: a wrong-arity call must not add one", got)
	}
	if got := sink.Observations("vault_thing_duration_seconds", map[string]string{"op": "get"}); got != 1 {
		t.Errorf("observations = %d, want 1", got)
	}
}

type ctxKey struct{}

func TestDetachDropsOnlyTheSpan(t *testing.T) {
	telemetrytest.Spans(t)
	parent, cancel := context.WithCancel(context.WithValue(t.Context(), ctxKey{}, "kept"))
	ctx, span := telemetry.Start(parent, "start vault")
	span.End()

	detached := telemetry.Detach(ctx)
	if trace.SpanContextFromContext(detached).IsValid() {
		t.Error("Detach kept the span")
	}
	if detached.Value(ctxKey{}) != "kept" {
		t.Error("Detach lost a value")
	}
	cancel()
	if detached.Err() == nil {
		t.Error("Detach lost the cancellation")
	}
}
