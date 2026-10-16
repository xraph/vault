// Package telemetry is vault's tracing and metrics plumbing: the
// instrumentation scope on every vault span, a way to mark a span failed
// that never copies error text, and label vectors over a go-utils metrics
// sink.
//
// Nothing here ever takes a secret value, a secret, flag or config key, a
// tenant or a user. Span attributes are counts, booleans and fixed enums, and
// metric labels are fixed enums. Error text stays off spans because store and
// rotator errors quote keys and, from a careless rotator, values.
package telemetry

import (
	"context"
	"errors"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/xraph/vault/core"
)

// ScopeName is the instrumentation scope on every span vault starts.
const ScopeName = "github.com/xraph/vault"

// Start starts an internal span on the global tracer provider, which
// forge.New installs. It looks the tracer up on every call, so a provider
// installed after vault was built still gets the spans.
func Start(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	opts = append(opts, trace.WithSpanKind(trace.SpanKindInternal))
	return otel.GetTracerProvider().Tracer(ScopeName).Start(ctx, name, opts...)
}

// StartRoot starts a span that begins its own trace, whatever span ctx
// carries. Background work uses it: a poll loop's ctx can carry the span of
// the call that started the loop, and every later tick would otherwise hang
// off that long-finished trace.
func StartRoot(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return Start(ctx, name, append(opts, trace.WithNewRoot())...)
}

// Detach returns ctx without its span, keeping its values and its
// cancellation. A long-lived loop calls it once on the ctx it was handed:
// that ctx can carry forge's "start <ext>" span or a request's server span,
// and grove starts a db.client span under any valid span context, even an
// ended one. Without Detach every idle tick's query would land in that old
// trace.
func Detach(ctx context.Context) context.Context {
	return trace.ContextWithSpanContext(ctx, trace.SpanContext{})
}

// Fail marks span as failed. The status description and the exception
// event's exception.type are both ErrorType(err), never err.Error().
func Fail(span trace.Span, err error) {
	FailAs(span, "", err)
}

// FailAs is Fail with the status description set to class, a short name for
// the step that failed, such as "decrypt failed". An empty class means
// ErrorType(err). The exception event still carries ErrorType(err).
func FailAs(span trace.Span, class string, err error) {
	t := ErrorType(err)
	if class == "" {
		class = t
	}
	span.SetStatus(codes.Error, class)
	span.AddEvent("exception", trace.WithAttributes(attribute.String("exception.type", t)))
}

// sentinels are the vault errors ErrorType names. The first match wins, so
// a specific error comes before a general one it may wrap.
var sentinels = []struct {
	err  error
	name string
}{
	{core.ErrDecryptionFailed, "ErrDecryptionFailed"},
	{core.ErrEncryptionFailed, "ErrEncryptionFailed"},
	{core.ErrInvalidKey, "ErrInvalidKey"},
	{core.ErrSecretNotFound, "ErrSecretNotFound"},
	{core.ErrFlagNotFound, "ErrFlagNotFound"},
	{core.ErrConfigNotFound, "ErrConfigNotFound"},
	{core.ErrOverrideNotFound, "ErrOverrideNotFound"},
	{core.ErrRotationNotFound, "ErrRotationNotFound"},
	{core.ErrKeyNotFound, "ErrKeyNotFound"},
	{core.ErrRotationFailed, "ErrRotationFailed"},
	{core.ErrNoStore, "ErrNoStore"},
	{context.Canceled, "context.Canceled"},
	{context.DeadlineExceeded, "context.DeadlineExceeded"},
}

// ErrorType names err without quoting it: a vault sentinel's name when err
// wraps one, otherwise the Go type of the innermost error in the chain.
func ErrorType(err error) string {
	if err == nil {
		return ""
	}
	for _, s := range sentinels {
		if errors.Is(err, s.err) {
			return s.name
		}
	}
	for {
		next := errors.Unwrap(err)
		if next == nil {
			return fmt.Sprintf("%T", err)
		}
		err = next
	}
}
