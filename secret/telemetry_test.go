package secret_test

import (
	"errors"
	"testing"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/xraph/vault"
	"github.com/xraph/vault/internal/telemetry"
	"github.com/xraph/vault/internal/telemetrytest"
	"github.com/xraph/vault/secret"
	"github.com/xraph/vault/store/memory"
)

// Recognisable enough that a substring match can't hit by accident.
const (
	leakKey   = "payments-db-password-7f3a"
	leakValue = "hunter2-correct-horse-9b1e"
)

func secretOps(op, result string) map[string]string {
	return map[string]string{"op": op, "result": result}
}

func TestSecretServiceSpansAndMetrics(t *testing.T) {
	rec := telemetrytest.Spans(t)
	sink := telemetrytest.NewSink()
	svc := secret.NewService(memory.New(), encryptorWithKey(t, 1),
		secret.WithAppID("app1"), secret.WithMetrics(sink))

	ctx, parent := telemetry.Start(t.Context(), "handle request")
	if _, err := svc.Set(ctx, leakKey, []byte(leakValue), ""); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, err := svc.Get(ctx, leakKey, ""); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := svc.GetVersion(ctx, leakKey, "", 1); err != nil {
		t.Fatalf("GetVersion: %v", err)
	}
	if err := svc.Delete(ctx, leakKey, ""); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := svc.Get(ctx, leakKey, ""); !errors.Is(err, vault.ErrSecretNotFound) {
		t.Fatalf("Get after delete: %v", err)
	}
	parent.End()

	want := []struct {
		name  string
		attrs map[string]string
	}{
		{"set secret", map[string]string{"vault.secret.encrypted": "true"}},
		{"get secret", map[string]string{"vault.secret.found": "true", "vault.secret.encrypted": "true"}},
		{"get secret version", map[string]string{"vault.secret.found": "true", "vault.secret.encrypted": "true"}},
		{"delete secret", map[string]string{"vault.secret.found": "true"}},
		{"get secret", map[string]string{"vault.secret.found": "false"}},
	}
	spans := rec.Ended()
	if len(spans) != len(want)+1 {
		t.Fatalf("got %d spans, want %d", len(spans), len(want)+1)
	}
	for i, w := range want {
		s := spans[i]
		if s.Name() != w.name {
			t.Errorf("span %d = %q, want %q", i, s.Name(), w.name)
			continue
		}
		if s.SpanKind() != trace.SpanKindInternal {
			t.Errorf("%s kind = %v", s.Name(), s.SpanKind())
		}
		if s.Parent().SpanID() != parent.SpanContext().SpanID() {
			t.Errorf("%s is not a child of the caller's span", s.Name())
		}
		if s.Status().Code == codes.Error {
			t.Errorf("%s marked failed: %+v", s.Name(), s.Status())
		}
		for k, v := range w.attrs {
			if got, ok := telemetrytest.Attr(s, k); !ok || got != v {
				t.Errorf("%s %s = %q (present %v), want %q", s.Name(), k, got, ok, v)
			}
		}
	}

	for _, c := range [][2]string{
		{"set", "ok"}, {"get", "ok"}, {"get_version", "ok"}, {"delete", "ok"}, {"get", "not_found"},
	} {
		if got := sink.Count(telemetry.MetricSecretOperations, secretOps(c[0], c[1])); got != 1 {
			t.Errorf("op=%s result=%s = %v, want 1", c[0], c[1], got)
		}
	}
	if n := len(sink.LabelSets(telemetry.MetricSecretOperations)); n != 5 {
		t.Errorf("%d secret operation series, want 5", n)
	}
	if got := sink.Count(telemetry.MetricCryptoOperations, secretOps("encrypt", "ok")); got != 1 {
		t.Errorf("encrypt ok = %v, want 1", got)
	}
	if got := sink.Count(telemetry.MetricCryptoOperations, secretOps("decrypt", "ok")); got != 2 {
		t.Errorf("decrypt ok = %v, want 2", got)
	}

	telemetrytest.AssertNoLeak(t, rec, leakKey, leakValue, "app1")
	sink.AssertNoLeak(t, leakKey, leakValue, "app1")
}

// A row sealed with another key fails to decrypt. The span says so without
// the error text, which names the key.
func TestSecretDecryptFailureSpan(t *testing.T) {
	store := memory.New()
	writer := secret.NewService(store, encryptorWithKey(t, 1), secret.WithAppID("app1"))
	if _, err := writer.Set(t.Context(), leakKey, []byte(leakValue), ""); err != nil {
		t.Fatalf("Set: %v", err)
	}

	rec := telemetrytest.Spans(t)
	sink := telemetrytest.NewSink()
	reader := secret.NewService(store, encryptorWithKey(t, 2), secret.WithAppID("app1"), secret.WithMetrics(sink))
	if _, err := reader.Get(t.Context(), leakKey, ""); err == nil {
		t.Fatal("Get with the wrong key succeeded")
	}

	got := telemetrytest.Named(rec, "get secret")
	if len(got) != 1 {
		t.Fatalf("got %d get spans", len(got))
	}
	if st := got[0].Status(); st.Code != codes.Error || st.Description != "decrypt failed" {
		t.Errorf("status = %+v, want error \"decrypt failed\"", st)
	}
	if sink.Count(telemetry.MetricCryptoOperations, secretOps("decrypt", "error")) != 1 {
		t.Error("the failed decrypt was not counted")
	}
	if sink.Count(telemetry.MetricSecretOperations, secretOps("get", "error")) != 1 {
		t.Error("the failed get was not counted")
	}
	telemetrytest.AssertNoLeak(t, rec, leakKey, leakValue)
}

func TestBackfillSpan(t *testing.T) {
	configured := encryptorWithKey(t, 1)
	st := newLegacyStore()
	sealed, err := configured.Encrypt([]byte(leakValue))
	if err != nil {
		t.Fatal(err)
	}
	st.add("app1", sealed)
	st.add("app1", []byte("just plaintext"))

	rec := telemetrytest.Spans(t)
	svc := secret.NewService(st, configured, secret.WithAppID("app1"))
	if _, err := svc.BackfillVersionEncryption(t.Context()); err != nil {
		t.Fatal(err)
	}

	got := telemetrytest.Named(rec, "backfill version encryption")
	if len(got) != 1 {
		t.Fatalf("got %d backfill spans", len(got))
	}
	for k, want := range map[string]string{"vault.backfill.scanned": "2", "vault.backfill.marked": "1"} {
		if v, _ := telemetrytest.Attr(got[0], k); v != want {
			t.Errorf("%s = %q, want %q", k, v, want)
		}
	}

	// No key, nothing to prove, no span.
	rec = telemetrytest.Spans(t)
	if _, err := secret.NewService(st, nil, secret.WithAppID("app1")).BackfillVersionEncryption(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := len(rec.Ended()); n != 0 {
		t.Errorf("a keyless backfill started %d spans", n)
	}
	telemetrytest.AssertNoLeak(t, rec, leakValue)
}
