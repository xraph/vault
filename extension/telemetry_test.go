package extension

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xraph/forge"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/xraph/vault"
	"github.com/xraph/vault/flag"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/internal/telemetry"
	"github.com/xraph/vault/internal/telemetrytest"
	"github.com/xraph/vault/store/memory"
)

func scrape(t *testing.T, app forge.App) string {
	t.Helper()
	p, ok := app.Metrics().(interface{ PrometheusHandler() http.Handler })
	if !ok {
		t.Fatalf("app metrics %T have no Prometheus handler", app.Metrics())
	}
	rr := httptest.NewRecorder()
	p.PrometheusHandler().ServeHTTP(rr, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/_/metrics", nil))
	body, err := io.ReadAll(rr.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func seriesLines(body, prefix string) []string {
	var out []string
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, prefix+"{") {
			out = append(out, line)
		}
	}
	return out
}

func hasSeries(lines []string, wantLabels ...string) bool {
	for _, line := range lines {
		all := true
		for _, l := range wantLabels {
			if !strings.Contains(line, l) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

// TestExtensionWiresTelemetryIntoForge registers the extension on a real
// forge app and checks that vault's spans reach forge's tracer provider and
// its metrics land on /_/metrics under their forge_ names.
func TestExtensionWiresTelemetryIntoForge(t *testing.T) {
	const (
		secretName  = "smtp-relay-password-0b5e"
		secretValue = "p4ss-smtp-value-1d7f"
		flagKey     = "dark-mode-3a90"
	)
	prevTP, prevProp := otel.GetTracerProvider(), otel.GetTextMapPropagator()
	t.Cleanup(func() {
		otel.SetTracerProvider(prevTP)
		otel.SetTextMapPropagator(prevProp)
	})

	app := forge.New(forge.WithAppName("vault-telemetry-test"), forge.WithAppLogger(forge.NewNoopLogger()))
	rec := tracetest.NewSpanRecorder()
	if err := forge.RegisterSpanProcessor(app, rec); err != nil {
		t.Fatalf("RegisterSpanProcessor: %v", err)
	}

	st := memory.New()
	ext := New(
		WithStore(st),
		WithAppID("app1"),
		WithVaultOption(vault.WithEncryptionKey(mustTestKey(t))),
	)
	if err := ext.Register(app); err != nil {
		t.Fatalf("Register: %v", err)
	}
	v := ext.Vault()

	ctx, span := forge.StartSpan(t.Context(), "handle request")
	if _, err := v.Secrets().Set(ctx, secretName, []byte(secretValue), ""); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, err := v.Secrets().Get(ctx, secretName, ""); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if err := st.DefineFlag(ctx, &flag.Definition{
		Entity: vault.NewEntity(), ID: id.NewFlagID(), Key: flagKey, Type: flag.TypeBool,
		DefaultValue: true, Enabled: true, AppID: "app1",
	}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := v.FlagEngine().Evaluate(ctx, flagKey, "app1"); err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
	}
	span.End()

	var names []string
	for _, s := range rec.Ended() {
		if s.InstrumentationScope().Name != telemetry.ScopeName {
			continue
		}
		names = append(names, s.Name())
		if s.Parent().SpanID() != span.SpanContext().SpanID() {
			t.Errorf("%s is not a child of the request span", s.Name())
		}
	}
	if got := strings.Join(names, ","); got != "set secret,get secret,evaluate flag" {
		t.Errorf("vault spans = %s", got)
	}

	// A manual rotation, so the duration histogram the docs query has a
	// series on the scrape.
	v.Rotation().RegisterRotator(secretName, func(_ context.Context, _ []byte) ([]byte, error) {
		return []byte(secretValue + "-rotated"), nil
	})
	if err := v.Rotation().RotateNow(t.Context(), secretName, ""); err != nil {
		t.Fatalf("RotateNow: %v", err)
	}

	body := scrape(t, app)
	ops := seriesLines(body, "forge_"+telemetry.MetricSecretOperations)
	// One get and one set each from the request, and one each from the
	// rotation, which reads the current value and writes the new one.
	if !hasSeries(ops, `op="set"`, `result="ok"`, "} 2") || !hasSeries(ops, `op="get"`, `result="ok"`, "} 2") {
		t.Errorf("secret operation series:\n%s", strings.Join(ops, "\n"))
	}
	cryptoOps := seriesLines(body, "forge_"+telemetry.MetricCryptoOperations)
	if !hasSeries(cryptoOps, `op="encrypt"`, `result="ok"`) || !hasSeries(cryptoOps, `op="decrypt"`, `result="ok"`) {
		t.Errorf("crypto series:\n%s", strings.Join(cryptoOps, "\n"))
	}
	flags := seriesLines(body, "forge_"+telemetry.MetricFlagEvaluations)
	if !hasSeries(flags, `source="store"`, `result="ok"`, "} 1") || !hasSeries(flags, `source="cache"`, `result="ok"`, "} 1") {
		t.Errorf("flag series:\n%s", strings.Join(flags, "\n"))
	}

	rotations := seriesLines(body, "forge_"+telemetry.MetricRotations)
	if !hasSeries(rotations, `trigger="manual"`, `result="ok"`, "} 1") {
		t.Errorf("rotation series:\n%s", strings.Join(rotations, "\n"))
	}
	buckets := seriesLines(body, "forge_"+telemetry.MetricRotationDuration+"_bucket")
	if len(buckets) != len(telemetry.RotationDurationBuckets)+1 {
		t.Errorf("got %d rotation duration buckets, want %d:\n%s",
			len(buckets), len(telemetry.RotationDurationBuckets)+1, strings.Join(buckets, "\n"))
	}
	if !hasSeries(buckets, `le="300"`, `trigger="manual"`, `result="ok"`, "} 1") ||
		!hasSeries(buckets, `le="+Inf"`, `trigger="manual"`, `result="ok"`, "} 1") {
		t.Errorf("rotation duration buckets:\n%s", strings.Join(buckets, "\n"))
	}
	if count := seriesLines(body, "forge_"+telemetry.MetricRotationDuration+"_count"); !hasSeries(count, `trigger="manual"`, "} 1") {
		t.Errorf("rotation duration count:\n%s", strings.Join(count, "\n"))
	}

	for _, needle := range []string{secretName, secretValue, flagKey} {
		if strings.Contains(body, needle) {
			t.Errorf("the scrape carries %q", needle)
		}
	}
	telemetrytest.AssertNoLeak(t, rec, secretName, secretValue, flagKey, "app1")
}

// A vault.WithMetrics you pass through WithVaultOption wins over the app's
// metrics, which the extension puts first.
func TestYourOwnWithMetricsWins(t *testing.T) {
	prevTP, prevProp := otel.GetTracerProvider(), otel.GetTextMapPropagator()
	t.Cleanup(func() {
		otel.SetTracerProvider(prevTP)
		otel.SetTextMapPropagator(prevProp)
	})

	app := forge.New(forge.WithAppName("vault-own-metrics-test"), forge.WithAppLogger(forge.NewNoopLogger()))
	sink := telemetrytest.NewSink()
	ext := New(WithStore(memory.New()), WithAppID("app1"), WithVaultOption(vault.WithMetrics(sink)))
	if err := ext.Register(app); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := ext.Vault().Secrets().Set(t.Context(), "k", []byte("v"), ""); err != nil {
		t.Fatalf("Set: %v", err)
	}

	if got := sink.Count(telemetry.MetricSecretOperations, map[string]string{"op": "set", "result": "ok"}); got != 1 {
		t.Errorf("your sink saw %v sets, want 1", got)
	}
	if lines := seriesLines(scrape(t, app), "forge_"+telemetry.MetricSecretOperations); len(lines) != 0 {
		t.Errorf("the app's metrics recorded too:\n%s", strings.Join(lines, "\n"))
	}
}
