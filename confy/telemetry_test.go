package confy_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/xraph/vault"
	"github.com/xraph/vault/config"
	vaultconfy "github.com/xraph/vault/confy"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/internal/telemetry"
	"github.com/xraph/vault/internal/telemetrytest"
	"github.com/xraph/vault/store/memory"
)

const (
	leakConfigKey   = "billing.webhook-signing-key-2e6c"
	leakConfigValue = "whsec-config-value-c0d4"
)

func polls(result string) map[string]string {
	return map[string]string{"source": "confy", "result": result}
}

type brokenConfigStore struct{ *memory.Store }

func (brokenConfigStore) ListConfig(context.Context, string, config.ListOpts) ([]*config.Entry, error) {
	return nil, errors.New("list " + leakConfigKey + " failed")
}

// Only a poll that finds a change starts a span, and it starts its own trace
// rather than join the span of whoever called Watch.
func TestPollSpansAndMetrics(t *testing.T) {
	store := memory.New()
	rec := telemetrytest.Spans(t)
	sink := telemetrytest.NewSink()
	src := vaultconfy.NewVaultConfigSource(store, newSecretsReader(store), "app1", vaultconfy.WithSourceMetrics(sink))
	ctx, watcher := telemetry.Start(t.Context(), "start confy")
	defer watcher.End()

	var calls int
	notify := func(map[string]any) { calls++ }

	src.PollForTest(ctx, notify)
	if n := len(rec.Ended()); n != 0 {
		t.Fatalf("an idle poll started %d spans", n)
	}

	if err := store.SetConfig(bg(), &config.Entry{
		Entity: vault.NewEntity(), ID: id.NewConfigID(), Key: leakConfigKey, Value: leakConfigValue, AppID: "app1",
	}); err != nil {
		t.Fatal(err)
	}
	src.PollForTest(ctx, notify)
	src.PollForTest(ctx, notify)

	spans := telemetrytest.Named(rec, "notify config watchers")
	if len(spans) != 1 || calls != 1 {
		t.Fatalf("spans = %d, callbacks = %d, want 1 and 1", len(spans), calls)
	}
	if spans[0].Parent().IsValid() {
		t.Error("the notify span hangs off the Watch caller's span; it must be a root")
	}
	for k, want := range map[string]string{"vault.config.source": "confy", "vault.config.changed": "1"} {
		if v, _ := telemetrytest.Attr(spans[0], k); v != want {
			t.Errorf("%s = %q, want %q", k, v, want)
		}
	}

	broken := vaultconfy.NewVaultConfigSource(brokenConfigStore{store}, nil, "app1", vaultconfy.WithSourceMetrics(sink))
	broken.PollForTest(ctx, notify)

	for result, want := range map[string]float64{"unchanged": 2, "changed": 1, "error": 1} {
		if got := sink.Count(telemetry.MetricConfigPolls, polls(result)); got != want {
			t.Errorf("result=%s = %v, want %v", result, got, want)
		}
	}
	telemetrytest.AssertNoLeak(t, rec, leakConfigKey, leakConfigValue, "app1")
	sink.AssertNoLeak(t, leakConfigKey, leakConfigValue, "app1")
}

// probeConfigStore reports, for every list, whether the ctx it got carries a
// valid span: grove would start a db.client span under one.
type probeConfigStore struct {
	*memory.Store
	listed chan bool
}

func (p probeConfigStore) ListConfig(ctx context.Context, appID string, opts config.ListOpts) ([]*config.Entry, error) {
	select {
	case p.listed <- trace.SpanContextFromContext(ctx).IsValid():
	default:
	}
	return p.Store.ListConfig(ctx, appID, opts)
}

// The watch loop outlives Watch, so its idle polls must not carry the span
// of whoever called Watch.
func TestWatchLoopDropsTheCallersSpan(t *testing.T) {
	store := memory.New()
	probe := probeConfigStore{Store: store, listed: make(chan bool, 1)}
	src := vaultconfy.NewVaultConfigSource(probe, nil, "app1", vaultconfy.WithSourcePollInterval(5*time.Millisecond))

	telemetrytest.Spans(t)
	ctx, caller := telemetry.Start(t.Context(), "start confy")
	if err := src.Watch(ctx, func(map[string]any) {}); err != nil {
		t.Fatal(err)
	}
	caller.End()
	defer func() {
		if err := src.StopWatch(); err != nil {
			t.Error(err)
		}
	}()

	select {
	case valid := <-probe.listed:
		if valid {
			t.Error("an idle poll ran under the Watch caller's span")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the watch loop never polled")
	}
}
