package source_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/xraph/vault"
	"github.com/xraph/vault/config"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/internal/telemetry"
	"github.com/xraph/vault/internal/telemetrytest"
	"github.com/xraph/vault/source"
	"github.com/xraph/vault/store/memory"
)

const (
	leakConfigKey   = "billing.webhook-signing-key-2e6c"
	leakConfigValue = "whsec-config-value-c0d4"
)

func dbPolls(result string) map[string]string {
	return map[string]string{"source": "database", "result": result}
}

// flakyConfigStore fails GetConfig while down is set.
type flakyConfigStore struct {
	*memory.Store
	down bool
}

func (f *flakyConfigStore) GetConfig(ctx context.Context, key, appID string) (*config.Entry, error) {
	if f.down {
		return nil, errors.New("read " + key + " failed")
	}
	return f.Store.GetConfig(ctx, key, appID)
}

func setConfig(t *testing.T, s *memory.Store, value string) {
	t.Helper()
	if err := s.SetConfig(t.Context(), &config.Entry{
		Entity: vault.NewEntity(), ID: id.NewConfigID(), Key: leakConfigKey, Value: value, AppID: "app1",
	}); err != nil {
		t.Fatal(err)
	}
}

// A poll that finds a change runs the watchers under a root span and hands
// them its context; an idle poll starts no span.
func TestDatabasePollSpansAndMetrics(t *testing.T) {
	mem := memory.New()
	setConfig(t, mem, "v1")
	store := &flakyConfigStore{Store: mem}

	rec := telemetrytest.Spans(t)
	sink := telemetrytest.NewSink()
	// The loop Watch starts never ticks; the test polls by hand.
	db := source.NewDatabase(store, "app1", source.WithPollInterval(time.Hour), source.WithMetrics(sink))
	defer db.Close()

	ctx, watcher := telemetry.Start(t.Context(), "start watcher")
	defer watcher.End()

	var watcherSpan trace.SpanID
	calls := 0
	if err := db.Watch(ctx, leakConfigKey, func(cbCtx context.Context, _ string, _ *source.Value) {
		calls++
		watcherSpan = trace.SpanContextFromContext(cbCtx).SpanID()
	}); err != nil {
		t.Fatal(err)
	}

	db.PollOnceForTest(ctx)
	if n := len(rec.Ended()); n != 0 {
		t.Fatalf("an idle poll started %d spans", n)
	}

	setConfig(t, mem, leakConfigValue)
	db.PollOnceForTest(ctx)

	spans := telemetrytest.Named(rec, "notify config watchers")
	if len(spans) != 1 || calls != 1 {
		t.Fatalf("spans = %d, callbacks = %d, want 1 and 1", len(spans), calls)
	}
	if spans[0].Parent().IsValid() {
		t.Error("the notify span hangs off the Watch caller's span; it must be a root")
	}
	if spans[0].SpanContext().SpanID() != watcherSpan {
		t.Error("the watcher did not get the notify span's context")
	}
	for k, want := range map[string]string{"vault.config.source": "database", "vault.config.changed": "1"} {
		if v, _ := telemetrytest.Attr(spans[0], k); v != want {
			t.Errorf("%s = %q, want %q", k, v, want)
		}
	}

	store.down = true
	db.PollOnceForTest(ctx)

	for result, want := range map[string]float64{"unchanged": 1, "changed": 1, "error": 1} {
		if got := sink.Count(telemetry.MetricConfigPolls, dbPolls(result)); got != want {
			t.Errorf("result=%s = %v, want %v", result, got, want)
		}
	}
	telemetrytest.AssertNoLeak(t, rec, leakConfigKey, leakConfigValue, "app1")
	sink.AssertNoLeak(t, leakConfigKey, leakConfigValue, "app1")
}
