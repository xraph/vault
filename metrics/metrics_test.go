package metrics_test

import (
	"sync"
	"testing"

	"github.com/xraph/vault/metrics"
)

// testCounter tracks inc/add calls for assertions.
type testCounter struct {
	mu    sync.Mutex
	count float64
}

func (c *testCounter) Inc()           { c.mu.Lock(); c.count++; c.mu.Unlock() }
func (c *testCounter) Add(v float64)  { c.mu.Lock(); c.count += v; c.mu.Unlock() }
func (c *testCounter) value() float64 { c.mu.Lock(); defer c.mu.Unlock(); return c.count }

// testHistogram tracks observed values.
type testHistogram struct {
	mu      sync.Mutex
	samples []float64
}

func (h *testHistogram) Observe(v float64) {
	h.mu.Lock()
	h.samples = append(h.samples, v)
	h.mu.Unlock()
}
func (h *testHistogram) count() int { h.mu.Lock(); defer h.mu.Unlock(); return len(h.samples) }

// testFactory creates test counters and histograms.
type testFactory struct {
	mu         sync.Mutex
	counters   map[string]*testCounter
	histograms map[string]*testHistogram
}

func newTestFactory() *testFactory {
	return &testFactory{
		counters:   make(map[string]*testCounter),
		histograms: make(map[string]*testHistogram),
	}
}

func (f *testFactory) Counter(name string) metrics.Counter {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := &testCounter{}
	f.counters[name] = c
	return c
}

func (f *testFactory) Histogram(name string) metrics.Histogram {
	f.mu.Lock()
	defer f.mu.Unlock()
	h := &testHistogram{}
	f.histograms[name] = h
	return h
}

func TestCollectorCreatesAllMetrics(t *testing.T) {
	f := newTestFactory()
	c := metrics.NewCollector(f)

	// All fields should be non-nil.
	if c.SecretAccessed == nil {
		t.Error("SecretAccessed is nil")
	}
	if c.SecretSet == nil {
		t.Error("SecretSet is nil")
	}
	if c.SecretDeleted == nil {
		t.Error("SecretDeleted is nil")
	}
	if c.SecretRotated == nil {
		t.Error("SecretRotated is nil")
	}
	if c.FlagEvaluated == nil {
		t.Error("FlagEvaluated is nil")
	}
	if c.FlagEvalTime == nil {
		t.Error("FlagEvalTime is nil")
	}
	if c.ConfigRead == nil {
		t.Error("ConfigRead is nil")
	}
	if c.ConfigWritten == nil {
		t.Error("ConfigWritten is nil")
	}
	if c.OverrideRead == nil {
		t.Error("OverrideRead is nil")
	}
	if c.AuditRecorded == nil {
		t.Error("AuditRecorded is nil")
	}
	if c.Encrypted == nil {
		t.Error("Encrypted is nil")
	}
	if c.Decrypted == nil {
		t.Error("Decrypted is nil")
	}
	if c.SourceLatency == nil {
		t.Error("SourceLatency is nil")
	}

	// Verify factory created the expected names.
	expectedCounters := []string{
		"vault_secret_accessed_total",
		"vault_secret_set_total",
		"vault_secret_deleted_total",
		"vault_secret_rotated_total",
		"vault_flag_evaluated_total",
		"vault_config_read_total",
		"vault_config_written_total",
		"vault_override_read_total",
		"vault_audit_recorded_total",
		"vault_encrypted_total",
		"vault_decrypted_total",
	}
	for _, name := range expectedCounters {
		if _, ok := f.counters[name]; !ok {
			t.Errorf("missing counter: %q", name)
		}
	}

	expectedHistograms := []string{
		"vault_flag_eval_duration_seconds",
		"vault_source_latency_seconds",
	}
	for _, name := range expectedHistograms {
		if _, ok := f.histograms[name]; !ok {
			t.Errorf("missing histogram: %q", name)
		}
	}
}

func TestCounterIncAndAdd(t *testing.T) {
	f := newTestFactory()
	c := metrics.NewCollector(f)

	c.SecretAccessed.Inc()
	c.SecretAccessed.Inc()
	c.SecretAccessed.Add(3)

	tc := f.counters["vault_secret_accessed_total"]
	if tc.value() != 5 {
		t.Errorf("counter: got %v, want 5", tc.value())
	}
}

func TestHistogramObserve(t *testing.T) {
	f := newTestFactory()
	c := metrics.NewCollector(f)

	c.FlagEvalTime.Observe(0.001)
	c.FlagEvalTime.Observe(0.005)

	th := f.histograms["vault_flag_eval_duration_seconds"]
	if th.count() != 2 {
		t.Errorf("histogram samples: got %d, want 2", th.count())
	}
}

func TestNoopCollector(_ *testing.T) {
	c := metrics.NewNoopCollector()

	// All operations should be safe (no-op).
	c.SecretAccessed.Inc()
	c.SecretAccessed.Add(10)
	c.FlagEvalTime.Observe(0.01)
	c.SourceLatency.Observe(0.5)
	c.Encrypted.Inc()
	c.Decrypted.Inc()
}

func TestNoopFactoryImplements(_ *testing.T) {
	var _ metrics.MetricFactory = metrics.NoopFactory{}
}
