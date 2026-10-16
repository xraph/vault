package telemetry

import (
	"strings"
	"sync"

	gometrics "github.com/xraph/go-utils/metrics"
)

// The metric names vault records. A Forge app scrapes each one with its
// namespace prefix, so vault_rotations_attempted_total appears as
// forge_vault_rotations_attempted_total.
const (
	// MetricSecretOperations counts secret service calls.
	// Labels: op (get, get_version, set, delete), result (ok, not_found, error).
	MetricSecretOperations = "vault_secret_operations_attempted_total"

	// MetricCryptoOperations counts AES-GCM encrypt and decrypt calls the
	// secret service makes. Labels: op (encrypt, decrypt), result (ok, error).
	MetricCryptoOperations = "vault_crypto_operations_attempted_total"

	// MetricFlagEvaluations counts flag evaluations.
	// Labels: source (cache, store), result (ok, not_found, error).
	MetricFlagEvaluations = "vault_flags_evaluated_total"

	// MetricRotations counts rotation attempts.
	// Labels: trigger (scheduled, manual), result (ok, error).
	MetricRotations = "vault_rotations_attempted_total"

	// MetricRotationDuration times rotation attempts, the rotator included.
	// Labels: trigger (scheduled, manual), result (ok, error).
	MetricRotationDuration = "vault_rotation_duration_seconds"

	// MetricConfigPolls counts the polls config sources make to spot
	// changes. Labels: source (confy, database), result (changed,
	// unchanged, error).
	MetricConfigPolls = "vault_config_sources_polled_total"
)

// Label values shared by more than one metric.
const (
	ResultOK       = "ok"
	ResultNotFound = "not_found"
	ResultError    = "error"
)

// RotationDurationBuckets are the bounds of MetricRotationDuration, in
// seconds. A rotator can call out to another system, and a rotation has to
// finish inside the five minute claim lease, so the top bucket is 300s.
var RotationDurationBuckets = []float64{0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30, 60, 300}

// Counter is a counter declared with label keys. Children are created on
// first use and cached, so a hot path takes no registry lock. A nil *Counter
// records nothing, which is what a nil sink gives you.
type Counter struct {
	vec[gometrics.Counter]
}

// NewCounter declares a counter on m. It returns nil when m is nil.
func NewCounter(m gometrics.Metrics, name, help string, labelKeys ...string) *Counter {
	if m == nil {
		return nil
	}
	return &Counter{vec[gometrics.Counter]{
		keys: labelKeys,
		build: func(labels map[string]string) gometrics.Counter {
			return m.Counter(name, gometrics.WithDescription(help), gometrics.WithLabels(labels))
		},
	}}
}

// Inc adds one to the series for values, given in label key order.
func (c *Counter) Inc(values ...string) {
	if c == nil {
		return
	}
	if child, ok := c.child(values); ok {
		child.Inc()
	}
}

// Histogram is a histogram declared with label keys. A nil *Histogram
// records nothing.
type Histogram struct {
	vec[gometrics.Histogram]
}

// NewHistogram declares a histogram in seconds on m. It returns nil when m
// is nil.
func NewHistogram(m gometrics.Metrics, name, help string, buckets []float64, labelKeys ...string) *Histogram {
	if m == nil {
		return nil
	}
	return &Histogram{vec[gometrics.Histogram]{
		keys: labelKeys,
		build: func(labels map[string]string) gometrics.Histogram {
			return m.Histogram(name,
				gometrics.WithDescription(help),
				gometrics.WithUnit("s"),
				gometrics.WithBuckets(buckets...),
				gometrics.WithLabels(labels))
		},
	}}
}

// Observe records v in the series for values, given in label key order.
func (h *Histogram) Observe(v float64, values ...string) {
	if h == nil {
		return
	}
	if child, ok := h.child(values); ok {
		child.Observe(v)
	}
}

// vec caches one child per label value tuple. Every label value vault
// passes comes from a fixed set, so the cache stays small.
type vec[T any] struct {
	keys  []string
	build func(map[string]string) T
	cache sync.Map // joined values -> T
}

// child returns the series for values. A call with the wrong number of
// values records nothing rather than create a series with a different label
// set from the rest of the family.
func (v *vec[T]) child(values []string) (T, bool) {
	var zero T
	if len(values) != len(v.keys) {
		return zero, false
	}
	key := strings.Join(values, "\xff")
	if c, ok := v.cache.Load(key); ok {
		if t, ok := c.(T); ok {
			return t, true
		}
	}
	labels := make(map[string]string, len(v.keys))
	for i, k := range v.keys {
		labels[k] = values[i]
	}
	actual, _ := v.cache.LoadOrStore(key, v.build(labels))
	t, ok := actual.(T)
	return t, ok
}
