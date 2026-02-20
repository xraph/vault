// Package metrics provides interfaces and a collector for Vault operational metrics.
// The interfaces are compatible with common metric libraries (Prometheus, etc.)
// and can be bridged to external systems via the MetricFactory.
package metrics

// Counter is a monotonically increasing counter.
type Counter interface {
	Inc()
	Add(float64)
}

// Histogram observes a distribution of values.
type Histogram interface {
	Observe(float64)
}

// MetricFactory creates named metric instances.
type MetricFactory interface {
	Counter(name string) Counter
	Histogram(name string) Histogram
}

// Collector holds all Vault metric instruments.
type Collector struct {
	SecretAccessed Counter
	SecretSet      Counter
	SecretDeleted  Counter
	SecretRotated  Counter
	FlagEvaluated  Counter
	FlagEvalTime   Histogram
	ConfigRead     Counter
	ConfigWritten  Counter
	OverrideRead   Counter
	AuditRecorded  Counter
	Encrypted      Counter
	Decrypted      Counter
	SourceLatency  Histogram
}

// NewCollector creates a Collector using the given factory.
func NewCollector(f MetricFactory) *Collector {
	return &Collector{
		SecretAccessed: f.Counter("vault_secret_accessed_total"),
		SecretSet:      f.Counter("vault_secret_set_total"),
		SecretDeleted:  f.Counter("vault_secret_deleted_total"),
		SecretRotated:  f.Counter("vault_secret_rotated_total"),
		FlagEvaluated:  f.Counter("vault_flag_evaluated_total"),
		FlagEvalTime:   f.Histogram("vault_flag_eval_duration_seconds"),
		ConfigRead:     f.Counter("vault_config_read_total"),
		ConfigWritten:  f.Counter("vault_config_written_total"),
		OverrideRead:   f.Counter("vault_override_read_total"),
		AuditRecorded:  f.Counter("vault_audit_recorded_total"),
		Encrypted:      f.Counter("vault_encrypted_total"),
		Decrypted:      f.Counter("vault_decrypted_total"),
		SourceLatency:  f.Histogram("vault_source_latency_seconds"),
	}
}
