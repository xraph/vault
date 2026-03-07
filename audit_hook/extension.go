package audithook

import (
	"context"

	log "github.com/xraph/go-utils/log"
)

// AuditEvent represents a single audit event emitted by the extension.
type AuditEvent struct {
	Action     string         `json:"action"`
	Resource   string         `json:"resource"`
	Category   string         `json:"category"`
	ResourceID string         `json:"resource_id"`
	Key        string         `json:"key"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	Outcome    string         `json:"outcome"`
	Severity   string         `json:"severity"`
	Reason     string         `json:"reason,omitempty"`
}

// Recorder records audit events to an external system.
type Recorder interface {
	Record(ctx context.Context, event *AuditEvent) error
}

// RecorderFunc is a function adapter for Recorder.
type RecorderFunc func(ctx context.Context, event *AuditEvent) error

// Record implements Recorder.
func (f RecorderFunc) Record(ctx context.Context, event *AuditEvent) error {
	return f(ctx, event)
}

// Extension is an audit recording extension that forwards events to a Recorder.
// Actions can be filtered so only selected events are recorded.
type Extension struct {
	recorder Recorder
	enabled  map[string]bool // nil = all actions enabled
	logger   log.Logger
}

// New creates an audit hook extension.
func New(recorder Recorder, opts ...Option) *Extension {
	e := &Extension{
		recorder: recorder,
		logger:   log.NewNoopLogger(),
	}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Name returns the extension name.
func (e *Extension) Name() string {
	return "vault.audit_hook"
}

// Record emits an audit event through the recorder.
// kvPairs are additional metadata key-value pairs (alternating string key, any value).
func (e *Extension) Record(
	ctx context.Context,
	action, severity, outcome, resource, resourceID, category, key string,
	err error,
	kvPairs ...any,
) {
	// Check if action is enabled.
	if e.enabled != nil && !e.enabled[action] {
		return
	}

	event := &AuditEvent{
		Action:     action,
		Resource:   resource,
		Category:   category,
		ResourceID: resourceID,
		Key:        key,
		Outcome:    outcome,
		Severity:   severity,
	}

	if err != nil {
		event.Reason = err.Error()
		event.Outcome = OutcomeFailure
	}

	// Build metadata from kvPairs.
	if len(kvPairs) > 0 {
		event.Metadata = make(map[string]any, len(kvPairs)/2)
		for i := 0; i+1 < len(kvPairs); i += 2 {
			if k, ok := kvPairs[i].(string); ok {
				event.Metadata[k] = kvPairs[i+1]
			}
		}
	}

	if rErr := e.recorder.Record(ctx, event); rErr != nil {
		e.logger.Error("audit_hook: record failed",
			log.String("action", action), log.String("key", key), log.Any("error", rErr))
	}
}
