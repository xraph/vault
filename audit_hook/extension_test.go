package audithook_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	audithook "github.com/xraph/vault/audit_hook"
)

func bg() context.Context { return context.Background() }

// captureRecorder collects events for assertions.
type captureRecorder struct {
	mu     sync.Mutex
	events []*audithook.AuditEvent
}

func (r *captureRecorder) Record(_ context.Context, event *audithook.AuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
	return nil
}

func (r *captureRecorder) last() *audithook.AuditEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.events) == 0 {
		return nil
	}
	return r.events[len(r.events)-1]
}

func (r *captureRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

func TestRecordEmitsEvent(t *testing.T) {
	rec := &captureRecorder{}
	ext := audithook.New(rec)

	ext.Record(bg(),
		audithook.ActionSecretAccessed,
		audithook.SeverityInfo,
		audithook.OutcomeSuccess,
		audithook.ResourceSecret,
		"sec-123",
		audithook.CategorySecret,
		"db-password",
		nil,
	)

	if rec.count() != 1 {
		t.Fatalf("count: got %d, want 1", rec.count())
	}

	ev := rec.last()
	if ev.Action != audithook.ActionSecretAccessed {
		t.Errorf("action: got %q", ev.Action)
	}
	if ev.Severity != audithook.SeverityInfo {
		t.Errorf("severity: got %q", ev.Severity)
	}
	if ev.Outcome != audithook.OutcomeSuccess {
		t.Errorf("outcome: got %q", ev.Outcome)
	}
	if ev.Resource != audithook.ResourceSecret {
		t.Errorf("resource: got %q", ev.Resource)
	}
	if ev.ResourceID != "sec-123" {
		t.Errorf("resource_id: got %q", ev.ResourceID)
	}
	if ev.Key != "db-password" {
		t.Errorf("key: got %q", ev.Key)
	}
}

func TestRecordWithMetadata(t *testing.T) {
	rec := &captureRecorder{}
	ext := audithook.New(rec)

	ext.Record(bg(),
		audithook.ActionConfigSet,
		audithook.SeverityInfo,
		audithook.OutcomeSuccess,
		audithook.ResourceConfig,
		"cfg-1",
		audithook.CategoryConfig,
		"pool.size",
		nil,
		"old_value", 10,
		"new_value", 50,
	)

	ev := rec.last()
	if ev.Metadata["old_value"] != 10 {
		t.Errorf("old_value: got %v", ev.Metadata["old_value"])
	}
	if ev.Metadata["new_value"] != 50 {
		t.Errorf("new_value: got %v", ev.Metadata["new_value"])
	}
}

func TestRecordWithError(t *testing.T) {
	rec := &captureRecorder{}
	ext := audithook.New(rec)

	ext.Record(bg(),
		audithook.ActionSecretAccessed,
		audithook.SeverityWarning,
		audithook.OutcomeSuccess, // will be overridden to failure
		audithook.ResourceSecret,
		"sec-err",
		audithook.CategorySecret,
		"missing-key",
		errors.New("key not found"),
	)

	ev := rec.last()
	if ev.Outcome != audithook.OutcomeFailure {
		t.Errorf("outcome: got %q, want %q", ev.Outcome, audithook.OutcomeFailure)
	}
	if ev.Reason != "key not found" {
		t.Errorf("reason: got %q", ev.Reason)
	}
}

func TestFilterByActions(t *testing.T) {
	rec := &captureRecorder{}
	ext := audithook.New(rec, audithook.WithActions(
		audithook.ActionSecretAccessed,
		audithook.ActionSecretSet,
	))

	// Allowed action.
	ext.Record(bg(),
		audithook.ActionSecretAccessed, audithook.SeverityInfo, audithook.OutcomeSuccess,
		audithook.ResourceSecret, "", audithook.CategorySecret, "key1", nil,
	)
	if rec.count() != 1 {
		t.Errorf("allowed action: count=%d, want 1", rec.count())
	}

	// Filtered action.
	ext.Record(bg(),
		audithook.ActionFlagEvaluated, audithook.SeverityInfo, audithook.OutcomeSuccess,
		audithook.ResourceFlag, "", audithook.CategoryFlag, "flag1", nil,
	)
	if rec.count() != 1 {
		t.Errorf("filtered action: count=%d, want 1 (unchanged)", rec.count())
	}

	// Another allowed action.
	ext.Record(bg(),
		audithook.ActionSecretSet, audithook.SeverityInfo, audithook.OutcomeSuccess,
		audithook.ResourceSecret, "", audithook.CategorySecret, "key2", nil,
	)
	if rec.count() != 2 {
		t.Errorf("second allowed action: count=%d, want 2", rec.count())
	}
}

func TestRecorderFuncAdapter(t *testing.T) {
	var called bool
	fn := audithook.RecorderFunc(func(_ context.Context, _ *audithook.AuditEvent) error {
		called = true
		return nil
	})

	ext := audithook.New(fn)
	ext.Record(bg(),
		audithook.ActionConfigSet, audithook.SeverityInfo, audithook.OutcomeSuccess,
		audithook.ResourceConfig, "", audithook.CategoryConfig, "k", nil,
	)

	if !called {
		t.Error("RecorderFunc was not called")
	}
}

func TestRecorderErrorNotFatal(_ *testing.T) {
	failing := audithook.RecorderFunc(func(_ context.Context, _ *audithook.AuditEvent) error {
		return errors.New("recorder down")
	})

	ext := audithook.New(failing)

	// Should not panic.
	ext.Record(bg(),
		audithook.ActionSecretDeleted, audithook.SeverityCritical, audithook.OutcomeSuccess,
		audithook.ResourceSecret, "", audithook.CategorySecret, "k", nil,
	)
}

func TestName(t *testing.T) {
	rec := &captureRecorder{}
	ext := audithook.New(rec)
	if ext.Name() != "vault.audit_hook" {
		t.Errorf("name: got %q", ext.Name())
	}
}

func TestAllActions(t *testing.T) {
	actions := audithook.AllActions()
	if len(actions) != 13 {
		t.Errorf("got %d actions, want 13", len(actions))
	}
}
