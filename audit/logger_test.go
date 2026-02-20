package audit_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/xraph/vault/audit"
	audithook "github.com/xraph/vault/audit_hook"
	"github.com/xraph/vault/scope"
	"github.com/xraph/vault/store/memory"
)

func bg() context.Context { return context.Background() }

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

func (r *captureRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

func (r *captureRecorder) last() *audithook.AuditEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.events) == 0 {
		return nil
	}
	return r.events[len(r.events)-1]
}

func TestLogAccessPersists(t *testing.T) {
	s := memory.New()
	logger := audit.NewLogger(s)

	ctx := scope.WithScope(bg(), "app1", "t-1", "u-1", "10.0.0.1")
	logger.LogAccess(ctx, "db-password", audithook.ActionSecretAccessed, audithook.ResourceSecret)

	entries, err := s.ListAudit(bg(), "app1", audit.ListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries: got %d, want 1", len(entries))
	}

	e := entries[0]
	if e.Action != audithook.ActionSecretAccessed {
		t.Errorf("action: got %q", e.Action)
	}
	if e.Resource != audithook.ResourceSecret {
		t.Errorf("resource: got %q", e.Resource)
	}
	if e.Key != "db-password" {
		t.Errorf("key: got %q", e.Key)
	}
	if e.AppID != "app1" {
		t.Errorf("appID: got %q", e.AppID)
	}
	if e.TenantID != "t-1" {
		t.Errorf("tenantID: got %q", e.TenantID)
	}
	if e.UserID != "u-1" {
		t.Errorf("userID: got %q", e.UserID)
	}
	if e.IP != "10.0.0.1" {
		t.Errorf("ip: got %q", e.IP)
	}
	if e.Outcome != audithook.OutcomeSuccess {
		t.Errorf("outcome: got %q", e.Outcome)
	}
}

func TestLogAccessEmitsHook(t *testing.T) {
	s := memory.New()
	rec := &captureRecorder{}
	hook := audithook.New(rec)
	logger := audit.NewLogger(s, audit.WithHook(hook))

	ctx := scope.WithScope(bg(), "app1", "", "", "")
	logger.LogAccess(ctx, "my-key", audithook.ActionConfigSet, audithook.ResourceConfig)

	if rec.count() != 1 {
		t.Fatalf("hook events: got %d, want 1", rec.count())
	}

	ev := rec.last()
	if ev.Action != audithook.ActionConfigSet {
		t.Errorf("action: got %q", ev.Action)
	}
	if ev.Category != audithook.CategoryConfig {
		t.Errorf("category: got %q", ev.Category)
	}
	if ev.Outcome != audithook.OutcomeSuccess {
		t.Errorf("outcome: got %q", ev.Outcome)
	}
}

func TestLogFailurePersists(t *testing.T) {
	s := memory.New()
	logger := audit.NewLogger(s)

	ctx := scope.WithScope(bg(), "app1", "t-2", "", "")
	logger.LogFailure(ctx, "missing-key", audithook.ActionSecretAccessed, audithook.ResourceSecret, errors.New("not found"))

	entries, err := s.ListAudit(bg(), "app1", audit.ListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries: got %d, want 1", len(entries))
	}

	e := entries[0]
	if e.Outcome != audithook.OutcomeFailure {
		t.Errorf("outcome: got %q", e.Outcome)
	}
	if e.Metadata["error"] != "not found" {
		t.Errorf("metadata error: got %v", e.Metadata["error"])
	}
}

func TestLogFailureEmitsHook(t *testing.T) {
	s := memory.New()
	rec := &captureRecorder{}
	hook := audithook.New(rec)
	logger := audit.NewLogger(s, audit.WithHook(hook))

	ctx := scope.WithScope(bg(), "app1", "", "", "")
	logger.LogFailure(ctx, "k", audithook.ActionFlagEvaluated, audithook.ResourceFlag, errors.New("eval error"))

	if rec.count() != 1 {
		t.Fatalf("hook events: got %d, want 1", rec.count())
	}

	ev := rec.last()
	if ev.Outcome != audithook.OutcomeFailure {
		t.Errorf("outcome: got %q", ev.Outcome)
	}
	if ev.Reason != "eval error" {
		t.Errorf("reason: got %q", ev.Reason)
	}
	if ev.Category != audithook.CategoryFlag {
		t.Errorf("category: got %q", ev.Category)
	}
}

func TestLogAccessNoHook(t *testing.T) {
	s := memory.New()
	logger := audit.NewLogger(s) // no hook

	ctx := scope.WithScope(bg(), "app1", "", "", "")
	logger.LogAccess(ctx, "k", audithook.ActionSecretSet, audithook.ResourceSecret)

	entries, _ := s.ListAudit(bg(), "app1", audit.ListOpts{})
	if len(entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(entries))
	}
}

func TestLogAccessEmptyContext(t *testing.T) {
	s := memory.New()
	logger := audit.NewLogger(s)

	// Empty context — all scope values are "".
	logger.LogAccess(bg(), "k", audithook.ActionConfigDeleted, audithook.ResourceConfig)

	entries, _ := s.ListAudit(bg(), "", audit.ListOpts{})
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	e := entries[0]
	if e.AppID != "" || e.TenantID != "" || e.UserID != "" || e.IP != "" {
		t.Errorf("expected empty scope, got appID=%q tenantID=%q userID=%q ip=%q",
			e.AppID, e.TenantID, e.UserID, e.IP)
	}
}
