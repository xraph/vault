package audit

import (
	"context"
	"time"

	log "github.com/xraph/go-utils/log"

	audithook "github.com/xraph/vault/audit_hook"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/scope"
)

// LoggerOption configures the Logger.
type LoggerOption func(*Logger)

// WithHook attaches an audit hook extension for event broadcasting.
func WithHook(h *audithook.Extension) LoggerOption {
	return func(l *Logger) { l.hook = h }
}

// WithLogger sets the slog logger for internal errors.
func WithLogger(sl log.Logger) LoggerOption {
	return func(l *Logger) { l.logger = sl }
}

// Logger records audit entries and optionally broadcasts them via an audit hook.
type Logger struct {
	store  Store
	hook   *audithook.Extension
	logger log.Logger
}

// NewLogger creates an audit logger.
func NewLogger(store Store, opts ...LoggerOption) *Logger {
	l := &Logger{
		store:  store,
		logger: log.NewNoopLogger(),
	}
	for _, o := range opts {
		o(l)
	}
	return l
}

// LogAccess records a successful access event.
func (l *Logger) LogAccess(ctx context.Context, key, action, resource string) {
	appID, tenantID, userID, ip := scope.FromContext(ctx)

	entry := &Entry{
		ID:        id.NewAuditID(),
		Action:    action,
		Resource:  resource,
		Key:       key,
		AppID:     appID,
		TenantID:  tenantID,
		UserID:    userID,
		IP:        ip,
		Outcome:   audithook.OutcomeSuccess,
		CreatedAt: time.Now().UTC(),
	}

	if err := l.store.RecordAudit(ctx, entry); err != nil {
		l.logger.Error("audit: record failed",
			log.String("action", action), log.String("key", key), log.Any("error", err))
	}

	if l.hook != nil {
		l.hook.Record(ctx,
			action,
			audithook.SeverityInfo,
			audithook.OutcomeSuccess,
			resource,
			entry.ID.String(),
			categoryForResource(resource),
			key,
			nil,
		)
	}
}

// LogFailure records a failed access event.
func (l *Logger) LogFailure(ctx context.Context, key, action, resource string, err error) {
	appID, tenantID, userID, ip := scope.FromContext(ctx)

	entry := &Entry{
		ID:        id.NewAuditID(),
		Action:    action,
		Resource:  resource,
		Key:       key,
		AppID:     appID,
		TenantID:  tenantID,
		UserID:    userID,
		IP:        ip,
		Outcome:   audithook.OutcomeFailure,
		CreatedAt: time.Now().UTC(),
	}

	if err != nil {
		entry.Metadata = map[string]any{"error": err.Error()}
	}

	if sErr := l.store.RecordAudit(ctx, entry); sErr != nil {
		l.logger.Error("audit: record failed",
			log.String("action", action), log.String("key", key), log.Any("error", sErr))
	}

	if l.hook != nil {
		l.hook.Record(ctx,
			action,
			audithook.SeverityWarning,
			audithook.OutcomeFailure,
			resource,
			entry.ID.String(),
			categoryForResource(resource),
			key,
			err,
		)
	}
}

// categoryForResource maps a resource type to its audit category.
func categoryForResource(resource string) string {
	switch resource {
	case audithook.ResourceSecret:
		return audithook.CategorySecret
	case audithook.ResourceFlag:
		return audithook.CategoryFlag
	case audithook.ResourceConfig:
		return audithook.CategoryConfig
	case audithook.ResourceOverride:
		return audithook.CategoryOverride
	default:
		return "vault.unknown"
	}
}
