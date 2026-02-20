package audit

import "context"

// Store defines the persistence interface for audit log entries.
type Store interface {
	// RecordAudit persists an audit log entry.
	RecordAudit(ctx context.Context, e *Entry) error

	// ListAudit returns audit entries for an app.
	ListAudit(ctx context.Context, appID string, opts ListOpts) ([]*Entry, error)

	// ListAuditByKey returns audit entries for a specific key within an app.
	ListAuditByKey(ctx context.Context, key, appID string, opts ListOpts) ([]*Entry, error)
}
