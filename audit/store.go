package audit

import "context"

// Store defines the persistence interface for audit log entries.
type Store interface {
	// RecordAudit persists an audit log entry.
	RecordAudit(ctx context.Context, e *Entry) error

	// ListAudit returns audit entries for an app. opts.Resource, when set,
	// filters in the query, before paging.
	ListAudit(ctx context.Context, appID string, opts ListOpts) ([]*Entry, error)

	// ListAuditByKey returns audit entries for a specific key within an app.
	// opts.Resource, when set, filters in the query, before paging.
	ListAuditByKey(ctx context.Context, key, appID string, opts ListOpts) ([]*Entry, error)

	// CountAudit returns the total number of audit entries for an app,
	// independent of any paging.
	CountAudit(ctx context.Context, appID string) (int64, error)

	// CountAuditMatching returns the number of audit entries for an app that
	// match opts. Only opts.Resource is honoured; Limit and Offset are
	// ignored, so the count is the total a paged list would page through.
	CountAuditMatching(ctx context.Context, appID string, opts ListOpts) (int64, error)
}
