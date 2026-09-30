package audit

import "context"

// Store defines the persistence interface for audit log entries.
//
// Every list and count honours the same ListOpts filters (Resource, Key,
// Action, Outcome, Since, ExcludeActions) in the query itself, never after
// the fact, so a page and its total always describe the same rows. Lists are
// ordered created_at DESC, id DESC: the id breaks ties between entries with
// the same timestamp, so paging never repeats or skips a row.
type Store interface {
	// RecordAudit persists an audit log entry.
	RecordAudit(ctx context.Context, e *Entry) error

	// ListAudit returns audit entries for an app that match opts, newest
	// first, filtered before paging.
	ListAudit(ctx context.Context, appID string, opts ListOpts) ([]*Entry, error)

	// ListAuditByKey returns audit entries for a specific key within an app.
	// The key argument decides the key and opts.Key is ignored; every other
	// filter in opts applies as it does for ListAudit.
	ListAuditByKey(ctx context.Context, key, appID string, opts ListOpts) ([]*Entry, error)

	// CountAudit returns the total number of audit entries for an app,
	// independent of any paging.
	CountAudit(ctx context.Context, appID string) (int64, error)

	// CountAuditMatching returns the number of audit entries for an app that
	// match opts. Limit and Offset are ignored, so the count is the total a
	// paged list would page through.
	CountAuditMatching(ctx context.Context, appID string, opts ListOpts) (int64, error)
}
