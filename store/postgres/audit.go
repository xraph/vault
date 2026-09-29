package postgres

import (
	"context"

	"github.com/xraph/vault/audit"
)

// RecordAudit persists an audit log entry.
func (s *Store) RecordAudit(ctx context.Context, e *audit.Entry) error {
	m := auditModelFromEntity(e)
	_, err := s.pgdb().NewInsert(m).Exec(ctx)
	return err
}

// ListAudit returns audit entries for an app.
func (s *Store) ListAudit(ctx context.Context, appID string, opts audit.ListOpts) ([]*audit.Entry, error) {
	var models []AuditModel
	q := s.pgdb().NewSelect(&models).
		Where("app_id = ?", appID).
		OrderExpr("created_at DESC")
	if opts.Resource != "" {
		q = q.Where("resource = ?", opts.Resource)
	}

	if opts.Limit > 0 {
		q = q.Limit(opts.Limit)
	}
	if opts.Offset > 0 {
		q = q.Offset(opts.Offset)
	}

	if err := q.Scan(ctx); err != nil {
		return nil, err
	}

	result := make([]*audit.Entry, len(models))
	for i := range models {
		result[i] = models[i].toEntity()
	}
	return result, nil
}

// ListAuditByKey returns audit entries for a specific key within an app.
func (s *Store) ListAuditByKey(ctx context.Context, key, appID string, opts audit.ListOpts) ([]*audit.Entry, error) {
	var models []AuditModel
	q := s.pgdb().NewSelect(&models).
		Where("key = ?", key).
		Where("app_id = ?", appID).
		OrderExpr("created_at DESC")
	if opts.Resource != "" {
		q = q.Where("resource = ?", opts.Resource)
	}

	if opts.Limit > 0 {
		q = q.Limit(opts.Limit)
	}
	if opts.Offset > 0 {
		q = q.Offset(opts.Offset)
	}

	if err := q.Scan(ctx); err != nil {
		return nil, err
	}

	result := make([]*audit.Entry, len(models))
	for i := range models {
		result[i] = models[i].toEntity()
	}
	return result, nil
}

// CountAudit returns the number of audit entries belonging to appID.
func (s *Store) CountAudit(ctx context.Context, appID string) (int64, error) {
	return s.pgdb().NewSelect((*AuditModel)(nil)).
		Where("app_id = ?", appID).
		Count(ctx)
}

// CountAuditMatching returns the number of audit entries belonging to appID
// that match opts. Limit and Offset are ignored.
func (s *Store) CountAuditMatching(ctx context.Context, appID string, opts audit.ListOpts) (int64, error) {
	q := s.pgdb().NewSelect((*AuditModel)(nil)).Where("app_id = ?", appID)
	if opts.Resource != "" {
		q = q.Where("resource = ?", opts.Resource)
	}
	return q.Count(ctx)
}
