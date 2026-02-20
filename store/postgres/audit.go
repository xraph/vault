package postgres

import (
	"context"
	"encoding/json"

	"github.com/xraph/vault/audit"
)

// RecordAudit persists an audit log entry.
func (s *Store) RecordAudit(ctx context.Context, e *audit.Entry) error {
	metaJSON, err := json.Marshal(e.Metadata)
	if err != nil {
		return err
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO vault_audit (id, action, resource, key, app_id, tenant_id, user_id, ip, outcome, metadata, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, e.ID.String(), e.Action, e.Resource, e.Key, e.AppID,
		e.TenantID, e.UserID, e.IP, e.Outcome, metaJSON, e.CreatedAt)
	return err
}

// ListAudit returns audit entries for an app.
func (s *Store) ListAudit(ctx context.Context, appID string, opts audit.ListOpts) ([]*audit.Entry, error) {
	query := `
		SELECT id, action, resource, key, app_id, tenant_id, user_id, ip, outcome, metadata, created_at
		FROM vault_audit WHERE app_id = $1 ORDER BY created_at DESC`

	args := []any{appID}
	if opts.Limit > 0 {
		query += " LIMIT $2"
		args = append(args, opts.Limit)
	}
	if opts.Offset > 0 {
		query += " OFFSET $" + pgPlaceholder(len(args)+1)
		args = append(args, opts.Offset)
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanAuditEntries(rows)
}

// ListAuditByKey returns audit entries for a specific key within an app.
func (s *Store) ListAuditByKey(ctx context.Context, key, appID string, opts audit.ListOpts) ([]*audit.Entry, error) {
	query := `
		SELECT id, action, resource, key, app_id, tenant_id, user_id, ip, outcome, metadata, created_at
		FROM vault_audit WHERE key = $1 AND app_id = $2 ORDER BY created_at DESC`

	args := []any{key, appID}
	if opts.Limit > 0 {
		query += " LIMIT $3"
		args = append(args, opts.Limit)
	}
	if opts.Offset > 0 {
		query += " OFFSET $" + pgPlaceholder(len(args)+1)
		args = append(args, opts.Offset)
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanAuditEntries(rows)
}

// scanAuditEntries reads audit rows into a slice.
func scanAuditEntries(rows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}) ([]*audit.Entry, error) {
	var result []*audit.Entry
	for rows.Next() {
		e := &audit.Entry{}
		var metaJSON []byte
		if err := rows.Scan(&e.ID, &e.Action, &e.Resource, &e.Key, &e.AppID,
			&e.TenantID, &e.UserID, &e.IP, &e.Outcome, &metaJSON, &e.CreatedAt); err != nil {
			return nil, err
		}
		if metaJSON != nil {
			_ = json.Unmarshal(metaJSON, &e.Metadata) //nolint:errcheck // best-effort decode
		}
		result = append(result, e)
	}
	return result, rows.Err()
}
