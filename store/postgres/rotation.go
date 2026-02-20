package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/xraph/vault"
	"github.com/xraph/vault/rotation"
)

// SaveRotationPolicy creates or updates a rotation policy.
func (s *Store) SaveRotationPolicy(ctx context.Context, p *rotation.Policy) error {
	now := time.Now().UTC()

	_, err := s.pool.Exec(ctx, `
		INSERT INTO vault_rotation_policies
		    (id, secret_key, app_id, interval_ns, enabled, last_rotated_at, next_rotation_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (secret_key, app_id) DO UPDATE SET
		    interval_ns = EXCLUDED.interval_ns,
		    enabled = EXCLUDED.enabled,
		    last_rotated_at = EXCLUDED.last_rotated_at,
		    next_rotation_at = EXCLUDED.next_rotation_at,
		    updated_at = EXCLUDED.updated_at
	`, p.ID.String(), p.SecretKey, p.AppID, int64(p.Interval),
		p.Enabled, p.LastRotatedAt, p.NextRotationAt, now, now)
	return err
}

// GetRotationPolicy retrieves a rotation policy by secret key and app ID.
func (s *Store) GetRotationPolicy(ctx context.Context, key, appID string) (*rotation.Policy, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, secret_key, app_id, interval_ns, enabled,
		       last_rotated_at, next_rotation_at, created_at, updated_at
		FROM vault_rotation_policies WHERE secret_key = $1 AND app_id = $2
	`, key, appID)

	p := &rotation.Policy{}
	var intervalNS int64
	err := row.Scan(&p.ID, &p.SecretKey, &p.AppID, &intervalNS, &p.Enabled,
		&p.LastRotatedAt, &p.NextRotationAt, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, vault.ErrRotationNotFound
		}
		return nil, err
	}
	p.Interval = time.Duration(intervalNS)
	return p, nil
}

// ListRotationPolicies returns all rotation policies for an app.
func (s *Store) ListRotationPolicies(ctx context.Context, appID string) ([]*rotation.Policy, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, secret_key, app_id, interval_ns, enabled,
		       last_rotated_at, next_rotation_at, created_at, updated_at
		FROM vault_rotation_policies WHERE app_id = $1 ORDER BY secret_key ASC
	`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*rotation.Policy
	for rows.Next() {
		p := &rotation.Policy{}
		var intervalNS int64
		if err := rows.Scan(&p.ID, &p.SecretKey, &p.AppID, &intervalNS, &p.Enabled,
			&p.LastRotatedAt, &p.NextRotationAt, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		p.Interval = time.Duration(intervalNS)
		result = append(result, p)
	}
	return result, rows.Err()
}

// DeleteRotationPolicy removes a rotation policy.
func (s *Store) DeleteRotationPolicy(ctx context.Context, key, appID string) error {
	tag, err := s.pool.Exec(ctx,
		"DELETE FROM vault_rotation_policies WHERE secret_key = $1 AND app_id = $2", key, appID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return vault.ErrRotationNotFound
	}
	return nil
}

// RecordRotation records a completed rotation event.
func (s *Store) RecordRotation(ctx context.Context, r *rotation.Record) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO vault_rotation_records (id, secret_key, app_id, old_version, new_version, rotated_by, rotated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, r.ID.String(), r.SecretKey, r.AppID, r.OldVersion, r.NewVersion, r.RotatedBy, r.RotatedAt)
	return err
}

// ListRotationRecords returns rotation history for a secret.
func (s *Store) ListRotationRecords(ctx context.Context, key, appID string, opts rotation.ListOpts) ([]*rotation.Record, error) {
	query := `
		SELECT id, secret_key, app_id, old_version, new_version, rotated_by, rotated_at
		FROM vault_rotation_records WHERE secret_key = $1 AND app_id = $2
		ORDER BY rotated_at DESC`

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

	var result []*rotation.Record
	for rows.Next() {
		r := &rotation.Record{}
		if err := rows.Scan(&r.ID, &r.SecretKey, &r.AppID,
			&r.OldVersion, &r.NewVersion, &r.RotatedBy, &r.RotatedAt); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}
