package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/xraph/vault"
	"github.com/xraph/vault/rotation"
)

// SaveRotationPolicy creates or updates a rotation policy.
func (s *Store) SaveRotationPolicy(ctx context.Context, p *rotation.Policy) error {
	now := time.Now().UTC()
	m := rotationPolicyModelFromEntity(p)
	m.CreatedAt = now
	m.UpdatedAt = now

	_, err := s.pgdb().NewInsert(m).
		OnConflict("(secret_key, app_id) DO UPDATE").
		Set("interval_ns = EXCLUDED.interval_ns").
		Set("enabled = EXCLUDED.enabled").
		Set("last_rotated_at = EXCLUDED.last_rotated_at").
		Set("next_rotation_at = EXCLUDED.next_rotation_at").
		Set("updated_at = EXCLUDED.updated_at").
		Exec(ctx)
	return err
}

// GetRotationPolicy retrieves a rotation policy by secret key and app ID.
func (s *Store) GetRotationPolicy(ctx context.Context, key, appID string) (*rotation.Policy, error) {
	m := new(RotationPolicyModel)
	err := s.pgdb().NewSelect(m).
		Where("secret_key = ?", key).
		Where("app_id = ?", appID).
		Scan(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, vault.ErrRotationNotFound
		}
		return nil, err
	}
	return m.toEntity(), nil
}

// ListRotationPolicies returns all rotation policies for an app.
func (s *Store) ListRotationPolicies(ctx context.Context, appID string) ([]*rotation.Policy, error) {
	var models []RotationPolicyModel
	err := s.pgdb().NewSelect(&models).
		Where("app_id = ?", appID).
		OrderExpr("secret_key ASC").
		Scan(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]*rotation.Policy, len(models))
	for i := range models {
		result[i] = models[i].toEntity()
	}
	return result, nil
}

// DeleteRotationPolicy removes a rotation policy.
func (s *Store) DeleteRotationPolicy(ctx context.Context, key, appID string) error {
	res, err := s.pgdb().NewDelete((*RotationPolicyModel)(nil)).
		Where("secret_key = ?", key).
		Where("app_id = ?", appID).
		Exec(ctx)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return vault.ErrRotationNotFound
	}
	return nil
}

// RecordRotation records a completed rotation event.
func (s *Store) RecordRotation(ctx context.Context, r *rotation.Record) error {
	m := &RotationRecordModel{
		ID: r.ID.String(), SecretKey: r.SecretKey, AppID: r.AppID,
		OldVersion: r.OldVersion, NewVersion: r.NewVersion,
		RotatedBy: r.RotatedBy, RotatedAt: r.RotatedAt,
	}
	_, err := s.pgdb().NewInsert(m).Exec(ctx)
	return err
}

// ListRotationRecords returns rotation history for a secret.
func (s *Store) ListRotationRecords(ctx context.Context, key, appID string, opts rotation.ListOpts) ([]*rotation.Record, error) {
	var models []RotationRecordModel
	q := s.pgdb().NewSelect(&models).
		Where("secret_key = ?", key).
		Where("app_id = ?", appID).
		OrderExpr("rotated_at DESC")

	if opts.Limit > 0 {
		q = q.Limit(opts.Limit)
	}
	if opts.Offset > 0 {
		q = q.Offset(opts.Offset)
	}

	if err := q.Scan(ctx); err != nil {
		return nil, err
	}

	result := make([]*rotation.Record, len(models))
	for i := range models {
		result[i] = models[i].toEntity()
	}
	return result, nil
}
