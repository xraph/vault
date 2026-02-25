package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/xraph/vault"
	"github.com/xraph/vault/override"
)

// GetOverride retrieves a tenant override by key, app ID, and tenant ID.
func (s *Store) GetOverride(ctx context.Context, key, appID, tenantID string) (*override.Override, error) {
	m := new(OverrideModel)
	err := s.pgdb().NewSelect(m).
		Where("key = ?", key).
		Where("app_id = ?", appID).
		Where("tenant_id = ?", tenantID).
		Scan(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, vault.ErrOverrideNotFound
		}
		return nil, err
	}
	return m.toEntity(), nil
}

// SetOverride creates or updates a tenant override.
func (s *Store) SetOverride(ctx context.Context, o *override.Override) error {
	valueJSON, err := json.Marshal(o.Value)
	if err != nil {
		return err
	}
	metaJSON, err := json.Marshal(o.Metadata)
	if err != nil {
		return err
	}
	now := time.Now().UTC()

	m := &OverrideModel{
		ID: o.ID.String(), Key: o.Key, Value: valueJSON,
		AppID: o.AppID, TenantID: o.TenantID,
		Metadata: metaJSON, CreatedAt: now, UpdatedAt: now,
	}
	_, err = s.pgdb().NewInsert(m).
		OnConflict("(key, app_id, tenant_id) DO UPDATE").
		Set("value = EXCLUDED.value").
		Set("metadata = EXCLUDED.metadata").
		Set("updated_at = EXCLUDED.updated_at").
		Exec(ctx)
	return err
}

// DeleteOverride removes a tenant override.
func (s *Store) DeleteOverride(ctx context.Context, key, appID, tenantID string) error {
	res, err := s.pgdb().NewDelete((*OverrideModel)(nil)).
		Where("key = ?", key).
		Where("app_id = ?", appID).
		Where("tenant_id = ?", tenantID).
		Exec(ctx)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return vault.ErrOverrideNotFound
	}
	return nil
}

// ListOverridesByTenant returns all overrides for a specific tenant.
func (s *Store) ListOverridesByTenant(ctx context.Context, appID, tenantID string) ([]*override.Override, error) {
	var models []OverrideModel
	err := s.pgdb().NewSelect(&models).
		Where("app_id = ?", appID).
		Where("tenant_id = ?", tenantID).
		OrderExpr("key ASC").
		Scan(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]*override.Override, len(models))
	for i := range models {
		result[i] = models[i].toEntity()
	}
	return result, nil
}

// ListOverridesByKey returns all tenant overrides for a specific config key.
func (s *Store) ListOverridesByKey(ctx context.Context, key, appID string) ([]*override.Override, error) {
	var models []OverrideModel
	err := s.pgdb().NewSelect(&models).
		Where("key = ?", key).
		Where("app_id = ?", appID).
		OrderExpr("tenant_id ASC").
		Scan(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]*override.Override, len(models))
	for i := range models {
		result[i] = models[i].toEntity()
	}
	return result, nil
}
