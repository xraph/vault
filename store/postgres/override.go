package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/xraph/vault"
	"github.com/xraph/vault/override"
)

// GetOverride retrieves a tenant override by key, app ID, and tenant ID.
func (s *Store) GetOverride(ctx context.Context, key, appID, tenantID string) (*override.Override, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, key, value, app_id, tenant_id, metadata, created_at, updated_at
		FROM vault_overrides WHERE key = $1 AND app_id = $2 AND tenant_id = $3
	`, key, appID, tenantID)

	o := &override.Override{}
	var valueJSON, metaJSON []byte
	err := row.Scan(&o.ID, &o.Key, &valueJSON, &o.AppID, &o.TenantID,
		&metaJSON, &o.CreatedAt, &o.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, vault.ErrOverrideNotFound
		}
		return nil, err
	}
	_ = json.Unmarshal(valueJSON, &o.Value) //nolint:errcheck // best-effort decode
	if metaJSON != nil {
		_ = json.Unmarshal(metaJSON, &o.Metadata) //nolint:errcheck // best-effort decode
	}
	return o, nil
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

	_, err = s.pool.Exec(ctx, `
		INSERT INTO vault_overrides (id, key, value, app_id, tenant_id, metadata, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (key, app_id, tenant_id) DO UPDATE SET
		    value = EXCLUDED.value,
		    metadata = EXCLUDED.metadata,
		    updated_at = EXCLUDED.updated_at
	`, o.ID.String(), o.Key, valueJSON, o.AppID, o.TenantID, metaJSON, now, now)
	return err
}

// DeleteOverride removes a tenant override.
func (s *Store) DeleteOverride(ctx context.Context, key, appID, tenantID string) error {
	tag, err := s.pool.Exec(ctx,
		"DELETE FROM vault_overrides WHERE key = $1 AND app_id = $2 AND tenant_id = $3",
		key, appID, tenantID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return vault.ErrOverrideNotFound
	}
	return nil
}

// ListOverridesByTenant returns all overrides for a specific tenant.
func (s *Store) ListOverridesByTenant(ctx context.Context, appID, tenantID string) ([]*override.Override, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, key, value, app_id, tenant_id, metadata, created_at, updated_at
		FROM vault_overrides WHERE app_id = $1 AND tenant_id = $2 ORDER BY key ASC
	`, appID, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanOverrides(rows)
}

// ListOverridesByKey returns all tenant overrides for a specific config key.
func (s *Store) ListOverridesByKey(ctx context.Context, key, appID string) ([]*override.Override, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, key, value, app_id, tenant_id, metadata, created_at, updated_at
		FROM vault_overrides WHERE key = $1 AND app_id = $2 ORDER BY tenant_id ASC
	`, key, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanOverrides(rows)
}

// scanOverrides reads override rows into a slice.
func scanOverrides(rows pgx.Rows) ([]*override.Override, error) {
	var result []*override.Override
	for rows.Next() {
		o := &override.Override{}
		var valueJSON, metaJSON []byte
		if err := rows.Scan(&o.ID, &o.Key, &valueJSON, &o.AppID, &o.TenantID,
			&metaJSON, &o.CreatedAt, &o.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(valueJSON, &o.Value) //nolint:errcheck // best-effort decode
		if metaJSON != nil {
			_ = json.Unmarshal(metaJSON, &o.Metadata) //nolint:errcheck // best-effort decode
		}
		result = append(result, o)
	}
	return result, rows.Err()
}
