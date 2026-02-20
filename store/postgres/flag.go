package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/xraph/vault"
	"github.com/xraph/vault/flag"
	"github.com/xraph/vault/id"
)

// DefineFlag creates or updates a flag definition.
func (s *Store) DefineFlag(ctx context.Context, f *flag.Definition) error {
	metaJSON, err := json.Marshal(f.Metadata)
	if err != nil {
		return err
	}
	tagsJSON, err := json.Marshal(f.Tags)
	if err != nil {
		return err
	}
	variantsJSON, err := json.Marshal(f.Variants)
	if err != nil {
		return err
	}
	defaultJSON, err := json.Marshal(f.DefaultValue)
	if err != nil {
		return err
	}
	now := time.Now().UTC()

	_, err = s.pool.Exec(ctx, `
		INSERT INTO vault_flags (id, key, type, default_value, description, tags, variants,
		    enabled, app_id, metadata, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (key, app_id) DO UPDATE SET
		    type = EXCLUDED.type,
		    default_value = EXCLUDED.default_value,
		    description = EXCLUDED.description,
		    tags = EXCLUDED.tags,
		    variants = EXCLUDED.variants,
		    enabled = EXCLUDED.enabled,
		    metadata = EXCLUDED.metadata,
		    updated_at = EXCLUDED.updated_at
	`, f.ID.String(), f.Key, string(f.Type), defaultJSON, f.Description,
		tagsJSON, variantsJSON, f.Enabled, f.AppID, metaJSON, now, now)
	return err
}

// GetFlagDefinition retrieves a flag definition.
func (s *Store) GetFlagDefinition(ctx context.Context, key, appID string) (*flag.Definition, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, key, type, default_value, description, tags, variants,
		       enabled, app_id, metadata, created_at, updated_at
		FROM vault_flags WHERE key = $1 AND app_id = $2
	`, key, appID)

	f := &flag.Definition{}
	var defaultJSON, tagsJSON, variantsJSON, metaJSON []byte
	err := row.Scan(&f.ID, &f.Key, &f.Type, &defaultJSON, &f.Description,
		&tagsJSON, &variantsJSON, &f.Enabled, &f.AppID, &metaJSON,
		&f.CreatedAt, &f.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, vault.ErrFlagNotFound
		}
		return nil, err
	}

	_ = json.Unmarshal(defaultJSON, &f.DefaultValue) //nolint:errcheck // best-effort decode
	_ = json.Unmarshal(tagsJSON, &f.Tags)            //nolint:errcheck // best-effort decode
	_ = json.Unmarshal(variantsJSON, &f.Variants)    //nolint:errcheck // best-effort decode
	if metaJSON != nil {
		_ = json.Unmarshal(metaJSON, &f.Metadata) //nolint:errcheck // best-effort decode
	}
	return f, nil
}

// ListFlagDefinitions returns all flag definitions for an app.
func (s *Store) ListFlagDefinitions(ctx context.Context, appID string, opts flag.ListOpts) ([]*flag.Definition, error) {
	query := `
		SELECT id, key, type, default_value, description, tags, variants,
		       enabled, app_id, metadata, created_at, updated_at
		FROM vault_flags WHERE app_id = $1 ORDER BY key ASC`

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

	var result []*flag.Definition
	for rows.Next() {
		f := &flag.Definition{}
		var defaultJSON, tagsJSON, variantsJSON, metaJSON []byte
		if err := rows.Scan(&f.ID, &f.Key, &f.Type, &defaultJSON, &f.Description,
			&tagsJSON, &variantsJSON, &f.Enabled, &f.AppID, &metaJSON,
			&f.CreatedAt, &f.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(defaultJSON, &f.DefaultValue) //nolint:errcheck // best-effort decode
		_ = json.Unmarshal(tagsJSON, &f.Tags)            //nolint:errcheck // best-effort decode
		_ = json.Unmarshal(variantsJSON, &f.Variants)    //nolint:errcheck // best-effort decode
		if metaJSON != nil {
			_ = json.Unmarshal(metaJSON, &f.Metadata) //nolint:errcheck // best-effort decode
		}
		result = append(result, f)
	}
	return result, rows.Err()
}

// DeleteFlagDefinition removes a flag definition and its rules and overrides.
func (s *Store) DeleteFlagDefinition(ctx context.Context, key, appID string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback on deferred cleanup

	tag, err := tx.Exec(ctx,
		"DELETE FROM vault_flags WHERE key = $1 AND app_id = $2", key, appID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return vault.ErrFlagNotFound
	}

	// Cascade delete related rules and overrides; errors are non-fatal.
	if _, err := tx.Exec(ctx,
		"DELETE FROM vault_flag_rules WHERE flag_key = $1 AND app_id = $2", key, appID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		"DELETE FROM vault_flag_overrides WHERE flag_key = $1 AND app_id = $2", key, appID); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// SetFlagRules replaces all targeting rules for a flag.
func (s *Store) SetFlagRules(ctx context.Context, key, appID string, rules []*flag.Rule) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback on deferred cleanup

	// Delete existing rules.
	_, err = tx.Exec(ctx,
		"DELETE FROM vault_flag_rules WHERE flag_key = $1 AND app_id = $2", key, appID)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	for _, r := range rules {
		configJSON, cErr := json.Marshal(r.Config)
		if cErr != nil {
			return cErr
		}
		returnJSON, rErr := json.Marshal(r.ReturnValue)
		if rErr != nil {
			return rErr
		}

		ruleID := r.ID
		if ruleID.String() == "" {
			ruleID = id.NewRuleID()
		}

		_, err = tx.Exec(ctx, `
			INSERT INTO vault_flag_rules (id, flag_key, app_id, priority, type, config, return_value, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		`, ruleID.String(), key, appID, r.Priority, string(r.Type), configJSON, returnJSON, now, now)
		if err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

// GetFlagRules returns targeting rules for a flag, ordered by priority.
func (s *Store) GetFlagRules(ctx context.Context, key, appID string) ([]*flag.Rule, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, flag_key, app_id, priority, type, config, return_value, created_at, updated_at
		FROM vault_flag_rules
		WHERE flag_key = $1 AND app_id = $2
		ORDER BY priority ASC
	`, key, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*flag.Rule
	for rows.Next() {
		r := &flag.Rule{}
		var configJSON, returnJSON []byte
		if err := rows.Scan(&r.ID, &r.FlagKey, &r.AppID, &r.Priority, &r.Type,
			&configJSON, &returnJSON, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(configJSON, &r.Config)      //nolint:errcheck // best-effort decode
		_ = json.Unmarshal(returnJSON, &r.ReturnValue) //nolint:errcheck // best-effort decode
		result = append(result, r)
	}
	return result, rows.Err()
}

// SetFlagTenantOverride sets a direct per-tenant override value.
func (s *Store) SetFlagTenantOverride(ctx context.Context, key, appID, tenantID string, value any) error {
	valueJSON, err := json.Marshal(value)
	if err != nil {
		return err
	}
	now := time.Now().UTC()

	_, err = s.pool.Exec(ctx, `
		INSERT INTO vault_flag_overrides (id, flag_key, app_id, tenant_id, value, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (flag_key, app_id, tenant_id) DO UPDATE SET
		    value = EXCLUDED.value,
		    updated_at = EXCLUDED.updated_at
	`, id.NewOverrideID().String(), key, appID, tenantID, valueJSON, now, now)
	return err
}

// GetFlagTenantOverride retrieves a tenant override for a flag.
func (s *Store) GetFlagTenantOverride(ctx context.Context, key, appID, tenantID string) (any, error) {
	var valueJSON []byte
	err := s.pool.QueryRow(ctx, `
		SELECT value FROM vault_flag_overrides
		WHERE flag_key = $1 AND app_id = $2 AND tenant_id = $3
	`, key, appID, tenantID).Scan(&valueJSON)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, vault.ErrOverrideNotFound
		}
		return nil, err
	}

	var val any
	_ = json.Unmarshal(valueJSON, &val) //nolint:errcheck // best-effort decode
	return val, nil
}

// DeleteFlagTenantOverride removes a tenant override.
func (s *Store) DeleteFlagTenantOverride(ctx context.Context, key, appID, tenantID string) error {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM vault_flag_overrides
		WHERE flag_key = $1 AND app_id = $2 AND tenant_id = $3
	`, key, appID, tenantID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return vault.ErrOverrideNotFound
	}
	return nil
}

// ListFlagTenantOverrides returns all tenant overrides for a flag.
func (s *Store) ListFlagTenantOverrides(ctx context.Context, key, appID string) ([]*flag.TenantOverride, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, flag_key, app_id, tenant_id, value, created_at, updated_at
		FROM vault_flag_overrides
		WHERE flag_key = $1 AND app_id = $2
		ORDER BY tenant_id ASC
	`, key, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*flag.TenantOverride
	for rows.Next() {
		o := &flag.TenantOverride{}
		var valueJSON []byte
		if err := rows.Scan(&o.ID, &o.FlagKey, &o.AppID, &o.TenantID,
			&valueJSON, &o.CreatedAt, &o.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(valueJSON, &o.Value) //nolint:errcheck // best-effort decode
		result = append(result, o)
	}
	return result, rows.Err()
}
