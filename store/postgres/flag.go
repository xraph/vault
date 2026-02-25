package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/xraph/vault"
	"github.com/xraph/vault/flag"
	"github.com/xraph/vault/id"
)

// DefineFlag creates or updates a flag definition.
func (s *Store) DefineFlag(ctx context.Context, f *flag.Definition) error {
	now := time.Now().UTC()
	m := flagModelFromEntity(f)
	m.CreatedAt = now
	m.UpdatedAt = now

	_, err := s.pgdb().NewInsert(m).
		OnConflict("(key, app_id) DO UPDATE").
		Set("type = EXCLUDED.type").
		Set("default_value = EXCLUDED.default_value").
		Set("description = EXCLUDED.description").
		Set("tags = EXCLUDED.tags").
		Set("variants = EXCLUDED.variants").
		Set("enabled = EXCLUDED.enabled").
		Set("metadata = EXCLUDED.metadata").
		Set("updated_at = EXCLUDED.updated_at").
		Exec(ctx)
	return err
}

// GetFlagDefinition retrieves a flag definition.
func (s *Store) GetFlagDefinition(ctx context.Context, key, appID string) (*flag.Definition, error) {
	m := new(FlagModel)
	err := s.pgdb().NewSelect(m).
		Where("key = ?", key).
		Where("app_id = ?", appID).
		Scan(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, vault.ErrFlagNotFound
		}
		return nil, err
	}
	return m.toEntity(), nil
}

// ListFlagDefinitions returns all flag definitions for an app.
func (s *Store) ListFlagDefinitions(ctx context.Context, appID string, opts flag.ListOpts) ([]*flag.Definition, error) {
	var models []FlagModel
	q := s.pgdb().NewSelect(&models).
		Where("app_id = ?", appID).
		OrderExpr("key ASC")

	if opts.Limit > 0 {
		q = q.Limit(opts.Limit)
	}
	if opts.Offset > 0 {
		q = q.Offset(opts.Offset)
	}

	if err := q.Scan(ctx); err != nil {
		return nil, err
	}

	result := make([]*flag.Definition, len(models))
	for i := range models {
		result[i] = models[i].toEntity()
	}
	return result, nil
}

// DeleteFlagDefinition removes a flag definition and its rules and overrides.
func (s *Store) DeleteFlagDefinition(ctx context.Context, key, appID string) error {
	tx, err := s.pgdb().BeginTxQuery(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // rollback on deferred cleanup

	res, err := tx.NewDelete((*FlagModel)(nil)).
		Where("key = ?", key).
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
		return vault.ErrFlagNotFound
	}

	if _, err := tx.NewDelete((*FlagRuleModel)(nil)).
		Where("flag_key = ?", key).
		Where("app_id = ?", appID).
		Exec(ctx); err != nil {
		return err
	}
	if _, err := tx.NewDelete((*FlagOverrideModel)(nil)).
		Where("flag_key = ?", key).
		Where("app_id = ?", appID).
		Exec(ctx); err != nil {
		return err
	}

	return tx.Commit()
}

// SetFlagRules replaces all targeting rules for a flag.
func (s *Store) SetFlagRules(ctx context.Context, key, appID string, rules []*flag.Rule) error {
	tx, err := s.pgdb().BeginTxQuery(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // rollback on deferred cleanup

	// Delete existing rules.
	if _, err := tx.NewDelete((*FlagRuleModel)(nil)).
		Where("flag_key = ?", key).
		Where("app_id = ?", appID).
		Exec(ctx); err != nil {
		return err
	}

	now := time.Now().UTC()
	for _, r := range rules {
		ruleID := r.ID
		if ruleID.String() == "" {
			ruleID = id.NewRuleID()
		}

		configJSON, cErr := json.Marshal(r.Config)
		if cErr != nil {
			return cErr
		}
		returnJSON, rErr := json.Marshal(r.ReturnValue)
		if rErr != nil {
			return rErr
		}

		m := &FlagRuleModel{
			ID: ruleID.String(), FlagKey: key, AppID: appID,
			Priority: r.Priority, Type: string(r.Type),
			Config: configJSON, ReturnValue: returnJSON,
			CreatedAt: now, UpdatedAt: now,
		}
		if _, err := tx.NewInsert(m).Exec(ctx); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// GetFlagRules returns targeting rules for a flag, ordered by priority.
func (s *Store) GetFlagRules(ctx context.Context, key, appID string) ([]*flag.Rule, error) {
	var models []FlagRuleModel
	err := s.pgdb().NewSelect(&models).
		Where("flag_key = ?", key).
		Where("app_id = ?", appID).
		OrderExpr("priority ASC").
		Scan(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]*flag.Rule, len(models))
	for i := range models {
		result[i] = models[i].toEntity()
	}
	return result, nil
}

// SetFlagTenantOverride sets a direct per-tenant override value.
func (s *Store) SetFlagTenantOverride(ctx context.Context, key, appID, tenantID string, value any) error {
	valueJSON, err := json.Marshal(value)
	if err != nil {
		return err
	}
	now := time.Now().UTC()

	m := &FlagOverrideModel{
		ID: id.NewOverrideID().String(), FlagKey: key, AppID: appID,
		TenantID: tenantID, Value: valueJSON,
		CreatedAt: now, UpdatedAt: now,
	}
	_, err = s.pgdb().NewInsert(m).
		OnConflict("(flag_key, app_id, tenant_id) DO UPDATE").
		Set("value = EXCLUDED.value").
		Set("updated_at = EXCLUDED.updated_at").
		Exec(ctx)
	return err
}

// GetFlagTenantOverride retrieves a tenant override for a flag.
func (s *Store) GetFlagTenantOverride(ctx context.Context, key, appID, tenantID string) (any, error) {
	m := new(FlagOverrideModel)
	err := s.pgdb().NewSelect(m).
		Where("flag_key = ?", key).
		Where("app_id = ?", appID).
		Where("tenant_id = ?", tenantID).
		Scan(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, vault.ErrOverrideNotFound
		}
		return nil, err
	}

	var val any
	_ = json.Unmarshal(m.Value, &val) //nolint:errcheck // best-effort decode
	return val, nil
}

// DeleteFlagTenantOverride removes a tenant override.
func (s *Store) DeleteFlagTenantOverride(ctx context.Context, key, appID, tenantID string) error {
	res, err := s.pgdb().NewDelete((*FlagOverrideModel)(nil)).
		Where("flag_key = ?", key).
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

// ListFlagTenantOverrides returns all tenant overrides for a flag.
func (s *Store) ListFlagTenantOverrides(ctx context.Context, key, appID string) ([]*flag.TenantOverride, error) {
	var models []FlagOverrideModel
	err := s.pgdb().NewSelect(&models).
		Where("flag_key = ?", key).
		Where("app_id = ?", appID).
		OrderExpr("tenant_id ASC").
		Scan(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]*flag.TenantOverride, len(models))
	for i := range models {
		result[i] = models[i].toEntity()
	}
	return result, nil
}
