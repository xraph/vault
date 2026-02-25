package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/xraph/vault"
	cfgpkg "github.com/xraph/vault/config"
	"github.com/xraph/vault/id"
)

// GetConfig retrieves a config entry by key and app ID.
func (s *Store) GetConfig(ctx context.Context, key, appID string) (*cfgpkg.Entry, error) {
	m := new(ConfigModel)
	err := s.pgdb().NewSelect(m).
		Where("key = ?", key).
		Where("app_id = ?", appID).
		Scan(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, vault.ErrConfigNotFound
		}
		return nil, err
	}
	return m.toEntity(), nil
}

// SetConfig creates or updates a config entry with auto-versioning.
func (s *Store) SetConfig(ctx context.Context, e *cfgpkg.Entry) error {
	tx, err := s.pgdb().BeginTxQuery(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // rollback on deferred cleanup

	// Get current version.
	var currentVersion int64
	err = tx.NewSelect((*ConfigModel)(nil)).
		Column("version").
		Where("key = ?", e.Key).
		Where("app_id = ?", e.AppID).
		Scan(ctx, &currentVersion)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	if errors.Is(err, sql.ErrNoRows) {
		if e.Version == 0 {
			e.Version = 1
		}
	} else {
		e.Version = currentVersion + 1
	}

	valueJSON, err := json.Marshal(e.Value)
	if err != nil {
		return err
	}
	metaJSON, err := json.Marshal(e.Metadata)
	if err != nil {
		return err
	}
	now := time.Now().UTC()

	m := &ConfigModel{
		ID: e.ID.String(), Key: e.Key, Value: valueJSON,
		ValueType: e.ValueType, Version: e.Version,
		Description: e.Description, AppID: e.AppID,
		Metadata: metaJSON, CreatedAt: now, UpdatedAt: now,
	}
	_, err = tx.NewInsert(m).
		OnConflict("(key, app_id) DO UPDATE").
		Set("value = EXCLUDED.value").
		Set("value_type = EXCLUDED.value_type").
		Set("version = EXCLUDED.version").
		Set("description = EXCLUDED.description").
		Set("metadata = EXCLUDED.metadata").
		Set("updated_at = EXCLUDED.updated_at").
		Exec(ctx)
	if err != nil {
		return err
	}

	// Append version record.
	vm := &ConfigVersionModel{
		ID: id.NewVersionID().String(), ConfigKey: e.Key, AppID: e.AppID,
		Version: e.Version, Value: valueJSON, CreatedAt: now,
	}
	if _, err := tx.NewInsert(vm).Exec(ctx); err != nil {
		return err
	}

	return tx.Commit()
}

// DeleteConfig removes a config entry and all its versions.
func (s *Store) DeleteConfig(ctx context.Context, key, appID string) error {
	tx, err := s.pgdb().BeginTxQuery(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // rollback on deferred cleanup

	res, err := tx.NewDelete((*ConfigModel)(nil)).
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
		return vault.ErrConfigNotFound
	}

	if _, err := tx.NewDelete((*ConfigVersionModel)(nil)).
		Where("config_key = ?", key).
		Where("app_id = ?", appID).
		Exec(ctx); err != nil {
		return err
	}

	return tx.Commit()
}

// ListConfig returns config entries for an app.
func (s *Store) ListConfig(ctx context.Context, appID string, opts cfgpkg.ListOpts) ([]*cfgpkg.Entry, error) {
	var models []ConfigModel
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

	result := make([]*cfgpkg.Entry, len(models))
	for i := range models {
		result[i] = models[i].toEntity()
	}
	return result, nil
}

// GetConfigVersion retrieves a specific version of a config entry.
func (s *Store) GetConfigVersion(ctx context.Context, key, appID string, version int64) (*cfgpkg.Entry, error) {
	e, err := s.GetConfig(ctx, key, appID)
	if err != nil {
		return nil, err
	}

	vm := new(ConfigVersionModel)
	err = s.pgdb().NewSelect(vm).
		Where("config_key = ?", key).
		Where("app_id = ?", appID).
		Where("version = ?", version).
		Scan(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, vault.ErrConfigNotFound
		}
		return nil, err
	}

	e.Version = version
	_ = json.Unmarshal(vm.Value, &e.Value) //nolint:errcheck // best-effort decode
	e.CreatedAt = vm.CreatedAt
	return e, nil
}

// ListConfigVersions returns all versions of a config entry.
func (s *Store) ListConfigVersions(ctx context.Context, key, appID string) ([]*cfgpkg.EntryVersion, error) {
	var models []ConfigVersionModel
	err := s.pgdb().NewSelect(&models).
		Where("config_key = ?", key).
		Where("app_id = ?", appID).
		OrderExpr("version ASC").
		Scan(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]*cfgpkg.EntryVersion, len(models))
	for i := range models {
		result[i] = models[i].toEntity()
	}
	return result, nil
}
