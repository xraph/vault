package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/xraph/vault"
	cfgpkg "github.com/xraph/vault/config"
	"github.com/xraph/vault/id"
)

// GetConfig retrieves a config entry by key and app ID.
func (s *Store) GetConfig(ctx context.Context, key, appID string) (*cfgpkg.Entry, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, key, value, value_type, version, description, app_id, metadata, created_at, updated_at
		FROM vault_config WHERE key = $1 AND app_id = $2
	`, key, appID)

	e := &cfgpkg.Entry{}
	var valueJSON, metaJSON []byte
	err := row.Scan(&e.ID, &e.Key, &valueJSON, &e.ValueType, &e.Version,
		&e.Description, &e.AppID, &metaJSON, &e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, vault.ErrConfigNotFound
		}
		return nil, err
	}
	_ = json.Unmarshal(valueJSON, &e.Value) //nolint:errcheck // best-effort decode
	if metaJSON != nil {
		_ = json.Unmarshal(metaJSON, &e.Metadata) //nolint:errcheck // best-effort decode
	}
	return e, nil
}

// SetConfig creates or updates a config entry with auto-versioning.
func (s *Store) SetConfig(ctx context.Context, e *cfgpkg.Entry) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback on deferred cleanup

	// Get current version.
	var currentVersion int64
	err = tx.QueryRow(ctx,
		"SELECT version FROM vault_config WHERE key = $1 AND app_id = $2",
		e.Key, e.AppID,
	).Scan(&currentVersion)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}

	if errors.Is(err, pgx.ErrNoRows) {
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

	_, err = tx.Exec(ctx, `
		INSERT INTO vault_config (id, key, value, value_type, version, description, app_id, metadata, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (key, app_id) DO UPDATE SET
		    value = EXCLUDED.value,
		    value_type = EXCLUDED.value_type,
		    version = EXCLUDED.version,
		    description = EXCLUDED.description,
		    metadata = EXCLUDED.metadata,
		    updated_at = EXCLUDED.updated_at
	`, e.ID.String(), e.Key, valueJSON, e.ValueType, e.Version,
		e.Description, e.AppID, metaJSON, now, now)
	if err != nil {
		return err
	}

	// Append version record.
	_, err = tx.Exec(ctx, `
		INSERT INTO vault_config_versions (id, config_key, app_id, version, value, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, id.NewVersionID().String(), e.Key, e.AppID, e.Version, valueJSON, now)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// DeleteConfig removes a config entry and all its versions.
func (s *Store) DeleteConfig(ctx context.Context, key, appID string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback on deferred cleanup

	tag, err := tx.Exec(ctx,
		"DELETE FROM vault_config WHERE key = $1 AND app_id = $2", key, appID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return vault.ErrConfigNotFound
	}

	if _, err := tx.Exec(ctx,
		"DELETE FROM vault_config_versions WHERE config_key = $1 AND app_id = $2", key, appID); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// ListConfig returns config entries for an app.
func (s *Store) ListConfig(ctx context.Context, appID string, opts cfgpkg.ListOpts) ([]*cfgpkg.Entry, error) {
	query := `
		SELECT id, key, value, value_type, version, description, app_id, metadata, created_at, updated_at
		FROM vault_config WHERE app_id = $1 ORDER BY key ASC`

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

	var result []*cfgpkg.Entry
	for rows.Next() {
		e := &cfgpkg.Entry{}
		var valueJSON, metaJSON []byte
		if err := rows.Scan(&e.ID, &e.Key, &valueJSON, &e.ValueType, &e.Version,
			&e.Description, &e.AppID, &metaJSON, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(valueJSON, &e.Value) //nolint:errcheck // best-effort decode
		if metaJSON != nil {
			_ = json.Unmarshal(metaJSON, &e.Metadata) //nolint:errcheck // best-effort decode
		}
		result = append(result, e)
	}
	return result, rows.Err()
}

// GetConfigVersion retrieves a specific version of a config entry.
func (s *Store) GetConfigVersion(ctx context.Context, key, appID string, version int64) (*cfgpkg.Entry, error) {
	e, err := s.GetConfig(ctx, key, appID)
	if err != nil {
		return nil, err
	}

	var valueJSON []byte
	var createdAt time.Time
	err = s.pool.QueryRow(ctx, `
		SELECT value, created_at FROM vault_config_versions
		WHERE config_key = $1 AND app_id = $2 AND version = $3
	`, key, appID, version).Scan(&valueJSON, &createdAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, vault.ErrConfigNotFound
		}
		return nil, err
	}

	e.Version = version
	_ = json.Unmarshal(valueJSON, &e.Value) //nolint:errcheck // best-effort decode
	e.CreatedAt = createdAt
	return e, nil
}

// ListConfigVersions returns all versions of a config entry.
func (s *Store) ListConfigVersions(ctx context.Context, key, appID string) ([]*cfgpkg.EntryVersion, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, config_key, app_id, version, value, created_by, created_at
		FROM vault_config_versions
		WHERE config_key = $1 AND app_id = $2
		ORDER BY version ASC
	`, key, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*cfgpkg.EntryVersion
	for rows.Next() {
		v := &cfgpkg.EntryVersion{}
		var valueJSON []byte
		if err := rows.Scan(&v.ID, &v.ConfigKey, &v.AppID, &v.Version,
			&valueJSON, &v.CreatedBy, &v.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(valueJSON, &v.Value) //nolint:errcheck // best-effort decode
		result = append(result, v)
	}
	return result, rows.Err()
}
