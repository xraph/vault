package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/xraph/vault"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/secret"
)

// GetSecret retrieves the latest version of a secret.
func (s *Store) GetSecret(ctx context.Context, key, appID string) (*secret.Secret, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, key, app_id, encrypted_value, encryption_alg, encryption_key_id,
		       version, metadata, expires_at, created_at, updated_at
		FROM vault_secrets WHERE key = $1 AND app_id = $2
	`, key, appID)

	sec := &secret.Secret{}
	var metaJSON []byte
	err := row.Scan(
		&sec.ID, &sec.Key, &sec.AppID, &sec.EncryptedValue,
		&sec.EncryptionAlg, &sec.EncryptionKeyID,
		&sec.Version, &metaJSON, &sec.ExpiresAt,
		&sec.CreatedAt, &sec.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, vault.ErrSecretNotFound
		}
		return nil, err
	}
	if metaJSON != nil {
		_ = json.Unmarshal(metaJSON, &sec.Metadata) //nolint:errcheck // best-effort decode
	}
	return sec, nil
}

// SetSecret creates or updates a secret with auto-versioning.
func (s *Store) SetSecret(ctx context.Context, sec *secret.Secret) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback on deferred cleanup

	// Get current version.
	var currentVersion int64
	err = tx.QueryRow(ctx,
		"SELECT version FROM vault_secrets WHERE key = $1 AND app_id = $2",
		sec.Key, sec.AppID,
	).Scan(&currentVersion)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}

	if errors.Is(err, pgx.ErrNoRows) {
		sec.Version = 1
	} else {
		sec.Version = currentVersion + 1
	}

	metaJSON, err := json.Marshal(sec.Metadata)
	if err != nil {
		return err
	}
	now := time.Now().UTC()

	// Upsert the secret.
	_, err = tx.Exec(ctx, `
		INSERT INTO vault_secrets (id, key, app_id, encrypted_value, encryption_alg,
		    encryption_key_id, version, metadata, expires_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (key, app_id) DO UPDATE SET
		    encrypted_value = EXCLUDED.encrypted_value,
		    encryption_alg = EXCLUDED.encryption_alg,
		    encryption_key_id = EXCLUDED.encryption_key_id,
		    version = EXCLUDED.version,
		    metadata = EXCLUDED.metadata,
		    expires_at = EXCLUDED.expires_at,
		    updated_at = EXCLUDED.updated_at
	`, sec.ID.String(), sec.Key, sec.AppID, sec.EncryptedValue,
		sec.EncryptionAlg, sec.EncryptionKeyID,
		sec.Version, metaJSON, sec.ExpiresAt, now, now)
	if err != nil {
		return err
	}

	// Record version.
	_, err = tx.Exec(ctx, `
		INSERT INTO vault_secret_versions (id, secret_key, app_id, version, encrypted_value, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, id.NewVersionID().String(), sec.Key, sec.AppID, sec.Version, sec.EncryptedValue, now)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// DeleteSecret removes a secret and all its versions.
func (s *Store) DeleteSecret(ctx context.Context, key, appID string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback on deferred cleanup

	tag, err := tx.Exec(ctx,
		"DELETE FROM vault_secrets WHERE key = $1 AND app_id = $2", key, appID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return vault.ErrSecretNotFound
	}

	_, err = tx.Exec(ctx,
		"DELETE FROM vault_secret_versions WHERE secret_key = $1 AND app_id = $2", key, appID)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// ListSecrets returns secret metadata for an app.
func (s *Store) ListSecrets(ctx context.Context, appID string, opts secret.ListOpts) ([]*secret.Meta, error) {
	query := `
		SELECT id, key, version, expires_at, app_id, metadata, created_at, updated_at
		FROM vault_secrets WHERE app_id = $1 ORDER BY key ASC`

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

	var result []*secret.Meta
	for rows.Next() {
		m := &secret.Meta{}
		var metaJSON []byte
		if err := rows.Scan(&m.ID, &m.Key, &m.Version, &m.ExpiresAt, &m.AppID,
			&metaJSON, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, err
		}
		if metaJSON != nil {
			_ = json.Unmarshal(metaJSON, &m.Metadata) //nolint:errcheck // best-effort decode
		}
		result = append(result, m)
	}
	return result, rows.Err()
}

// GetSecretVersion retrieves a specific version of a secret.
func (s *Store) GetSecretVersion(ctx context.Context, key, appID string, version int64) (*secret.Secret, error) {
	// Get the main secret row first.
	sec, err := s.GetSecret(ctx, key, appID)
	if err != nil {
		return nil, err
	}

	// Get the version's encrypted value.
	row := s.pool.QueryRow(ctx, `
		SELECT encrypted_value, created_at
		FROM vault_secret_versions
		WHERE secret_key = $1 AND app_id = $2 AND version = $3
	`, key, appID, version)

	var encVal []byte
	var createdAt time.Time
	err = row.Scan(&encVal, &createdAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, vault.ErrSecretNotFound
		}
		return nil, err
	}

	sec.Version = version
	sec.EncryptedValue = encVal
	sec.CreatedAt = createdAt
	return sec, nil
}

// ListSecretVersions returns all versions of a secret.
func (s *Store) ListSecretVersions(ctx context.Context, key, appID string) ([]*secret.Version, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, secret_key, app_id, version, encrypted_value, created_by, created_at
		FROM vault_secret_versions
		WHERE secret_key = $1 AND app_id = $2
		ORDER BY version ASC
	`, key, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*secret.Version
	for rows.Next() {
		v := &secret.Version{}
		if err := rows.Scan(&v.ID, &v.SecretKey, &v.AppID, &v.Version,
			&v.EncryptedValue, &v.CreatedBy, &v.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, v)
	}
	return result, rows.Err()
}

func pgPlaceholder(n int) string {
	return "$" + strconv.Itoa(n)
}
