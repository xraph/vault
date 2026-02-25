package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/xraph/vault"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/secret"
)

// GetSecret retrieves the latest version of a secret.
func (s *Store) GetSecret(ctx context.Context, key, appID string) (*secret.Secret, error) {
	m := new(SecretModel)
	err := s.pgdb().NewSelect(m).
		Where("key = ?", key).
		Where("app_id = ?", appID).
		Scan(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, vault.ErrSecretNotFound
		}
		return nil, err
	}
	return m.toEntity(), nil
}

// SetSecret creates or updates a secret with auto-versioning.
func (s *Store) SetSecret(ctx context.Context, sec *secret.Secret) error {
	tx, err := s.pgdb().BeginTxQuery(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // rollback on deferred cleanup

	// Get current version.
	var currentVersion int64
	err = tx.NewSelect((*SecretModel)(nil)).
		Column("version").
		Where("key = ?", sec.Key).
		Where("app_id = ?", sec.AppID).
		Scan(ctx, &currentVersion)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	if errors.Is(err, sql.ErrNoRows) {
		sec.Version = 1
	} else {
		sec.Version = currentVersion + 1
	}

	now := time.Now().UTC()
	m := secretModelFromEntity(sec)
	m.CreatedAt = now
	m.UpdatedAt = now

	_, err = tx.NewInsert(m).
		OnConflict("(key, app_id) DO UPDATE").
		Set("encrypted_value = EXCLUDED.encrypted_value").
		Set("encryption_alg = EXCLUDED.encryption_alg").
		Set("encryption_key_id = EXCLUDED.encryption_key_id").
		Set("version = EXCLUDED.version").
		Set("metadata = EXCLUDED.metadata").
		Set("expires_at = EXCLUDED.expires_at").
		Set("updated_at = EXCLUDED.updated_at").
		Exec(ctx)
	if err != nil {
		return err
	}

	// Record version.
	metaJSON, err := json.Marshal(sec.Metadata)
	if err != nil {
		return err
	}
	_ = metaJSON // metadata not stored in version table

	vm := &SecretVersionModel{
		ID: id.NewVersionID().String(), SecretKey: sec.Key, AppID: sec.AppID,
		Version: sec.Version, EncryptedValue: sec.EncryptedValue, CreatedAt: now,
	}
	if _, err := tx.NewInsert(vm).Exec(ctx); err != nil {
		return err
	}

	return tx.Commit()
}

// DeleteSecret removes a secret and all its versions.
func (s *Store) DeleteSecret(ctx context.Context, key, appID string) error {
	tx, err := s.pgdb().BeginTxQuery(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // rollback on deferred cleanup

	res, err := tx.NewDelete((*SecretModel)(nil)).
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
		return vault.ErrSecretNotFound
	}

	if _, err := tx.NewDelete((*SecretVersionModel)(nil)).
		Where("secret_key = ?", key).
		Where("app_id = ?", appID).
		Exec(ctx); err != nil {
		return err
	}

	return tx.Commit()
}

// ListSecrets returns secret metadata for an app.
func (s *Store) ListSecrets(ctx context.Context, appID string, opts secret.ListOpts) ([]*secret.Meta, error) {
	var models []SecretModel
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

	result := make([]*secret.Meta, len(models))
	for i := range models {
		result[i] = models[i].toMeta()
	}
	return result, nil
}

// GetSecretVersion retrieves a specific version of a secret.
func (s *Store) GetSecretVersion(ctx context.Context, key, appID string, version int64) (*secret.Secret, error) {
	sec, err := s.GetSecret(ctx, key, appID)
	if err != nil {
		return nil, err
	}

	vm := new(SecretVersionModel)
	err = s.pgdb().NewSelect(vm).
		Where("secret_key = ?", key).
		Where("app_id = ?", appID).
		Where("version = ?", version).
		Scan(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, vault.ErrSecretNotFound
		}
		return nil, err
	}

	sec.Version = version
	sec.EncryptedValue = vm.EncryptedValue
	sec.CreatedAt = vm.CreatedAt
	return sec, nil
}

// ListSecretVersions returns all versions of a secret.
func (s *Store) ListSecretVersions(ctx context.Context, key, appID string) ([]*secret.Version, error) {
	var models []SecretVersionModel
	err := s.pgdb().NewSelect(&models).
		Where("secret_key = ?", key).
		Where("app_id = ?", appID).
		OrderExpr("version ASC").
		Scan(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]*secret.Version, len(models))
	for i := range models {
		result[i] = models[i].toEntity()
	}
	return result, nil
}
