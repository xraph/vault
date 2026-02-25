package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/sqlitedriver"
	"github.com/xraph/grove/migrate"

	"github.com/xraph/vault"
	"github.com/xraph/vault/audit"
	cfgpkg "github.com/xraph/vault/config"
	"github.com/xraph/vault/flag"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/override"
	"github.com/xraph/vault/rotation"
	"github.com/xraph/vault/secret"
)

// Compile-time interface checks.
var (
	_ secret.Store   = (*Store)(nil)
	_ flag.Store     = (*Store)(nil)
	_ cfgpkg.Store   = (*Store)(nil)
	_ override.Store = (*Store)(nil)
	_ rotation.Store = (*Store)(nil)
	_ audit.Store    = (*Store)(nil)
)

// StoreOption configures the Store.
type StoreOption func(*Store)

// WithLogger sets the logger for the store.
func WithLogger(l *slog.Logger) StoreOption {
	return func(s *Store) { s.logger = l }
}

// Store is a Grove ORM SQLite implementation of all Vault store interfaces.
type Store struct {
	db     *grove.DB
	sdb    *sqlitedriver.SqliteDB
	logger *slog.Logger
}

// New creates a new SQLite store backed by Grove ORM.
func New(db *grove.DB, opts ...StoreOption) *Store {
	s := &Store{
		db:     db,
		sdb:    sqlitedriver.Unwrap(db),
		logger: slog.Default(),
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// DB returns the underlying grove database for direct access.
func (s *Store) DB() *grove.DB { return s.db }

// Migrate creates the required tables and indexes using the grove orchestrator.
func (s *Store) Migrate(ctx context.Context) error {
	executor, err := migrate.NewExecutorFor(s.sdb)
	if err != nil {
		return fmt.Errorf("vault/sqlite: create migration executor: %w", err)
	}
	orch := migrate.NewOrchestrator(executor, Migrations)
	if _, err := orch.Migrate(ctx); err != nil {
		return fmt.Errorf("vault/sqlite: migration failed: %w", err)
	}
	s.logger.Info("sqlite: migrations complete")
	return nil
}

// Ping checks database connectivity.
func (s *Store) Ping(ctx context.Context) error {
	return s.db.Ping(ctx)
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// isNoRows checks for the standard sql.ErrNoRows sentinel.
func isNoRows(err error) bool {
	return errors.Is(err, sql.ErrNoRows)
}

// now returns the current UTC time.
func now() time.Time {
	return time.Now().UTC()
}

// ==================== Secret Store ====================

// GetSecret retrieves the latest version of a secret.
func (s *Store) GetSecret(ctx context.Context, key, appID string) (*secret.Secret, error) {
	m := new(SecretModel)
	err := s.sdb.NewSelect(m).
		Where("key = ?", key).
		Where("app_id = ?", appID).
		Scan(ctx)
	if err != nil {
		if isNoRows(err) {
			return nil, vault.ErrSecretNotFound
		}
		return nil, err
	}
	return m.toEntity(), nil
}

// SetSecret creates or updates a secret with auto-versioning.
func (s *Store) SetSecret(ctx context.Context, sec *secret.Secret) error {
	tx, err := s.sdb.BeginTxQuery(ctx, nil)
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
	if err != nil && !isNoRows(err) {
		return err
	}

	if isNoRows(err) {
		sec.Version = 1
	} else {
		sec.Version = currentVersion + 1
	}

	t := now()
	m := secretModelFromEntity(sec)
	m.CreatedAt = t
	m.UpdatedAt = t

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
	vm := &SecretVersionModel{
		ID: id.NewVersionID().String(), SecretKey: sec.Key, AppID: sec.AppID,
		Version: sec.Version, EncryptedValue: sec.EncryptedValue, CreatedAt: t,
	}
	if _, err := tx.NewInsert(vm).Exec(ctx); err != nil {
		return err
	}

	return tx.Commit()
}

// DeleteSecret removes a secret and all its versions.
func (s *Store) DeleteSecret(ctx context.Context, key, appID string) error {
	tx, err := s.sdb.BeginTxQuery(ctx, nil)
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
	q := s.sdb.NewSelect(&models).
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
	err = s.sdb.NewSelect(vm).
		Where("secret_key = ?", key).
		Where("app_id = ?", appID).
		Where("version = ?", version).
		Scan(ctx)
	if err != nil {
		if isNoRows(err) {
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
	err := s.sdb.NewSelect(&models).
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

// ==================== Flag Store ====================

// DefineFlag creates or updates a flag definition.
func (s *Store) DefineFlag(ctx context.Context, f *flag.Definition) error {
	t := now()
	m := flagModelFromEntity(f)
	m.CreatedAt = t
	m.UpdatedAt = t

	_, err := s.sdb.NewInsert(m).
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
	err := s.sdb.NewSelect(m).
		Where("key = ?", key).
		Where("app_id = ?", appID).
		Scan(ctx)
	if err != nil {
		if isNoRows(err) {
			return nil, vault.ErrFlagNotFound
		}
		return nil, err
	}
	return m.toEntity(), nil
}

// ListFlagDefinitions returns all flag definitions for an app.
func (s *Store) ListFlagDefinitions(ctx context.Context, appID string, opts flag.ListOpts) ([]*flag.Definition, error) {
	var models []FlagModel
	q := s.sdb.NewSelect(&models).
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
	tx, err := s.sdb.BeginTxQuery(ctx, nil)
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
	tx, err := s.sdb.BeginTxQuery(ctx, nil)
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

	t := now()
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
			Config: string(configJSON), ReturnValue: string(returnJSON),
			CreatedAt: t, UpdatedAt: t,
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
	err := s.sdb.NewSelect(&models).
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
	t := now()

	m := &FlagOverrideModel{
		ID: id.NewOverrideID().String(), FlagKey: key, AppID: appID,
		TenantID: tenantID, Value: string(valueJSON),
		CreatedAt: t, UpdatedAt: t,
	}
	_, err = s.sdb.NewInsert(m).
		OnConflict("(flag_key, app_id, tenant_id) DO UPDATE").
		Set("value = EXCLUDED.value").
		Set("updated_at = EXCLUDED.updated_at").
		Exec(ctx)
	return err
}

// GetFlagTenantOverride retrieves a tenant override for a flag.
func (s *Store) GetFlagTenantOverride(ctx context.Context, key, appID, tenantID string) (any, error) {
	m := new(FlagOverrideModel)
	err := s.sdb.NewSelect(m).
		Where("flag_key = ?", key).
		Where("app_id = ?", appID).
		Where("tenant_id = ?", tenantID).
		Scan(ctx)
	if err != nil {
		if isNoRows(err) {
			return nil, vault.ErrOverrideNotFound
		}
		return nil, err
	}

	var val any
	_ = json.Unmarshal([]byte(m.Value), &val) //nolint:errcheck // best-effort decode
	return val, nil
}

// DeleteFlagTenantOverride removes a tenant override.
func (s *Store) DeleteFlagTenantOverride(ctx context.Context, key, appID, tenantID string) error {
	res, err := s.sdb.NewDelete((*FlagOverrideModel)(nil)).
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
	err := s.sdb.NewSelect(&models).
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

// ==================== Config Store ====================

// GetConfig retrieves a config entry by key and app ID.
func (s *Store) GetConfig(ctx context.Context, key, appID string) (*cfgpkg.Entry, error) {
	m := new(ConfigModel)
	err := s.sdb.NewSelect(m).
		Where("key = ?", key).
		Where("app_id = ?", appID).
		Scan(ctx)
	if err != nil {
		if isNoRows(err) {
			return nil, vault.ErrConfigNotFound
		}
		return nil, err
	}
	return m.toEntity(), nil
}

// SetConfig creates or updates a config entry with auto-versioning.
func (s *Store) SetConfig(ctx context.Context, e *cfgpkg.Entry) error {
	tx, err := s.sdb.BeginTxQuery(ctx, nil)
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
	if err != nil && !isNoRows(err) {
		return err
	}

	if isNoRows(err) {
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
	t := now()

	m := &ConfigModel{
		ID: e.ID.String(), Key: e.Key, Value: string(valueJSON),
		ValueType: e.ValueType, Version: e.Version,
		Description: e.Description, AppID: e.AppID,
		Metadata: string(metaJSON), CreatedAt: t, UpdatedAt: t,
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
		Version: e.Version, Value: string(valueJSON), CreatedAt: t,
	}
	if _, err := tx.NewInsert(vm).Exec(ctx); err != nil {
		return err
	}

	return tx.Commit()
}

// DeleteConfig removes a config entry and all its versions.
func (s *Store) DeleteConfig(ctx context.Context, key, appID string) error {
	tx, err := s.sdb.BeginTxQuery(ctx, nil)
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
	q := s.sdb.NewSelect(&models).
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
	err = s.sdb.NewSelect(vm).
		Where("config_key = ?", key).
		Where("app_id = ?", appID).
		Where("version = ?", version).
		Scan(ctx)
	if err != nil {
		if isNoRows(err) {
			return nil, vault.ErrConfigNotFound
		}
		return nil, err
	}

	e.Version = version
	_ = json.Unmarshal([]byte(vm.Value), &e.Value) //nolint:errcheck // best-effort decode
	e.CreatedAt = vm.CreatedAt
	return e, nil
}

// ListConfigVersions returns all versions of a config entry.
func (s *Store) ListConfigVersions(ctx context.Context, key, appID string) ([]*cfgpkg.EntryVersion, error) {
	var models []ConfigVersionModel
	err := s.sdb.NewSelect(&models).
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

// ==================== Override Store ====================

// GetOverride retrieves a tenant override by key, app ID, and tenant ID.
func (s *Store) GetOverride(ctx context.Context, key, appID, tenantID string) (*override.Override, error) {
	m := new(OverrideModel)
	err := s.sdb.NewSelect(m).
		Where("key = ?", key).
		Where("app_id = ?", appID).
		Where("tenant_id = ?", tenantID).
		Scan(ctx)
	if err != nil {
		if isNoRows(err) {
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
	t := now()

	m := &OverrideModel{
		ID: o.ID.String(), Key: o.Key, Value: string(valueJSON),
		AppID: o.AppID, TenantID: o.TenantID,
		Metadata: string(metaJSON), CreatedAt: t, UpdatedAt: t,
	}
	_, err = s.sdb.NewInsert(m).
		OnConflict("(key, app_id, tenant_id) DO UPDATE").
		Set("value = EXCLUDED.value").
		Set("metadata = EXCLUDED.metadata").
		Set("updated_at = EXCLUDED.updated_at").
		Exec(ctx)
	return err
}

// DeleteOverride removes a tenant override.
func (s *Store) DeleteOverride(ctx context.Context, key, appID, tenantID string) error {
	res, err := s.sdb.NewDelete((*OverrideModel)(nil)).
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
	err := s.sdb.NewSelect(&models).
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
	err := s.sdb.NewSelect(&models).
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

// ==================== Rotation Store ====================

// SaveRotationPolicy creates or updates a rotation policy.
func (s *Store) SaveRotationPolicy(ctx context.Context, p *rotation.Policy) error {
	t := now()
	m := rotationPolicyModelFromEntity(p)
	m.CreatedAt = t
	m.UpdatedAt = t

	_, err := s.sdb.NewInsert(m).
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
	err := s.sdb.NewSelect(m).
		Where("secret_key = ?", key).
		Where("app_id = ?", appID).
		Scan(ctx)
	if err != nil {
		if isNoRows(err) {
			return nil, vault.ErrRotationNotFound
		}
		return nil, err
	}
	return m.toEntity(), nil
}

// ListRotationPolicies returns all rotation policies for an app.
func (s *Store) ListRotationPolicies(ctx context.Context, appID string) ([]*rotation.Policy, error) {
	var models []RotationPolicyModel
	err := s.sdb.NewSelect(&models).
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
	res, err := s.sdb.NewDelete((*RotationPolicyModel)(nil)).
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
	_, err := s.sdb.NewInsert(m).Exec(ctx)
	return err
}

// ListRotationRecords returns rotation history for a secret.
func (s *Store) ListRotationRecords(ctx context.Context, key, appID string, opts rotation.ListOpts) ([]*rotation.Record, error) {
	var models []RotationRecordModel
	q := s.sdb.NewSelect(&models).
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

// ==================== Audit Store ====================

// RecordAudit persists an audit log entry.
func (s *Store) RecordAudit(ctx context.Context, e *audit.Entry) error {
	m := auditModelFromEntity(e)
	_, err := s.sdb.NewInsert(m).Exec(ctx)
	return err
}

// ListAudit returns audit entries for an app.
func (s *Store) ListAudit(ctx context.Context, appID string, opts audit.ListOpts) ([]*audit.Entry, error) {
	var models []AuditModel
	q := s.sdb.NewSelect(&models).
		Where("app_id = ?", appID).
		OrderExpr("created_at DESC")

	if opts.Limit > 0 {
		q = q.Limit(opts.Limit)
	}
	if opts.Offset > 0 {
		q = q.Offset(opts.Offset)
	}

	if err := q.Scan(ctx); err != nil {
		return nil, err
	}

	result := make([]*audit.Entry, len(models))
	for i := range models {
		result[i] = models[i].toEntity()
	}
	return result, nil
}

// ListAuditByKey returns audit entries for a specific key within an app.
func (s *Store) ListAuditByKey(ctx context.Context, key, appID string, opts audit.ListOpts) ([]*audit.Entry, error) {
	var models []AuditModel
	q := s.sdb.NewSelect(&models).
		Where("key = ?", key).
		Where("app_id = ?", appID).
		OrderExpr("created_at DESC")

	if opts.Limit > 0 {
		q = q.Limit(opts.Limit)
	}
	if opts.Offset > 0 {
		q = q.Offset(opts.Offset)
	}

	if err := q.Scan(ctx); err != nil {
		return nil, err
	}

	result := make([]*audit.Entry, len(models))
	for i := range models {
		result[i] = models[i].toEntity()
	}
	return result, nil
}
