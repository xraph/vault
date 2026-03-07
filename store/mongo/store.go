package mongo

import (
	"context"
	"errors"
	"fmt"
	"time"

	log "github.com/xraph/go-utils/log"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/mongodriver"

	"github.com/xraph/vault"
	"github.com/xraph/vault/audit"
	cfgpkg "github.com/xraph/vault/config"
	"github.com/xraph/vault/flag"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/override"
	"github.com/xraph/vault/rotation"
	"github.com/xraph/vault/secret"
)

// Collection name constants.
const (
	colSecrets          = "vault_secrets"
	colSecretVersions   = "vault_secret_versions"
	colFlags            = "vault_flags"
	colFlagRules        = "vault_flag_rules"
	colFlagOverrides    = "vault_flag_overrides"
	colConfig           = "vault_config"
	colConfigVersions   = "vault_config_versions"
	colOverrides        = "vault_overrides"
	colRotationPolicies = "vault_rotation_policies"
	colRotationRecords  = "vault_rotation_records"
	colAudit            = "vault_audit"
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
func WithLogger(l log.Logger) StoreOption {
	return func(s *Store) { s.logger = l }
}

// Store is a Grove ORM MongoDB implementation of all Vault store interfaces.
type Store struct {
	db     *grove.DB
	mdb    *mongodriver.MongoDB
	logger log.Logger
}

// New creates a new MongoDB store backed by Grove ORM.
func New(db *grove.DB, opts ...StoreOption) *Store {
	s := &Store{
		db:     db,
		mdb:    mongodriver.Unwrap(db),
		logger: log.NewNoopLogger(),
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// DB returns the underlying grove database for direct access.
func (s *Store) DB() *grove.DB { return s.db }

// Migrate creates indexes for all vault collections.
func (s *Store) Migrate(ctx context.Context) error {
	indexes := migrationIndexes()

	for col, models := range indexes {
		if len(models) == 0 {
			continue
		}

		_, err := s.mdb.Collection(col).Indexes().CreateMany(ctx, models)
		if err != nil {
			return fmt.Errorf("vault/mongo: migrate %s indexes: %w", col, err)
		}
	}

	s.logger.Info("mongo: migrations complete")
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

// now returns the current UTC time.
func now() time.Time {
	return time.Now().UTC()
}

// isNoDocuments checks if an error wraps mongo.ErrNoDocuments.
func isNoDocuments(err error) bool {
	return errors.Is(err, mongo.ErrNoDocuments)
}

// migrationIndexes returns the index definitions for all vault collections.
func migrationIndexes() map[string][]mongo.IndexModel {
	return map[string][]mongo.IndexModel{
		colSecrets: {
			{
				Keys:    bson.D{{Key: "key", Value: 1}, {Key: "app_id", Value: 1}},
				Options: options.Index().SetUnique(true),
			},
		},
		colSecretVersions: {
			{
				Keys:    bson.D{{Key: "secret_key", Value: 1}, {Key: "app_id", Value: 1}, {Key: "version", Value: 1}},
				Options: options.Index().SetUnique(true),
			},
			{Keys: bson.D{{Key: "secret_key", Value: 1}, {Key: "app_id", Value: 1}}},
		},
		colFlags: {
			{
				Keys:    bson.D{{Key: "key", Value: 1}, {Key: "app_id", Value: 1}},
				Options: options.Index().SetUnique(true),
			},
		},
		colFlagRules: {
			{Keys: bson.D{{Key: "flag_key", Value: 1}, {Key: "app_id", Value: 1}, {Key: "priority", Value: 1}}},
		},
		colFlagOverrides: {
			{
				Keys:    bson.D{{Key: "flag_key", Value: 1}, {Key: "app_id", Value: 1}, {Key: "tenant_id", Value: 1}},
				Options: options.Index().SetUnique(true),
			},
		},
		colConfig: {
			{
				Keys:    bson.D{{Key: "key", Value: 1}, {Key: "app_id", Value: 1}},
				Options: options.Index().SetUnique(true),
			},
		},
		colConfigVersions: {
			{
				Keys:    bson.D{{Key: "config_key", Value: 1}, {Key: "app_id", Value: 1}, {Key: "version", Value: 1}},
				Options: options.Index().SetUnique(true),
			},
			{Keys: bson.D{{Key: "config_key", Value: 1}, {Key: "app_id", Value: 1}}},
		},
		colOverrides: {
			{
				Keys:    bson.D{{Key: "key", Value: 1}, {Key: "app_id", Value: 1}, {Key: "tenant_id", Value: 1}},
				Options: options.Index().SetUnique(true),
			},
		},
		colRotationPolicies: {
			{
				Keys:    bson.D{{Key: "secret_key", Value: 1}, {Key: "app_id", Value: 1}},
				Options: options.Index().SetUnique(true),
			},
		},
		colRotationRecords: {
			{Keys: bson.D{{Key: "secret_key", Value: 1}, {Key: "app_id", Value: 1}, {Key: "rotated_at", Value: -1}}},
		},
		colAudit: {
			{Keys: bson.D{{Key: "app_id", Value: 1}, {Key: "created_at", Value: -1}}},
			{Keys: bson.D{{Key: "key", Value: 1}, {Key: "app_id", Value: 1}, {Key: "created_at", Value: -1}}},
		},
	}
}

// ==================== Secret Store ====================

// GetSecret retrieves the latest version of a secret.
func (s *Store) GetSecret(ctx context.Context, key, appID string) (*secret.Secret, error) {
	var m SecretModel
	err := s.mdb.NewFind(&m).
		Filter(bson.M{"key": key, "app_id": appID}).
		Scan(ctx)
	if err != nil {
		if isNoDocuments(err) {
			return nil, vault.ErrSecretNotFound
		}
		return nil, err
	}
	return m.toEntity(), nil
}

// SetSecret creates or updates a secret with auto-versioning.
func (s *Store) SetSecret(ctx context.Context, sec *secret.Secret) error {
	// Get current version.
	var existing SecretModel
	err := s.mdb.NewFind(&existing).
		Filter(bson.M{"key": sec.Key, "app_id": sec.AppID}).
		Scan(ctx)
	if err != nil && !isNoDocuments(err) {
		return err
	}

	if isNoDocuments(err) {
		sec.Version = 1
	} else {
		sec.Version = existing.Version + 1
	}

	t := now()
	m := secretModelFromEntity(sec)
	m.CreatedAt = t
	m.UpdatedAt = t

	_, err = s.mdb.NewUpdate(m).
		Filter(bson.M{"key": sec.Key, "app_id": sec.AppID}).
		Upsert().
		Exec(ctx)
	if err != nil {
		return err
	}

	// Record version.
	vm := &SecretVersionModel{
		ID: id.NewVersionID().String(), SecretKey: sec.Key, AppID: sec.AppID,
		Version: sec.Version, EncryptedValue: sec.EncryptedValue, CreatedAt: t,
	}
	_, err = s.mdb.NewInsert(vm).Exec(ctx)
	return err
}

// DeleteSecret removes a secret and all its versions.
func (s *Store) DeleteSecret(ctx context.Context, key, appID string) error {
	res, err := s.mdb.NewDelete((*SecretModel)(nil)).
		Filter(bson.M{"key": key, "app_id": appID}).
		Exec(ctx)
	if err != nil {
		return err
	}
	if res.DeletedCount() == 0 {
		return vault.ErrSecretNotFound
	}

	_, err = s.mdb.NewDelete((*SecretVersionModel)(nil)).
		Many().
		Filter(bson.M{"secret_key": key, "app_id": appID}).
		Exec(ctx)
	return err
}

// ListSecrets returns secret metadata for an app.
func (s *Store) ListSecrets(ctx context.Context, appID string, opts secret.ListOpts) ([]*secret.Meta, error) {
	var models []SecretModel
	q := s.mdb.NewFind(&models).
		Filter(bson.M{"app_id": appID}).
		Sort(bson.D{{Key: "key", Value: 1}})

	if opts.Limit > 0 {
		q = q.Limit(int64(opts.Limit))
	}
	if opts.Offset > 0 {
		q = q.Skip(int64(opts.Offset))
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

	var vm SecretVersionModel
	err = s.mdb.NewFind(&vm).
		Filter(bson.M{"secret_key": key, "app_id": appID, "version": version}).
		Scan(ctx)
	if err != nil {
		if isNoDocuments(err) {
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
	err := s.mdb.NewFind(&models).
		Filter(bson.M{"secret_key": key, "app_id": appID}).
		Sort(bson.D{{Key: "version", Value: 1}}).
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

	_, err := s.mdb.NewUpdate(m).
		Filter(bson.M{"key": f.Key, "app_id": f.AppID}).
		Upsert().
		Exec(ctx)
	return err
}

// GetFlagDefinition retrieves a flag definition.
func (s *Store) GetFlagDefinition(ctx context.Context, key, appID string) (*flag.Definition, error) {
	var m FlagModel
	err := s.mdb.NewFind(&m).
		Filter(bson.M{"key": key, "app_id": appID}).
		Scan(ctx)
	if err != nil {
		if isNoDocuments(err) {
			return nil, vault.ErrFlagNotFound
		}
		return nil, err
	}
	return m.toEntity(), nil
}

// ListFlagDefinitions returns all flag definitions for an app.
func (s *Store) ListFlagDefinitions(ctx context.Context, appID string, opts flag.ListOpts) ([]*flag.Definition, error) {
	var models []FlagModel
	q := s.mdb.NewFind(&models).
		Filter(bson.M{"app_id": appID}).
		Sort(bson.D{{Key: "key", Value: 1}})

	if opts.Limit > 0 {
		q = q.Limit(int64(opts.Limit))
	}
	if opts.Offset > 0 {
		q = q.Skip(int64(opts.Offset))
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
	res, err := s.mdb.NewDelete((*FlagModel)(nil)).
		Filter(bson.M{"key": key, "app_id": appID}).
		Exec(ctx)
	if err != nil {
		return err
	}
	if res.DeletedCount() == 0 {
		return vault.ErrFlagNotFound
	}

	// Delete associated rules and overrides.
	if _, err := s.mdb.NewDelete((*FlagRuleModel)(nil)).
		Many().
		Filter(bson.M{"flag_key": key, "app_id": appID}).
		Exec(ctx); err != nil {
		return err
	}
	if _, err := s.mdb.NewDelete((*FlagOverrideModel)(nil)).
		Many().
		Filter(bson.M{"flag_key": key, "app_id": appID}).
		Exec(ctx); err != nil {
		return err
	}

	return nil
}

// SetFlagRules replaces all targeting rules for a flag.
func (s *Store) SetFlagRules(ctx context.Context, key, appID string, rules []*flag.Rule) error {
	// Delete existing rules.
	if _, err := s.mdb.NewDelete((*FlagRuleModel)(nil)).
		Many().
		Filter(bson.M{"flag_key": key, "app_id": appID}).
		Exec(ctx); err != nil {
		return err
	}

	t := now()
	for _, r := range rules {
		ruleID := r.ID
		if ruleID.String() == "" {
			ruleID = id.NewRuleID()
		}

		m := &FlagRuleModel{
			ID: ruleID.String(), FlagKey: key, AppID: appID,
			Priority: r.Priority, Type: string(r.Type),
			Config: r.Config, ReturnValue: r.ReturnValue,
			CreatedAt: t, UpdatedAt: t,
		}
		if _, err := s.mdb.NewInsert(m).Exec(ctx); err != nil {
			return err
		}
	}

	return nil
}

// GetFlagRules returns targeting rules for a flag, ordered by priority.
func (s *Store) GetFlagRules(ctx context.Context, key, appID string) ([]*flag.Rule, error) {
	var models []FlagRuleModel
	err := s.mdb.NewFind(&models).
		Filter(bson.M{"flag_key": key, "app_id": appID}).
		Sort(bson.D{{Key: "priority", Value: 1}}).
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
	t := now()
	m := &FlagOverrideModel{
		ID: id.NewOverrideID().String(), FlagKey: key, AppID: appID,
		TenantID: tenantID, Value: value,
		CreatedAt: t, UpdatedAt: t,
	}

	_, err := s.mdb.NewUpdate(m).
		Filter(bson.M{"flag_key": key, "app_id": appID, "tenant_id": tenantID}).
		Upsert().
		Exec(ctx)
	return err
}

// GetFlagTenantOverride retrieves a tenant override for a flag.
func (s *Store) GetFlagTenantOverride(ctx context.Context, key, appID, tenantID string) (any, error) {
	var m FlagOverrideModel
	err := s.mdb.NewFind(&m).
		Filter(bson.M{"flag_key": key, "app_id": appID, "tenant_id": tenantID}).
		Scan(ctx)
	if err != nil {
		if isNoDocuments(err) {
			return nil, vault.ErrOverrideNotFound
		}
		return nil, err
	}
	return m.Value, nil
}

// DeleteFlagTenantOverride removes a tenant override.
func (s *Store) DeleteFlagTenantOverride(ctx context.Context, key, appID, tenantID string) error {
	res, err := s.mdb.NewDelete((*FlagOverrideModel)(nil)).
		Filter(bson.M{"flag_key": key, "app_id": appID, "tenant_id": tenantID}).
		Exec(ctx)
	if err != nil {
		return err
	}
	if res.DeletedCount() == 0 {
		return vault.ErrOverrideNotFound
	}
	return nil
}

// ListFlagTenantOverrides returns all tenant overrides for a flag.
func (s *Store) ListFlagTenantOverrides(ctx context.Context, key, appID string) ([]*flag.TenantOverride, error) {
	var models []FlagOverrideModel
	err := s.mdb.NewFind(&models).
		Filter(bson.M{"flag_key": key, "app_id": appID}).
		Sort(bson.D{{Key: "tenant_id", Value: 1}}).
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
	var m ConfigModel
	err := s.mdb.NewFind(&m).
		Filter(bson.M{"key": key, "app_id": appID}).
		Scan(ctx)
	if err != nil {
		if isNoDocuments(err) {
			return nil, vault.ErrConfigNotFound
		}
		return nil, err
	}
	return m.toEntity(), nil
}

// SetConfig creates or updates a config entry with auto-versioning.
func (s *Store) SetConfig(ctx context.Context, e *cfgpkg.Entry) error {
	// Get current version.
	var existing ConfigModel
	err := s.mdb.NewFind(&existing).
		Filter(bson.M{"key": e.Key, "app_id": e.AppID}).
		Scan(ctx)
	if err != nil && !isNoDocuments(err) {
		return err
	}

	if isNoDocuments(err) {
		if e.Version == 0 {
			e.Version = 1
		}
	} else {
		e.Version = existing.Version + 1
	}

	t := now()
	m := &ConfigModel{
		ID: e.ID.String(), Key: e.Key, Value: e.Value,
		ValueType: e.ValueType, Version: e.Version,
		Description: e.Description, AppID: e.AppID,
		Metadata: e.Metadata, CreatedAt: t, UpdatedAt: t,
	}

	_, err = s.mdb.NewUpdate(m).
		Filter(bson.M{"key": e.Key, "app_id": e.AppID}).
		Upsert().
		Exec(ctx)
	if err != nil {
		return err
	}

	// Append version record.
	vm := &ConfigVersionModel{
		ID: id.NewVersionID().String(), ConfigKey: e.Key, AppID: e.AppID,
		Version: e.Version, Value: e.Value, CreatedAt: t,
	}
	_, err = s.mdb.NewInsert(vm).Exec(ctx)
	return err
}

// DeleteConfig removes a config entry and all its versions.
func (s *Store) DeleteConfig(ctx context.Context, key, appID string) error {
	res, err := s.mdb.NewDelete((*ConfigModel)(nil)).
		Filter(bson.M{"key": key, "app_id": appID}).
		Exec(ctx)
	if err != nil {
		return err
	}
	if res.DeletedCount() == 0 {
		return vault.ErrConfigNotFound
	}

	_, err = s.mdb.NewDelete((*ConfigVersionModel)(nil)).
		Many().
		Filter(bson.M{"config_key": key, "app_id": appID}).
		Exec(ctx)
	return err
}

// ListConfig returns config entries for an app.
func (s *Store) ListConfig(ctx context.Context, appID string, opts cfgpkg.ListOpts) ([]*cfgpkg.Entry, error) {
	var models []ConfigModel
	q := s.mdb.NewFind(&models).
		Filter(bson.M{"app_id": appID}).
		Sort(bson.D{{Key: "key", Value: 1}})

	if opts.Limit > 0 {
		q = q.Limit(int64(opts.Limit))
	}
	if opts.Offset > 0 {
		q = q.Skip(int64(opts.Offset))
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

	var vm ConfigVersionModel
	err = s.mdb.NewFind(&vm).
		Filter(bson.M{"config_key": key, "app_id": appID, "version": version}).
		Scan(ctx)
	if err != nil {
		if isNoDocuments(err) {
			return nil, vault.ErrConfigNotFound
		}
		return nil, err
	}

	e.Version = version
	e.Value = vm.Value
	e.CreatedAt = vm.CreatedAt
	return e, nil
}

// ListConfigVersions returns all versions of a config entry.
func (s *Store) ListConfigVersions(ctx context.Context, key, appID string) ([]*cfgpkg.EntryVersion, error) {
	var models []ConfigVersionModel
	err := s.mdb.NewFind(&models).
		Filter(bson.M{"config_key": key, "app_id": appID}).
		Sort(bson.D{{Key: "version", Value: 1}}).
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
	var m OverrideModel
	err := s.mdb.NewFind(&m).
		Filter(bson.M{"key": key, "app_id": appID, "tenant_id": tenantID}).
		Scan(ctx)
	if err != nil {
		if isNoDocuments(err) {
			return nil, vault.ErrOverrideNotFound
		}
		return nil, err
	}
	return m.toEntity(), nil
}

// SetOverride creates or updates a tenant override.
func (s *Store) SetOverride(ctx context.Context, o *override.Override) error {
	t := now()
	m := &OverrideModel{
		ID: o.ID.String(), Key: o.Key, Value: o.Value,
		AppID: o.AppID, TenantID: o.TenantID,
		Metadata: o.Metadata, CreatedAt: t, UpdatedAt: t,
	}

	_, err := s.mdb.NewUpdate(m).
		Filter(bson.M{"key": o.Key, "app_id": o.AppID, "tenant_id": o.TenantID}).
		Upsert().
		Exec(ctx)
	return err
}

// DeleteOverride removes a tenant override.
func (s *Store) DeleteOverride(ctx context.Context, key, appID, tenantID string) error {
	res, err := s.mdb.NewDelete((*OverrideModel)(nil)).
		Filter(bson.M{"key": key, "app_id": appID, "tenant_id": tenantID}).
		Exec(ctx)
	if err != nil {
		return err
	}
	if res.DeletedCount() == 0 {
		return vault.ErrOverrideNotFound
	}
	return nil
}

// ListOverridesByTenant returns all overrides for a specific tenant.
func (s *Store) ListOverridesByTenant(ctx context.Context, appID, tenantID string) ([]*override.Override, error) {
	var models []OverrideModel
	err := s.mdb.NewFind(&models).
		Filter(bson.M{"app_id": appID, "tenant_id": tenantID}).
		Sort(bson.D{{Key: "key", Value: 1}}).
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
	err := s.mdb.NewFind(&models).
		Filter(bson.M{"key": key, "app_id": appID}).
		Sort(bson.D{{Key: "tenant_id", Value: 1}}).
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

	_, err := s.mdb.NewUpdate(m).
		Filter(bson.M{"secret_key": p.SecretKey, "app_id": p.AppID}).
		Upsert().
		Exec(ctx)
	return err
}

// GetRotationPolicy retrieves a rotation policy by secret key and app ID.
func (s *Store) GetRotationPolicy(ctx context.Context, key, appID string) (*rotation.Policy, error) {
	var m RotationPolicyModel
	err := s.mdb.NewFind(&m).
		Filter(bson.M{"secret_key": key, "app_id": appID}).
		Scan(ctx)
	if err != nil {
		if isNoDocuments(err) {
			return nil, vault.ErrRotationNotFound
		}
		return nil, err
	}
	return m.toEntity(), nil
}

// ListRotationPolicies returns all rotation policies for an app.
func (s *Store) ListRotationPolicies(ctx context.Context, appID string) ([]*rotation.Policy, error) {
	var models []RotationPolicyModel
	err := s.mdb.NewFind(&models).
		Filter(bson.M{"app_id": appID}).
		Sort(bson.D{{Key: "secret_key", Value: 1}}).
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
	res, err := s.mdb.NewDelete((*RotationPolicyModel)(nil)).
		Filter(bson.M{"secret_key": key, "app_id": appID}).
		Exec(ctx)
	if err != nil {
		return err
	}
	if res.DeletedCount() == 0 {
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
	_, err := s.mdb.NewInsert(m).Exec(ctx)
	return err
}

// ListRotationRecords returns rotation history for a secret.
func (s *Store) ListRotationRecords(ctx context.Context, key, appID string, opts rotation.ListOpts) ([]*rotation.Record, error) {
	var models []RotationRecordModel
	q := s.mdb.NewFind(&models).
		Filter(bson.M{"secret_key": key, "app_id": appID}).
		Sort(bson.D{{Key: "rotated_at", Value: -1}})

	if opts.Limit > 0 {
		q = q.Limit(int64(opts.Limit))
	}
	if opts.Offset > 0 {
		q = q.Skip(int64(opts.Offset))
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
	_, err := s.mdb.NewInsert(m).Exec(ctx)
	return err
}

// ListAudit returns audit entries for an app.
func (s *Store) ListAudit(ctx context.Context, appID string, opts audit.ListOpts) ([]*audit.Entry, error) {
	var models []AuditModel
	q := s.mdb.NewFind(&models).
		Filter(bson.M{"app_id": appID}).
		Sort(bson.D{{Key: "created_at", Value: -1}})

	if opts.Limit > 0 {
		q = q.Limit(int64(opts.Limit))
	}
	if opts.Offset > 0 {
		q = q.Skip(int64(opts.Offset))
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
	q := s.mdb.NewFind(&models).
		Filter(bson.M{"key": key, "app_id": appID}).
		Sort(bson.D{{Key: "created_at", Value: -1}})

	if opts.Limit > 0 {
		q = q.Limit(int64(opts.Limit))
	}
	if opts.Offset > 0 {
		q = q.Skip(int64(opts.Offset))
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
