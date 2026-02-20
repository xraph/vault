// Package memory provides a fully in-memory implementation of store.Store.
// Safe for concurrent access. Intended for unit testing and development.
package memory

import (
	"context"
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/xraph/vault"
	"github.com/xraph/vault/audit"
	"github.com/xraph/vault/config"
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
	_ config.Store   = (*Store)(nil)
	_ override.Store = (*Store)(nil)
	_ rotation.Store = (*Store)(nil)
	_ audit.Store    = (*Store)(nil)
)

// Store is a fully in-memory implementation of store.Store.
type Store struct {
	mu sync.RWMutex

	// Secrets: keyed by "key:appID"
	secrets        map[string]*secret.Secret
	secretVersions map[string][]*secret.Version // key: "key:appID"

	// Flags: keyed by "key:appID"
	flags         map[string]*flag.Definition
	flagRules     map[string][]*flag.Rule         // key: "key:appID"
	flagOverrides map[string]*flag.TenantOverride // key: "key:appID:tenantID"

	// Config: keyed by "key:appID"
	configs        map[string]*config.Entry
	configVersions map[string][]*config.EntryVersion // key: "key:appID"

	// Overrides: keyed by "key:appID:tenantID"
	overrides map[string]*override.Override

	// Rotation: keyed by "key:appID"
	rotationPolicies map[string]*rotation.Policy
	rotationRecords  map[string][]*rotation.Record // key: "key:appID"

	// Audit entries
	auditEntries []*audit.Entry
}

// New returns a new empty Store.
func New() *Store {
	return &Store{
		secrets:          make(map[string]*secret.Secret),
		secretVersions:   make(map[string][]*secret.Version),
		flags:            make(map[string]*flag.Definition),
		flagRules:        make(map[string][]*flag.Rule),
		flagOverrides:    make(map[string]*flag.TenantOverride),
		configs:          make(map[string]*config.Entry),
		configVersions:   make(map[string][]*config.EntryVersion),
		overrides:        make(map[string]*override.Override),
		rotationPolicies: make(map[string]*rotation.Policy),
		rotationRecords:  make(map[string][]*rotation.Record),
	}
}

// ──────────────────────────────────────────────────
// Lifecycle — Migrate / Ping / Close
// ──────────────────────────────────────────────────

// Migrate is a no-op for the memory store.
func (m *Store) Migrate(_ context.Context) error { return nil }

// Ping always succeeds for the memory store.
func (m *Store) Ping(_ context.Context) error { return nil }

// Close is a no-op for the memory store.
func (m *Store) Close() error { return nil }

// ──────────────────────────────────────────────────
// Secret Store
// ──────────────────────────────────────────────────

func sKey(key, appID string) string { return key + ":" + appID }

// GetSecret retrieves the latest version of a secret by key and app ID.
func (m *Store) GetSecret(_ context.Context, key, appID string) (*secret.Secret, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	s, ok := m.secrets[sKey(key, appID)]
	if !ok {
		return nil, vault.ErrSecretNotFound
	}
	cp := *s
	return &cp, nil
}

// SetSecret creates or updates a secret with auto-versioning.
func (m *Store) SetSecret(_ context.Context, s *secret.Secret) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	k := sKey(s.Key, s.AppID)

	// Auto-version: if secret exists, increment version.
	if existing, ok := m.secrets[k]; ok {
		s.Version = existing.Version + 1
	} else if s.Version == 0 {
		s.Version = 1
	}

	// Store the current version as a version record.
	ver := &secret.Version{
		ID:             id.NewVersionID(),
		SecretKey:      s.Key,
		AppID:          s.AppID,
		Version:        s.Version,
		EncryptedValue: copyBytes(s.EncryptedValue),
		CreatedAt:      time.Now().UTC(),
	}
	m.secretVersions[k] = append(m.secretVersions[k], ver)

	cp := *s
	cp.EncryptedValue = copyBytes(s.EncryptedValue)
	cp.Value = copyBytes(s.Value)
	m.secrets[k] = &cp
	return nil
}

// DeleteSecret removes a secret and all its versions.
func (m *Store) DeleteSecret(_ context.Context, key, appID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	k := sKey(key, appID)
	if _, ok := m.secrets[k]; !ok {
		return vault.ErrSecretNotFound
	}
	delete(m.secrets, k)
	delete(m.secretVersions, k)
	return nil
}

// ListSecrets returns secret metadata for an app.
func (m *Store) ListSecrets(_ context.Context, appID string, opts secret.ListOpts) ([]*secret.Meta, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*secret.Meta, 0, len(m.secrets))
	for _, s := range m.secrets {
		if s.AppID != appID {
			continue
		}
		result = append(result, s.ToMeta())
	}

	sort.Slice(result, func(i, j int) bool { return result[i].Key < result[j].Key })
	return applyPagination(result, opts.Offset, opts.Limit), nil
}

// GetSecretVersion retrieves a specific version of a secret.
func (m *Store) GetSecretVersion(_ context.Context, key, appID string, version int64) (*secret.Secret, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	k := sKey(key, appID)
	versions, ok := m.secretVersions[k]
	if !ok {
		return nil, vault.ErrSecretNotFound
	}
	for _, v := range versions {
		if v.Version != version {
			continue
		}
		s, exists := m.secrets[k]
		if !exists {
			return nil, vault.ErrSecretNotFound
		}
		cp := *s
		cp.Version = v.Version
		cp.EncryptedValue = copyBytes(v.EncryptedValue)
		cp.CreatedAt = v.CreatedAt
		return &cp, nil
	}
	return nil, vault.ErrSecretNotFound
}

// ListSecretVersions returns all versions of a secret.
func (m *Store) ListSecretVersions(_ context.Context, key, appID string) ([]*secret.Version, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	k := sKey(key, appID)
	versions := m.secretVersions[k]
	if len(versions) == 0 {
		return nil, nil
	}

	result := make([]*secret.Version, len(versions))
	for i, v := range versions {
		cp := *v
		cp.EncryptedValue = copyBytes(v.EncryptedValue)
		result[i] = &cp
	}
	return result, nil
}

// ──────────────────────────────────────────────────
// Flag Store
// ──────────────────────────────────────────────────

func fKey(key, appID string) string { return key + ":" + appID }

// DefineFlag creates or updates a flag definition.
func (m *Store) DefineFlag(_ context.Context, f *flag.Definition) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cp := *f
	m.flags[fKey(f.Key, f.AppID)] = &cp
	return nil
}

// GetFlagDefinition retrieves a flag definition by key and app ID.
func (m *Store) GetFlagDefinition(_ context.Context, key, appID string) (*flag.Definition, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	f, ok := m.flags[fKey(key, appID)]
	if !ok {
		return nil, vault.ErrFlagNotFound
	}
	cp := *f
	return &cp, nil
}

// ListFlagDefinitions returns all flag definitions for an app.
func (m *Store) ListFlagDefinitions(_ context.Context, appID string, opts flag.ListOpts) ([]*flag.Definition, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*flag.Definition, 0, len(m.flags))
	for _, f := range m.flags {
		if f.AppID != appID {
			continue
		}
		cp := *f
		result = append(result, &cp)
	}

	sort.Slice(result, func(i, j int) bool { return result[i].Key < result[j].Key })
	return applyPaginationDef(result, opts.Offset, opts.Limit), nil
}

// DeleteFlagDefinition removes a flag definition and its rules.
func (m *Store) DeleteFlagDefinition(_ context.Context, key, appID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	k := fKey(key, appID)
	if _, ok := m.flags[k]; !ok {
		return vault.ErrFlagNotFound
	}
	delete(m.flags, k)
	delete(m.flagRules, k)

	// Clean up tenant overrides for this flag.
	prefix := key + ":" + appID + ":"
	for ok := range m.flagOverrides {
		if len(ok) >= len(prefix) && ok[:len(prefix)] == prefix {
			delete(m.flagOverrides, ok)
		}
	}
	return nil
}

// SetFlagRules replaces all targeting rules for a flag.
func (m *Store) SetFlagRules(_ context.Context, key, appID string, rules []*flag.Rule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	k := fKey(key, appID)
	if _, ok := m.flags[k]; !ok {
		return vault.ErrFlagNotFound
	}

	copied := make([]*flag.Rule, len(rules))
	for i, r := range rules {
		cp := *r
		copied[i] = &cp
	}

	sort.Slice(copied, func(i, j int) bool { return copied[i].Priority < copied[j].Priority })
	m.flagRules[k] = copied
	return nil
}

// GetFlagRules returns targeting rules for a flag, ordered by priority.
func (m *Store) GetFlagRules(_ context.Context, key, appID string) ([]*flag.Rule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	k := fKey(key, appID)
	rules := m.flagRules[k]
	if len(rules) == 0 {
		return nil, nil
	}

	result := make([]*flag.Rule, len(rules))
	for i, r := range rules {
		cp := *r
		result[i] = &cp
	}
	return result, nil
}

func foKey(key, appID, tenantID string) string {
	return key + ":" + appID + ":" + tenantID
}

// SetFlagTenantOverride sets a direct per-tenant override value.
func (m *Store) SetFlagTenantOverride(_ context.Context, key, appID, tenantID string, value any) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	k := foKey(key, appID, tenantID)
	now := time.Now().UTC()

	existing, ok := m.flagOverrides[k]
	if ok {
		existing.Value = deepCopyValue(value)
		existing.UpdatedAt = now
		return nil
	}

	m.flagOverrides[k] = &flag.TenantOverride{
		Entity:   vault.Entity{CreatedAt: now, UpdatedAt: now},
		ID:       id.NewOverrideID(),
		FlagKey:  key,
		AppID:    appID,
		TenantID: tenantID,
		Value:    deepCopyValue(value),
	}
	return nil
}

// GetFlagTenantOverride retrieves a tenant override for a flag.
func (m *Store) GetFlagTenantOverride(_ context.Context, key, appID, tenantID string) (any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	o, ok := m.flagOverrides[foKey(key, appID, tenantID)]
	if !ok {
		return nil, vault.ErrOverrideNotFound
	}
	return o.Value, nil
}

// DeleteFlagTenantOverride removes a tenant override.
func (m *Store) DeleteFlagTenantOverride(_ context.Context, key, appID, tenantID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	k := foKey(key, appID, tenantID)
	if _, ok := m.flagOverrides[k]; !ok {
		return vault.ErrOverrideNotFound
	}
	delete(m.flagOverrides, k)
	return nil
}

// ListFlagTenantOverrides returns all tenant overrides for a flag.
func (m *Store) ListFlagTenantOverrides(_ context.Context, key, appID string) ([]*flag.TenantOverride, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	prefix := key + ":" + appID + ":"
	var result []*flag.TenantOverride
	for k, o := range m.flagOverrides {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			cp := *o
			result = append(result, &cp)
		}
	}
	return result, nil
}

// ──────────────────────────────────────────────────
// Config Store
// ──────────────────────────────────────────────────

func cKey(key, appID string) string { return key + ":" + appID }

// GetConfig retrieves a config entry by key and app ID.
func (m *Store) GetConfig(_ context.Context, key, appID string) (*config.Entry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	e, ok := m.configs[cKey(key, appID)]
	if !ok {
		return nil, vault.ErrConfigNotFound
	}
	cp := *e
	return &cp, nil
}

// SetConfig creates or updates a config entry with auto-versioning.
func (m *Store) SetConfig(_ context.Context, e *config.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	k := cKey(e.Key, e.AppID)

	if existing, ok := m.configs[k]; ok {
		e.Version = existing.Version + 1
	} else if e.Version == 0 {
		e.Version = 1
	}

	ver := &config.EntryVersion{
		ID:        id.NewVersionID(),
		ConfigKey: e.Key,
		AppID:     e.AppID,
		Version:   e.Version,
		Value:     deepCopyValue(e.Value),
		CreatedAt: time.Now().UTC(),
	}
	m.configVersions[k] = append(m.configVersions[k], ver)

	cp := *e
	m.configs[k] = &cp
	return nil
}

// DeleteConfig removes a config entry.
func (m *Store) DeleteConfig(_ context.Context, key, appID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	k := cKey(key, appID)
	if _, ok := m.configs[k]; !ok {
		return vault.ErrConfigNotFound
	}
	delete(m.configs, k)
	delete(m.configVersions, k)
	return nil
}

// ListConfig returns config entries for an app.
func (m *Store) ListConfig(_ context.Context, appID string, opts config.ListOpts) ([]*config.Entry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*config.Entry, 0, len(m.configs))
	for _, e := range m.configs {
		if e.AppID != appID {
			continue
		}
		cp := *e
		result = append(result, &cp)
	}

	sort.Slice(result, func(i, j int) bool { return result[i].Key < result[j].Key })
	return applyPaginationCfg(result, opts.Offset, opts.Limit), nil
}

// GetConfigVersion retrieves a specific version of a config entry.
func (m *Store) GetConfigVersion(_ context.Context, key, appID string, version int64) (*config.Entry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	k := cKey(key, appID)
	versions := m.configVersions[k]
	for _, v := range versions {
		if v.Version != version {
			continue
		}
		e, exists := m.configs[k]
		if !exists {
			return nil, vault.ErrConfigNotFound
		}
		cp := *e
		cp.Version = v.Version
		cp.Value = deepCopyValue(v.Value)
		cp.CreatedAt = v.CreatedAt
		return &cp, nil
	}
	return nil, vault.ErrConfigNotFound
}

// ListConfigVersions returns all versions of a config entry.
func (m *Store) ListConfigVersions(_ context.Context, key, appID string) ([]*config.EntryVersion, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	k := cKey(key, appID)
	versions := m.configVersions[k]
	if len(versions) == 0 {
		return nil, nil
	}

	result := make([]*config.EntryVersion, len(versions))
	for i, v := range versions {
		cp := *v
		result[i] = &cp
	}
	return result, nil
}

// ──────────────────────────────────────────────────
// Override Store
// ──────────────────────────────────────────────────

func oKey(key, appID, tenantID string) string { return key + ":" + appID + ":" + tenantID }

// GetOverride retrieves a tenant override by key, app ID, and tenant ID.
func (m *Store) GetOverride(_ context.Context, key, appID, tenantID string) (*override.Override, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	o, ok := m.overrides[oKey(key, appID, tenantID)]
	if !ok {
		return nil, vault.ErrOverrideNotFound
	}
	cp := *o
	return &cp, nil
}

// SetOverride creates or updates a tenant override.
func (m *Store) SetOverride(_ context.Context, o *override.Override) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cp := *o
	m.overrides[oKey(o.Key, o.AppID, o.TenantID)] = &cp
	return nil
}

// DeleteOverride removes a tenant override.
func (m *Store) DeleteOverride(_ context.Context, key, appID, tenantID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	k := oKey(key, appID, tenantID)
	if _, ok := m.overrides[k]; !ok {
		return vault.ErrOverrideNotFound
	}
	delete(m.overrides, k)
	return nil
}

// ListOverridesByTenant returns all overrides for a specific tenant.
func (m *Store) ListOverridesByTenant(_ context.Context, appID, tenantID string) ([]*override.Override, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*override.Override
	for _, o := range m.overrides {
		if o.AppID == appID && o.TenantID == tenantID {
			cp := *o
			result = append(result, &cp)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Key < result[j].Key })
	return result, nil
}

// ListOverridesByKey returns all tenant overrides for a specific config key.
func (m *Store) ListOverridesByKey(_ context.Context, key, appID string) ([]*override.Override, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*override.Override
	for _, o := range m.overrides {
		if o.Key == key && o.AppID == appID {
			cp := *o
			result = append(result, &cp)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].TenantID < result[j].TenantID })
	return result, nil
}

// ──────────────────────────────────────────────────
// Rotation Store
// ──────────────────────────────────────────────────

func rKey(key, appID string) string { return key + ":" + appID }

// SaveRotationPolicy creates or updates a rotation policy.
func (m *Store) SaveRotationPolicy(_ context.Context, p *rotation.Policy) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cp := *p
	m.rotationPolicies[rKey(p.SecretKey, p.AppID)] = &cp
	return nil
}

// GetRotationPolicy retrieves a rotation policy by secret key and app ID.
func (m *Store) GetRotationPolicy(_ context.Context, key, appID string) (*rotation.Policy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	p, ok := m.rotationPolicies[rKey(key, appID)]
	if !ok {
		return nil, vault.ErrRotationNotFound
	}
	cp := *p
	return &cp, nil
}

// ListRotationPolicies returns all rotation policies for an app.
func (m *Store) ListRotationPolicies(_ context.Context, appID string) ([]*rotation.Policy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*rotation.Policy, 0, len(m.rotationPolicies))
	for _, p := range m.rotationPolicies {
		if p.AppID != appID {
			continue
		}
		cp := *p
		result = append(result, &cp)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].SecretKey < result[j].SecretKey })
	return result, nil
}

// DeleteRotationPolicy removes a rotation policy.
func (m *Store) DeleteRotationPolicy(_ context.Context, key, appID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	k := rKey(key, appID)
	if _, ok := m.rotationPolicies[k]; !ok {
		return vault.ErrRotationNotFound
	}
	delete(m.rotationPolicies, k)
	return nil
}

// RecordRotation records a completed rotation event.
func (m *Store) RecordRotation(_ context.Context, r *rotation.Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	k := rKey(r.SecretKey, r.AppID)
	cp := *r
	m.rotationRecords[k] = append(m.rotationRecords[k], &cp)
	return nil
}

// ListRotationRecords returns rotation history for a secret.
func (m *Store) ListRotationRecords(_ context.Context, key, appID string, opts rotation.ListOpts) ([]*rotation.Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	k := rKey(key, appID)
	records := m.rotationRecords[k]
	if len(records) == 0 {
		return nil, nil
	}

	result := make([]*rotation.Record, len(records))
	for i, r := range records {
		cp := *r
		result[i] = &cp
	}

	sort.Slice(result, func(i, j int) bool { return result[i].RotatedAt.After(result[j].RotatedAt) })

	if opts.Offset > 0 && opts.Offset < len(result) {
		result = result[opts.Offset:]
	} else if opts.Offset >= len(result) {
		return nil, nil
	}
	if opts.Limit > 0 && opts.Limit < len(result) {
		result = result[:opts.Limit]
	}

	return result, nil
}

// ──────────────────────────────────────────────────
// Audit Store
// ──────────────────────────────────────────────────

// RecordAudit persists an audit log entry.
func (m *Store) RecordAudit(_ context.Context, e *audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cp := *e
	m.auditEntries = append(m.auditEntries, &cp)
	return nil
}

// ListAudit returns audit entries for an app.
func (m *Store) ListAudit(_ context.Context, appID string, opts audit.ListOpts) ([]*audit.Entry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*audit.Entry, 0, len(m.auditEntries))
	for _, e := range m.auditEntries {
		if e.AppID != appID {
			continue
		}
		cp := *e
		result = append(result, &cp)
	}

	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.After(result[j].CreatedAt) })

	if opts.Offset > 0 && opts.Offset < len(result) {
		result = result[opts.Offset:]
	} else if opts.Offset >= len(result) {
		return nil, nil
	}
	if opts.Limit > 0 && opts.Limit < len(result) {
		result = result[:opts.Limit]
	}

	return result, nil
}

// ListAuditByKey returns audit entries for a specific key within an app.
func (m *Store) ListAuditByKey(_ context.Context, key, appID string, opts audit.ListOpts) ([]*audit.Entry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*audit.Entry, 0, len(m.auditEntries))
	for _, e := range m.auditEntries {
		if e.AppID != appID || e.Key != key {
			continue
		}
		cp := *e
		result = append(result, &cp)
	}

	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.After(result[j].CreatedAt) })

	if opts.Offset > 0 && opts.Offset < len(result) {
		result = result[opts.Offset:]
	} else if opts.Offset >= len(result) {
		return nil, nil
	}
	if opts.Limit > 0 && opts.Limit < len(result) {
		result = result[:opts.Limit]
	}

	return result, nil
}

// ──────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────

func copyBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	return cp
}

func deepCopyValue(v any) any {
	if v == nil {
		return nil
	}
	data, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var cp any
	if err := json.Unmarshal(data, &cp); err != nil {
		return v
	}
	return cp
}

func applyPagination(result []*secret.Meta, offset, limit int) []*secret.Meta {
	if offset > 0 && offset < len(result) {
		result = result[offset:]
	} else if offset >= len(result) {
		return nil
	}
	if limit > 0 && limit < len(result) {
		result = result[:limit]
	}
	return result
}

func applyPaginationDef(result []*flag.Definition, offset, limit int) []*flag.Definition {
	if offset > 0 && offset < len(result) {
		result = result[offset:]
	} else if offset >= len(result) {
		return nil
	}
	if limit > 0 && limit < len(result) {
		result = result[:limit]
	}
	return result
}

func applyPaginationCfg(result []*config.Entry, offset, limit int) []*config.Entry {
	if offset > 0 && offset < len(result) {
		result = result[offset:]
	} else if offset >= len(result) {
		return nil
	}
	if limit > 0 && limit < len(result) {
		result = result[:limit]
	}
	return result
}
