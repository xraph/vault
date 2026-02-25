// Package sqlite provides a Grove ORM SQLite implementation of all Vault store interfaces.
package sqlite

import (
	"encoding/json"
	"time"

	"github.com/xraph/grove"

	"github.com/xraph/vault/audit"
	cfgpkg "github.com/xraph/vault/config"
	"github.com/xraph/vault/flag"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/override"
	"github.com/xraph/vault/rotation"
	"github.com/xraph/vault/secret"
)

// mustParseID parses a TypeID string from the database.
// IDs stored in the DB are always valid, so parse errors indicate data corruption.
func mustParseID(s string) id.ID {
	parsed, _ := id.Parse(s) //nolint:errcheck // DB IDs are always valid; zero ID on corruption is acceptable
	return parsed
}

// ──────────────────────────────────────────────────
// Secret models
// ──────────────────────────────────────────────────

// SecretModel is the Grove model for vault_secrets (SQLite).
type SecretModel struct {
	grove.BaseModel `grove:"table:vault_secrets,alias:s"`
	ID              string     `grove:"id,pk"`
	Key             string     `grove:"key,notnull"`
	AppID           string     `grove:"app_id,notnull"`
	EncryptedValue  []byte     `grove:"encrypted_value"`
	EncryptionAlg   string     `grove:"encryption_alg"`
	EncryptionKeyID string     `grove:"encryption_key_id"`
	Version         int64      `grove:"version,notnull"`
	Metadata        string     `grove:"metadata"`
	ExpiresAt       *time.Time `grove:"expires_at"`
	CreatedAt       time.Time  `grove:"created_at,notnull"`
	UpdatedAt       time.Time  `grove:"updated_at,notnull"`
}

func secretModelFromEntity(s *secret.Secret) *SecretModel {
	meta, _ := json.Marshal(s.Metadata) //nolint:errcheck // best-effort encode
	return &SecretModel{
		ID: s.ID.String(), Key: s.Key, AppID: s.AppID,
		EncryptedValue: s.EncryptedValue, EncryptionAlg: s.EncryptionAlg,
		EncryptionKeyID: s.EncryptionKeyID, Version: s.Version,
		Metadata: string(meta), ExpiresAt: s.ExpiresAt,
		CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt,
	}
}

func (m *SecretModel) toEntity() *secret.Secret {
	s := &secret.Secret{
		ID: mustParseID(m.ID), Key: m.Key, AppID: m.AppID,
		EncryptedValue: m.EncryptedValue, EncryptionAlg: m.EncryptionAlg,
		EncryptionKeyID: m.EncryptionKeyID, Version: m.Version,
		ExpiresAt: m.ExpiresAt,
	}
	s.CreatedAt = m.CreatedAt
	s.UpdatedAt = m.UpdatedAt
	if m.Metadata != "" {
		_ = json.Unmarshal([]byte(m.Metadata), &s.Metadata) //nolint:errcheck // best-effort decode
	}
	return s
}

func (m *SecretModel) toMeta() *secret.Meta {
	meta := &secret.Meta{
		ID: mustParseID(m.ID), Key: m.Key, Version: m.Version,
		ExpiresAt: m.ExpiresAt, AppID: m.AppID,
	}
	meta.CreatedAt = m.CreatedAt
	meta.UpdatedAt = m.UpdatedAt
	if m.Metadata != "" {
		_ = json.Unmarshal([]byte(m.Metadata), &meta.Metadata) //nolint:errcheck // best-effort decode
	}
	return meta
}

// SecretVersionModel is the Grove model for vault_secret_versions (SQLite).
type SecretVersionModel struct {
	grove.BaseModel `grove:"table:vault_secret_versions,alias:sv"`
	ID              string    `grove:"id,pk"`
	SecretKey       string    `grove:"secret_key,notnull"`
	AppID           string    `grove:"app_id,notnull"`
	Version         int64     `grove:"version,notnull"`
	EncryptedValue  []byte    `grove:"encrypted_value"`
	CreatedBy       string    `grove:"created_by"`
	CreatedAt       time.Time `grove:"created_at,notnull"`
}

func (m *SecretVersionModel) toEntity() *secret.Version {
	return &secret.Version{
		ID: mustParseID(m.ID), SecretKey: m.SecretKey, AppID: m.AppID,
		Version: m.Version, EncryptedValue: m.EncryptedValue,
		CreatedBy: m.CreatedBy, CreatedAt: m.CreatedAt,
	}
}

// ──────────────────────────────────────────────────
// Flag models
// ──────────────────────────────────────────────────

// FlagModel is the Grove model for vault_flags (SQLite).
type FlagModel struct {
	grove.BaseModel `grove:"table:vault_flags,alias:f"`
	ID              string    `grove:"id,pk"`
	Key             string    `grove:"key,notnull"`
	Type            string    `grove:"type,notnull"`
	DefaultValue    string    `grove:"default_value"`
	Description     string    `grove:"description"`
	Tags            string    `grove:"tags"`
	Variants        string    `grove:"variants"`
	Enabled         bool      `grove:"enabled,notnull"`
	AppID           string    `grove:"app_id,notnull"`
	Metadata        string    `grove:"metadata"`
	CreatedAt       time.Time `grove:"created_at,notnull"`
	UpdatedAt       time.Time `grove:"updated_at,notnull"`
}

func flagModelFromEntity(f *flag.Definition) *FlagModel {
	defaultJSON, _ := json.Marshal(f.DefaultValue) //nolint:errcheck // best-effort encode
	tagsJSON, _ := json.Marshal(f.Tags)            //nolint:errcheck // best-effort encode
	variantsJSON, _ := json.Marshal(f.Variants)    //nolint:errcheck // best-effort encode
	metaJSON, _ := json.Marshal(f.Metadata)        //nolint:errcheck // best-effort encode
	return &FlagModel{
		ID: f.ID.String(), Key: f.Key, Type: string(f.Type),
		DefaultValue: string(defaultJSON), Description: f.Description,
		Tags: string(tagsJSON), Variants: string(variantsJSON),
		Enabled: f.Enabled, AppID: f.AppID, Metadata: string(metaJSON),
		CreatedAt: f.CreatedAt, UpdatedAt: f.UpdatedAt,
	}
}

func (m *FlagModel) toEntity() *flag.Definition {
	f := &flag.Definition{
		ID: mustParseID(m.ID), Key: m.Key, Type: flag.Type(m.Type),
		Description: m.Description, Enabled: m.Enabled, AppID: m.AppID,
	}
	f.CreatedAt = m.CreatedAt
	f.UpdatedAt = m.UpdatedAt
	_ = json.Unmarshal([]byte(m.DefaultValue), &f.DefaultValue) //nolint:errcheck // best-effort decode
	_ = json.Unmarshal([]byte(m.Tags), &f.Tags)                 //nolint:errcheck // best-effort decode
	_ = json.Unmarshal([]byte(m.Variants), &f.Variants)         //nolint:errcheck // best-effort decode
	if m.Metadata != "" {
		_ = json.Unmarshal([]byte(m.Metadata), &f.Metadata) //nolint:errcheck // best-effort decode
	}
	return f
}

// FlagRuleModel is the Grove model for vault_flag_rules (SQLite).
type FlagRuleModel struct {
	grove.BaseModel `grove:"table:vault_flag_rules,alias:fr"`
	ID              string    `grove:"id,pk"`
	FlagKey         string    `grove:"flag_key,notnull"`
	AppID           string    `grove:"app_id,notnull"`
	Priority        int       `grove:"priority,notnull"`
	Type            string    `grove:"type,notnull"`
	Config          string    `grove:"config"`
	ReturnValue     string    `grove:"return_value"`
	CreatedAt       time.Time `grove:"created_at,notnull"`
	UpdatedAt       time.Time `grove:"updated_at,notnull"`
}

func (m *FlagRuleModel) toEntity() *flag.Rule {
	r := &flag.Rule{
		ID: mustParseID(m.ID), FlagKey: m.FlagKey, AppID: m.AppID,
		Priority: m.Priority, Type: flag.RuleType(m.Type),
	}
	r.CreatedAt = m.CreatedAt
	r.UpdatedAt = m.UpdatedAt
	_ = json.Unmarshal([]byte(m.Config), &r.Config)           //nolint:errcheck // best-effort decode
	_ = json.Unmarshal([]byte(m.ReturnValue), &r.ReturnValue) //nolint:errcheck // best-effort decode
	return r
}

// FlagOverrideModel is the Grove model for vault_flag_overrides (SQLite).
type FlagOverrideModel struct {
	grove.BaseModel `grove:"table:vault_flag_overrides,alias:fo"`
	ID              string    `grove:"id,pk"`
	FlagKey         string    `grove:"flag_key,notnull"`
	AppID           string    `grove:"app_id,notnull"`
	TenantID        string    `grove:"tenant_id,notnull"`
	Value           string    `grove:"value"`
	CreatedAt       time.Time `grove:"created_at,notnull"`
	UpdatedAt       time.Time `grove:"updated_at,notnull"`
}

func (m *FlagOverrideModel) toEntity() *flag.TenantOverride {
	o := &flag.TenantOverride{
		ID: mustParseID(m.ID), FlagKey: m.FlagKey,
		AppID: m.AppID, TenantID: m.TenantID,
	}
	o.CreatedAt = m.CreatedAt
	o.UpdatedAt = m.UpdatedAt
	_ = json.Unmarshal([]byte(m.Value), &o.Value) //nolint:errcheck // best-effort decode
	return o
}

// ──────────────────────────────────────────────────
// Config models
// ──────────────────────────────────────────────────

// ConfigModel is the Grove model for vault_config (SQLite).
type ConfigModel struct {
	grove.BaseModel `grove:"table:vault_config,alias:c"`
	ID              string    `grove:"id,pk"`
	Key             string    `grove:"key,notnull"`
	Value           string    `grove:"value"`
	ValueType       string    `grove:"value_type"`
	Version         int64     `grove:"version,notnull"`
	Description     string    `grove:"description"`
	AppID           string    `grove:"app_id,notnull"`
	Metadata        string    `grove:"metadata"`
	CreatedAt       time.Time `grove:"created_at,notnull"`
	UpdatedAt       time.Time `grove:"updated_at,notnull"`
}

func (m *ConfigModel) toEntity() *cfgpkg.Entry {
	e := &cfgpkg.Entry{
		ID: mustParseID(m.ID), Key: m.Key, ValueType: m.ValueType,
		Version: m.Version, Description: m.Description, AppID: m.AppID,
	}
	e.CreatedAt = m.CreatedAt
	e.UpdatedAt = m.UpdatedAt
	_ = json.Unmarshal([]byte(m.Value), &e.Value) //nolint:errcheck // best-effort decode
	if m.Metadata != "" {
		_ = json.Unmarshal([]byte(m.Metadata), &e.Metadata) //nolint:errcheck // best-effort decode
	}
	return e
}

// ConfigVersionModel is the Grove model for vault_config_versions (SQLite).
type ConfigVersionModel struct {
	grove.BaseModel `grove:"table:vault_config_versions,alias:cv"`
	ID              string    `grove:"id,pk"`
	ConfigKey       string    `grove:"config_key,notnull"`
	AppID           string    `grove:"app_id,notnull"`
	Version         int64     `grove:"version,notnull"`
	Value           string    `grove:"value"`
	CreatedBy       string    `grove:"created_by"`
	CreatedAt       time.Time `grove:"created_at,notnull"`
}

func (m *ConfigVersionModel) toEntity() *cfgpkg.EntryVersion {
	v := &cfgpkg.EntryVersion{
		ID: mustParseID(m.ID), ConfigKey: m.ConfigKey,
		AppID: m.AppID, Version: m.Version,
		CreatedBy: m.CreatedBy, CreatedAt: m.CreatedAt,
	}
	_ = json.Unmarshal([]byte(m.Value), &v.Value) //nolint:errcheck // best-effort decode
	return v
}

// ──────────────────────────────────────────────────
// Override model
// ──────────────────────────────────────────────────

// OverrideModel is the Grove model for vault_overrides (SQLite).
type OverrideModel struct {
	grove.BaseModel `grove:"table:vault_overrides,alias:ov"`
	ID              string    `grove:"id,pk"`
	Key             string    `grove:"key,notnull"`
	Value           string    `grove:"value"`
	AppID           string    `grove:"app_id,notnull"`
	TenantID        string    `grove:"tenant_id,notnull"`
	Metadata        string    `grove:"metadata"`
	CreatedAt       time.Time `grove:"created_at,notnull"`
	UpdatedAt       time.Time `grove:"updated_at,notnull"`
}

func (m *OverrideModel) toEntity() *override.Override {
	o := &override.Override{
		ID: mustParseID(m.ID), Key: m.Key,
		AppID: m.AppID, TenantID: m.TenantID,
	}
	o.CreatedAt = m.CreatedAt
	o.UpdatedAt = m.UpdatedAt
	_ = json.Unmarshal([]byte(m.Value), &o.Value) //nolint:errcheck // best-effort decode
	if m.Metadata != "" {
		_ = json.Unmarshal([]byte(m.Metadata), &o.Metadata) //nolint:errcheck // best-effort decode
	}
	return o
}

// ──────────────────────────────────────────────────
// Rotation models
// ──────────────────────────────────────────────────

// RotationPolicyModel is the Grove model for vault_rotation_policies (SQLite).
type RotationPolicyModel struct {
	grove.BaseModel `grove:"table:vault_rotation_policies,alias:rp"`
	ID              string     `grove:"id,pk"`
	SecretKey       string     `grove:"secret_key,notnull"`
	AppID           string     `grove:"app_id,notnull"`
	IntervalNS      int64      `grove:"interval_ns,notnull"`
	Enabled         bool       `grove:"enabled,notnull"`
	LastRotatedAt   *time.Time `grove:"last_rotated_at"`
	NextRotationAt  *time.Time `grove:"next_rotation_at"`
	CreatedAt       time.Time  `grove:"created_at,notnull"`
	UpdatedAt       time.Time  `grove:"updated_at,notnull"`
}

func rotationPolicyModelFromEntity(p *rotation.Policy) *RotationPolicyModel {
	return &RotationPolicyModel{
		ID: p.ID.String(), SecretKey: p.SecretKey, AppID: p.AppID,
		IntervalNS: int64(p.Interval), Enabled: p.Enabled,
		LastRotatedAt: p.LastRotatedAt, NextRotationAt: p.NextRotationAt,
		CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt,
	}
}

func (m *RotationPolicyModel) toEntity() *rotation.Policy {
	p := &rotation.Policy{
		ID: mustParseID(m.ID), SecretKey: m.SecretKey, AppID: m.AppID,
		Interval: time.Duration(m.IntervalNS), Enabled: m.Enabled,
		LastRotatedAt: m.LastRotatedAt, NextRotationAt: m.NextRotationAt,
	}
	p.CreatedAt = m.CreatedAt
	p.UpdatedAt = m.UpdatedAt
	return p
}

// RotationRecordModel is the Grove model for vault_rotation_records (SQLite).
type RotationRecordModel struct {
	grove.BaseModel `grove:"table:vault_rotation_records,alias:rr"`
	ID              string    `grove:"id,pk"`
	SecretKey       string    `grove:"secret_key,notnull"`
	AppID           string    `grove:"app_id,notnull"`
	OldVersion      int64     `grove:"old_version,notnull"`
	NewVersion      int64     `grove:"new_version,notnull"`
	RotatedBy       string    `grove:"rotated_by"`
	RotatedAt       time.Time `grove:"rotated_at,notnull"`
}

func (m *RotationRecordModel) toEntity() *rotation.Record {
	return &rotation.Record{
		ID: mustParseID(m.ID), SecretKey: m.SecretKey, AppID: m.AppID,
		OldVersion: m.OldVersion, NewVersion: m.NewVersion,
		RotatedBy: m.RotatedBy, RotatedAt: m.RotatedAt,
	}
}

// ──────────────────────────────────────────────────
// Audit model
// ──────────────────────────────────────────────────

// AuditModel is the Grove model for vault_audit (SQLite).
type AuditModel struct {
	grove.BaseModel `grove:"table:vault_audit,alias:a"`
	ID              string    `grove:"id,pk"`
	Action          string    `grove:"action,notnull"`
	Resource        string    `grove:"resource,notnull"`
	Key             string    `grove:"key"`
	AppID           string    `grove:"app_id"`
	TenantID        string    `grove:"tenant_id"`
	UserID          string    `grove:"user_id"`
	IP              string    `grove:"ip"`
	Outcome         string    `grove:"outcome"`
	Metadata        string    `grove:"metadata"`
	CreatedAt       time.Time `grove:"created_at,notnull"`
}

func auditModelFromEntity(e *audit.Entry) *AuditModel {
	meta, _ := json.Marshal(e.Metadata) //nolint:errcheck // best-effort encode
	return &AuditModel{
		ID: e.ID.String(), Action: e.Action, Resource: e.Resource,
		Key: e.Key, AppID: e.AppID, TenantID: e.TenantID,
		UserID: e.UserID, IP: e.IP, Outcome: e.Outcome,
		Metadata: string(meta), CreatedAt: e.CreatedAt,
	}
}

func (m *AuditModel) toEntity() *audit.Entry {
	e := &audit.Entry{
		ID: mustParseID(m.ID), Action: m.Action, Resource: m.Resource,
		Key: m.Key, AppID: m.AppID, TenantID: m.TenantID,
		UserID: m.UserID, IP: m.IP, Outcome: m.Outcome,
		CreatedAt: m.CreatedAt,
	}
	if m.Metadata != "" {
		_ = json.Unmarshal([]byte(m.Metadata), &e.Metadata) //nolint:errcheck // best-effort decode
	}
	return e
}
