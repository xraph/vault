// Package mongo provides a Grove ORM MongoDB implementation of all Vault store interfaces.
package mongo

import (
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

// SecretModel is the Grove model for vault_secrets (MongoDB).
type SecretModel struct {
	grove.BaseModel `grove:"table:vault_secrets"`
	ID              string            `grove:"id,pk"              bson:"_id"`
	Key             string            `grove:"key,notnull"        bson:"key"`
	AppID           string            `grove:"app_id,notnull"     bson:"app_id"`
	EncryptedValue  []byte            `grove:"encrypted_value"    bson:"encrypted_value"`
	EncryptionAlg   string            `grove:"encryption_alg"     bson:"encryption_alg"`
	EncryptionKeyID string            `grove:"encryption_key_id"  bson:"encryption_key_id"`
	Version         int64             `grove:"version,notnull"    bson:"version"`
	Metadata        map[string]string `grove:"metadata"           bson:"metadata,omitempty"`
	ExpiresAt       *time.Time        `grove:"expires_at"         bson:"expires_at,omitempty"`
	CreatedAt       time.Time         `grove:"created_at,notnull" bson:"created_at"`
	UpdatedAt       time.Time         `grove:"updated_at,notnull" bson:"updated_at"`
}

func secretModelFromEntity(s *secret.Secret) *SecretModel {
	return &SecretModel{
		ID: s.ID.String(), Key: s.Key, AppID: s.AppID,
		EncryptedValue: s.EncryptedValue, EncryptionAlg: s.EncryptionAlg,
		EncryptionKeyID: s.EncryptionKeyID, Version: s.Version,
		Metadata: s.Metadata, ExpiresAt: s.ExpiresAt,
		CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt,
	}
}

func (m *SecretModel) toEntity() *secret.Secret {
	s := &secret.Secret{
		ID: mustParseID(m.ID), Key: m.Key, AppID: m.AppID,
		EncryptedValue: m.EncryptedValue, EncryptionAlg: m.EncryptionAlg,
		EncryptionKeyID: m.EncryptionKeyID, Version: m.Version,
		Metadata: m.Metadata, ExpiresAt: m.ExpiresAt,
	}
	s.CreatedAt = m.CreatedAt
	s.UpdatedAt = m.UpdatedAt
	return s
}

func (m *SecretModel) toMeta() *secret.Meta {
	meta := &secret.Meta{
		ID: mustParseID(m.ID), Key: m.Key, Version: m.Version,
		ExpiresAt: m.ExpiresAt, AppID: m.AppID,
		Metadata: m.Metadata,
	}
	meta.CreatedAt = m.CreatedAt
	meta.UpdatedAt = m.UpdatedAt
	return meta
}

// SecretVersionModel is the Grove model for vault_secret_versions (MongoDB).
type SecretVersionModel struct {
	grove.BaseModel `grove:"table:vault_secret_versions"`
	ID              string    `grove:"id,pk"              bson:"_id"`
	SecretKey       string    `grove:"secret_key,notnull" bson:"secret_key"`
	AppID           string    `grove:"app_id,notnull"     bson:"app_id"`
	Version         int64     `grove:"version,notnull"    bson:"version"`
	EncryptedValue  []byte    `grove:"encrypted_value"    bson:"encrypted_value"`
	CreatedBy       string    `grove:"created_by"         bson:"created_by"`
	CreatedAt       time.Time `grove:"created_at,notnull" bson:"created_at"`
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

// FlagModel is the Grove model for vault_flags (MongoDB).
type FlagModel struct {
	grove.BaseModel `grove:"table:vault_flags"`
	ID              string            `grove:"id,pk"              bson:"_id"`
	Key             string            `grove:"key,notnull"        bson:"key"`
	Type            string            `grove:"type,notnull"       bson:"type"`
	DefaultValue    any               `grove:"default_value"      bson:"default_value"`
	Description     string            `grove:"description"        bson:"description"`
	Tags            []string          `grove:"tags"               bson:"tags,omitempty"`
	Variants        []flag.Variant    `grove:"variants"           bson:"variants,omitempty"`
	Enabled         bool              `grove:"enabled,notnull"    bson:"enabled"`
	AppID           string            `grove:"app_id,notnull"     bson:"app_id"`
	Metadata        map[string]string `grove:"metadata"           bson:"metadata,omitempty"`
	CreatedAt       time.Time         `grove:"created_at,notnull" bson:"created_at"`
	UpdatedAt       time.Time         `grove:"updated_at,notnull" bson:"updated_at"`
}

func flagModelFromEntity(f *flag.Definition) *FlagModel {
	return &FlagModel{
		ID: f.ID.String(), Key: f.Key, Type: string(f.Type),
		DefaultValue: f.DefaultValue, Description: f.Description,
		Tags: f.Tags, Variants: f.Variants,
		Enabled: f.Enabled, AppID: f.AppID, Metadata: f.Metadata,
		CreatedAt: f.CreatedAt, UpdatedAt: f.UpdatedAt,
	}
}

func (m *FlagModel) toEntity() *flag.Definition {
	f := &flag.Definition{
		ID: mustParseID(m.ID), Key: m.Key, Type: flag.Type(m.Type),
		DefaultValue: m.DefaultValue, Description: m.Description,
		Tags: m.Tags, Variants: m.Variants,
		Enabled: m.Enabled, AppID: m.AppID, Metadata: m.Metadata,
	}
	f.CreatedAt = m.CreatedAt
	f.UpdatedAt = m.UpdatedAt
	return f
}

// FlagRuleModel is the Grove model for vault_flag_rules (MongoDB).
type FlagRuleModel struct {
	grove.BaseModel `grove:"table:vault_flag_rules"`
	ID              string          `grove:"id,pk"              bson:"_id"`
	FlagKey         string          `grove:"flag_key,notnull"   bson:"flag_key"`
	AppID           string          `grove:"app_id,notnull"     bson:"app_id"`
	Priority        int             `grove:"priority,notnull"   bson:"priority"`
	Type            string          `grove:"type,notnull"       bson:"type"`
	Config          flag.RuleConfig `grove:"config"             bson:"config,omitempty"`
	ReturnValue     any             `grove:"return_value"       bson:"return_value"`
	CreatedAt       time.Time       `grove:"created_at,notnull" bson:"created_at"`
	UpdatedAt       time.Time       `grove:"updated_at,notnull" bson:"updated_at"`
}

func (m *FlagRuleModel) toEntity() *flag.Rule {
	r := &flag.Rule{
		ID: mustParseID(m.ID), FlagKey: m.FlagKey, AppID: m.AppID,
		Priority: m.Priority, Type: flag.RuleType(m.Type),
		Config: m.Config, ReturnValue: m.ReturnValue,
	}
	r.CreatedAt = m.CreatedAt
	r.UpdatedAt = m.UpdatedAt
	return r
}

// FlagOverrideModel is the Grove model for vault_flag_overrides (MongoDB).
type FlagOverrideModel struct {
	grove.BaseModel `grove:"table:vault_flag_overrides"`
	ID              string    `grove:"id,pk"              bson:"_id"`
	FlagKey         string    `grove:"flag_key,notnull"   bson:"flag_key"`
	AppID           string    `grove:"app_id,notnull"     bson:"app_id"`
	TenantID        string    `grove:"tenant_id,notnull"  bson:"tenant_id"`
	Value           any       `grove:"value"              bson:"value"`
	CreatedAt       time.Time `grove:"created_at,notnull" bson:"created_at"`
	UpdatedAt       time.Time `grove:"updated_at,notnull" bson:"updated_at"`
}

func (m *FlagOverrideModel) toEntity() *flag.TenantOverride {
	o := &flag.TenantOverride{
		ID: mustParseID(m.ID), FlagKey: m.FlagKey,
		AppID: m.AppID, TenantID: m.TenantID,
		Value: m.Value,
	}
	o.CreatedAt = m.CreatedAt
	o.UpdatedAt = m.UpdatedAt
	return o
}

// ──────────────────────────────────────────────────
// Config models
// ──────────────────────────────────────────────────

// ConfigModel is the Grove model for vault_config (MongoDB).
type ConfigModel struct {
	grove.BaseModel `grove:"table:vault_config"`
	ID              string            `grove:"id,pk"              bson:"_id"`
	Key             string            `grove:"key,notnull"        bson:"key"`
	Value           any               `grove:"value"              bson:"value"`
	ValueType       string            `grove:"value_type"         bson:"value_type"`
	Version         int64             `grove:"version,notnull"    bson:"version"`
	Description     string            `grove:"description"        bson:"description"`
	AppID           string            `grove:"app_id,notnull"     bson:"app_id"`
	Metadata        map[string]string `grove:"metadata"           bson:"metadata,omitempty"`
	CreatedAt       time.Time         `grove:"created_at,notnull" bson:"created_at"`
	UpdatedAt       time.Time         `grove:"updated_at,notnull" bson:"updated_at"`
}

func (m *ConfigModel) toEntity() *cfgpkg.Entry {
	e := &cfgpkg.Entry{
		ID: mustParseID(m.ID), Key: m.Key, Value: m.Value,
		ValueType: m.ValueType, Version: m.Version,
		Description: m.Description, AppID: m.AppID, Metadata: m.Metadata,
	}
	e.CreatedAt = m.CreatedAt
	e.UpdatedAt = m.UpdatedAt
	return e
}

// ConfigVersionModel is the Grove model for vault_config_versions (MongoDB).
type ConfigVersionModel struct {
	grove.BaseModel `grove:"table:vault_config_versions"`
	ID              string    `grove:"id,pk"              bson:"_id"`
	ConfigKey       string    `grove:"config_key,notnull" bson:"config_key"`
	AppID           string    `grove:"app_id,notnull"     bson:"app_id"`
	Version         int64     `grove:"version,notnull"    bson:"version"`
	Value           any       `grove:"value"              bson:"value"`
	CreatedBy       string    `grove:"created_by"         bson:"created_by"`
	CreatedAt       time.Time `grove:"created_at,notnull" bson:"created_at"`
}

func (m *ConfigVersionModel) toEntity() *cfgpkg.EntryVersion {
	return &cfgpkg.EntryVersion{
		ID: mustParseID(m.ID), ConfigKey: m.ConfigKey,
		AppID: m.AppID, Version: m.Version,
		Value: m.Value, CreatedBy: m.CreatedBy, CreatedAt: m.CreatedAt,
	}
}

// ──────────────────────────────────────────────────
// Override model
// ──────────────────────────────────────────────────

// OverrideModel is the Grove model for vault_overrides (MongoDB).
type OverrideModel struct {
	grove.BaseModel `grove:"table:vault_overrides"`
	ID              string            `grove:"id,pk"              bson:"_id"`
	Key             string            `grove:"key,notnull"        bson:"key"`
	Value           any               `grove:"value"              bson:"value"`
	AppID           string            `grove:"app_id,notnull"     bson:"app_id"`
	TenantID        string            `grove:"tenant_id,notnull"  bson:"tenant_id"`
	Metadata        map[string]string `grove:"metadata"           bson:"metadata,omitempty"`
	CreatedAt       time.Time         `grove:"created_at,notnull" bson:"created_at"`
	UpdatedAt       time.Time         `grove:"updated_at,notnull" bson:"updated_at"`
}

func (m *OverrideModel) toEntity() *override.Override {
	o := &override.Override{
		ID: mustParseID(m.ID), Key: m.Key,
		Value: m.Value, AppID: m.AppID, TenantID: m.TenantID,
		Metadata: m.Metadata,
	}
	o.CreatedAt = m.CreatedAt
	o.UpdatedAt = m.UpdatedAt
	return o
}

// ──────────────────────────────────────────────────
// Rotation models
// ──────────────────────────────────────────────────

// RotationPolicyModel is the Grove model for vault_rotation_policies (MongoDB).
type RotationPolicyModel struct {
	grove.BaseModel `grove:"table:vault_rotation_policies"`
	ID              string     `grove:"id,pk"                bson:"_id"`
	SecretKey       string     `grove:"secret_key,notnull"   bson:"secret_key"`
	AppID           string     `grove:"app_id,notnull"       bson:"app_id"`
	IntervalNS      int64      `grove:"interval_ns,notnull"  bson:"interval_ns"`
	Enabled         bool       `grove:"enabled,notnull"      bson:"enabled"`
	LastRotatedAt   *time.Time `grove:"last_rotated_at"      bson:"last_rotated_at,omitempty"`
	NextRotationAt  *time.Time `grove:"next_rotation_at"     bson:"next_rotation_at,omitempty"`
	CreatedAt       time.Time  `grove:"created_at,notnull"   bson:"created_at"`
	UpdatedAt       time.Time  `grove:"updated_at,notnull"   bson:"updated_at"`
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

// RotationRecordModel is the Grove model for vault_rotation_records (MongoDB).
type RotationRecordModel struct {
	grove.BaseModel `grove:"table:vault_rotation_records"`
	ID              string    `grove:"id,pk"              bson:"_id"`
	SecretKey       string    `grove:"secret_key,notnull" bson:"secret_key"`
	AppID           string    `grove:"app_id,notnull"     bson:"app_id"`
	OldVersion      int64     `grove:"old_version,notnull" bson:"old_version"`
	NewVersion      int64     `grove:"new_version,notnull" bson:"new_version"`
	RotatedBy       string    `grove:"rotated_by"         bson:"rotated_by"`
	RotatedAt       time.Time `grove:"rotated_at,notnull" bson:"rotated_at"`
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

// AuditModel is the Grove model for vault_audit (MongoDB).
type AuditModel struct {
	grove.BaseModel `grove:"table:vault_audit"`
	ID              string         `grove:"id,pk"              bson:"_id"`
	Action          string         `grove:"action,notnull"     bson:"action"`
	Resource        string         `grove:"resource,notnull"   bson:"resource"`
	Key             string         `grove:"key"                bson:"key"`
	AppID           string         `grove:"app_id"             bson:"app_id"`
	TenantID        string         `grove:"tenant_id"          bson:"tenant_id"`
	UserID          string         `grove:"user_id"            bson:"user_id"`
	IP              string         `grove:"ip"                 bson:"ip"`
	Outcome         string         `grove:"outcome"            bson:"outcome"`
	Metadata        map[string]any `grove:"metadata"           bson:"metadata,omitempty"`
	CreatedAt       time.Time      `grove:"created_at,notnull" bson:"created_at"`
}

func auditModelFromEntity(e *audit.Entry) *AuditModel {
	return &AuditModel{
		ID: e.ID.String(), Action: e.Action, Resource: e.Resource,
		Key: e.Key, AppID: e.AppID, TenantID: e.TenantID,
		UserID: e.UserID, IP: e.IP, Outcome: e.Outcome,
		Metadata: e.Metadata, CreatedAt: e.CreatedAt,
	}
}

func (m *AuditModel) toEntity() *audit.Entry {
	return &audit.Entry{
		ID: mustParseID(m.ID), Action: m.Action, Resource: m.Resource,
		Key: m.Key, AppID: m.AppID, TenantID: m.TenantID,
		UserID: m.UserID, IP: m.IP, Outcome: m.Outcome,
		Metadata: m.Metadata, CreatedAt: m.CreatedAt,
	}
}
