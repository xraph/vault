//go:build integration

package bunstore_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"

	"github.com/xraph/vault"
	"github.com/xraph/vault/audit"
	"github.com/xraph/vault/config"
	"github.com/xraph/vault/flag"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/override"
	"github.com/xraph/vault/rotation"
	"github.com/xraph/vault/secret"
	bunstore "github.com/xraph/vault/store/bun"
)

// testStore returns a migrated Bun Store for integration tests.
// Set VAULT_TEST_PG_URL to a Postgres connection string.
func testStore(t *testing.T) *bunstore.Store {
	t.Helper()

	connStr := os.Getenv("VAULT_TEST_PG_URL")
	if connStr == "" {
		t.Skip("VAULT_TEST_PG_URL not set; skipping integration test")
	}

	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(connStr)))
	db := bun.NewDB(sqldb, pgdialect.New())
	t.Cleanup(func() { db.Close() })

	ctx := context.Background()
	s := bunstore.New(db)

	// Run migrations.
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Clean tables for a fresh run.
	tables := []string{
		"vault_secret_versions", "vault_secrets",
		"vault_flag_overrides", "vault_flag_rules", "vault_flags",
		"vault_config_versions", "vault_config",
		"vault_overrides",
		"vault_rotation_records", "vault_rotation_policies",
		"vault_audit",
	}
	for _, tbl := range tables {
		if _, err := db.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s", tbl)); err != nil {
			t.Fatalf("clean %s: %v", tbl, err)
		}
	}

	return s
}

// ──────────────────────────────────────────────────
// Secret store
// ──────────────────────────────────────────────────

func TestSecretCRUD(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	sec := &secret.Secret{
		ID:              id.New(),
		Key:             "db-password",
		AppID:           "app1",
		EncryptedValue:  []byte("encrypted-v1"),
		EncryptionAlg:   "aes-256-gcm",
		EncryptionKeyID: "key-1",
		Metadata:        map[string]string{"env": "prod"},
	}

	// Set.
	if err := s.SetSecret(ctx, sec); err != nil {
		t.Fatalf("SetSecret: %v", err)
	}
	if sec.Version != 1 {
		t.Errorf("version: got %d, want 1", sec.Version)
	}

	// Get.
	got, err := s.GetSecret(ctx, "db-password", "app1")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if got.Key != "db-password" {
		t.Errorf("key: got %q", got.Key)
	}

	// Update.
	sec.EncryptedValue = []byte("encrypted-v2")
	if err := s.SetSecret(ctx, sec); err != nil {
		t.Fatalf("SetSecret v2: %v", err)
	}
	if sec.Version != 2 {
		t.Errorf("version: got %d, want 2", sec.Version)
	}

	// List.
	metas, err := s.ListSecrets(ctx, "app1", secret.ListOpts{})
	if err != nil {
		t.Fatalf("ListSecrets: %v", err)
	}
	if len(metas) != 1 {
		t.Errorf("list: got %d, want 1", len(metas))
	}

	// Versions.
	versions, err := s.ListSecretVersions(ctx, "db-password", "app1")
	if err != nil {
		t.Fatalf("ListSecretVersions: %v", err)
	}
	if len(versions) != 2 {
		t.Errorf("versions: got %d, want 2", len(versions))
	}

	// Get specific version.
	v1, err := s.GetSecretVersion(ctx, "db-password", "app1", 1)
	if err != nil {
		t.Fatalf("GetSecretVersion: %v", err)
	}
	if string(v1.EncryptedValue) != "encrypted-v1" {
		t.Errorf("v1 value: got %q", v1.EncryptedValue)
	}

	// Delete.
	if err := s.DeleteSecret(ctx, "db-password", "app1"); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}

	// Not found.
	_, err = s.GetSecret(ctx, "db-password", "app1")
	if err != vault.ErrSecretNotFound {
		t.Errorf("err: got %v, want ErrSecretNotFound", err)
	}
}

// ──────────────────────────────────────────────────
// Flag store
// ──────────────────────────────────────────────────

func TestFlagCRUD(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	def := &flag.Definition{
		ID:           id.New(),
		Key:          "dark-mode",
		Type:         "boolean",
		DefaultValue: true,
		Description:  "Enable dark mode",
		Tags:         []string{"ui"},
		Enabled:      true,
		AppID:        "app1",
		Metadata:     map[string]string{"team": "frontend"},
	}

	// Define.
	if err := s.DefineFlag(ctx, def); err != nil {
		t.Fatalf("DefineFlag: %v", err)
	}

	// Get.
	got, err := s.GetFlagDefinition(ctx, "dark-mode", "app1")
	if err != nil {
		t.Fatalf("GetFlagDefinition: %v", err)
	}
	if got.Key != "dark-mode" {
		t.Errorf("key: got %q", got.Key)
	}

	// List.
	defs, err := s.ListFlagDefinitions(ctx, "app1", flag.ListOpts{})
	if err != nil {
		t.Fatalf("ListFlagDefinitions: %v", err)
	}
	if len(defs) != 1 {
		t.Errorf("list: got %d, want 1", len(defs))
	}

	// Rules.
	rules := []*flag.Rule{
		{ID: id.New(), FlagKey: "dark-mode", AppID: "app1", Type: "percentage", Priority: 1,
			Config: flag.RuleConfig{Percentage: intPtr(50)}, ReturnValue: true},
	}
	if err := s.SetFlagRules(ctx, "dark-mode", "app1", rules); err != nil {
		t.Fatalf("SetFlagRules: %v", err)
	}

	gotRules, err := s.GetFlagRules(ctx, "dark-mode", "app1")
	if err != nil {
		t.Fatalf("GetFlagRules: %v", err)
	}
	if len(gotRules) != 1 {
		t.Errorf("rules: got %d, want 1", len(gotRules))
	}

	// Tenant override.
	if err := s.SetFlagTenantOverride(ctx, "dark-mode", "app1", "tenant1", false); err != nil {
		t.Fatalf("SetFlagTenantOverride: %v", err)
	}

	gotFO, err := s.GetFlagTenantOverride(ctx, "dark-mode", "app1", "tenant1")
	if err != nil {
		t.Fatalf("GetFlagTenantOverride: %v", err)
	}
	if gotFO != false {
		t.Errorf("value: got %v, want false", gotFO)
	}

	overrides, err := s.ListFlagTenantOverrides(ctx, "dark-mode", "app1")
	if err != nil {
		t.Fatalf("ListFlagTenantOverrides: %v", err)
	}
	if len(overrides) != 1 {
		t.Errorf("overrides: got %d, want 1", len(overrides))
	}

	// Delete override.
	if err := s.DeleteFlagTenantOverride(ctx, "dark-mode", "app1", "tenant1"); err != nil {
		t.Fatalf("DeleteFlagTenantOverride: %v", err)
	}

	// Delete flag.
	if err := s.DeleteFlagDefinition(ctx, "dark-mode", "app1"); err != nil {
		t.Fatalf("DeleteFlagDefinition: %v", err)
	}

	_, err = s.GetFlagDefinition(ctx, "dark-mode", "app1")
	if err != vault.ErrFlagNotFound {
		t.Errorf("err: got %v, want ErrFlagNotFound", err)
	}
}

// ──────────────────────────────────────────────────
// Config store
// ──────────────────────────────────────────────────

func TestConfigCRUD(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	entry := &config.Entry{
		ID:          id.New(),
		Key:         "pool.size",
		Value:       10,
		ValueType:   "int",
		Description: "Connection pool size",
		AppID:       "app1",
		Metadata:    map[string]string{"unit": "connections"},
	}

	// Set.
	if err := s.SetConfig(ctx, entry); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	if entry.Version != 1 {
		t.Errorf("version: got %d, want 1", entry.Version)
	}

	// Get.
	got, err := s.GetConfig(ctx, "pool.size", "app1")
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if got.Key != "pool.size" {
		t.Errorf("key: got %q", got.Key)
	}

	// Update → version 2.
	entry.Value = 20
	if err := s.SetConfig(ctx, entry); err != nil {
		t.Fatalf("SetConfig v2: %v", err)
	}
	if entry.Version != 2 {
		t.Errorf("version: got %d, want 2", entry.Version)
	}

	// List.
	entries, err := s.ListConfig(ctx, "app1", config.ListOpts{})
	if err != nil {
		t.Fatalf("ListConfig: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("list: got %d, want 1", len(entries))
	}

	// Versions.
	versions, err := s.ListConfigVersions(ctx, "pool.size", "app1")
	if err != nil {
		t.Fatalf("ListConfigVersions: %v", err)
	}
	if len(versions) != 2 {
		t.Errorf("versions: got %d, want 2", len(versions))
	}

	// Get specific version.
	v1, err := s.GetConfigVersion(ctx, "pool.size", "app1", 1)
	if err != nil {
		t.Fatalf("GetConfigVersion: %v", err)
	}
	if v1.Version != 1 {
		t.Errorf("v1 version: got %d", v1.Version)
	}

	// Delete.
	if err := s.DeleteConfig(ctx, "pool.size", "app1"); err != nil {
		t.Fatalf("DeleteConfig: %v", err)
	}

	_, err = s.GetConfig(ctx, "pool.size", "app1")
	if err != vault.ErrConfigNotFound {
		t.Errorf("err: got %v, want ErrConfigNotFound", err)
	}
}

// ──────────────────────────────────────────────────
// Override store
// ──────────────────────────────────────────────────

func TestOverrideCRUD(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	o := &override.Override{
		ID:       id.New(),
		Key:      "pool.size",
		Value:    50,
		AppID:    "app1",
		TenantID: "tenant1",
		Metadata: map[string]string{"reason": "high traffic"},
	}

	// Set.
	if err := s.SetOverride(ctx, o); err != nil {
		t.Fatalf("SetOverride: %v", err)
	}

	// Get.
	got, err := s.GetOverride(ctx, "pool.size", "app1", "tenant1")
	if err != nil {
		t.Fatalf("GetOverride: %v", err)
	}
	if got.TenantID != "tenant1" {
		t.Errorf("tenant: got %q", got.TenantID)
	}

	// List by tenant.
	byTenant, err := s.ListOverridesByTenant(ctx, "app1", "tenant1")
	if err != nil {
		t.Fatalf("ListOverridesByTenant: %v", err)
	}
	if len(byTenant) != 1 {
		t.Errorf("by tenant: got %d, want 1", len(byTenant))
	}

	// List by key.
	byKey, err := s.ListOverridesByKey(ctx, "pool.size", "app1")
	if err != nil {
		t.Fatalf("ListOverridesByKey: %v", err)
	}
	if len(byKey) != 1 {
		t.Errorf("by key: got %d, want 1", len(byKey))
	}

	// Delete.
	if err := s.DeleteOverride(ctx, "pool.size", "app1", "tenant1"); err != nil {
		t.Fatalf("DeleteOverride: %v", err)
	}

	_, err = s.GetOverride(ctx, "pool.size", "app1", "tenant1")
	if err != vault.ErrOverrideNotFound {
		t.Errorf("err: got %v, want ErrOverrideNotFound", err)
	}
}

// ──────────────────────────────────────────────────
// Rotation store
// ──────────────────────────────────────────────────

func TestRotationCRUD(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	now := time.Now().UTC()
	next := now.Add(24 * time.Hour)

	policy := &rotation.Policy{
		ID:             id.New(),
		SecretKey:      "api-key",
		AppID:          "app1",
		Interval:       24 * time.Hour,
		Enabled:        true,
		LastRotatedAt:  &now,
		NextRotationAt: &next,
	}

	// Save.
	if err := s.SaveRotationPolicy(ctx, policy); err != nil {
		t.Fatalf("SaveRotationPolicy: %v", err)
	}

	// Get.
	got, err := s.GetRotationPolicy(ctx, "api-key", "app1")
	if err != nil {
		t.Fatalf("GetRotationPolicy: %v", err)
	}
	if got.Interval != 24*time.Hour {
		t.Errorf("interval: got %v", got.Interval)
	}
	if !got.Enabled {
		t.Error("enabled: got false")
	}

	// List.
	policies, err := s.ListRotationPolicies(ctx, "app1")
	if err != nil {
		t.Fatalf("ListRotationPolicies: %v", err)
	}
	if len(policies) != 1 {
		t.Errorf("policies: got %d, want 1", len(policies))
	}

	// Record.
	rec := &rotation.Record{
		ID:         id.New(),
		SecretKey:  "api-key",
		AppID:      "app1",
		OldVersion: 1,
		NewVersion: 2,
		RotatedBy:  "system",
		RotatedAt:  now,
	}
	if err := s.RecordRotation(ctx, rec); err != nil {
		t.Fatalf("RecordRotation: %v", err)
	}

	records, err := s.ListRotationRecords(ctx, "api-key", "app1", rotation.ListOpts{})
	if err != nil {
		t.Fatalf("ListRotationRecords: %v", err)
	}
	if len(records) != 1 {
		t.Errorf("records: got %d, want 1", len(records))
	}
	if records[0].OldVersion != 1 || records[0].NewVersion != 2 {
		t.Errorf("record versions: got %d→%d", records[0].OldVersion, records[0].NewVersion)
	}

	// Delete policy.
	if err := s.DeleteRotationPolicy(ctx, "api-key", "app1"); err != nil {
		t.Fatalf("DeleteRotationPolicy: %v", err)
	}

	_, err = s.GetRotationPolicy(ctx, "api-key", "app1")
	if err != vault.ErrRotationNotFound {
		t.Errorf("err: got %v, want ErrRotationNotFound", err)
	}
}

// ──────────────────────────────────────────────────
// Audit store
// ──────────────────────────────────────────────────

func TestAuditCRUD(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	entry := &audit.Entry{
		ID:        id.New(),
		Action:    "secret.accessed",
		Resource:  "secret",
		Key:       "db-password",
		AppID:     "app1",
		TenantID:  "t1",
		UserID:    "u1",
		IP:        "10.0.0.1",
		Outcome:   "success",
		Metadata:  map[string]any{"source": "api"},
		CreatedAt: time.Now().UTC(),
	}

	// Record.
	if err := s.RecordAudit(ctx, entry); err != nil {
		t.Fatalf("RecordAudit: %v", err)
	}

	// List by app.
	entries, err := s.ListAudit(ctx, "app1", audit.ListOpts{})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("entries: got %d, want 1", len(entries))
	}

	// List by key.
	byKey, err := s.ListAuditByKey(ctx, "db-password", "app1", audit.ListOpts{})
	if err != nil {
		t.Fatalf("ListAuditByKey: %v", err)
	}
	if len(byKey) != 1 {
		t.Errorf("by key: got %d, want 1", len(byKey))
	}

	// Verify fields.
	got := entries[0]
	if got.Action != "secret.accessed" {
		t.Errorf("action: got %q", got.Action)
	}
	if got.TenantID != "t1" {
		t.Errorf("tenant: got %q", got.TenantID)
	}
	if got.Outcome != "success" {
		t.Errorf("outcome: got %q", got.Outcome)
	}
}

// ──────────────────────────────────────────────────
// Ping
// ──────────────────────────────────────────────────

func TestPing(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	if err := s.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestMigrateIdempotent(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Second migration should be a no-op.
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate (idempotent): %v", err)
	}
}

// helpers

func intPtr(v int) *int { return &v }
