package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xraph/vault"
	"github.com/xraph/vault/audit"
	"github.com/xraph/vault/config"
	"github.com/xraph/vault/flag"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/override"
	"github.com/xraph/vault/rotation"
	"github.com/xraph/vault/secret"
	"github.com/xraph/vault/store/memory"
)

func newStore() *memory.Store { return memory.New() }
func bg() context.Context     { return context.Background() }

const testApp = "app_test"

func timePtr(t time.Time) *time.Time { return &t }

// ──────────────────────────────────────────────────
// Lifecycle
// ──────────────────────────────────────────────────

func TestLifecycle(t *testing.T) {
	s := newStore()
	if err := s.Migrate(bg()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if err := s.Ping(bg()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// ──────────────────────────────────────────────────
// Secret Store
// ──────────────────────────────────────────────────

func TestSecretCRUD(t *testing.T) {
	s := newStore()

	// Set a secret.
	sec := &secret.Secret{
		Entity:         vault.NewEntity(),
		ID:             id.NewSecretID(),
		Key:            "db-password",
		Value:          []byte("plaintext"),
		EncryptedValue: []byte("encrypted-data"),
		AppID:          testApp,
		Metadata:       map[string]string{"env": "prod"},
	}
	if err := s.SetSecret(bg(), sec); err != nil {
		t.Fatalf("SetSecret: %v", err)
	}

	// Get the secret.
	got, err := s.GetSecret(bg(), "db-password", testApp)
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if got.Key != "db-password" {
		t.Errorf("Key = %q, want %q", got.Key, "db-password")
	}
	if got.Version != 1 {
		t.Errorf("Version = %d, want 1", got.Version)
	}
	if string(got.EncryptedValue) != "encrypted-data" {
		t.Errorf("EncryptedValue = %q, want %q", got.EncryptedValue, "encrypted-data")
	}

	// Get returns copy (mutating doesn't affect store).
	got.Key = "mutated"
	got2, _ := s.GetSecret(bg(), "db-password", testApp)
	if got2.Key != "db-password" {
		t.Error("store returned reference instead of copy")
	}

	// Delete the secret.
	delErr := s.DeleteSecret(bg(), "db-password", testApp)
	if delErr != nil {
		t.Fatalf("DeleteSecret: %v", delErr)
	}

	// Get after delete.
	_, err = s.GetSecret(bg(), "db-password", testApp)
	if !errors.Is(err, vault.ErrSecretNotFound) {
		t.Errorf("GetSecret after delete: got %v, want ErrSecretNotFound", err)
	}

	// Delete non-existent.
	delErr = s.DeleteSecret(bg(), "no-such-key", testApp)
	if !errors.Is(delErr, vault.ErrSecretNotFound) {
		t.Errorf("DeleteSecret non-existent: got %v, want ErrSecretNotFound", delErr)
	}
}

func TestSecretAutoVersioning(t *testing.T) {
	s := newStore()

	sec := &secret.Secret{
		Entity:         vault.NewEntity(),
		ID:             id.NewSecretID(),
		Key:            "api-key",
		EncryptedValue: []byte("v1"),
		AppID:          testApp,
	}
	if err := s.SetSecret(bg(), sec); err != nil {
		t.Fatal(err)
	}

	// Second set → version 2.
	sec2 := &secret.Secret{
		Entity:         vault.NewEntity(),
		ID:             id.NewSecretID(),
		Key:            "api-key",
		EncryptedValue: []byte("v2"),
		AppID:          testApp,
	}
	if err := s.SetSecret(bg(), sec2); err != nil {
		t.Fatal(err)
	}

	got, _ := s.GetSecret(bg(), "api-key", testApp)
	if got.Version != 2 {
		t.Errorf("Version = %d, want 2", got.Version)
	}

	// Get version 1.
	v1, err := s.GetSecretVersion(bg(), "api-key", testApp, 1)
	if err != nil {
		t.Fatalf("GetSecretVersion(1): %v", err)
	}
	if v1.Version != 1 {
		t.Errorf("v1.Version = %d, want 1", v1.Version)
	}
	if string(v1.EncryptedValue) != "v1" {
		t.Errorf("v1.EncryptedValue = %q, want %q", v1.EncryptedValue, "v1")
	}

	// List versions.
	versions, err := s.ListSecretVersions(bg(), "api-key", testApp)
	if err != nil {
		t.Fatalf("ListSecretVersions: %v", err)
	}
	if len(versions) != 2 {
		t.Errorf("len(versions) = %d, want 2", len(versions))
	}

	// Non-existent version.
	_, err = s.GetSecretVersion(bg(), "api-key", testApp, 99)
	if !errors.Is(err, vault.ErrSecretNotFound) {
		t.Errorf("GetSecretVersion(99): got %v, want ErrSecretNotFound", err)
	}
}

func TestSecretList(t *testing.T) {
	s := newStore()

	for _, key := range []string{"c-key", "a-key", "b-key"} {
		_ = s.SetSecret(bg(), &secret.Secret{
			Entity:         vault.NewEntity(),
			ID:             id.NewSecretID(),
			Key:            key,
			EncryptedValue: []byte("data"),
			AppID:          testApp,
		})
	}

	// Also add secret for different app — should NOT appear.
	_ = s.SetSecret(bg(), &secret.Secret{
		Entity:         vault.NewEntity(),
		ID:             id.NewSecretID(),
		Key:            "other-key",
		EncryptedValue: []byte("data"),
		AppID:          "other_app",
	})

	list, err := s.ListSecrets(bg(), testApp, secret.ListOpts{})
	if err != nil {
		t.Fatalf("ListSecrets: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("len = %d, want 3", len(list))
	}
	// Should be sorted by key.
	if list[0].Key != "a-key" || list[1].Key != "b-key" || list[2].Key != "c-key" {
		t.Errorf("order = [%s, %s, %s], want [a-key, b-key, c-key]", list[0].Key, list[1].Key, list[2].Key)
	}

	// Pagination.
	page, _ := s.ListSecrets(bg(), testApp, secret.ListOpts{Offset: 1, Limit: 1})
	if len(page) != 1 || page[0].Key != "b-key" {
		t.Errorf("pagination: got %v, want [b-key]", page)
	}
}

// ──────────────────────────────────────────────────
// Flag Store
// ──────────────────────────────────────────────────

func TestFlagDefinitionCRUD(t *testing.T) {
	s := newStore()

	def := &flag.Definition{
		Entity:       vault.NewEntity(),
		ID:           id.NewFlagID(),
		Key:          "dark-mode",
		Type:         flag.TypeBool,
		DefaultValue: false,
		Description:  "Enable dark mode",
		Enabled:      true,
		AppID:        testApp,
	}
	if err := s.DefineFlag(bg(), def); err != nil {
		t.Fatalf("DefineFlag: %v", err)
	}

	got, err := s.GetFlagDefinition(bg(), "dark-mode", testApp)
	if err != nil {
		t.Fatalf("GetFlagDefinition: %v", err)
	}
	if got.Key != "dark-mode" || got.Type != flag.TypeBool {
		t.Errorf("got = %+v", got)
	}

	// Update the definition.
	def.Description = "Updated description"
	updateErr := s.DefineFlag(bg(), def)
	if updateErr != nil {
		t.Fatalf("DefineFlag update: %v", updateErr)
	}
	got2, _ := s.GetFlagDefinition(bg(), "dark-mode", testApp)
	if got2.Description != "Updated description" {
		t.Errorf("Description = %q, want %q", got2.Description, "Updated description")
	}

	// Delete.
	delErr := s.DeleteFlagDefinition(bg(), "dark-mode", testApp)
	if delErr != nil {
		t.Fatalf("DeleteFlagDefinition: %v", delErr)
	}
	_, err = s.GetFlagDefinition(bg(), "dark-mode", testApp)
	if !errors.Is(err, vault.ErrFlagNotFound) {
		t.Errorf("GetFlagDefinition after delete: got %v, want ErrFlagNotFound", err)
	}

	// Delete non-existent.
	delErr = s.DeleteFlagDefinition(bg(), "no-flag", testApp)
	if !errors.Is(delErr, vault.ErrFlagNotFound) {
		t.Errorf("DeleteFlagDefinition non-existent: got %v, want ErrFlagNotFound", delErr)
	}
}

func TestFlagDefinitionList(t *testing.T) {
	s := newStore()

	for _, key := range []string{"z-flag", "a-flag", "m-flag"} {
		_ = s.DefineFlag(bg(), &flag.Definition{
			Entity: vault.NewEntity(),
			ID:     id.NewFlagID(),
			Key:    key,
			Type:   flag.TypeBool,
			AppID:  testApp,
		})
	}

	list, err := s.ListFlagDefinitions(bg(), testApp, flag.ListOpts{})
	if err != nil {
		t.Fatalf("ListFlagDefinitions: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("len = %d, want 3", len(list))
	}
	if list[0].Key != "a-flag" || list[1].Key != "m-flag" || list[2].Key != "z-flag" {
		t.Errorf("order = [%s, %s, %s], want [a-flag, m-flag, z-flag]", list[0].Key, list[1].Key, list[2].Key)
	}
}

func TestFlagRules(t *testing.T) {
	s := newStore()

	// Must define the flag first.
	_ = s.DefineFlag(bg(), &flag.Definition{
		Entity: vault.NewEntity(),
		ID:     id.NewFlagID(),
		Key:    "feature-x",
		Type:   flag.TypeBool,
		AppID:  testApp,
	})

	rules := []*flag.Rule{
		{Entity: vault.NewEntity(), ID: id.NewRuleID(), FlagKey: "feature-x", AppID: testApp, Priority: 2, Type: flag.RuleWhenUser},
		{Entity: vault.NewEntity(), ID: id.NewRuleID(), FlagKey: "feature-x", AppID: testApp, Priority: 1, Type: flag.RuleWhenTenant},
	}
	if err := s.SetFlagRules(bg(), "feature-x", testApp, rules); err != nil {
		t.Fatalf("SetFlagRules: %v", err)
	}

	got, err := s.GetFlagRules(bg(), "feature-x", testApp)
	if err != nil {
		t.Fatalf("GetFlagRules: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	// Should be sorted by priority.
	if got[0].Priority != 1 || got[1].Priority != 2 {
		t.Errorf("priorities = [%d, %d], want [1, 2]", got[0].Priority, got[1].Priority)
	}

	// SetRules on non-existent flag.
	err = s.SetFlagRules(bg(), "no-flag", testApp, rules)
	if !errors.Is(err, vault.ErrFlagNotFound) {
		t.Errorf("SetFlagRules non-existent: got %v, want ErrFlagNotFound", err)
	}

	// Empty rules for non-existent key.
	empty, _ := s.GetFlagRules(bg(), "no-flag", testApp)
	if empty != nil {
		t.Errorf("GetFlagRules non-existent: got %v, want nil", empty)
	}

	// Delete flag should also remove rules.
	_ = s.DeleteFlagDefinition(bg(), "feature-x", testApp)
	afterDelete, _ := s.GetFlagRules(bg(), "feature-x", testApp)
	if afterDelete != nil {
		t.Error("rules should be deleted when flag is deleted")
	}
}

func TestFlagTenantOverrides(t *testing.T) {
	s := newStore()

	// Set override.
	if err := s.SetFlagTenantOverride(bg(), "feature-y", testApp, "tenant-1", true); err != nil {
		t.Fatalf("SetFlagTenantOverride: %v", err)
	}

	// Get override.
	val, err := s.GetFlagTenantOverride(bg(), "feature-y", testApp, "tenant-1")
	if err != nil {
		t.Fatalf("GetFlagTenantOverride: %v", err)
	}
	if val != true {
		t.Errorf("val = %v, want true", val)
	}

	// Update override.
	updateErr := s.SetFlagTenantOverride(bg(), "feature-y", testApp, "tenant-1", false)
	if updateErr != nil {
		t.Fatalf("SetFlagTenantOverride update: %v", updateErr)
	}
	val2, _ := s.GetFlagTenantOverride(bg(), "feature-y", testApp, "tenant-1")
	if val2 != false {
		t.Errorf("val2 = %v, want false", val2)
	}

	// Add another tenant override.
	_ = s.SetFlagTenantOverride(bg(), "feature-y", testApp, "tenant-2", "custom-value")

	// List overrides.
	list, err := s.ListFlagTenantOverrides(bg(), "feature-y", testApp)
	if err != nil {
		t.Fatalf("ListFlagTenantOverrides: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("len = %d, want 2", len(list))
	}

	// Delete override.
	delErr := s.DeleteFlagTenantOverride(bg(), "feature-y", testApp, "tenant-1")
	if delErr != nil {
		t.Fatalf("DeleteFlagTenantOverride: %v", delErr)
	}
	_, err = s.GetFlagTenantOverride(bg(), "feature-y", testApp, "tenant-1")
	if !errors.Is(err, vault.ErrOverrideNotFound) {
		t.Errorf("GetFlagTenantOverride after delete: got %v, want ErrOverrideNotFound", err)
	}

	// Delete non-existent.
	delErr = s.DeleteFlagTenantOverride(bg(), "feature-y", testApp, "no-tenant")
	if !errors.Is(delErr, vault.ErrOverrideNotFound) {
		t.Errorf("DeleteFlagTenantOverride non-existent: got %v, want ErrOverrideNotFound", delErr)
	}
}

// ──────────────────────────────────────────────────
// Config Store
// ──────────────────────────────────────────────────

func TestConfigCRUD(t *testing.T) {
	s := newStore()

	entry := &config.Entry{
		Entity:    vault.NewEntity(),
		ID:        id.NewConfigID(),
		Key:       "max-retries",
		Value:     3,
		ValueType: "int",
		AppID:     testApp,
	}
	if err := s.SetConfig(bg(), entry); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}

	got, err := s.GetConfig(bg(), "max-retries", testApp)
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if got.Key != "max-retries" {
		t.Errorf("Key = %q, want %q", got.Key, "max-retries")
	}
	if got.Version != 1 {
		t.Errorf("Version = %d, want 1", got.Version)
	}

	// Delete.
	delErr := s.DeleteConfig(bg(), "max-retries", testApp)
	if delErr != nil {
		t.Fatalf("DeleteConfig: %v", delErr)
	}
	_, err = s.GetConfig(bg(), "max-retries", testApp)
	if !errors.Is(err, vault.ErrConfigNotFound) {
		t.Errorf("GetConfig after delete: got %v, want ErrConfigNotFound", err)
	}

	// Delete non-existent.
	delErr = s.DeleteConfig(bg(), "no-config", testApp)
	if !errors.Is(delErr, vault.ErrConfigNotFound) {
		t.Errorf("DeleteConfig non-existent: got %v, want ErrConfigNotFound", delErr)
	}
}

func TestConfigVersioning(t *testing.T) {
	s := newStore()

	e1 := &config.Entry{
		Entity: vault.NewEntity(),
		ID:     id.NewConfigID(),
		Key:    "timeout",
		Value:  30,
		AppID:  testApp,
	}
	_ = s.SetConfig(bg(), e1)

	e2 := &config.Entry{
		Entity: vault.NewEntity(),
		ID:     id.NewConfigID(),
		Key:    "timeout",
		Value:  60,
		AppID:  testApp,
	}
	_ = s.SetConfig(bg(), e2)

	got, _ := s.GetConfig(bg(), "timeout", testApp)
	if got.Version != 2 {
		t.Errorf("Version = %d, want 2", got.Version)
	}

	v1, err := s.GetConfigVersion(bg(), "timeout", testApp, 1)
	if err != nil {
		t.Fatalf("GetConfigVersion(1): %v", err)
	}
	if v1.Version != 1 {
		t.Errorf("v1.Version = %d, want 1", v1.Version)
	}

	versions, err := s.ListConfigVersions(bg(), "timeout", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 2 {
		t.Errorf("len(versions) = %d, want 2", len(versions))
	}

	// Non-existent version.
	_, err = s.GetConfigVersion(bg(), "timeout", testApp, 99)
	if !errors.Is(err, vault.ErrConfigNotFound) {
		t.Errorf("GetConfigVersion(99): got %v, want ErrConfigNotFound", err)
	}
}

func TestConfigList(t *testing.T) {
	s := newStore()

	for _, key := range []string{"z-cfg", "a-cfg", "m-cfg"} {
		_ = s.SetConfig(bg(), &config.Entry{
			Entity: vault.NewEntity(),
			ID:     id.NewConfigID(),
			Key:    key,
			Value:  "val",
			AppID:  testApp,
		})
	}

	list, err := s.ListConfig(bg(), testApp, config.ListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("len = %d, want 3", len(list))
	}
	if list[0].Key != "a-cfg" || list[1].Key != "m-cfg" || list[2].Key != "z-cfg" {
		t.Errorf("order = [%s, %s, %s]", list[0].Key, list[1].Key, list[2].Key)
	}
}

// ──────────────────────────────────────────────────
// Override Store
// ──────────────────────────────────────────────────

func TestOverrideCRUD(t *testing.T) {
	s := newStore()

	o := &override.Override{
		Entity:   vault.NewEntity(),
		ID:       id.NewOverrideID(),
		Key:      "max-retries",
		Value:    5,
		AppID:    testApp,
		TenantID: "tenant-1",
	}
	if err := s.SetOverride(bg(), o); err != nil {
		t.Fatalf("SetOverride: %v", err)
	}

	got, err := s.GetOverride(bg(), "max-retries", testApp, "tenant-1")
	if err != nil {
		t.Fatalf("GetOverride: %v", err)
	}
	if got.Key != "max-retries" || got.TenantID != "tenant-1" {
		t.Errorf("got = %+v", got)
	}

	// Delete.
	delErr := s.DeleteOverride(bg(), "max-retries", testApp, "tenant-1")
	if delErr != nil {
		t.Fatalf("DeleteOverride: %v", delErr)
	}
	_, err = s.GetOverride(bg(), "max-retries", testApp, "tenant-1")
	if !errors.Is(err, vault.ErrOverrideNotFound) {
		t.Errorf("GetOverride after delete: got %v, want ErrOverrideNotFound", err)
	}

	// Delete non-existent.
	delErr = s.DeleteOverride(bg(), "no-key", testApp, "no-tenant")
	if !errors.Is(delErr, vault.ErrOverrideNotFound) {
		t.Errorf("DeleteOverride non-existent: got %v, want ErrOverrideNotFound", delErr)
	}
}

func TestOverrideListByTenant(t *testing.T) {
	s := newStore()

	for _, key := range []string{"c-key", "a-key", "b-key"} {
		_ = s.SetOverride(bg(), &override.Override{
			Entity:   vault.NewEntity(),
			ID:       id.NewOverrideID(),
			Key:      key,
			Value:    "val",
			AppID:    testApp,
			TenantID: "tenant-1",
		})
	}
	// Different tenant.
	_ = s.SetOverride(bg(), &override.Override{
		Entity:   vault.NewEntity(),
		ID:       id.NewOverrideID(),
		Key:      "other-key",
		Value:    "val",
		AppID:    testApp,
		TenantID: "tenant-2",
	})

	list, err := s.ListOverridesByTenant(bg(), testApp, "tenant-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("len = %d, want 3", len(list))
	}
	// Sorted by key.
	if list[0].Key != "a-key" || list[1].Key != "b-key" || list[2].Key != "c-key" {
		t.Errorf("order = [%s, %s, %s]", list[0].Key, list[1].Key, list[2].Key)
	}
}

func TestOverrideListByKey(t *testing.T) {
	s := newStore()

	for _, tid := range []string{"t-c", "t-a", "t-b"} {
		_ = s.SetOverride(bg(), &override.Override{
			Entity:   vault.NewEntity(),
			ID:       id.NewOverrideID(),
			Key:      "shared-key",
			Value:    tid,
			AppID:    testApp,
			TenantID: tid,
		})
	}

	list, err := s.ListOverridesByKey(bg(), "shared-key", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("len = %d, want 3", len(list))
	}
	// Sorted by tenant ID.
	if list[0].TenantID != "t-a" || list[1].TenantID != "t-b" || list[2].TenantID != "t-c" {
		t.Errorf("order = [%s, %s, %s]", list[0].TenantID, list[1].TenantID, list[2].TenantID)
	}
}

// ──────────────────────────────────────────────────
// Rotation Store
// ──────────────────────────────────────────────────

func TestRotationPolicyCRUD(t *testing.T) {
	s := newStore()

	p := &rotation.Policy{
		Entity:         vault.NewEntity(),
		ID:             id.NewRotationID(),
		SecretKey:      "db-password",
		AppID:          testApp,
		Interval:       24 * time.Hour,
		Enabled:        true,
		NextRotationAt: timePtr(time.Now().Add(24 * time.Hour)),
	}
	if err := s.SaveRotationPolicy(bg(), p); err != nil {
		t.Fatalf("SaveRotationPolicy: %v", err)
	}

	got, err := s.GetRotationPolicy(bg(), "db-password", testApp)
	if err != nil {
		t.Fatalf("GetRotationPolicy: %v", err)
	}
	if got.SecretKey != "db-password" || !got.Enabled {
		t.Errorf("got = %+v", got)
	}

	// Update.
	p.Enabled = false
	_ = s.SaveRotationPolicy(bg(), p)
	got2, _ := s.GetRotationPolicy(bg(), "db-password", testApp)
	if got2.Enabled {
		t.Error("policy should be disabled after update")
	}

	// Delete.
	delErr := s.DeleteRotationPolicy(bg(), "db-password", testApp)
	if delErr != nil {
		t.Fatalf("DeleteRotationPolicy: %v", delErr)
	}
	_, err = s.GetRotationPolicy(bg(), "db-password", testApp)
	if !errors.Is(err, vault.ErrRotationNotFound) {
		t.Errorf("GetRotationPolicy after delete: got %v, want ErrRotationNotFound", err)
	}

	// Delete non-existent.
	delErr = s.DeleteRotationPolicy(bg(), "no-key", testApp)
	if !errors.Is(delErr, vault.ErrRotationNotFound) {
		t.Errorf("DeleteRotationPolicy non-existent: got %v, want ErrRotationNotFound", delErr)
	}
}

func TestRotationPolicyList(t *testing.T) {
	s := newStore()

	for _, key := range []string{"z-secret", "a-secret"} {
		_ = s.SaveRotationPolicy(bg(), &rotation.Policy{
			Entity:    vault.NewEntity(),
			ID:        id.NewRotationID(),
			SecretKey: key,
			AppID:     testApp,
			Interval:  time.Hour,
		})
	}
	// Different app.
	_ = s.SaveRotationPolicy(bg(), &rotation.Policy{
		Entity:    vault.NewEntity(),
		ID:        id.NewRotationID(),
		SecretKey: "other",
		AppID:     "other_app",
		Interval:  time.Hour,
	})

	list, err := s.ListRotationPolicies(bg(), testApp)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("len = %d, want 2", len(list))
	}
	if list[0].SecretKey != "a-secret" || list[1].SecretKey != "z-secret" {
		t.Errorf("order = [%s, %s]", list[0].SecretKey, list[1].SecretKey)
	}
}

func TestRotationRecords(t *testing.T) {
	s := newStore()

	now := time.Now().UTC()
	for i := range 3 {
		_ = s.RecordRotation(bg(), &rotation.Record{
			ID:         id.NewRotationID(),
			SecretKey:  "db-password",
			AppID:      testApp,
			OldVersion: int64(i),
			NewVersion: int64(i + 1),
			RotatedBy:  "system",
			RotatedAt:  now.Add(time.Duration(i) * time.Hour),
		})
	}

	records, err := s.ListRotationRecords(bg(), "db-password", testApp, rotation.ListOpts{})
	if err != nil {
		t.Fatalf("ListRotationRecords: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("len = %d, want 3", len(records))
	}
	// Sorted by newest first.
	if records[0].NewVersion != 3 {
		t.Errorf("records[0].NewVersion = %d, want 3", records[0].NewVersion)
	}

	// Pagination.
	page, _ := s.ListRotationRecords(bg(), "db-password", testApp, rotation.ListOpts{Offset: 1, Limit: 1})
	if len(page) != 1 {
		t.Fatalf("len = %d, want 1", len(page))
	}

	// Empty result for unknown key.
	empty, _ := s.ListRotationRecords(bg(), "unknown", testApp, rotation.ListOpts{})
	if empty != nil {
		t.Errorf("expected nil, got %v", empty)
	}
}

// ──────────────────────────────────────────────────
// Audit Store
// ──────────────────────────────────────────────────

func TestAuditRecordAndList(t *testing.T) {
	s := newStore()

	now := time.Now().UTC()
	for i := range 3 {
		_ = s.RecordAudit(bg(), &audit.Entry{
			ID:        id.NewAuditID(),
			Action:    "secret.read",
			Resource:  "secret",
			Key:       "db-password",
			AppID:     testApp,
			Outcome:   "success",
			CreatedAt: now.Add(time.Duration(i) * time.Minute),
		})
	}

	// Different key.
	_ = s.RecordAudit(bg(), &audit.Entry{
		ID:        id.NewAuditID(),
		Action:    "config.write",
		Resource:  "config",
		Key:       "timeout",
		AppID:     testApp,
		Outcome:   "success",
		CreatedAt: now.Add(10 * time.Minute),
	})

	// Different app.
	_ = s.RecordAudit(bg(), &audit.Entry{
		ID:        id.NewAuditID(),
		Action:    "secret.read",
		Resource:  "secret",
		Key:       "other",
		AppID:     "other_app",
		Outcome:   "success",
		CreatedAt: now,
	})

	// ListAudit for app.
	list, err := s.ListAudit(bg(), testApp, audit.ListOpts{})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(list) != 4 {
		t.Fatalf("len = %d, want 4", len(list))
	}
	// Newest first.
	if list[0].Key != "timeout" {
		t.Errorf("list[0].Key = %q, want %q", list[0].Key, "timeout")
	}

	// ListAuditByKey.
	byKey, err := s.ListAuditByKey(bg(), "db-password", testApp, audit.ListOpts{})
	if err != nil {
		t.Fatalf("ListAuditByKey: %v", err)
	}
	if len(byKey) != 3 {
		t.Fatalf("len = %d, want 3", len(byKey))
	}

	// Pagination.
	page, _ := s.ListAudit(bg(), testApp, audit.ListOpts{Offset: 1, Limit: 2})
	if len(page) != 2 {
		t.Errorf("len = %d, want 2", len(page))
	}
}

// ──────────────────────────────────────────────────
// Get not found
// ──────────────────────────────────────────────────

func TestGetNotFound(t *testing.T) {
	s := newStore()

	tests := []struct {
		name string
		fn   func() error
		want error
	}{
		{"GetSecret", func() error { _, e := s.GetSecret(bg(), "x", testApp); return e }, vault.ErrSecretNotFound},
		{"GetFlagDefinition", func() error { _, e := s.GetFlagDefinition(bg(), "x", testApp); return e }, vault.ErrFlagNotFound},
		{"GetConfig", func() error { _, e := s.GetConfig(bg(), "x", testApp); return e }, vault.ErrConfigNotFound},
		{"GetOverride", func() error { _, e := s.GetOverride(bg(), "x", testApp, "t"); return e }, vault.ErrOverrideNotFound},
		{"GetRotationPolicy", func() error { _, e := s.GetRotationPolicy(bg(), "x", testApp); return e }, vault.ErrRotationNotFound},
		{"GetFlagTenantOverride", func() error { _, e := s.GetFlagTenantOverride(bg(), "x", testApp, "t"); return e }, vault.ErrOverrideNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.fn(); !errors.Is(err, tt.want) {
				t.Errorf("got %v, want %v", err, tt.want)
			}
		})
	}
}
