package mongo_test

import (
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/xraph/grove/drivers/mongodriver"
	"github.com/xraph/grove/drivers/mongodriver/mongomigrate"
	"github.com/xraph/grove/migrate"

	"github.com/xraph/vault/audit"
	cfgpkg "github.com/xraph/vault/config"
	"github.com/xraph/vault/flag"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/override"
	"github.com/xraph/vault/rotation"
	"github.com/xraph/vault/secret"
	mongostore "github.com/xraph/vault/store/mongo"
)

// TestMigrationsGroupAcceptsEveryRow migrates through the exported Migrations
// group, the path a host's migration runner takes, rather than Store.Migrate.
// The group creates each collection with a $jsonSchema validator, so this is
// the test that catches a row the validator rejects. Every row kind the store
// writes is saved here in its plainest shape: nil maps and slices, and values
// of every type a flag or config entry can hold.
func TestMigrationsGroupAcceptsEveryRow(t *testing.T) {
	db := testDB(t)
	ctx := t.Context()

	orch := migrate.NewOrchestrator(mongomigrate.New(mongodriver.Unwrap(db)), mongostore.Migrations)
	if _, err := orch.Migrate(ctx); err != nil {
		t.Fatalf("migrate group: %v", err)
	}
	s := mongostore.New(db)
	const app = "app1"

	t.Run("secret without metadata", func(t *testing.T) {
		sec := &secret.Secret{
			ID: id.NewSecretID(), Key: "plain", AppID: app,
			EncryptedValue: []byte("v"),
		}
		if err := s.SetSecret(ctx, sec); err != nil {
			t.Fatalf("SetSecret: %v", err)
		}
		got, err := s.GetSecret(ctx, "plain", app)
		if err != nil {
			t.Fatalf("GetSecret: %v", err)
		}
		if len(got.Metadata) != 0 {
			t.Fatalf("metadata = %v, want empty", got.Metadata)
		}
	})

	t.Run("secret with metadata and expiry, second version", func(t *testing.T) {
		exp := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
		for range 2 {
			sec := &secret.Secret{
				ID: id.NewSecretID(), Key: "rich", AppID: app,
				EncryptedValue: []byte("c"), EncryptionAlg: "AES-256-GCM",
				EncryptionKeyID: "k1", ExpiresAt: &exp,
				Metadata: map[string]string{"owner": "ops"},
			}
			if err := s.SetSecret(ctx, sec); err != nil {
				t.Fatalf("SetSecret: %v", err)
			}
		}
		versions, err := s.ListSecretVersions(ctx, "rich", app)
		if err != nil {
			t.Fatalf("ListSecretVersions: %v", err)
		}
		if len(versions) != 2 {
			t.Fatalf("versions = %d, want 2", len(versions))
		}
	})

	flags := []struct {
		name  string
		typ   flag.Type
		value any
	}{
		{"bool", flag.TypeBool, true},
		{"string", flag.TypeString, "on"},
		{"int", flag.TypeInt, int64(3)},
		{"float", flag.TypeFloat, 0.5},
		{"json", flag.TypeJSON, map[string]any{"a": int64(1)}},
	}
	for _, f := range flags {
		t.Run("flag "+f.name+" with no tags, variants or metadata", func(t *testing.T) {
			def := &flag.Definition{
				ID: id.NewFlagID(), Key: "f-" + f.name, Type: f.typ,
				DefaultValue: f.value, Enabled: true, AppID: app,
			}
			if err := s.DefineFlag(ctx, def); err != nil {
				t.Fatalf("DefineFlag: %v", err)
			}
			if _, err := s.GetFlagDefinition(ctx, def.Key, app); err != nil {
				t.Fatalf("GetFlagDefinition: %v", err)
			}
		})
	}

	t.Run("flag with tags, variants and metadata", func(t *testing.T) {
		def := &flag.Definition{
			ID: id.NewFlagID(), Key: "f-full", Type: flag.TypeString,
			DefaultValue: "a", Enabled: true, AppID: app,
			Tags:     []string{"beta"},
			Variants: []flag.Variant{{Value: "a"}, {Value: "b", Description: "B"}},
			Metadata: map[string]string{"team": "core"},
		}
		if err := s.DefineFlag(ctx, def); err != nil {
			t.Fatalf("DefineFlag: %v", err)
		}
	})

	t.Run("rules", func(t *testing.T) {
		start := time.Now().UTC().Truncate(time.Second)
		rules := []*flag.Rule{
			{Priority: 1, Type: flag.RuleWhenTenant, Config: flag.RuleConfig{TenantIDs: []string{"t1"}}, ReturnValue: false},
			{Priority: 2, Type: flag.RuleRollout, Config: flag.RuleConfig{Percentage: 10}, ReturnValue: int64(7)},
			{Priority: 3, Type: flag.RuleSchedule, Config: flag.RuleConfig{StartAt: &start}, ReturnValue: "on"},
		}
		if err := s.SetFlagRules(ctx, "f-bool", app, rules); err != nil {
			t.Fatalf("SetFlagRules: %v", err)
		}
		got, err := s.GetFlagRules(ctx, "f-bool", app)
		if err != nil {
			t.Fatalf("GetFlagRules: %v", err)
		}
		if len(got) != 3 {
			t.Fatalf("rules = %d, want 3", len(got))
		}
	})

	for _, v := range []any{true, int64(2), "x"} {
		t.Run("flag tenant override", func(t *testing.T) {
			if err := s.SetFlagTenantOverride(ctx, "f-bool", app, "tenant-1", v); err != nil {
				t.Fatalf("SetFlagTenantOverride(%v): %v", v, err)
			}
		})
	}

	configs := []struct {
		typ   string
		value any
	}{
		{cfgpkg.TypeString, "hello"},
		{cfgpkg.TypeInt, int64(42)},
		{cfgpkg.TypeFloat, 1.5},
		{cfgpkg.TypeBool, false},
		{cfgpkg.TypeDuration, "5s"},
		{cfgpkg.TypeJSON, map[string]any{"k": []any{"a", int64(1)}}},
	}
	for _, c := range configs {
		t.Run("config "+c.typ+" without metadata, two versions", func(t *testing.T) {
			for range 2 {
				e := &cfgpkg.Entry{
					ID: id.NewConfigID(), Key: "c-" + c.typ, Value: c.value,
					ValueType: c.typ, AppID: app,
				}
				if err := s.SetConfig(ctx, e); err != nil {
					t.Fatalf("SetConfig: %v", err)
				}
			}
			versions, err := s.ListConfigVersions(ctx, "c-"+c.typ, app)
			if err != nil {
				t.Fatalf("ListConfigVersions: %v", err)
			}
			if len(versions) != 2 {
				t.Fatalf("versions = %d, want 2", len(versions))
			}
		})
	}

	for _, v := range []any{"s", int64(9), true} {
		t.Run("override without metadata", func(t *testing.T) {
			o := &override.Override{
				ID: id.NewOverrideID(), Key: "c-int", Value: v,
				AppID: app, TenantID: "tenant-1",
			}
			if err := s.SetOverride(ctx, o); err != nil {
				t.Fatalf("SetOverride(%v): %v", v, err)
			}
		})
	}

	t.Run("rotation policy and record", func(t *testing.T) {
		p := &rotation.Policy{
			ID: id.NewRotationID(), SecretKey: "plain", AppID: app,
			Interval: time.Hour, Enabled: true,
		}
		if err := s.SaveRotationPolicy(ctx, p); err != nil {
			t.Fatalf("SaveRotationPolicy: %v", err)
		}
		r := &rotation.Record{
			ID: id.NewRotationID(), SecretKey: "plain", AppID: app,
			OldVersion: 1, NewVersion: 2, RotatedAt: time.Now().UTC(),
		}
		if err := s.RecordRotation(ctx, r); err != nil {
			t.Fatalf("RecordRotation: %v", err)
		}
	})

	t.Run("audit entry without metadata", func(t *testing.T) {
		e := &audit.Entry{
			ID: id.NewAuditID(), Action: "secret.set", Resource: "secret",
			Key: "plain", AppID: app, Outcome: "success",
			CreatedAt: time.Now().UTC(),
		}
		if err := s.RecordAudit(ctx, e); err != nil {
			t.Fatalf("RecordAudit: %v", err)
		}
	})

	// The validators are relaxed, not removed: a null map (as an older vault
	// wrote it) passes, and a field of the wrong type is still refused.
	raw := mongodriver.Unwrap(db).Database()
	t.Run("validator accepts a null map from an older writer", func(t *testing.T) {
		_, err := raw.Collection("vault_audit").InsertOne(ctx, bson.M{
			"_id": id.NewAuditID().String(), "action": "secret.set", "resource": "secret",
			"key": "plain", "app_id": app, "tenant_id": "", "user_id": "", "ip": "",
			"outcome": "success", "metadata": nil, "created_at": time.Now().UTC(),
		})
		if err != nil {
			t.Fatalf("insert audit row with null metadata: %v", err)
		}
	})
	t.Run("validator still refuses a wrong type", func(t *testing.T) {
		_, err := raw.Collection("vault_secrets").InsertOne(ctx, bson.M{
			"_id": id.NewSecretID().String(), "key": 5, "app_id": app, "version": int64(1),
			"created_at": time.Now().UTC(), "updated_at": time.Now().UTC(),
		})
		if err == nil {
			t.Fatal("insert of a numeric secret key succeeded, want a validation error")
		}
	})

	t.Run("audit entry with metadata", func(t *testing.T) {
		e := &audit.Entry{
			ID: id.NewAuditID(), Action: "secret.get", Resource: "secret",
			Key: "plain", AppID: app, Outcome: "failure",
			Metadata:  map[string]any{"error": "boom"},
			CreatedAt: time.Now().UTC(),
		}
		if err := s.RecordAudit(ctx, e); err != nil {
			t.Fatalf("RecordAudit: %v", err)
		}
	})
}
