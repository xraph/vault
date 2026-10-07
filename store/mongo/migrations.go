package mongo

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/xraph/grove/drivers/mongodriver/mongomigrate"
	"github.com/xraph/grove/migrate"
)

// Migrations is the grove migration group for the Vault mongo store.
var Migrations = migrate.NewGroup("vault")

func init() {
	Migrations.MustRegister(
		&migrate.Migration{
			Name:    "create_vault_secrets",
			Version: "20240101000001",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := mexec.CreateCollection(ctx, (*SecretModel)(nil)); err != nil {
					return err
				}

				return mexec.CreateIndexes(ctx, colSecrets, []mongo.IndexModel{
					{
						Keys:    bson.D{{Key: "key", Value: 1}, {Key: "app_id", Value: 1}},
						Options: options.Index().SetUnique(true),
					},
				})
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				return mexec.DropCollection(ctx, (*SecretModel)(nil))
			},
		},
		&migrate.Migration{
			Name:    "create_vault_secret_versions",
			Version: "20240101000002",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := mexec.CreateCollection(ctx, (*SecretVersionModel)(nil)); err != nil {
					return err
				}

				return mexec.CreateIndexes(ctx, colSecretVersions, []mongo.IndexModel{
					{
						Keys:    bson.D{{Key: "secret_key", Value: 1}, {Key: "app_id", Value: 1}, {Key: "version", Value: 1}},
						Options: options.Index().SetUnique(true),
					},
					{Keys: bson.D{{Key: "secret_key", Value: 1}, {Key: "app_id", Value: 1}}},
				})
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				return mexec.DropCollection(ctx, (*SecretVersionModel)(nil))
			},
		},
		&migrate.Migration{
			Name:    "create_vault_flags",
			Version: "20240101000003",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := mexec.CreateCollection(ctx, (*FlagModel)(nil)); err != nil {
					return err
				}

				return mexec.CreateIndexes(ctx, colFlags, []mongo.IndexModel{
					{
						Keys:    bson.D{{Key: "key", Value: 1}, {Key: "app_id", Value: 1}},
						Options: options.Index().SetUnique(true),
					},
				})
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				return mexec.DropCollection(ctx, (*FlagModel)(nil))
			},
		},
		&migrate.Migration{
			Name:    "create_vault_flag_rules",
			Version: "20240101000004",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := mexec.CreateCollection(ctx, (*FlagRuleModel)(nil)); err != nil {
					return err
				}

				return mexec.CreateIndexes(ctx, colFlagRules, []mongo.IndexModel{
					{Keys: bson.D{{Key: "flag_key", Value: 1}, {Key: "app_id", Value: 1}, {Key: "priority", Value: 1}}},
				})
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				return mexec.DropCollection(ctx, (*FlagRuleModel)(nil))
			},
		},
		&migrate.Migration{
			Name:    "create_vault_flag_overrides",
			Version: "20240101000005",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := mexec.CreateCollection(ctx, (*FlagOverrideModel)(nil)); err != nil {
					return err
				}

				return mexec.CreateIndexes(ctx, colFlagOverrides, []mongo.IndexModel{
					{
						Keys:    bson.D{{Key: "flag_key", Value: 1}, {Key: "app_id", Value: 1}, {Key: "tenant_id", Value: 1}},
						Options: options.Index().SetUnique(true),
					},
				})
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				return mexec.DropCollection(ctx, (*FlagOverrideModel)(nil))
			},
		},
		&migrate.Migration{
			Name:    "create_vault_config",
			Version: "20240101000006",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := mexec.CreateCollection(ctx, (*ConfigModel)(nil)); err != nil {
					return err
				}

				return mexec.CreateIndexes(ctx, colConfig, []mongo.IndexModel{
					{
						Keys:    bson.D{{Key: "key", Value: 1}, {Key: "app_id", Value: 1}},
						Options: options.Index().SetUnique(true),
					},
				})
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				return mexec.DropCollection(ctx, (*ConfigModel)(nil))
			},
		},
		&migrate.Migration{
			Name:    "create_vault_config_versions",
			Version: "20240101000007",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := mexec.CreateCollection(ctx, (*ConfigVersionModel)(nil)); err != nil {
					return err
				}

				return mexec.CreateIndexes(ctx, colConfigVersions, []mongo.IndexModel{
					{
						Keys:    bson.D{{Key: "config_key", Value: 1}, {Key: "app_id", Value: 1}, {Key: "version", Value: 1}},
						Options: options.Index().SetUnique(true),
					},
					{Keys: bson.D{{Key: "config_key", Value: 1}, {Key: "app_id", Value: 1}}},
				})
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				return mexec.DropCollection(ctx, (*ConfigVersionModel)(nil))
			},
		},
		&migrate.Migration{
			Name:    "create_vault_overrides",
			Version: "20240101000008",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := mexec.CreateCollection(ctx, (*OverrideModel)(nil)); err != nil {
					return err
				}

				return mexec.CreateIndexes(ctx, colOverrides, []mongo.IndexModel{
					{
						Keys:    bson.D{{Key: "key", Value: 1}, {Key: "app_id", Value: 1}, {Key: "tenant_id", Value: 1}},
						Options: options.Index().SetUnique(true),
					},
				})
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				return mexec.DropCollection(ctx, (*OverrideModel)(nil))
			},
		},
		&migrate.Migration{
			Name:    "create_vault_rotation_policies",
			Version: "20240101000009",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := mexec.CreateCollection(ctx, (*RotationPolicyModel)(nil)); err != nil {
					return err
				}

				return mexec.CreateIndexes(ctx, colRotationPolicies, []mongo.IndexModel{
					{
						Keys:    bson.D{{Key: "secret_key", Value: 1}, {Key: "app_id", Value: 1}},
						Options: options.Index().SetUnique(true),
					},
				})
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				return mexec.DropCollection(ctx, (*RotationPolicyModel)(nil))
			},
		},
		&migrate.Migration{
			Name:    "create_vault_rotation_records",
			Version: "20240101000010",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := mexec.CreateCollection(ctx, (*RotationRecordModel)(nil)); err != nil {
					return err
				}

				return mexec.CreateIndexes(ctx, colRotationRecords, []mongo.IndexModel{
					{Keys: bson.D{{Key: "secret_key", Value: 1}, {Key: "app_id", Value: 1}, {Key: "rotated_at", Value: -1}}},
				})
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				return mexec.DropCollection(ctx, (*RotationRecordModel)(nil))
			},
		},
		&migrate.Migration{
			Name:    "create_vault_audit",
			Version: "20240101000011",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := mexec.CreateCollection(ctx, (*AuditModel)(nil)); err != nil {
					return err
				}

				return mexec.CreateIndexes(ctx, colAudit, []mongo.IndexModel{
					{Keys: bson.D{{Key: "app_id", Value: 1}, {Key: "created_at", Value: -1}}},
					{Keys: bson.D{{Key: "key", Value: 1}, {Key: "app_id", Value: 1}, {Key: "created_at", Value: -1}}},
				})
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				return mexec.DropCollection(ctx, (*AuditModel)(nil))
			},
		},
		&migrate.Migration{
			Name:    "add_secret_expiry_and_version_alg_indexes",
			Version: "20240101000012",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := mexec.CreateIndexes(ctx, colSecrets, []mongo.IndexModel{secretsExpiryIndex}); err != nil {
					return err
				}
				return mexec.CreateIndexes(ctx, colSecretVersions, []mongo.IndexModel{secretVersionsAlgIndex})
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				db := mexec.DB().Database()
				if err := db.Collection(colSecrets).Indexes().DropOne(ctx, "app_id_1_expires_at_1"); err != nil {
					return err
				}
				return db.Collection(colSecretVersions).Indexes().DropOne(ctx, "app_id_1_encryption_alg_1")
			},
		},
		&migrate.Migration{
			Name:    "relax_vault_validators",
			Version: "20240101000013",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				for _, model := range validatedModels() {
					if err := setValidator(ctx, mexec, model, relaxedSchema); err != nil {
						return err
					}
				}
				return nil
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				for _, model := range validatedModels() {
					if err := setValidator(ctx, mexec, model, nil); err != nil {
						return err
					}
				}
				return nil
			},
		},
	)
}

// validatedModels lists the model of every collection the group validates.
func validatedModels() []any {
	return []any{
		(*SecretModel)(nil), (*SecretVersionModel)(nil),
		(*FlagModel)(nil), (*FlagRuleModel)(nil), (*FlagOverrideModel)(nil),
		(*ConfigModel)(nil), (*ConfigVersionModel)(nil), (*OverrideModel)(nil),
		(*RotationPolicyModel)(nil), (*RotationRecordModel)(nil), (*AuditModel)(nil),
	}
}

// setValidator replaces the $jsonSchema validator on model's collection with
// the one grove generates for model, passed through relax when it is non-nil.
// A nil relax restores grove's generated validator unchanged.
//
// The level is moderate, so a document stored before the validator changed
// can still be updated even if it does not match.
func setValidator(ctx context.Context, mexec *mongomigrate.Executor, model any, relax func(bson.M, reflect.Type)) error {
	q := mexec.DB().NewCreateCollection(model)
	schema, err := q.BuildSchema()
	if err != nil {
		return fmt.Errorf("build %s validator: %w", q.GetCollection(), err)
	}
	if relax != nil {
		relax(schema, reflect.TypeOf(model).Elem())
	}
	cmd := bson.D{
		{Key: "collMod", Value: q.GetCollection()},
		{Key: "validator", Value: bson.M{"$jsonSchema": schema}},
		{Key: "validationLevel", Value: "moderate"},
		{Key: "validationAction", Value: "error"},
	}
	if err := mexec.DB().Database().RunCommand(ctx, cmd).Err(); err != nil {
		return fmt.Errorf("collMod %s: %w", q.GetCollection(), err)
	}
	return nil
}

// relaxedSchema loosens grove's generated schema for model type t where it
// rejects rows vault writes. Grove types an interface field (a flag's default
// or a config value, which may be a bool, number, string or object) as
// string; the field loses its bsonType so any value passes. Maps and slices
// may also be null, which is how vault wrote nil ones before it wrote {} and
// [], so an older replica still running during a rolling deploy is not
// rejected either.
func relaxedSchema(schema bson.M, t reflect.Type) {
	props, ok := schema["properties"].(bson.M)
	if !ok {
		return
	}
	for i := range t.NumField() {
		f := t.Field(i)
		col, _, _ := strings.Cut(f.Tag.Get("grove"), ",")
		if col == "" || col == "id" || strings.HasPrefix(col, "table:") {
			continue
		}
		prop, ok := props[col].(bson.M)
		if !ok {
			continue
		}
		switch f.Type.Kind() {
		case reflect.Interface:
			delete(prop, "bsonType")
		case reflect.Map, reflect.Slice:
			if base, isString := prop["bsonType"].(string); isString {
				prop["bsonType"] = bson.A{base, "null"}
			}
		default:
		}
	}
}
