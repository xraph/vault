package mongo

import (
	"context"
	"fmt"

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
	)
}
