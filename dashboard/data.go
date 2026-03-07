package dashboard

import (
	"context"

	"github.com/xraph/vault/audit"
	"github.com/xraph/vault/config"
	"github.com/xraph/vault/flag"
	"github.com/xraph/vault/override"
	"github.com/xraph/vault/rotation"
	"github.com/xraph/vault/secret"
	"github.com/xraph/vault/store"
)

// ─── Secret Helpers ──────────────────────────────────────────────────────────

func fetchSecretCount(ctx context.Context, s store.Store, appID string) int {
	metas, err := s.ListSecrets(ctx, appID, secret.ListOpts{Limit: 10000})
	if err != nil {
		return 0
	}
	return len(metas)
}

func fetchSecrets(ctx context.Context, s store.Store, appID string, opts secret.ListOpts) ([]*secret.Meta, error) {
	return s.ListSecrets(ctx, appID, opts)
}

func fetchSecretVersions(ctx context.Context, s store.Store, key, appID string) ([]*secret.Version, error) {
	return s.ListSecretVersions(ctx, key, appID)
}

// ─── Flag Helpers ────────────────────────────────────────────────────────────

func fetchFlagCount(ctx context.Context, s store.Store, appID string) int {
	defs, err := s.ListFlagDefinitions(ctx, appID, flag.ListOpts{Limit: 10000})
	if err != nil {
		return 0
	}
	return len(defs)
}

func fetchFlags(ctx context.Context, s store.Store, appID string, opts flag.ListOpts) ([]*flag.Definition, error) {
	return s.ListFlagDefinitions(ctx, appID, opts)
}

func fetchFlagRules(ctx context.Context, s store.Store, key, appID string) ([]*flag.Rule, error) {
	return s.GetFlagRules(ctx, key, appID)
}

func fetchFlagOverrides(ctx context.Context, s store.Store, key, appID string) ([]*flag.TenantOverride, error) {
	return s.ListFlagTenantOverrides(ctx, key, appID)
}

// ─── Config Helpers ──────────────────────────────────────────────────────────

func fetchConfigCount(ctx context.Context, s store.Store, appID string) int {
	entries, err := s.ListConfig(ctx, appID, config.ListOpts{Limit: 10000})
	if err != nil {
		return 0
	}
	return len(entries)
}

func fetchConfigs(ctx context.Context, s store.Store, appID string, opts config.ListOpts) ([]*config.Entry, error) {
	return s.ListConfig(ctx, appID, opts)
}

func fetchConfigVersions(ctx context.Context, s store.Store, key, appID string) ([]*config.EntryVersion, error) {
	return s.ListConfigVersions(ctx, key, appID)
}

// ─── Override Helpers ────────────────────────────────────────────────────────

func fetchOverridesByKey(ctx context.Context, s store.Store, key, appID string) ([]*override.Override, error) {
	return s.ListOverridesByKey(ctx, key, appID)
}

func fetchOverridesByTenant(ctx context.Context, s store.Store, appID, tenantID string) ([]*override.Override, error) {
	return s.ListOverridesByTenant(ctx, appID, tenantID)
}

// ─── Rotation Helpers ────────────────────────────────────────────────────────

func fetchRotationPolicyCount(ctx context.Context, s store.Store, appID string) int {
	policies, err := s.ListRotationPolicies(ctx, appID)
	if err != nil {
		return 0
	}
	return len(policies)
}

func fetchRotationPolicies(ctx context.Context, s store.Store, appID string) ([]*rotation.Policy, error) {
	return s.ListRotationPolicies(ctx, appID)
}

func fetchRotationRecords(ctx context.Context, s store.Store, key, appID string, opts rotation.ListOpts) ([]*rotation.Record, error) {
	return s.ListRotationRecords(ctx, key, appID, opts)
}

// ─── Audit Helpers ───────────────────────────────────────────────────────────

func fetchAuditCount(ctx context.Context, s store.Store, appID string) int {
	entries, err := s.ListAudit(ctx, appID, audit.ListOpts{Limit: 10000})
	if err != nil {
		return 0
	}
	return len(entries)
}

func fetchAuditEntries(ctx context.Context, s store.Store, appID string, opts audit.ListOpts) ([]*audit.Entry, error) {
	return s.ListAudit(ctx, appID, opts)
}

func fetchAuditByKey(ctx context.Context, s store.Store, key, appID string, opts audit.ListOpts) ([]*audit.Entry, error) {
	return s.ListAuditByKey(ctx, key, appID, opts)
}
