// Package vault provides composable secrets management, feature flags,
// and runtime configuration for Go applications.
//
// Vault unifies three capabilities behind a single API surface:
//   - Secrets: Encrypted key-value storage with versioning and rotation
//   - Feature Flags: Boolean/string/int/float toggles with targeting rules
//   - Runtime Config: Hot-reloadable settings with per-tenant overrides
//
// All entity IDs use TypeID (go.jetify.com/typeid) via a single id.ID struct
// with dynamic prefixes, consistent with Chronicle and the broader Forge ecosystem.
//
// Usage:
//
//	v, err := vault.New(
//	    vault.WithStore(memoryStore),
//	    vault.WithEncryptionKey(key),
//	)
//	if err != nil { ... }
//
//	// Secrets
//	secret, _ := v.Secrets().Get(ctx, "openai_api_key")
//
//	// Feature flags
//	enabled := v.Flags().Bool(ctx, "new_dashboard", false)
//
//	// Runtime config
//	limit := v.Config().Int(ctx, "rate_limit", 100)
package vault
