// Package audithook provides an audit event recording extension for Vault.
// It bridges Vault operations to external audit systems (e.g. Chronicle).
package audithook

// ──────────────────────────────────────────────────
// Actions
// ──────────────────────────────────────────────────

// Standard audit actions for Vault operations.
const (
	// Secret actions.
	ActionSecretAccessed = "secret.accessed"
	ActionSecretSet      = "secret.set"
	ActionSecretDeleted  = "secret.deleted"
	ActionSecretRotated  = "secret.rotated"

	// Flag actions.
	ActionFlagEvaluated = "flag.evaluated"
	ActionFlagCreated   = "flag.created"
	ActionFlagUpdated   = "flag.updated"
	ActionFlagDeleted   = "flag.deleted"
	ActionFlagToggled   = "flag.toggled"

	// ActionFlagRulesSet records a whole-list replacement of a flag's
	// targeting rules.
	ActionFlagRulesSet = "flag.rules_set"

	// ActionFlagOverrideSet records a per-tenant override being written.
	ActionFlagOverrideSet = "flag.override_set"

	// ActionFlagOverrideDeleted records a per-tenant override being removed.
	ActionFlagOverrideDeleted = "flag.override_deleted"

	// Config actions.
	ActionConfigSet     = "config.set"
	ActionConfigDeleted = "config.deleted"

	// ActionConfigRolledBack records a config entry's value being restored
	// from an earlier version.
	ActionConfigRolledBack = "config.rolled_back"

	// Override actions.
	ActionOverrideSet     = "override.set"
	ActionOverrideDeleted = "override.deleted"
)

// AllActions returns all registered audit action strings.
func AllActions() []string {
	return []string{
		ActionSecretAccessed, ActionSecretSet, ActionSecretDeleted, ActionSecretRotated,
		ActionFlagEvaluated, ActionFlagCreated, ActionFlagUpdated, ActionFlagDeleted, ActionFlagToggled,
		ActionFlagRulesSet, ActionFlagOverrideSet, ActionFlagOverrideDeleted,
		ActionConfigSet, ActionConfigDeleted, ActionConfigRolledBack,
		ActionOverrideSet, ActionOverrideDeleted,
	}
}

// ──────────────────────────────────────────────────
// Categories
// ──────────────────────────────────────────────────

// Audit event categories.
const (
	CategorySecret   = "vault.secret"
	CategoryFlag     = "vault.flag"
	CategoryConfig   = "vault.config"
	CategoryOverride = "vault.override"
)

// ──────────────────────────────────────────────────
// Resources
// ──────────────────────────────────────────────────

// Resource types.
const (
	ResourceSecret   = "secret"
	ResourceFlag     = "flag"
	ResourceConfig   = "config"
	ResourceOverride = "override"
)

// ──────────────────────────────────────────────────
// Severity & Outcome
// ──────────────────────────────────────────────────

// Severity levels.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Outcome values.
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
)
