package flag

import (
	"time"

	"github.com/xraph/vault"
	"github.com/xraph/vault/id"
)

// RuleType represents the type of a targeting rule.
type RuleType string

// Targeting rule types.
const (
	RuleWhenTenant    RuleType = "when_tenant"
	RuleWhenTenantTag RuleType = "when_tenant_tag"
	RuleWhenUser      RuleType = "when_user"
	RuleRollout       RuleType = "rollout"
	RuleSchedule      RuleType = "schedule"
	RuleCustom        RuleType = "custom"
)

// Rule represents a targeting rule for a feature flag.
// Rules are evaluated in priority order (lower number = higher priority).
type Rule struct {
	vault.Entity
	ID          id.ID      `json:"id"`
	FlagKey     string     `json:"flag_key"`
	AppID       string     `json:"app_id"`
	Priority    int        `json:"priority"` // lower = higher priority
	Type        RuleType   `json:"type"`
	Config      RuleConfig `json:"config"`
	ReturnValue any        `json:"return_value"`
}

// RuleConfig holds the configuration for a targeting rule.
type RuleConfig struct {
	// WhenTenant: match specific tenant IDs.
	TenantIDs []string `json:"tenant_ids,omitempty"`

	// WhenTenantTag: match tenants with a specific tag.
	TagKey   string `json:"tag_key,omitempty"`
	TagValue string `json:"tag_value,omitempty"`

	// WhenUser: match specific user IDs.
	UserIDs []string `json:"user_ids,omitempty"`

	// Rollout: percentage (0-100).
	Percentage int `json:"percentage,omitempty"`

	// Schedule: time-based activation.
	StartAt *time.Time `json:"start_at,omitempty"`
	EndAt   *time.Time `json:"end_at,omitempty"`

	// Custom: plugin-evaluated.
	Evaluator string         `json:"evaluator,omitempty"` // plugin name
	Params    map[string]any `json:"params,omitempty"`
}

// TenantOverride represents a direct per-tenant flag value override.
type TenantOverride struct {
	vault.Entity
	ID       id.ID  `json:"id"`
	FlagKey  string `json:"flag_key"`
	AppID    string `json:"app_id"`
	TenantID string `json:"tenant_id"`
	Value    any    `json:"value"`
}

// ──────────────────────────────────────────────────
// Convenience constructors
// ──────────────────────────────────────────────────

// WhenTenant creates a rule that matches specific tenant IDs.
func WhenTenant(tenantIDs ...string) *Rule {
	return &Rule{
		Entity: vault.NewEntity(),
		ID:     id.NewRuleID(),
		Type:   RuleWhenTenant,
		Config: RuleConfig{TenantIDs: tenantIDs},
	}
}

// WhenTenantTag creates a rule that matches tenants with a specific tag.
func WhenTenantTag(key, value string) *Rule {
	return &Rule{
		Entity: vault.NewEntity(),
		ID:     id.NewRuleID(),
		Type:   RuleWhenTenantTag,
		Config: RuleConfig{TagKey: key, TagValue: value},
	}
}

// WhenUser creates a rule that matches specific user IDs.
func WhenUser(userIDs ...string) *Rule {
	return &Rule{
		Entity: vault.NewEntity(),
		ID:     id.NewRuleID(),
		Type:   RuleWhenUser,
		Config: RuleConfig{UserIDs: userIDs},
	}
}

// Rollout creates a rule for percentage-based rollout (0-100).
func Rollout(percentage int) *Rule {
	return &Rule{
		Entity: vault.NewEntity(),
		ID:     id.NewRuleID(),
		Type:   RuleRollout,
		Config: RuleConfig{Percentage: percentage},
	}
}

// Schedule creates a rule active only within a time window.
func Schedule(start, end time.Time) *Rule {
	return &Rule{
		Entity: vault.NewEntity(),
		ID:     id.NewRuleID(),
		Type:   RuleSchedule,
		Config: RuleConfig{StartAt: &start, EndAt: &end},
	}
}

// Return sets the value returned when this rule matches.
func (r *Rule) Return(value any) *Rule {
	r.ReturnValue = value
	return r
}
