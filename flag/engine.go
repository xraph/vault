package flag

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"

	"github.com/xraph/vault"
)

// ContextKey is the type for context value keys used by the flag engine.
type ContextKey string

const (
	// ContextKeyTenantID is the context key for tenant ID.
	ContextKeyTenantID ContextKey = "vault.tenant_id"
	// ContextKeyUserID is the context key for user ID.
	ContextKeyUserID ContextKey = "vault.user_id"
)

// EngineOption configures the Engine.
type EngineOption func(*Engine)

// WithCacheTTL sets the evaluation cache TTL.
func WithCacheTTL(ttl time.Duration) EngineOption {
	return func(e *Engine) { e.cache = newEvaluationCache(ttl) }
}

// Engine evaluates feature flags using definitions, rules, and overrides.
type Engine struct {
	store Store
	cache *evaluationCache
}

// NewEngine creates a flag evaluation engine.
func NewEngine(store Store, opts ...EngineOption) *Engine {
	e := &Engine{store: store}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Evaluate returns the value for a flag key and app ID.
// Evaluation order: disabled -> tenant override -> rules (by priority) -> default.
func (e *Engine) Evaluate(ctx context.Context, key, appID string) (any, error) {
	tenantID := contextString(ctx, ContextKeyTenantID)
	userID := contextString(ctx, ContextKeyUserID)

	// Check cache.
	if e.cache != nil {
		if val, ok := e.cache.get(key, tenantID); ok {
			return val, nil
		}
	}

	// Get definition.
	def, err := e.store.GetFlagDefinition(ctx, key, appID)
	if err != nil {
		return nil, err
	}

	// Disabled flag: always return default.
	if !def.Enabled {
		return def.DefaultValue, nil
	}

	// Check tenant override.
	if tenantID != "" {
		overrideVal, oErr := e.store.GetFlagTenantOverride(ctx, key, appID, tenantID)
		if oErr == nil {
			e.cacheSet(key, tenantID, overrideVal)
			return overrideVal, nil
		}
		// Ignore ErrOverrideNotFound, propagate other errors.
		if !errors.Is(oErr, vault.ErrOverrideNotFound) {
			return nil, oErr
		}
	}

	// Evaluate rules in priority order.
	rules, err := e.store.GetFlagRules(ctx, key, appID)
	if err != nil {
		return nil, err
	}

	for _, rule := range rules {
		if e.evaluateRule(rule, key, tenantID, userID) {
			result := rule.ReturnValue
			e.cacheSet(key, tenantID, result)
			return result, nil
		}
	}

	// No rule matched: return default.
	result := def.DefaultValue
	e.cacheSet(key, tenantID, result)
	return result, nil
}

// evaluateRule checks if a single rule matches the current context.
func (e *Engine) evaluateRule(rule *Rule, flagKey, tenantID, userID string) bool {
	switch rule.Type {
	case RuleWhenTenant:
		return e.evalWhenTenant(rule, tenantID)
	case RuleWhenUser:
		return e.evalWhenUser(rule, userID)
	case RuleRollout:
		return e.evalRollout(rule, flagKey, tenantID)
	case RuleSchedule:
		return e.evalSchedule(rule)
	case RuleWhenTenantTag:
		// Tag evaluation requires an external callback - not yet implemented.
		return false
	case RuleCustom:
		// Custom evaluator - not yet implemented.
		return false
	default:
		return false
	}
}

func (e *Engine) evalWhenTenant(rule *Rule, tenantID string) bool {
	if tenantID == "" {
		return false
	}
	for _, id := range rule.Config.TenantIDs {
		if id == tenantID {
			return true
		}
	}
	return false
}

func (e *Engine) evalWhenUser(rule *Rule, userID string) bool {
	if userID == "" {
		return false
	}
	for _, id := range rule.Config.UserIDs {
		if id == userID {
			return true
		}
	}
	return false
}

// evalRollout uses a deterministic hash of (tenantID + flagKey) to decide.
func (e *Engine) evalRollout(rule *Rule, flagKey, tenantID string) bool {
	if tenantID == "" {
		return false
	}
	pct := rule.Config.Percentage
	if pct <= 0 {
		return false
	}
	if pct >= 100 {
		return true
	}

	hash := sha256.Sum256([]byte(tenantID + ":" + flagKey))
	bucket := binary.BigEndian.Uint32(hash[:4]) % 100
	return bucket < uint32(pct)
}

func (e *Engine) evalSchedule(rule *Rule) bool {
	now := time.Now().UTC()
	if rule.Config.StartAt != nil && now.Before(*rule.Config.StartAt) {
		return false
	}
	if rule.Config.EndAt != nil && now.After(*rule.Config.EndAt) {
		return false
	}
	return true
}

func (e *Engine) cacheSet(key, tenantID string, val any) {
	if e.cache != nil {
		e.cache.set(key, tenantID, val)
	}
}

// contextString extracts a string value from the context, returning "" if absent.
func contextString(ctx context.Context, key ContextKey) string {
	v, ok := ctx.Value(key).(string)
	if !ok {
		return ""
	}
	return v
}
