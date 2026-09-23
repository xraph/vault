package flag

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/xraph/vault/core"
	"github.com/xraph/vault/scope"
)

// ContextKey is the context key type for flag evaluation. It is the same type
// as scope.ContextKey, so a tenant or user set with the scope helpers is the
// one the engine reads.
type ContextKey = scope.ContextKey

const (
	// ContextKeyTenantID is the context key for tenant ID.
	ContextKeyTenantID ContextKey = "vault.tenant_id"
	// ContextKeyUserID is the context key for user ID.
	ContextKeyUserID ContextKey = "vault.user_id"
)

// Reasons a flag evaluated the way it did. These are the four outcomes
// the engine can reach, in the order it reaches them.
const (
	ReasonDisabled       = "disabled"
	ReasonTenantOverride = "tenantOverride"
	ReasonRule           = "rule"
	ReasonDefault        = "default"
)

// TraceStep records one targeting rule the engine considered.
// Reached is false for rules after the one that matched: the engine stops
// at the first match, and a trace that hid that would misreport precedence.
type TraceStep struct {
	Priority int      `json:"priority"`
	Type     RuleType `json:"type"`
	Matched  bool     `json:"matched"`
	Reached  bool     `json:"reached"`
	Note     string   `json:"note,omitempty"`
}

// Detail is an explained evaluation: the value, why it was chosen, the rule
// that chose it when one did, and every rule considered on the way.
// MatchedRule is nil unless Reason is ReasonRule.
type Detail struct {
	Value       any         `json:"value"`
	Reason      string      `json:"reason"`
	MatchedRule *Rule       `json:"matched_rule,omitempty"`
	Trace       []TraceStep `json:"trace"`
}

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
//
// This is the hot path every SDK flag read goes through, so it keeps the
// evaluation cache. EvaluateDetail deliberately does not.
func (e *Engine) Evaluate(ctx context.Context, key, appID string) (any, error) {
	tenantID := contextString(ctx, ContextKeyTenantID)
	userID := contextString(ctx, ContextKeyUserID)

	if e.cache != nil {
		if val, ok := e.cache.get(key, appID, tenantID, userID); ok {
			return val, nil
		}
	}

	d, err := e.evaluate(ctx, key, appID, false)
	if err != nil {
		return nil, err
	}
	// A disabled flag was never cached before, and still is not: flipping
	// Enabled must take effect immediately rather than after the TTL.
	if d.Reason != ReasonDisabled {
		e.cacheSet(key, appID, tenantID, userID, d.Value)
	}
	return d.Value, nil
}

// EvaluateDetail returns the value together with why it was chosen and every
// rule considered. It always bypasses the evaluation cache, because it exists
// to answer "why is this tenant seeing this right now" and a cached answer is
// the wrong answer to that question.
func (e *Engine) EvaluateDetail(ctx context.Context, key, appID string) (Detail, error) {
	return e.evaluate(ctx, key, appID, true)
}

// evaluate holds the precedence. Both entry points go through it so the
// explained path and the hot path can never disagree about the order.
func (e *Engine) evaluate(ctx context.Context, key, appID string, withTrace bool) (Detail, error) {
	tenantID := contextString(ctx, ContextKeyTenantID)
	userID := contextString(ctx, ContextKeyUserID)

	def, err := e.store.GetFlagDefinition(ctx, key, appID)
	if err != nil {
		return Detail{}, err
	}

	// An explained evaluation always carries a trace, empty on the paths
	// that consult no rules, so it marshals as [] and never as null.
	var trace []TraceStep
	if withTrace {
		trace = []TraceStep{}
	}

	// Disabled: the default, and nothing below is consulted at all.
	if !def.Enabled {
		return Detail{Value: def.DefaultValue, Reason: ReasonDisabled, Trace: trace}, nil
	}

	if tenantID != "" {
		overrideVal, oErr := e.store.GetFlagTenantOverride(ctx, key, appID, tenantID)
		if oErr == nil {
			return Detail{Value: overrideVal, Reason: ReasonTenantOverride, Trace: trace}, nil
		}
		if !errors.Is(oErr, core.ErrOverrideNotFound) {
			return Detail{}, oErr
		}
	}

	rules, err := e.store.GetFlagRules(ctx, key, appID)
	if err != nil {
		return Detail{}, err
	}

	if withTrace {
		trace = make([]TraceStep, 0, len(rules))
	}

	for i, rule := range rules {
		matched := e.evaluateRule(rule, key, tenantID, userID)
		if withTrace {
			trace = append(trace, TraceStep{
				Priority: rule.Priority,
				Type:     rule.Type,
				Matched:  matched,
				Reached:  true,
				Note:     ruleNote(rule, key, tenantID, userID),
			})
		}
		if !matched {
			continue
		}
		if withTrace {
			for _, rest := range rules[i+1:] {
				trace = append(trace, TraceStep{
					Priority: rest.Priority,
					Type:     rest.Type,
					Reached:  false,
				})
			}
		}
		return Detail{Value: rule.ReturnValue, Reason: ReasonRule, MatchedRule: rule, Trace: trace}, nil
	}

	return Detail{Value: def.DefaultValue, Reason: ReasonDefault, Trace: trace}, nil
}

// ruleNote explains one rule's verdict in a line an operator can act on.
// It never re-derives a verdict: the rollout case calls the same
// RolloutBucket the evaluator used.
func ruleNote(rule *Rule, flagKey, tenantID, userID string) string {
	switch rule.Type {
	case RuleWhenTenant:
		if tenantID == "" {
			return "no tenant in context"
		}
		return "tenant " + tenantID
	case RuleWhenUser:
		if userID == "" {
			return "no user in context"
		}
		return "user " + userID
	case RuleRollout:
		if tenantID == "" {
			return "no tenant in context, a rollout cannot match"
		}
		return fmt.Sprintf("bucket %d of 100, threshold %d",
			RolloutBucket(tenantID, flagKey), rule.Config.Percentage)
	case RuleSchedule:
		now := time.Now().UTC()
		if rule.Config.StartAt != nil && now.Before(*rule.Config.StartAt) {
			return "the window has not started"
		}
		if rule.Config.EndAt != nil && now.After(*rule.Config.EndAt) {
			return "the window has ended"
		}
		return "inside the window"
	case RuleWhenTenantTag, RuleCustom:
		return "this rule type is not implemented and never matches"
	default:
		return ""
	}
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

// RolloutBucket returns the deterministic 0-99 bucket a tenant falls into for
// a flag. A rollout rule matches when the bucket is below its percentage.
// Exported so an explained evaluation can report the same number the verdict
// used; two copies of this arithmetic would eventually disagree.
func RolloutBucket(tenantID, flagKey string) uint32 {
	hash := sha256.Sum256([]byte(tenantID + ":" + flagKey))
	return binary.BigEndian.Uint32(hash[:4]) % 100
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
	return RolloutBucket(tenantID, flagKey) < uint32(pct)
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

func (e *Engine) cacheSet(key, appID, tenantID, userID string, val any) {
	if e.cache != nil {
		e.cache.set(key, appID, tenantID, userID, val)
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
