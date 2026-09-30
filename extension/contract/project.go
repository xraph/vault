package contract

import (
	"encoding/json"
	"time"

	"github.com/xraph/vault/audit"
	"github.com/xraph/vault/flag"
	"github.com/xraph/vault/rotation"
	"github.com/xraph/vault/secret"
)

// SecretSummary is the wire projection of a secret's metadata. It never
// carries a value: only secrets.create and secrets.update ever put one on
// the wire, and only in their request, never a response.
type SecretSummary struct {
	ID      string `json:"id"`
	Key     string `json:"key"`
	Version int64  `json:"version"`
	// EncryptionAlg names the algorithm the stored value was encrypted
	// with. It has no omitempty: an empty string must reach the client as
	// "", because absence and "not encrypted" must not be confusable, and
	// "" is what every row written by an unconfigured Vault produces.
	EncryptionAlg string            `json:"encryptionAlg"`
	ExpiresAt     *string           `json:"expiresAt,omitempty"` // RFC3339
	AppID         string            `json:"appId"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	CreatedAt     string            `json:"createdAt"`
	UpdatedAt     string            `json:"updatedAt"`
}

// SecretVersionSummary is the wire projection of one historical version's
// metadata. Like SecretSummary, it never carries a value.
type SecretVersionSummary struct {
	ID        string `json:"id"`
	Version   int64  `json:"version"`
	CreatedBy string `json:"createdBy,omitempty"`
	CreatedAt string `json:"createdAt"`
}

// RotationPolicySummary is the wire projection of a rotation policy.
type RotationPolicySummary struct {
	ID              string `json:"id"`
	SecretKey       string `json:"secretKey"`
	IntervalSeconds int64  `json:"intervalSeconds"`
	Enabled         bool   `json:"enabled"`
	// Rotatable reports whether an application has registered a rotator
	// for this key. A policy without one will never rotate, however due it
	// gets: the loop logs an error every minute and changes nothing.
	Rotatable      bool    `json:"rotatable"`
	LastRotatedAt  *string `json:"lastRotatedAt,omitempty"`
	NextRotationAt *string `json:"nextRotationAt,omitempty"` // omitted when disabled
	CreatedAt      string  `json:"createdAt"`
	UpdatedAt      string  `json:"updatedAt"`
}

// RotationRecordSummary is the wire projection of one completed rotation
// event.
type RotationRecordSummary struct {
	ID         string `json:"id"`
	OldVersion int64  `json:"oldVersion"`
	NewVersion int64  `json:"newVersion"`
	RotatedBy  string `json:"rotatedBy,omitempty"`
	RotatedAt  string `json:"rotatedAt"`
}

// AuditSummary is the wire projection of one audit log entry, trimmed to
// what a secret or rotation detail page shows.
type AuditSummary struct {
	ID        string `json:"id"`
	Action    string `json:"action"`
	Outcome   string `json:"outcome"`
	UserID    string `json:"userId,omitempty"`
	CreatedAt string `json:"createdAt"`
}

// formatTime renders t as UTC RFC3339, the wire format every timestamp in
// this package uses.
func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

// formatTimePtr is formatTime for an optional timestamp: nil in, nil out.
func formatTimePtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := formatTime(*t)
	return &s
}

// projectSecretSummary projects a secret.Meta onto its wire type.
func projectSecretSummary(m *secret.Meta) SecretSummary {
	return SecretSummary{
		ID:            m.ID.String(),
		Key:           m.Key,
		Version:       m.Version,
		EncryptionAlg: m.EncryptionAlg,
		ExpiresAt:     formatTimePtr(m.ExpiresAt),
		AppID:         m.AppID,
		Metadata:      m.Metadata,
		CreatedAt:     formatTime(m.CreatedAt),
		UpdatedAt:     formatTime(m.UpdatedAt),
	}
}

// projectSecretVersionSummary projects a secret.Version onto its wire type.
func projectSecretVersionSummary(v *secret.Version) SecretVersionSummary {
	return SecretVersionSummary{
		ID:        v.ID.String(),
		Version:   v.Version,
		CreatedBy: v.CreatedBy,
		CreatedAt: formatTime(v.CreatedAt),
	}
}

// projectRotationPolicy projects a rotation.Policy onto its wire type.
// rotatable is looked up by the caller (rotation.Manager.RotatorKeys),
// because Policy itself has no notion of which keys have a registered
// rotator. NextRotationAt is projected as nil whenever the policy is
// disabled, whatever the stored value says: a disabled policy has no next
// rotation.
func projectRotationPolicy(p *rotation.Policy, rotatable bool) RotationPolicySummary {
	var next *string
	if p.Enabled {
		next = formatTimePtr(p.NextRotationAt)
	}
	return RotationPolicySummary{
		ID:              p.ID.String(),
		SecretKey:       p.SecretKey,
		IntervalSeconds: int64(p.Interval / time.Second),
		Enabled:         p.Enabled,
		Rotatable:       rotatable,
		LastRotatedAt:   formatTimePtr(p.LastRotatedAt),
		NextRotationAt:  next,
		CreatedAt:       formatTime(p.CreatedAt),
		UpdatedAt:       formatTime(p.UpdatedAt),
	}
}

// projectRotationRecord projects a rotation.Record onto its wire type.
func projectRotationRecord(r *rotation.Record) RotationRecordSummary {
	return RotationRecordSummary{
		ID:         r.ID.String(),
		OldVersion: r.OldVersion,
		NewVersion: r.NewVersion,
		RotatedBy:  r.RotatedBy,
		RotatedAt:  formatTime(r.RotatedAt),
	}
}

// projectAuditSummary projects an audit.Entry onto its wire type.
func projectAuditSummary(e *audit.Entry) AuditSummary {
	return AuditSummary{
		ID:        e.ID.String(),
		Action:    e.Action,
		Outcome:   e.Outcome,
		UserID:    e.UserID,
		CreatedAt: formatTime(e.CreatedAt),
	}
}

// isRotatable reports whether key appears in the sorted list a
// rotation.Manager's RotatorKeys returns.
func isRotatable(keys []string, key string) bool {
	for _, k := range keys {
		if k == key {
			return true
		}
	}
	return false
}

// FlagSummary is the wire projection of a flag definition. Its values leave
// through wireValue, so every backend produces the same JSON shape.
type FlagSummary struct {
	ID   string `json:"id"`
	Key  string `json:"key"`
	Type string `json:"type"`
	// DefaultValue is whatever is stored, which is not always a value of
	// Type: see DefaultMatchesType.
	DefaultValue any `json:"defaultValue"`
	// DefaultMatchesType is false when the stored default is not a value of
	// Type, e.g. the templ page's string "true" on a bool flag.
	DefaultMatchesType bool     `json:"defaultMatchesType"`
	Description        string   `json:"description"`
	Tags               []string `json:"tags"`
	Enabled            bool     `json:"enabled"`
	CreatedAt          string   `json:"createdAt"`
	UpdatedAt          string   `json:"updatedAt"`
}

// FlagRuleSummary is the wire projection of one targeting rule.
type FlagRuleSummary struct {
	ID       string `json:"id"`
	Priority int    `json:"priority"`
	Type     string `json:"type"`
	// Implemented is false for when_tenant_tag and custom: the engine never
	// matches them.
	Implemented bool     `json:"implemented"`
	TenantIDs   []string `json:"tenantIds"`
	UserIDs     []string `json:"userIds"`
	Percentage  int      `json:"percentage"`
	// StartAt and EndAt are UTC RFC3339, omitted for an open end.
	StartAt           *string        `json:"startAt,omitempty"`
	EndAt             *string        `json:"endAt,omitempty"`
	TagKey            string         `json:"tagKey,omitempty"`
	TagValue          string         `json:"tagValue,omitempty"`
	Evaluator         string         `json:"evaluator,omitempty"`
	Params            map[string]any `json:"params,omitempty"`
	ReturnValue       any            `json:"returnValue"`
	ReturnMatchesType bool           `json:"returnMatchesType"`
}

// FlagOverrideSummary is the wire projection of one per-tenant override.
type FlagOverrideSummary struct {
	TenantID         string `json:"tenantId"`
	Value            any    `json:"value"`
	ValueMatchesType bool   `json:"valueMatchesType"`
	UpdatedAt        string `json:"updatedAt"`
}

// FlagVariantSummary is the wire projection of one named variant.
type FlagVariantSummary struct {
	Value       any    `json:"value"`
	Description string `json:"description"`
}

// FlagTraceStep is the wire projection of one rule the engine considered
// during an explained evaluation. RuleID is the rule's id. Note has no omitempty: a rule the engine
// never reached carries "".
type FlagTraceStep struct {
	RuleID   string `json:"ruleId"`
	Priority int    `json:"priority"`
	Type     string `json:"type"`
	Matched  bool   `json:"matched"`
	Reached  bool   `json:"reached"`
	Note     string `json:"note"`
}

// wireValue normalises a stored flag value for the wire. A value that is
// already a JSON scalar (nil, bool, string, float64) passes through; every
// other value, whether a Go int, a map or slice, or the bson.D and bson.A a
// mongo read produces, goes through one JSON round trip, so all backends
// give the same plain map[string]any / []any / float64 shapes. A value that
// cannot be marshalled projects as nil: no backend can have stored one.
func wireValue(v any) any {
	switch v.(type) {
	case nil, bool, string, float64:
		return v
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}

// valueMatchesType reports whether v, as it will appear on the wire, is a
// value of type t.
func valueMatchesType(t flag.Type, v any) bool {
	return flag.ValidateValue(t, wireValue(v)) == nil
}

// nonNilStrings returns a copy of s that is never nil, so a list never
// marshals as null.
func nonNilStrings(s []string) []string {
	return append(make([]string, 0, len(s)), s...)
}

// projectFlagSummary projects a flag.Definition onto its wire type.
func projectFlagSummary(d *flag.Definition) FlagSummary {
	return FlagSummary{
		ID:                 d.ID.String(),
		Key:                d.Key,
		Type:               string(d.Type),
		DefaultValue:       wireValue(d.DefaultValue),
		DefaultMatchesType: valueMatchesType(d.Type, d.DefaultValue),
		Description:        d.Description,
		Tags:               nonNilStrings(d.Tags),
		Enabled:            d.Enabled,
		CreatedAt:          formatTime(d.CreatedAt),
		UpdatedAt:          formatTime(d.UpdatedAt),
	}
}

// projectFlagVariant projects a flag.Variant onto its wire type.
func projectFlagVariant(v flag.Variant) FlagVariantSummary {
	return FlagVariantSummary{Value: wireValue(v.Value), Description: v.Description}
}

// ruleImplemented reports whether the engine can match a rule of type t.
// Every other type, including one it has never heard of, never matches.
func ruleImplemented(t flag.RuleType) bool {
	switch t {
	case flag.RuleWhenTenant, flag.RuleWhenUser, flag.RuleRollout, flag.RuleSchedule:
		return true
	default:
		return false
	}
}

// projectFlagRule projects a flag.Rule onto its wire type. flagType is the
// type of the flag the rule belongs to, which its return value is checked
// against.
func projectFlagRule(r *flag.Rule, flagType flag.Type) FlagRuleSummary {
	return projectFlagRuleMatching(r, valueMatchesType(flagType, r.ReturnValue))
}

// projectFlagRuleMatching is projectFlagRule with the return value's type
// check already decided. A command that has just stored the rule through
// flag.Manager knows the answer is true (the manager validated the value
// against the flag's type before writing), so it does not read the flag
// again just to ask.
func projectFlagRuleMatching(r *flag.Rule, returnMatchesType bool) FlagRuleSummary {
	var params map[string]any
	if len(r.Config.Params) > 0 {
		params = make(map[string]any, len(r.Config.Params))
		for k, v := range r.Config.Params {
			params[k] = wireValue(v)
		}
	}
	return FlagRuleSummary{
		ID:                r.ID.String(),
		Priority:          r.Priority,
		Type:              string(r.Type),
		Implemented:       ruleImplemented(r.Type),
		TenantIDs:         nonNilStrings(r.Config.TenantIDs),
		UserIDs:           nonNilStrings(r.Config.UserIDs),
		Percentage:        r.Config.Percentage,
		StartAt:           formatTimePtr(r.Config.StartAt),
		EndAt:             formatTimePtr(r.Config.EndAt),
		TagKey:            r.Config.TagKey,
		TagValue:          r.Config.TagValue,
		Evaluator:         r.Config.Evaluator,
		Params:            params,
		ReturnValue:       wireValue(r.ReturnValue),
		ReturnMatchesType: returnMatchesType,
	}
}

// projectFlagOverride projects a flag.TenantOverride onto its wire type.
func projectFlagOverride(o *flag.TenantOverride, flagType flag.Type) FlagOverrideSummary {
	return projectFlagOverrideMatching(o, valueMatchesType(flagType, o.Value))
}

// projectFlagOverrideMatching is projectFlagOverride with the type check
// already decided, for the same reason as projectFlagRuleMatching.
func projectFlagOverrideMatching(o *flag.TenantOverride, valueMatchesType bool) FlagOverrideSummary {
	return FlagOverrideSummary{
		TenantID:         o.TenantID,
		Value:            wireValue(o.Value),
		ValueMatchesType: valueMatchesType,
		UpdatedAt:        formatTime(o.UpdatedAt),
	}
}
