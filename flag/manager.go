package flag

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	audithook "github.com/xraph/vault/audit_hook"
	"github.com/xraph/vault/core"
	"github.com/xraph/vault/id"
)

// maxKeyBytes bounds a flag key. It is generous for a name and small enough
// to index on every backend.
const maxKeyBytes = 256

// Manager is the flag write service. Every backend's DefineFlag is an upsert
// that never checks anything, so the store on its own will overwrite a flag
// with a different type, accept a default that does not match the type, and
// leave rules behind for a key that has no flag. Manager is the one path
// that refuses those writes, drops the evaluation cache after each change,
// and reports it to an audit hook.
//
// It is safe for concurrent use as far as its store is. Update and
// SetEnabled are read-modify-write of one row with no version check, so two
// concurrent writers to the same flag can lose one write.
type Manager struct {
	store    Store
	engine   *Engine
	appID    string
	onMutate func(ctx context.Context, action, key, appID string)
}

// ManagerOption configures a Manager.
type ManagerOption func(*Manager)

// WithManagerAppID sets the app every flag the manager touches belongs to.
// It is not called WithAppID because that name already configures the read
// Service in this package.
func WithManagerAppID(appID string) ManagerOption {
	return func(m *Manager) { m.appID = appID }
}

// WithOnFlagMutate registers a callback invoked after each successful write,
// with the context the write ran under and one of the flag.* audit actions.
func WithOnFlagMutate(fn func(ctx context.Context, action, key, appID string)) ManagerOption {
	return func(m *Manager) { m.onMutate = fn }
}

// NewManager builds a flag write service over store. engine may be nil, in
// which case no evaluation cache is invalidated.
func NewManager(store Store, engine *Engine, opts ...ManagerOption) *Manager {
	m := &Manager{store: store, engine: engine}
	for _, o := range opts {
		o(m)
	}
	return m
}

// CreateInput is everything a new flag carries. DefaultValue must match Type.
type CreateInput struct {
	Key          string
	Type         Type
	DefaultValue any
	Description  string
	Tags         []string
	Enabled      bool
}

// UpdateInput changes only the fields that are non-nil.
type UpdateInput struct {
	Description  *string
	DefaultValue *any
	Tags         *[]string
}

// RuleInput is one targeting rule as a caller writes it. Priority is not an
// input: SetRules derives it from the rule's index.
type RuleInput struct {
	Type        RuleType
	Config      RuleConfig
	ReturnValue any
}

// Create defines a new flag. It refuses an invalid key, type or default, and
// returns core.ErrFlagExists (vault.ErrFlagExists) when the key is taken,
// rather than overwriting the flag the way the store's upsert would.
func (m *Manager) Create(ctx context.Context, in CreateInput) (*Definition, error) {
	if err := validateKey(in.Key); err != nil {
		return nil, err
	}
	if !validType(in.Type) {
		return nil, &ValidationError{Field: "type", Message: "must be one of bool, string, int, float, json"}
	}
	if err := ValidateValue(in.Type, in.DefaultValue); err != nil {
		return nil, &ValidationError{Field: "defaultValue", Message: err.Error()}
	}

	_, err := m.store.GetFlagDefinition(ctx, in.Key, m.appID)
	switch {
	case err == nil:
		return nil, core.ErrFlagExists
	case errors.Is(err, core.ErrFlagNotFound):
	default:
		return nil, err
	}

	// Rules and overrides written for this key before the flag existed
	// (a delete that failed part way, or an override set on a missing flag)
	// are live the moment the flag is. A new flag starts empty, so they are
	// cleared first: a failure here leaves no flag behind, and a retry finds
	// the key free.
	if err = m.clearOrphans(ctx, in.Key); err != nil {
		return nil, err
	}

	def := &Definition{
		Entity:       core.NewEntity(),
		ID:           id.NewFlagID(),
		Key:          in.Key,
		Type:         in.Type,
		DefaultValue: in.DefaultValue,
		Description:  in.Description,
		Tags:         copyTags(in.Tags),
		Enabled:      in.Enabled,
		AppID:        m.appID,
	}
	if err = m.store.DefineFlag(ctx, def); err != nil {
		return nil, err
	}

	// The flag exists from here on, so whatever happens next it is audited
	// and the cache is dropped before Create returns.
	m.invalidate(in.Key)
	m.audit(ctx, audithook.ActionFlagCreated, in.Key)
	return m.store.GetFlagDefinition(ctx, in.Key, m.appID)
}

// clearOrphans drops the rules and tenant overrides stored under a key that
// has no flag. A backend that refuses rules for a missing flag (memory
// returns ErrFlagNotFound) has nothing to clear there, so that one error is
// not a failure.
func (m *Manager) clearOrphans(ctx context.Context, key string) error {
	err := m.store.SetFlagRules(ctx, key, m.appID, []*Rule{})
	if err != nil && !errors.Is(err, core.ErrFlagNotFound) {
		return err
	}
	orphans, err := m.store.ListFlagTenantOverrides(ctx, key, m.appID)
	if err != nil {
		return err
	}
	for _, o := range orphans {
		err = m.store.DeleteFlagTenantOverride(ctx, key, m.appID, o.TenantID)
		if err != nil && !errors.Is(err, core.ErrOverrideNotFound) {
			return err
		}
	}
	return nil
}

// Update changes the description, default value or tags of an existing flag.
// Only non-nil fields change; the rest of the row (variants, metadata, id,
// creation time) is carried over untouched. A new default is validated
// against the flag's stored type.
func (m *Manager) Update(ctx context.Context, key string, in UpdateInput) (*Definition, error) {
	def, err := m.store.GetFlagDefinition(ctx, key, m.appID)
	if err != nil {
		return nil, err
	}
	if in.DefaultValue != nil {
		if err := ValidateValue(def.Type, *in.DefaultValue); err != nil {
			return nil, &ValidationError{Field: "defaultValue", Message: err.Error()}
		}
		def.DefaultValue = *in.DefaultValue
	}
	if in.Description != nil {
		def.Description = *in.Description
	}
	if in.Tags != nil {
		def.Tags = copyTags(*in.Tags)
	}
	return m.write(ctx, def, audithook.ActionFlagUpdated)
}

// SetEnabled turns a flag on or off. Setting the value it already has writes
// nothing and records nothing.
func (m *Manager) SetEnabled(ctx context.Context, key string, enabled bool) (*Definition, error) {
	def, err := m.store.GetFlagDefinition(ctx, key, m.appID)
	if err != nil {
		return nil, err
	}
	if def.Enabled == enabled {
		return def, nil
	}
	def.Enabled = enabled
	return m.write(ctx, def, audithook.ActionFlagToggled)
}

// write stores def whole, so Variants and Metadata survive, then drops the
// cache, records action and returns the stored row.
func (m *Manager) write(ctx context.Context, def *Definition, action string) (*Definition, error) {
	def.Touch()
	if err := m.store.DefineFlag(ctx, def); err != nil {
		return nil, err
	}
	m.invalidate(def.Key)
	m.audit(ctx, action, def.Key)
	return m.store.GetFlagDefinition(ctx, def.Key, m.appID)
}

// Delete removes a flag together with its rules and overrides.
func (m *Manager) Delete(ctx context.Context, key string) error {
	if err := m.store.DeleteFlagDefinition(ctx, key, m.appID); err != nil {
		return err
	}
	m.invalidate(key)
	m.audit(ctx, audithook.ActionFlagDeleted, key)
	return nil
}

// SetRules replaces the flag's whole rule list. Priority is the index, so
// the first rule wins. Every rule is validated before anything is written.
func (m *Manager) SetRules(ctx context.Context, key string, rules []RuleInput) ([]*Rule, error) {
	def, err := m.store.GetFlagDefinition(ctx, key, m.appID)
	if err != nil {
		return nil, err
	}

	out := make([]*Rule, 0, len(rules))
	for i, in := range rules {
		cfg, verr := validateRule(i, def.Type, in)
		if verr != nil {
			return nil, verr
		}
		out = append(out, &Rule{
			Entity:      core.NewEntity(),
			ID:          id.NewRuleID(),
			FlagKey:     key,
			AppID:       m.appID,
			Priority:    i,
			Type:        in.Type,
			Config:      cfg,
			ReturnValue: in.ReturnValue,
		})
	}

	err = m.store.SetFlagRules(ctx, key, m.appID, out)
	if err != nil {
		return nil, err
	}
	m.invalidate(key)
	m.audit(ctx, audithook.ActionFlagRulesSet, key)

	stored, err := m.store.GetFlagRules(ctx, key, m.appID)
	if err != nil {
		return nil, err
	}
	if stored == nil {
		stored = []*Rule{}
	}
	return stored, nil
}

// SetTenantOverride pins a flag's value for one tenant. The flag must exist:
// no backend checks that for an override.
func (m *Manager) SetTenantOverride(ctx context.Context, key, tenantID string, value any) (*TenantOverride, error) {
	def, err := m.store.GetFlagDefinition(ctx, key, m.appID)
	if err != nil {
		return nil, err
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, &ValidationError{Field: "tenantId", Message: "is required"}
	}
	if err = ValidateValue(def.Type, value); err != nil {
		return nil, &ValidationError{Field: "value", Message: err.Error()}
	}

	err = m.store.SetFlagTenantOverride(ctx, key, m.appID, tenantID, value)
	if err != nil {
		return nil, err
	}
	m.invalidate(key)
	m.audit(ctx, audithook.ActionFlagOverrideSet, key)

	all, err := m.store.ListFlagTenantOverrides(ctx, key, m.appID)
	if err != nil {
		return nil, err
	}
	for _, o := range all {
		if o.TenantID == tenantID {
			return o, nil
		}
	}
	return nil, fmt.Errorf("flag: override for %q on %q vanished after it was written", tenantID, key)
}

// DeleteTenantOverride removes a tenant's override. A tenant with none
// returns core.ErrOverrideNotFound from the store.
func (m *Manager) DeleteTenantOverride(ctx context.Context, key, tenantID string) error {
	if _, err := m.store.GetFlagDefinition(ctx, key, m.appID); err != nil {
		return err
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return &ValidationError{Field: "tenantId", Message: "is required"}
	}
	if err := m.store.DeleteFlagTenantOverride(ctx, key, m.appID, tenantID); err != nil {
		return err
	}
	m.invalidate(key)
	m.audit(ctx, audithook.ActionFlagOverrideDeleted, key)
	return nil
}

func (m *Manager) invalidate(key string) {
	if m.engine != nil {
		m.engine.Invalidate(key)
	}
}

func (m *Manager) audit(ctx context.Context, action, key string) {
	if m.onMutate != nil {
		m.onMutate(ctx, action, key, m.appID)
	}
}

func copyTags(tags []string) []string {
	out := make([]string, len(tags))
	copy(out, tags)
	return out
}

func validType(t Type) bool {
	switch t {
	case TypeBool, TypeString, TypeInt, TypeFloat, TypeJSON:
		return true
	default:
		return false
	}
}

func validateKey(key string) error {
	switch {
	case strings.TrimSpace(key) == "":
		return &ValidationError{Field: "key", Message: "is required"}
	case key != strings.TrimSpace(key):
		return &ValidationError{Field: "key", Message: "must not start or end with whitespace"}
	case len(key) > maxKeyBytes:
		return &ValidationError{Field: "key", Message: fmt.Sprintf("must be at most %d bytes", maxKeyBytes)}
	}
	return nil
}

// validateRule checks one rule and returns the config to store: only the
// fields its type reads, normalised (ids trimmed, times in UTC).
// when_tenant_tag and custom keep their config as given; the engine does not
// evaluate them yet, but a caller may author them ahead of that.
func validateRule(i int, flagType Type, in RuleInput) (RuleConfig, error) {
	field := func(name string) string { return fmt.Sprintf("rules[%d].%s", i, name) }
	bad := func(name, msg string) (RuleConfig, error) {
		return RuleConfig{}, &ValidationError{Field: field(name), Message: msg}
	}

	var cfg RuleConfig
	switch in.Type {
	case RuleWhenTenant:
		ids, msg := cleanIDs(in.Config.TenantIDs)
		if msg != "" {
			return bad("config.tenantIds", msg)
		}
		cfg.TenantIDs = ids
	case RuleWhenUser:
		ids, msg := cleanIDs(in.Config.UserIDs)
		if msg != "" {
			return bad("config.userIds", msg)
		}
		cfg.UserIDs = ids
	case RuleRollout:
		if in.Config.Percentage < 0 || in.Config.Percentage > 100 {
			return bad("config.percentage", "must be between 0 and 100")
		}
		cfg.Percentage = in.Config.Percentage
	case RuleSchedule:
		start, end := in.Config.StartAt, in.Config.EndAt
		if start == nil && end == nil {
			return bad("config", "a schedule needs a start, an end, or both")
		}
		if start != nil && end != nil && !start.Before(*end) {
			return bad("config.endAt", "must be after the start")
		}
		cfg.StartAt = utcCopy(start)
		cfg.EndAt = utcCopy(end)
	case RuleWhenTenantTag, RuleCustom:
		cfg = in.Config
	default:
		return bad("type", fmt.Sprintf("unknown rule type %q", in.Type))
	}

	if err := ValidateValue(flagType, in.ReturnValue); err != nil {
		return bad("returnValue", err.Error())
	}
	return cfg, nil
}

// cleanIDs trims each id and refuses an empty list, a blank id or a
// duplicate. The second result is the refusal, empty when the list is fine.
func cleanIDs(in []string) (ids []string, refusal string) {
	if len(in) == 0 {
		return nil, "must list at least one id"
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		if s == "" {
			return nil, "must not contain a blank id"
		}
		if _, dup := seen[s]; dup {
			return nil, fmt.Sprintf("lists %q more than once", s)
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out, ""
}

func utcCopy(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}
