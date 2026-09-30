// Package configmgr is the write service for runtime config entries and
// their per-tenant overrides.
//
// It lives apart from package config because package override imports
// config: a manager that touches both stores cannot sit in either. configmgr
// imports both and neither imports it.
package configmgr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"go.mongodb.org/mongo-driver/v2/bson"

	audithook "github.com/xraph/vault/audit_hook"
	"github.com/xraph/vault/config"
	"github.com/xraph/vault/core"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/override"
)

// maxKeyBytes bounds a config key, as it does a flag key.
const maxKeyBytes = 256

// Manager is the config write service. Every backend's SetConfig is an
// upsert that never checks anything and versions on every call, and no
// backend deletes a key's overrides with the key, so the store on its own
// will overwrite an existing entry, store "abc" as an int, erase a
// description on update, and bring a deleted key's overrides back to life
// when the key is recreated. Manager is the one path that refuses those
// writes, keeps every field a request did not name, drops the resolver
// cache and runs the watchers after each change, and reports it to an audit
// hook.
//
// It is safe for concurrent use as far as its stores are. Update and
// Rollback are read-modify-write of one row with no version check, so two
// concurrent writers to the same key can lose one write. A SetOverride that
// races a Delete of its key can leave an orphan override behind until the key
// is recreated, when Create clears it.
type Manager struct {
	store     config.Store
	overrides override.Store
	resolver  *override.Resolver
	service   *config.Service
	appID     string
	onMutate  func(ctx context.Context, action, resource, key, appID, tenantID string)
}

// ManagerOption configures a Manager.
type ManagerOption func(*Manager)

// WithManagerAppID sets the app every entry and override the manager
// touches belongs to.
func WithManagerAppID(appID string) ManagerOption {
	return func(m *Manager) { m.appID = appID }
}

// WithOnConfigMutate registers a callback invoked after each successful
// write, with the context the write ran under, one of the config.* or
// override.* audit actions, the resource it concerns (config or override),
// the config key, the app, and the tenant an override write targets (empty
// for a write to the entry itself).
func WithOnConfigMutate(fn func(ctx context.Context, action, resource, key, appID, tenantID string)) ManagerOption {
	return func(m *Manager) { m.onMutate = fn }
}

// NewManager builds a config write service. resolver may be nil, in which
// case no resolver cache is invalidated; svc may be nil, in which case no
// watchers run.
func NewManager(store config.Store, overrides override.Store, resolver *override.Resolver, svc *config.Service, opts ...ManagerOption) *Manager {
	m := &Manager{store: store, overrides: overrides, resolver: resolver, service: svc}
	for _, o := range opts {
		o(m)
	}
	return m
}

// CreateInput is everything a new entry carries. Value must be valid for
// ValueType, which is required.
type CreateInput struct {
	Key         string
	ValueType   string
	Description string
	Value       any
}

// UpdateInput changes only the fields that are non-nil. Value is a pointer
// to an any so that a json entry can be set to null: a nil Value pointer
// means "leave the value", a pointer to nil means null.
type UpdateInput struct {
	Value       *any
	ValueType   *string
	Description *string
}

// Create defines a new entry. It refuses an invalid key, type or value, and
// returns core.ErrConfigExists (vault.ErrConfigExists) when the key is
// taken, rather than overwriting the entry the way the store's upsert would.
func (m *Manager) Create(ctx context.Context, in CreateInput) (*config.Entry, error) {
	if err := validateKey(in.Key); err != nil {
		return nil, err
	}
	if !config.KnownType(in.ValueType) {
		return nil, &config.ValidationError{Field: "valueType", Message: typeList}
	}
	if err := validateValue(in.ValueType, in.Value); err != nil {
		return nil, err
	}

	_, err := m.store.GetConfig(ctx, in.Key, m.appID)
	switch {
	case err == nil:
		return nil, core.ErrConfigExists
	case errors.Is(err, core.ErrConfigNotFound):
	default:
		return nil, err
	}

	// Overrides written for this key before the entry existed (a delete
	// that failed part way, or an override set on a missing key) are live
	// the moment the entry is. A new entry starts with none, so they are
	// cleared first: a failure here leaves no entry behind, and a retry
	// finds the key free.
	if err := m.clearOverrides(ctx, in.Key); err != nil {
		return nil, err
	}
	m.invalidate(in.Key)

	entry := &config.Entry{
		Entity:      core.NewEntity(),
		ID:          id.NewConfigID(),
		Key:         in.Key,
		Value:       in.Value,
		ValueType:   in.ValueType,
		Description: in.Description,
		AppID:       m.appID,
	}
	if err := m.store.SetConfig(ctx, entry); err != nil {
		return nil, err
	}

	// The entry exists from here on, so whatever happens next it is
	// audited and the watchers hear of it before Create returns.
	m.changed(ctx, audithook.ActionConfigSet, in.Key, nil, in.Value)
	return m.store.GetConfig(ctx, in.Key, m.appID)
}

// Update changes the value, type or description of an existing entry. Only
// non-nil fields change; the rest of the row (id, metadata, creation time)
// is carried over. A new value is validated against the entry's type, or
// against the new type when the type changes, which needs a value, and every
// tenant override must be a valid value of the new type too, or the change is
// refused naming the first tenant (in tenant order) whose is not. An entry
// whose stored type is not one the manager supports is read-only for its
// value. Asking for what the entry already holds writes, audits and
// notifies nothing.
func (m *Manager) Update(ctx context.Context, key string, in UpdateInput) (*config.Entry, error) {
	entry, err := m.store.GetConfig(ctx, key, m.appID)
	if err != nil {
		return nil, err
	}

	merged := *entry
	switch {
	case in.ValueType != nil && *in.ValueType != entry.ValueType:
		if !config.KnownType(*in.ValueType) {
			return nil, &config.ValidationError{Field: "valueType", Message: typeList}
		}
		if in.Value == nil {
			return nil, &config.ValidationError{Field: "valueType", Message: "changing the type needs a value of that type"}
		}
		if err := validateValue(*in.ValueType, *in.Value); err != nil {
			return nil, err
		}
		if err := m.checkOverridesFit(ctx, key, *in.ValueType); err != nil {
			return nil, err
		}
		merged.ValueType = *in.ValueType
		merged.Value = *in.Value
	case in.Value != nil:
		if !config.KnownType(entry.ValueType) {
			return nil, unsupportedType(entry.ValueType)
		}
		if err := validateValue(entry.ValueType, *in.Value); err != nil {
			return nil, err
		}
		merged.Value = *in.Value
	}
	if in.Description != nil {
		merged.Description = *in.Description
	}

	if merged.ValueType == entry.ValueType &&
		merged.Description == entry.Description &&
		sameValue(merged.Value, entry.Value) {
		return entry, nil
	}
	return m.write(ctx, &merged, entry.Value, audithook.ActionConfigSet)
}

// Rollback restores the value an entry held at version. The entry keeps its
// current type, description and metadata, because a version row keeps only
// the value. A version whose value does not fit the current type is refused,
// and rolling back to the value the entry already holds writes nothing.
// The result is a new version, not a rewrite of history.
func (m *Manager) Rollback(ctx context.Context, key string, version int64) (*config.Entry, error) {
	entry, err := m.store.GetConfig(ctx, key, m.appID)
	if err != nil {
		return nil, err
	}

	// ListConfigVersions, not GetConfigVersion: the latter returns the
	// current type, description and metadata with the old value.
	all, err := m.store.ListConfigVersions(ctx, key, m.appID)
	if err != nil {
		return nil, err
	}
	var target *config.EntryVersion
	for _, v := range all {
		if v.Version == version {
			target = v
			break
		}
	}
	if target == nil {
		return nil, core.ErrConfigVersionNotFound
	}

	if !config.KnownType(entry.ValueType) {
		return nil, unsupportedType(entry.ValueType)
	}
	if verr := config.ValidateValue(entry.ValueType, target.Value); verr != nil {
		return nil, &config.ValidationError{
			Field:   "version",
			Message: fmt.Sprintf("version %d holds %s, not a %s", version, config.DescribeValue(target.Value), entry.ValueType),
		}
	}

	if sameValue(target.Value, entry.Value) {
		return entry, nil
	}
	merged := *entry
	merged.Value = target.Value
	return m.write(ctx, &merged, entry.Value, audithook.ActionConfigRolledBack)
}

// write stores merged whole, so ID, metadata and creation time survive
// (memory and mongo replace the row with what they are given), then tells
// everyone and returns the stored row.
func (m *Manager) write(ctx context.Context, merged *config.Entry, oldValue any, action string) (*config.Entry, error) {
	merged.Touch()
	if err := m.store.SetConfig(ctx, merged); err != nil {
		return nil, err
	}
	m.changed(ctx, action, merged.Key, oldValue, merged.Value)
	return m.store.GetConfig(ctx, merged.Key, m.appID)
}

// Delete removes an entry together with its versions and every override for
// the key. Overrides go first and the entry last: a failure part way leaves
// the entry, so a retry finds it and finishes the job.
func (m *Manager) Delete(ctx context.Context, key string) error {
	entry, err := m.store.GetConfig(ctx, key, m.appID)
	if err != nil {
		return err
	}
	if err := m.clearOverrides(ctx, key); err != nil {
		return err
	}
	m.invalidate(key)
	if err := m.store.DeleteConfig(ctx, key, m.appID); err != nil {
		return err
	}
	m.changed(ctx, audithook.ActionConfigDeleted, key, entry.Value, nil)
	return nil
}

// SetOverride pins an entry's value for one tenant. The entry must exist and
// the value must be valid for its type: a mistyped override makes that
// tenant silently read the caller's fallback instead of the app value. An
// existing override for the tenant keeps its id, creation time and metadata.
func (m *Manager) SetOverride(ctx context.Context, key, tenantID string, value any) (*override.Override, error) {
	entry, err := m.store.GetConfig(ctx, key, m.appID)
	if err != nil {
		return nil, err
	}
	tenantID, err = validateTenant(tenantID)
	if err != nil {
		return nil, err
	}
	if !config.KnownType(entry.ValueType) {
		return nil, unsupportedType(entry.ValueType)
	}
	if verr := validateValue(entry.ValueType, value); verr != nil {
		return nil, verr
	}

	o := &override.Override{
		Entity:   core.NewEntity(),
		ID:       id.NewOverrideID(),
		Key:      key,
		Value:    value,
		AppID:    m.appID,
		TenantID: tenantID,
	}
	existing, err := m.overrides.GetOverride(ctx, key, m.appID, tenantID)
	switch {
	case err == nil:
		o.ID = existing.ID
		o.Entity = existing.Entity
		o.Touch()
		o.Metadata = existing.Metadata
	case errors.Is(err, core.ErrOverrideNotFound):
	default:
		return nil, err
	}

	if err := m.overrides.SetOverride(ctx, o); err != nil {
		return nil, err
	}
	m.overrideChanged(ctx, audithook.ActionOverrideSet, key, tenantID)
	return m.overrides.GetOverride(ctx, key, m.appID, tenantID)
}

// DeleteOverride removes a tenant's override. It does not read the entry: an
// override whose entry is gone still resolves for its tenant (the resolver
// answers from the override before it reads the entry), so it has to be
// removable. A tenant with no override returns core.ErrOverrideNotFound from
// the store, whether or not the key exists.
func (m *Manager) DeleteOverride(ctx context.Context, key, tenantID string) error {
	tenantID, err := validateTenant(tenantID)
	if err != nil {
		return err
	}
	if err := m.overrides.DeleteOverride(ctx, key, m.appID, tenantID); err != nil {
		return err
	}
	m.overrideChanged(ctx, audithook.ActionOverrideDeleted, key, tenantID)
	return nil
}

// checkOverridesFit refuses a change to newType while any tenant holds an
// override that is not a value of it: that tenant would silently read the
// caller's fallback instead of the override. Overrides are checked in tenant
// order and the first that fails is named, so the answer is stable.
func (m *Manager) checkOverridesFit(ctx context.Context, key, newType string) error {
	all, err := m.overrides.ListOverridesByKey(ctx, key, m.appID)
	if err != nil {
		return err
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].TenantID < all[j].TenantID })
	for _, o := range all {
		if config.ValidateValue(newType, o.Value) != nil {
			return &config.ValidationError{
				Field: "valueType",
				Message: fmt.Sprintf("tenant %s has an override of %s, which is not a valid %s; change or revert it first",
					o.TenantID, config.DescribeValue(o.Value), newType),
			}
		}
	}
	return nil
}

// clearOverrides deletes every override for key. An override that is gone by
// the time it is deleted is not a failure.
func (m *Manager) clearOverrides(ctx context.Context, key string) error {
	all, err := m.overrides.ListOverridesByKey(ctx, key, m.appID)
	if err != nil {
		return err
	}
	for _, o := range all {
		err = m.overrides.DeleteOverride(ctx, key, m.appID, o.TenantID)
		if err != nil && !errors.Is(err, core.ErrOverrideNotFound) {
			return err
		}
	}
	return nil
}

// changed is what follows every committed write to an entry: drop the
// resolver cache, run the watchers, record the audit row.
func (m *Manager) changed(ctx context.Context, action, key string, oldValue, newValue any) {
	m.invalidate(key)
	if m.service != nil {
		m.service.Notify(ctx, key, oldValue, newValue)
	}
	m.audit(ctx, action, audithook.ResourceConfig, key, "")
}

// overrideChanged is what follows every committed write to an override.
func (m *Manager) overrideChanged(ctx context.Context, action, key, tenantID string) {
	m.invalidate(key)
	m.audit(ctx, action, audithook.ResourceOverride, key, tenantID)
}

func (m *Manager) invalidate(key string) {
	if m.resolver != nil {
		m.resolver.Invalidate(key, m.appID)
	}
}

func (m *Manager) audit(ctx context.Context, action, resource, key, tenantID string) {
	if m.onMutate != nil {
		m.onMutate(ctx, action, resource, key, m.appID, tenantID)
	}
}

const typeList = "must be one of string, int, float, bool, json, duration"

func unsupportedType(t string) error {
	return &config.ValidationError{
		Field:   "valueType",
		Message: fmt.Sprintf("this entry's type %s is not one the vault supports", t),
	}
}

// validateValue checks v against t and names the value in the refusal. An
// error ValidateValue already made into a *ValidationError passes as is.
func validateValue(t string, v any) error {
	err := config.ValidateValue(t, v)
	if err == nil {
		return nil
	}
	var ve *config.ValidationError
	if errors.As(err, &ve) {
		return err
	}
	return &config.ValidationError{Field: "value", Message: err.Error()}
}

func validateKey(key string) error {
	switch {
	case strings.TrimSpace(key) == "":
		return &config.ValidationError{Field: "key", Message: "is required"}
	case key != strings.TrimSpace(key):
		return &config.ValidationError{Field: "key", Message: "must not start or end with whitespace"}
	case len(key) > maxKeyBytes:
		return &config.ValidationError{Field: "key", Message: fmt.Sprintf("must be at most %d bytes", maxKeyBytes)}
	}
	return nil
}

func validateTenant(tenantID string) (string, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return "", &config.ValidationError{Field: "tenantId", Message: "is required"}
	}
	return tenantID, nil
}

// sameValue compares two values as the wire would show them: each side is
// reduced to plain JSON shapes and the results are deep-compared. Object key
// order does not matter (a mongo read gives bson.D in document order, and a
// map written from Go has none), and int, int32 and float64 meet as float64.
// A value that cannot be reduced is never the same as anything.
func sameValue(a, b any) bool {
	wa, ok := wireForm(a)
	if !ok {
		return false
	}
	wb, ok := wireForm(b)
	if !ok {
		return false
	}
	return reflect.DeepEqual(wa, wb)
}

// wireForm reduces v to the shapes a JSON decode produces (nil, bool,
// string, float64, []any, map[string]any), and reports false for a value no
// backend could have stored. bson.D and bson.A are walked directly rather
// than marshalled: their JSON form is extended JSON, which would turn a
// plain 1 into {"$numberInt":"1"}.
func wireForm(v any) (any, bool) {
	switch x := v.(type) {
	case nil, bool, string, float64:
		return x, true
	case int:
		return float64(x), true
	case int8:
		return float64(x), true
	case int16:
		return float64(x), true
	case int32:
		return float64(x), true
	case int64:
		return float64(x), true
	case uint:
		return float64(x), true
	case uint8:
		return float64(x), true
	case uint16:
		return float64(x), true
	case uint32:
		return float64(x), true
	case uint64:
		return float64(x), true
	case float32:
		return float64(x), true
	case bson.D:
		out := make(map[string]any, len(x))
		for _, e := range x {
			w, ok := wireForm(e.Value)
			if !ok {
				return nil, false
			}
			out[e.Key] = w
		}
		return out, true
	case bson.A:
		return wireForm([]any(x))
	case bson.M:
		return wireForm(map[string]any(x))
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			w, ok := wireForm(e)
			if !ok {
				return nil, false
			}
			out[i] = w
		}
		return out, true
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			w, ok := wireForm(e)
			if !ok {
				return nil, false
			}
			out[k] = w
		}
		return out, true
	}
	// Any other type (a struct, a typed slice or map) goes through one JSON
	// round trip and is then reduced again.
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, false
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, false
	}
	return wireForm(decoded)
}
