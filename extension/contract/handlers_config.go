package contract

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/xraph/forge/extensions/dashboard/contract"

	"github.com/xraph/vault"
	"github.com/xraph/vault/audit"
	audithook "github.com/xraph/vault/audit_hook"
	"github.com/xraph/vault/config"
	"github.com/xraph/vault/configmgr"
	"github.com/xraph/vault/override"
	"github.com/xraph/vault/scope"
)

// defaultConfigListLimit and maxConfigListLimit bound config.list and
// overrides.list paging. Like flags.list, a request that omits limit gets the
// default and one that asks for more than the maximum is capped rather than
// rejected.
const (
	defaultConfigListLimit = 25
	maxConfigListLimit     = 100
)

// recentConfigAuditLimit bounds how many audit entries config.detail returns
// alongside an entry.
const recentConfigAuditLimit = 10

// The two answers config.resolve gives for where a value came from.
const (
	sourceOverride   = "override"
	sourceAppDefault = "appDefault"
)

// clampPaging turns a request's limit and offset into the page the store is
// asked for: the default limit when none is given, the maximum when more is
// asked for, and never a negative offset. The store is always given a limit,
// because sqlite rejects an offset without one.
func clampPaging(limit, offset int) (clampedLimit, clampedOffset int) {
	if limit <= 0 {
		limit = defaultConfigListLimit
	}
	if limit > maxConfigListLimit {
		limit = maxConfigListLimit
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

// configListRequest is the wire request for config.list.
type configListRequest struct {
	KeyPrefix string `json:"keyPrefix,omitempty"`
	Limit     int    `json:"limit"`
	Offset    int    `json:"offset"`
}

// configListResponse is the wire response for config.list. Total is the count
// of entries matching the prefix, whatever the page.
type configListResponse struct {
	Entries []ConfigEntrySummary `json:"entries"`
	Total   int64                `json:"total"`
}

// configListHandler answers config.list for deps.Vault.AppID() alone.
func configListHandler(deps Deps) func(ctx context.Context, in configListRequest, p contract.Principal) (configListResponse, error) {
	return func(ctx context.Context, in configListRequest, _ contract.Principal) (configListResponse, error) {
		appID := deps.Vault.AppID()
		limit, offset := clampPaging(in.Limit, in.Offset)

		opts := config.ListOpts{Limit: limit, Offset: offset, AppID: appID, KeyPrefix: strings.TrimSpace(in.KeyPrefix)}
		entries, err := deps.Vault.Store().ListConfig(ctx, appID, opts)
		if err != nil {
			return configListResponse{}, deps.mapError("config.list", err)
		}
		total, err := deps.Vault.Store().CountConfigMatching(ctx, appID, opts)
		if err != nil {
			return configListResponse{}, deps.mapError("config.list", err)
		}

		out := make([]ConfigEntrySummary, 0, len(entries))
		for _, e := range entries {
			out = append(out, projectConfigEntry(e))
		}
		return configListResponse{Entries: out, Total: total}, nil
	}
}

// configDetailRequest is the wire request for config.detail.
type configDetailRequest struct {
	Key string `json:"key"`
}

// configDetailResponse is the wire response for config.detail. Overrides are
// in tenant order. RecentAudit is the entry's own rows and its overrides' rows
// together, newest first.
type configDetailResponse struct {
	Entry       ConfigEntrySummary `json:"entry"`
	Overrides   []OverrideSummary  `json:"overrides"`
	RecentAudit []AuditSummary     `json:"recentAudit"`
}

// configDetailHandler answers config.detail for deps.Vault.AppID() alone. It
// reads through the store, not the manager: the manager is for writes.
func configDetailHandler(deps Deps) func(ctx context.Context, in configDetailRequest, p contract.Principal) (configDetailResponse, error) {
	return func(ctx context.Context, in configDetailRequest, _ contract.Principal) (configDetailResponse, error) {
		appID := deps.Vault.AppID()
		key, err := requireKey(in.Key)
		if err != nil {
			return configDetailResponse{}, err
		}
		st := deps.Vault.Store()

		entry, err := st.GetConfig(ctx, key, appID)
		if err != nil {
			return configDetailResponse{}, deps.mapError("config.detail", err)
		}

		overrides, err := st.ListOverridesByKey(ctx, key, appID)
		if err != nil {
			return configDetailResponse{}, deps.mapError("config.detail", err)
		}
		// The memory store iterates a map, so the order is not the
		// backends' own to promise: sort here, by tenant.
		sort.Slice(overrides, func(i, j int) bool { return overrides[i].TenantID < overrides[j].TenantID })
		overrideSummaries := make([]OverrideSummary, 0, len(overrides))
		for _, o := range overrides {
			overrideSummaries = append(overrideSummaries, projectOverride(o, entry))
		}

		// A key's history is on two resources: the entry's own writes and
		// its overrides'. Each is fetched with its own Resource filter, so a
		// flag or secret with the same key never bleeds in, and each with
		// the full limit, so that the ten newest of the two together are
		// always among what comes back. They are then merged by time.
		var rows []*audit.Entry
		for _, resource := range []string{audithook.ResourceConfig, audithook.ResourceOverride} {
			got, aerr := st.ListAuditByKey(ctx, key, appID, audit.ListOpts{Limit: recentConfigAuditLimit, Resource: resource})
			if aerr != nil {
				return configDetailResponse{}, deps.mapError("config.detail", aerr)
			}
			rows = append(rows, got...)
		}
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].CreatedAt.After(rows[j].CreatedAt) })
		if len(rows) > recentConfigAuditLimit {
			rows = rows[:recentConfigAuditLimit]
		}
		recentAudit := make([]AuditSummary, 0, len(rows))
		for _, e := range rows {
			recentAudit = append(recentAudit, projectAuditSummary(e))
		}

		return configDetailResponse{
			Entry:       projectConfigEntry(entry),
			Overrides:   overrideSummaries,
			RecentAudit: recentAudit,
		}, nil
	}
}

// configVersionsRequest is the wire request for config.versions.
type configVersionsRequest struct {
	Key string `json:"key"`
}

// configVersionsResponse is the wire response for config.versions, newest
// version first.
type configVersionsResponse struct {
	Versions []ConfigVersionSummary `json:"versions"`
}

// configVersionsHandler answers config.versions for deps.Vault.AppID() alone.
// The store answers an unknown key with an empty list, so the entry is read
// first: that is what says not found, and what says which version is current.
func configVersionsHandler(deps Deps) func(ctx context.Context, in configVersionsRequest, p contract.Principal) (configVersionsResponse, error) {
	return func(ctx context.Context, in configVersionsRequest, _ contract.Principal) (configVersionsResponse, error) {
		appID := deps.Vault.AppID()
		key, err := requireKey(in.Key)
		if err != nil {
			return configVersionsResponse{}, err
		}
		st := deps.Vault.Store()

		entry, err := st.GetConfig(ctx, key, appID)
		if err != nil {
			return configVersionsResponse{}, deps.mapError("config.versions", err)
		}
		// ListConfigVersions, not GetConfigVersion: the latter returns the
		// current entry's type and description with the old value.
		versions, err := st.ListConfigVersions(ctx, key, appID)
		if err != nil {
			return configVersionsResponse{}, deps.mapError("config.versions", err)
		}
		sort.Slice(versions, func(i, j int) bool { return versions[i].Version > versions[j].Version })

		out := make([]ConfigVersionSummary, 0, len(versions))
		for _, v := range versions {
			out = append(out, projectConfigVersion(v, entry))
		}
		return configVersionsResponse{Versions: out}, nil
	}
}

// configResolveRequest is the wire request for config.resolve. TenantID is
// the tenant to explain the key for and is optional.
type configResolveRequest struct {
	Key      string `json:"key"`
	TenantID string `json:"tenantId,omitempty"`
}

// configResolveResponse is the wire response for config.resolve. Source says
// which of the two answered, "override" or "appDefault", and Value is what
// that source holds. AppValue is always the entry's own value. OverrideValue
// is present exactly when Source is "override". It is a pointer so an
// override whose value is the empty string, false, 0 or a JSON null still
// reaches the client, which must be able to tell "no override" from "an
// override of nothing". TenantID echoes the tenant asked about, if any.
type configResolveResponse struct {
	Value            any    `json:"value"`
	ValueMatchesType bool   `json:"valueMatchesType"`
	Source           string `json:"source"`
	AppValue         any    `json:"appValue"`
	OverrideValue    *any   `json:"overrideValue,omitempty"`
	TenantID         string `json:"tenantId,omitempty"`
}

// configResolveHandler answers config.resolve for deps.Vault.AppID() alone.
//
// The resolver returns a value and nothing about where it came from, so this
// reads the entry and the tenant's override itself, in the resolver's own
// order (override first, then the entry). That also keeps a value the
// resolver's cache holds from standing in for what is stored.
//
// Whose tenant it explains is the request's alone. The context this handler
// is handed belongs to the operator's own request and may carry a tenant of
// its own, so it is not used: the reads run on a fresh context with the app
// and tenant each set explicitly, the tenant to "" when the request names
// none. A key with no entry is not found even when an orphaned override
// exists for it, which the resolver alone would still answer.
func configResolveHandler(deps Deps) func(ctx context.Context, in configResolveRequest, p contract.Principal) (configResolveResponse, error) {
	return func(_ context.Context, in configResolveRequest, _ contract.Principal) (configResolveResponse, error) {
		appID := deps.Vault.AppID()
		key, err := requireKey(in.Key)
		if err != nil {
			return configResolveResponse{}, err
		}
		tenantID := strings.TrimSpace(in.TenantID)

		evalCtx := scope.WithAppID(context.Background(), appID)
		evalCtx = scope.WithTenantID(evalCtx, tenantID)
		st := deps.Vault.Store()

		entry, err := st.GetConfig(evalCtx, key, appID)
		if err != nil {
			return configResolveResponse{}, deps.mapError("config.resolve", err)
		}
		out := configResolveResponse{
			Value:    wireValue(entry.Value),
			Source:   sourceAppDefault,
			AppValue: wireValue(entry.Value),
			TenantID: tenantID,
		}
		valueForType := entry.Value

		if tenantID != "" {
			ov, oerr := st.GetOverride(evalCtx, key, appID, tenantID)
			switch {
			case oerr == nil:
				w := wireValue(ov.Value)
				out.Value = w
				out.Source = sourceOverride
				out.OverrideValue = &w
				valueForType = ov.Value
			case errors.Is(oerr, vault.ErrOverrideNotFound):
				// No override for this tenant: the app default answers.
			default:
				return configResolveResponse{}, deps.mapError("config.resolve", oerr)
			}
		}
		out.ValueMatchesType = configValueMatchesType(entry.ValueType, valueForType)
		return out, nil
	}
}

// overridesListRequest is the wire request for overrides.list. At least one of
// TenantID and Key is required.
type overridesListRequest struct {
	TenantID string `json:"tenantId,omitempty"`
	Key      string `json:"key,omitempty"`
	Limit    int    `json:"limit"`
	Offset   int    `json:"offset"`
}

// overridesListResponse is the wire response for overrides.list. Total is the
// count of overrides matching the request, whatever the page.
type overridesListResponse struct {
	Overrides []OverrideSummary `json:"overrides"`
	Total     int64             `json:"total"`
}

// overridesListHandler answers overrides.list for deps.Vault.AppID() alone.
//
// The store lists overrides by tenant or by key and neither call takes a page
// or counts, so the handler pages the list in memory: Total is the number of
// matches and the page is a slice of them. With both a tenant and a key the
// answer is that one override, or nothing. With neither the request is
// refused: there is no list of every override in the store to page.
//
// An override whose key has no entry is listed, not hidden, with keyExists
// false and valueMatchesType false, so the page can say so.
func overridesListHandler(deps Deps) func(ctx context.Context, in overridesListRequest, p contract.Principal) (overridesListResponse, error) {
	return func(ctx context.Context, in overridesListRequest, _ contract.Principal) (overridesListResponse, error) {
		appID := deps.Vault.AppID()
		tenantID := strings.TrimSpace(in.TenantID)
		key := strings.TrimSpace(in.Key)
		if tenantID == "" && key == "" {
			return overridesListResponse{}, badRequest("give a tenantId or a key")
		}
		limit, offset := clampPaging(in.Limit, in.Offset)
		st := deps.Vault.Store()

		var all []*override.Override
		switch {
		case tenantID != "" && key != "":
			o, err := st.GetOverride(ctx, key, appID, tenantID)
			switch {
			case err == nil:
				all = []*override.Override{o}
			case errors.Is(err, vault.ErrOverrideNotFound):
			default:
				return overridesListResponse{}, deps.mapError("overrides.list", err)
			}
		case tenantID != "":
			got, err := st.ListOverridesByTenant(ctx, appID, tenantID)
			if err != nil {
				return overridesListResponse{}, deps.mapError("overrides.list", err)
			}
			all = got
			sort.Slice(all, func(i, j int) bool { return all[i].Key < all[j].Key })
		default:
			got, err := st.ListOverridesByKey(ctx, key, appID)
			if err != nil {
				return overridesListResponse{}, deps.mapError("overrides.list", err)
			}
			all = got
			sort.Slice(all, func(i, j int) bool { return all[i].TenantID < all[j].TenantID })
		}

		total := int64(len(all))
		page := []*override.Override{}
		if offset < len(all) {
			page = all[offset:]
			if len(page) > limit {
				page = page[:limit]
			}
		}

		// Each key's entry is read once for the whole page. nil records a
		// key with no entry.
		entries := make(map[string]*config.Entry, len(page))
		out := make([]OverrideSummary, 0, len(page))
		for _, o := range page {
			entry, seen := entries[o.Key]
			if !seen {
				e, err := st.GetConfig(ctx, o.Key, appID)
				switch {
				case err == nil:
					entry = e
				case errors.Is(err, vault.ErrConfigNotFound):
					entry = nil
				default:
					return overridesListResponse{}, deps.mapError("overrides.list", err)
				}
				entries[o.Key] = entry
			}
			out = append(out, projectOverride(o, entry))
		}
		return overridesListResponse{Overrides: out, Total: total}, nil
	}
}

// --- commands ---
//
// Every command below goes through deps.Vault.ConfigManager(), never the
// store. The manager is the one path that checks a value against its entry's
// type, refuses to overwrite on create, keeps the fields a request did not
// name, clears a deleted key's overrides, drops the resolver's cache and
// records the audit row; a store write does none of that. The responses are
// projected with the same projectors the queries use, so a command answers
// in the shape the page then reads back.

// configEntryResponse is the wire response of every command that answers
// with the entry it changed.
type configEntryResponse struct {
	Entry ConfigEntrySummary `json:"entry"`
}

// configCreateRequest is the wire request for config.create. Value is a
// plain any: a new entry has no stored value to keep, so an absent value and
// a null one are both nil, and the manager refuses nil for every type but
// json.
type configCreateRequest struct {
	Key         string `json:"key"`
	ValueType   string `json:"valueType"`
	Value       any    `json:"value"`
	Description string `json:"description,omitempty"`
}

// configCreateHandler answers config.create for deps.Vault.AppID() alone. An
// existing key is CONFLICT and the entry is left exactly as it was. The type
// is never guessed: an absent valueType is refused.
func configCreateHandler(deps Deps) func(ctx context.Context, in configCreateRequest, p contract.Principal) (configEntryResponse, error) {
	return func(ctx context.Context, in configCreateRequest, _ contract.Principal) (configEntryResponse, error) {
		key, err := requireKey(in.Key)
		if err != nil {
			return configEntryResponse{}, err
		}
		valueType := strings.TrimSpace(in.ValueType)
		if valueType == "" {
			return configEntryResponse{}, badRequest("valueType is required")
		}
		entry, err := deps.Vault.ConfigManager().Create(ctx, configmgr.CreateInput{
			Key:         key,
			ValueType:   valueType,
			Description: in.Description,
			Value:       in.Value,
		})
		if err != nil {
			return configEntryResponse{}, deps.mapError("config.create", err)
		}
		return configEntryResponse{Entry: projectConfigEntry(entry)}, nil
	}
}

// configUpdateRequest is the wire request for config.update. Every field but
// the key is optional and only a field that is present changes. Value is a
// json.RawMessage so an absent value (leave it) and a null one (set it to
// null, which only a json entry accepts) can be told apart: see
// optionalValue.
type configUpdateRequest struct {
	Key         string          `json:"key"`
	Value       json.RawMessage `json:"value,omitempty"`
	ValueType   *string         `json:"valueType,omitempty"`
	Description *string         `json:"description,omitempty"`
}

// configUpdateHandler answers config.update for deps.Vault.AppID() alone. A
// request that asks for what the entry already holds is not an error: the
// entry comes back and no version is added.
func configUpdateHandler(deps Deps) func(ctx context.Context, in configUpdateRequest, p contract.Principal) (configEntryResponse, error) {
	return func(ctx context.Context, in configUpdateRequest, _ contract.Principal) (configEntryResponse, error) {
		key, err := requireKey(in.Key)
		if err != nil {
			return configEntryResponse{}, err
		}
		value, err := optionalValue("value", in.Value)
		if err != nil {
			return configEntryResponse{}, err
		}
		var valueType *string
		if in.ValueType != nil {
			trimmed := strings.TrimSpace(*in.ValueType)
			valueType = &trimmed
		}
		entry, err := deps.Vault.ConfigManager().Update(ctx, key, configmgr.UpdateInput{
			Value:       value,
			ValueType:   valueType,
			Description: in.Description,
		})
		if err != nil {
			return configEntryResponse{}, deps.mapError("config.update", err)
		}
		return configEntryResponse{Entry: projectConfigEntry(entry)}, nil
	}
}

// configDeleteRequest is the wire request for config.delete.
type configDeleteRequest struct {
	Key string `json:"key"`
}

// configDeleteResponse is the wire response for config.delete.
type configDeleteResponse struct {
	OK  bool   `json:"ok"`
	Key string `json:"key"`
}

// configDeleteHandler answers config.delete for deps.Vault.AppID() alone. The
// manager removes the entry's versions and every override for the key with
// it, so recreating the key never brings an old override back.
func configDeleteHandler(deps Deps) func(ctx context.Context, in configDeleteRequest, p contract.Principal) (configDeleteResponse, error) {
	return func(ctx context.Context, in configDeleteRequest, _ contract.Principal) (configDeleteResponse, error) {
		key, err := requireKey(in.Key)
		if err != nil {
			return configDeleteResponse{}, err
		}
		if err := deps.Vault.ConfigManager().Delete(ctx, key); err != nil {
			return configDeleteResponse{}, deps.mapError("config.delete", err)
		}
		return configDeleteResponse{OK: true, Key: key}, nil
	}
}

// configRollbackRequest is the wire request for config.rollback.
type configRollbackRequest struct {
	Key     string `json:"key"`
	Version int64  `json:"version"`
}

// configRollbackHandler answers config.rollback for deps.Vault.AppID() alone.
// The entry keeps its type, description and metadata and takes the old
// version's value as a new version. A version whose value does not fit the
// entry's current type is refused.
func configRollbackHandler(deps Deps) func(ctx context.Context, in configRollbackRequest, p contract.Principal) (configEntryResponse, error) {
	return func(ctx context.Context, in configRollbackRequest, _ contract.Principal) (configEntryResponse, error) {
		key, err := requireKey(in.Key)
		if err != nil {
			return configEntryResponse{}, err
		}
		entry, err := deps.Vault.ConfigManager().Rollback(ctx, key, in.Version)
		if err != nil {
			return configEntryResponse{}, deps.mapError("config.rollback", err)
		}
		return configEntryResponse{Entry: projectConfigEntry(entry)}, nil
	}
}

// overridesSetRequest is the wire request for overrides.set. Value is a
// json.RawMessage because absent is not null: a missing value is refused,
// where a null is a value (only a json entry accepts it) and so is "".
type overridesSetRequest struct {
	Key      string          `json:"key"`
	TenantID string          `json:"tenantId"`
	Value    json.RawMessage `json:"value,omitempty"`
}

// overridesSetResponse is the wire response for overrides.set.
type overridesSetResponse struct {
	Override OverrideSummary `json:"override"`
}

// overridesSetHandler answers overrides.set for deps.Vault.AppID() alone. The
// entry must exist and the value must be a value of its type. Setting "" is
// an override of the empty string; taking an override away is
// overrides.delete.
func overridesSetHandler(deps Deps) func(ctx context.Context, in overridesSetRequest, p contract.Principal) (overridesSetResponse, error) {
	return func(ctx context.Context, in overridesSetRequest, _ contract.Principal) (overridesSetResponse, error) {
		key, err := requireKey(in.Key)
		if err != nil {
			return overridesSetResponse{}, err
		}
		value, err := optionalValue("value", in.Value)
		if err != nil {
			return overridesSetResponse{}, err
		}
		if value == nil {
			return overridesSetResponse{}, badRequest("value is required")
		}
		o, err := deps.Vault.ConfigManager().SetOverride(ctx, key, in.TenantID, *value)
		if err != nil {
			return overridesSetResponse{}, deps.mapError("overrides.set", err)
		}
		// The manager has just read this entry and judged the value against
		// it; the read here is for the projection.
		entry, err := deps.Vault.Store().GetConfig(ctx, key, deps.Vault.AppID())
		if err != nil {
			return overridesSetResponse{}, deps.mapError("overrides.set", err)
		}
		return overridesSetResponse{Override: projectOverride(o, entry)}, nil
	}
}

// overridesDeleteRequest is the wire request for overrides.delete.
type overridesDeleteRequest struct {
	Key      string `json:"key"`
	TenantID string `json:"tenantId"`
}

// overridesDeleteResponse is the wire response for overrides.delete.
type overridesDeleteResponse struct {
	OK       bool   `json:"ok"`
	Key      string `json:"key"`
	TenantID string `json:"tenantId"`
}

// overridesDeleteHandler answers overrides.delete for deps.Vault.AppID()
// alone: the tenant reads the app default again. A tenant with no override is
// NOT_FOUND. The sentinel behind that is shared with the flag overrides, so
// mapError does not map it; this handler does, because here it can only mean
// a tenant's config override.
func overridesDeleteHandler(deps Deps) func(ctx context.Context, in overridesDeleteRequest, p contract.Principal) (overridesDeleteResponse, error) {
	return func(ctx context.Context, in overridesDeleteRequest, _ contract.Principal) (overridesDeleteResponse, error) {
		key, err := requireKey(in.Key)
		if err != nil {
			return overridesDeleteResponse{}, err
		}
		tenantID := strings.TrimSpace(in.TenantID)
		if err := deps.Vault.ConfigManager().DeleteOverride(ctx, key, in.TenantID); err != nil {
			if errors.Is(err, vault.ErrOverrideNotFound) {
				return overridesDeleteResponse{}, &contract.Error{Code: contract.CodeNotFound, Message: "tenant override not found"}
			}
			return overridesDeleteResponse{}, deps.mapError("overrides.delete", err)
		}
		return overridesDeleteResponse{OK: true, Key: key, TenantID: tenantID}, nil
	}
}
