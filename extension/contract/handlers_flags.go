package contract

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/xraph/forge/extensions/dashboard/contract"

	"github.com/xraph/vault"
	"github.com/xraph/vault/audit"
	audithook "github.com/xraph/vault/audit_hook"
	"github.com/xraph/vault/flag"
	"github.com/xraph/vault/scope"
)

// defaultFlagListLimit and maxFlagListLimit bound flags.list paging. Like
// secrets.list, a request that omits limit gets the default and one that
// asks for more than the maximum is capped rather than rejected.
const (
	defaultFlagListLimit = 25
	maxFlagListLimit     = 100
)

// recentFlagAuditLimit bounds how many audit entries flags.detail returns
// alongside a flag.
const recentFlagAuditLimit = 10

// parseFlagType validates a wire flag type. Empty means every type and is
// returned as the zero flag.Type; anything that is not one of the five types
// is BAD_REQUEST, so a typo never reads as "no flags of that type".
func parseFlagType(raw string) (flag.Type, error) {
	switch t := flag.Type(raw); t {
	case "", flag.TypeBool, flag.TypeString, flag.TypeInt, flag.TypeFloat, flag.TypeJSON:
		return t, nil
	default:
		return "", badRequest("type must be one of bool, string, int, float, json")
	}
}

// flagsListRequest is the wire request for flags.list.
type flagsListRequest struct {
	Type   string `json:"type,omitempty"`
	Limit  int    `json:"limit"`
	Offset int    `json:"offset"`
}

// flagsListResponse is the wire response for flags.list. Total is the count
// of flags matching the type filter, whatever the page.
type flagsListResponse struct {
	Flags []FlagSummary `json:"flags"`
	Total int64         `json:"total"`
}

// flagsListHandler answers flags.list for deps.Vault.AppID() alone.
func flagsListHandler(deps Deps) func(ctx context.Context, in flagsListRequest, p contract.Principal) (flagsListResponse, error) {
	return func(ctx context.Context, in flagsListRequest, _ contract.Principal) (flagsListResponse, error) {
		appID := deps.Vault.AppID()

		typ, err := parseFlagType(in.Type)
		if err != nil {
			return flagsListResponse{}, err
		}

		limit := in.Limit
		if limit <= 0 {
			limit = defaultFlagListLimit
		}
		if limit > maxFlagListLimit {
			limit = maxFlagListLimit
		}
		offset := in.Offset
		if offset < 0 {
			offset = 0
		}

		opts := flag.ListOpts{Limit: limit, Offset: offset, AppID: appID, Type: typ}
		defs, err := deps.Vault.Store().ListFlagDefinitions(ctx, appID, opts)
		if err != nil {
			return flagsListResponse{}, deps.mapError("flags.list", err)
		}
		total, err := deps.Vault.Store().CountFlagDefinitionsMatching(ctx, appID, opts)
		if err != nil {
			return flagsListResponse{}, deps.mapError("flags.list", err)
		}

		flags := make([]FlagSummary, 0, len(defs))
		for _, d := range defs {
			flags = append(flags, projectFlagSummary(d))
		}
		return flagsListResponse{Flags: flags, Total: total}, nil
	}
}

// flagsDetailRequest is the wire request for flags.detail.
type flagsDetailRequest struct {
	Key string `json:"key"`
}

// flagsDetailResponse is the wire response for flags.detail. Rules come in
// the order the store's GetFlagRules returns them, which is the order the
// engine walks them.
type flagsDetailResponse struct {
	Flag        FlagSummary           `json:"flag"`
	Variants    []FlagVariantSummary  `json:"variants"`
	Metadata    map[string]string     `json:"metadata"`
	Rules       []FlagRuleSummary     `json:"rules"`
	Overrides   []FlagOverrideSummary `json:"overrides"`
	RecentAudit []AuditSummary        `json:"recentAudit"`
	// CacheTTLSeconds is how long the flag engine caches an evaluation, so
	// the page can say how stale a hot-path read may be after a write.
	CacheTTLSeconds int `json:"cacheTtlSeconds"`
}

// flagsDetailHandler answers flags.detail for deps.Vault.AppID() alone. It
// reads through the store, not the manager: the manager is for writes.
func flagsDetailHandler(deps Deps) func(ctx context.Context, in flagsDetailRequest, p contract.Principal) (flagsDetailResponse, error) {
	return func(ctx context.Context, in flagsDetailRequest, _ contract.Principal) (flagsDetailResponse, error) {
		appID := deps.Vault.AppID()
		key, err := requireKey(in.Key)
		if err != nil {
			return flagsDetailResponse{}, err
		}
		st := deps.Vault.Store()

		def, err := st.GetFlagDefinition(ctx, key, appID)
		if err != nil {
			return flagsDetailResponse{}, deps.mapError("flags.detail", err)
		}

		rules, err := st.GetFlagRules(ctx, key, appID)
		if err != nil {
			return flagsDetailResponse{}, deps.mapError("flags.detail", err)
		}
		ruleSummaries := make([]FlagRuleSummary, 0, len(rules))
		for _, r := range rules {
			ruleSummaries = append(ruleSummaries, projectFlagRule(r, def.Type))
		}

		overrides, err := st.ListFlagTenantOverrides(ctx, key, appID)
		if err != nil {
			return flagsDetailResponse{}, deps.mapError("flags.detail", err)
		}
		// The memory store iterates a map, so the order is not the
		// backends' own to promise: sort here, by tenant.
		sort.Slice(overrides, func(i, j int) bool { return overrides[i].TenantID < overrides[j].TenantID })
		overrideSummaries := make([]FlagOverrideSummary, 0, len(overrides))
		for _, o := range overrides {
			overrideSummaries = append(overrideSummaries, projectFlagOverride(o, def.Type))
		}

		entries, err := st.ListAuditByKey(ctx, key, appID, audit.ListOpts{Limit: recentFlagAuditLimit, Resource: audithook.ResourceFlag})
		if err != nil {
			return flagsDetailResponse{}, deps.mapError("flags.detail", err)
		}
		recentAudit := make([]AuditSummary, 0, len(entries))
		for _, e := range entries {
			recentAudit = append(recentAudit, projectAuditSummary(e))
		}

		variants := make([]FlagVariantSummary, 0, len(def.Variants))
		for _, v := range def.Variants {
			variants = append(variants, projectFlagVariant(v))
		}
		metadata := make(map[string]string, len(def.Metadata))
		for k, v := range def.Metadata {
			metadata[k] = v
		}

		return flagsDetailResponse{
			Flag:            projectFlagSummary(def),
			Variants:        variants,
			Metadata:        metadata,
			Rules:           ruleSummaries,
			Overrides:       overrideSummaries,
			RecentAudit:     recentAudit,
			CacheTTLSeconds: int(deps.Vault.FlagCacheTTL() / time.Second),
		}, nil
	}
}

// flagsEvaluateRequest is the wire request for flags.evaluate. TenantID and
// UserID are the subject to explain the flag for; both are optional.
type flagsEvaluateRequest struct {
	Key      string `json:"key"`
	TenantID string `json:"tenantId,omitempty"`
	UserID   string `json:"userId,omitempty"`
}

// flagsEvaluateResponse is the wire response for flags.evaluate. Bucket and
// MatchedRulePriority are pointers so a bucket or priority of 0 still
// reaches the client. MatchedRuleID is present exactly when Reason is "rule".
type flagsEvaluateResponse struct {
	Value               any             `json:"value"`
	ValueMatchesType    bool            `json:"valueMatchesType"`
	Reason              string          `json:"reason"`
	MatchedRulePriority *int            `json:"matchedRulePriority,omitempty"`
	MatchedRuleID       string          `json:"matchedRuleId,omitempty"`
	Trace               []FlagTraceStep `json:"trace"`
	Bucket              *int            `json:"bucket,omitempty"`
	EvaluatedAt         string          `json:"evaluatedAt"`
}

// flagsEvaluateHandler answers flags.evaluate for deps.Vault.AppID() alone.
//
// The engine reads the tenant and the user from the context it is given. The
// context this handler is handed belongs to the operator's own request and
// may carry a tenant or user of its own, so it is not used: the evaluation
// runs on a fresh context with the app, tenant and user each set explicitly,
// to "" when the request names none. Otherwise "what does no tenant get"
// could be answered for whichever tenant the operator happens to belong to.
func flagsEvaluateHandler(deps Deps) func(ctx context.Context, in flagsEvaluateRequest, p contract.Principal) (flagsEvaluateResponse, error) {
	return func(ctx context.Context, in flagsEvaluateRequest, _ contract.Principal) (flagsEvaluateResponse, error) {
		appID := deps.Vault.AppID()
		key, err := requireKey(in.Key)
		if err != nil {
			return flagsEvaluateResponse{}, err
		}
		tenantID := strings.TrimSpace(in.TenantID)
		userID := strings.TrimSpace(in.UserID)

		evalCtx := scope.WithAppID(context.Background(), appID)
		evalCtx = scope.WithTenantID(evalCtx, tenantID)
		evalCtx = scope.WithUserID(evalCtx, userID)

		detail, err := deps.Vault.FlagEngine().EvaluateDetail(evalCtx, key, appID)
		if err != nil {
			return flagsEvaluateResponse{}, deps.mapError("flags.evaluate", err)
		}
		// The engine explains the verdict but not the flag, and the flag's
		// type is what says whether the value it chose is a sane one.
		def, err := deps.Vault.Store().GetFlagDefinition(ctx, key, appID)
		if err != nil {
			return flagsEvaluateResponse{}, deps.mapError("flags.evaluate", err)
		}

		trace := make([]FlagTraceStep, 0, len(detail.Trace))
		for _, s := range detail.Trace {
			trace = append(trace, FlagTraceStep{
				RuleID:   s.RuleID,
				Priority: s.Priority,
				Type:     string(s.Type),
				Matched:  s.Matched,
				Reached:  s.Reached,
				Note:     s.Note,
			})
		}

		out := flagsEvaluateResponse{
			Value:            wireValue(detail.Value),
			ValueMatchesType: valueMatchesType(def.Type, detail.Value),
			Reason:           detail.Reason,
			Trace:            trace,
			EvaluatedAt:      formatTime(time.Now()),
		}
		if detail.MatchedRule != nil {
			p := detail.MatchedRule.Priority
			out.MatchedRulePriority = &p
			out.MatchedRuleID = detail.MatchedRule.ID.String()
		}
		if tenantID != "" {
			b := int(flag.RolloutBucket(tenantID, key))
			out.Bucket = &b
		}
		return out, nil
	}
}

// --- commands ---
//
// Every command below goes through deps.Vault.FlagManager(), never the
// store. The manager is the one path that validates a value against the
// flag's type, refuses to overwrite on create, drops the engine's cache and
// records the audit row; a store write does none of that.

// flagResponse is the wire response of every command that answers with the
// flag it changed.
type flagResponse struct {
	Flag FlagSummary `json:"flag"`
}

// optionalValue decodes a request field that has to tell "absent" from JSON
// null. raw is the field as json.RawMessage captured it: empty when the
// field was not sent, the literal null when it was sent as null. Absent
// returns nil, leaving the stored value alone; anything else returns a
// pointer to the decoded value, so a present null is a *any holding nil,
// which only a json flag accepts. It is the one place that decision is made.
func optionalValue(raw json.RawMessage) (*any, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, badRequest("defaultValue is not valid JSON")
	}
	return &v, nil
}

// flagsCreateRequest is the wire request for flags.create. DefaultValue is a
// plain any: for a create there is no stored value to keep, so an absent
// default and a null one are both nil, and the manager refuses nil for every
// type but json.
type flagsCreateRequest struct {
	Key          string   `json:"key"`
	Type         string   `json:"type"`
	DefaultValue any      `json:"defaultValue"`
	Description  string   `json:"description,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	Enabled      bool     `json:"enabled"`
}

// flagsCreateHandler answers flags.create for deps.Vault.AppID() alone. An
// existing key is CONFLICT and the flag is left exactly as it was.
func flagsCreateHandler(deps Deps) func(ctx context.Context, in flagsCreateRequest, p contract.Principal) (flagResponse, error) {
	return func(ctx context.Context, in flagsCreateRequest, _ contract.Principal) (flagResponse, error) {
		key, err := requireKey(in.Key)
		if err != nil {
			return flagResponse{}, err
		}
		def, err := deps.Vault.FlagManager().Create(ctx, flag.CreateInput{
			Key:          key,
			Type:         flag.Type(in.Type),
			DefaultValue: in.DefaultValue,
			Description:  in.Description,
			Tags:         in.Tags,
			Enabled:      in.Enabled,
		})
		if err != nil {
			return flagResponse{}, deps.mapError("flags.create", err)
		}
		return flagResponse{Flag: projectFlagSummary(def)}, nil
	}
}

// flagsUpdateRequest is the wire request for flags.update. Every field but
// the key is optional and only a field that is present changes. DefaultValue
// is a json.RawMessage so an absent default (leave it) and a null one (set
// it to null, which only a json flag accepts) can be told apart: see
// optionalValue.
type flagsUpdateRequest struct {
	Key          string          `json:"key"`
	Description  *string         `json:"description,omitempty"`
	DefaultValue json.RawMessage `json:"defaultValue,omitempty"`
	Tags         *[]string       `json:"tags,omitempty"`
}

// flagsUpdateHandler answers flags.update for deps.Vault.AppID() alone.
func flagsUpdateHandler(deps Deps) func(ctx context.Context, in flagsUpdateRequest, p contract.Principal) (flagResponse, error) {
	return func(ctx context.Context, in flagsUpdateRequest, _ contract.Principal) (flagResponse, error) {
		key, err := requireKey(in.Key)
		if err != nil {
			return flagResponse{}, err
		}
		def, err := optionalValue(in.DefaultValue)
		if err != nil {
			return flagResponse{}, err
		}
		updated, err := deps.Vault.FlagManager().Update(ctx, key, flag.UpdateInput{
			Description:  in.Description,
			DefaultValue: def,
			Tags:         in.Tags,
		})
		if err != nil {
			return flagResponse{}, deps.mapError("flags.update", err)
		}
		return flagResponse{Flag: projectFlagSummary(updated)}, nil
	}
}

// flagsDeleteRequest is the wire request for flags.delete.
type flagsDeleteRequest struct {
	Key string `json:"key"`
}

// flagsDeleteResponse is the wire response for flags.delete.
type flagsDeleteResponse struct {
	OK  bool   `json:"ok"`
	Key string `json:"key"`
}

// flagsDeleteHandler answers flags.delete for deps.Vault.AppID() alone. The
// store removes the flag's rules and overrides with it.
func flagsDeleteHandler(deps Deps) func(ctx context.Context, in flagsDeleteRequest, p contract.Principal) (flagsDeleteResponse, error) {
	return func(ctx context.Context, in flagsDeleteRequest, _ contract.Principal) (flagsDeleteResponse, error) {
		key, err := requireKey(in.Key)
		if err != nil {
			return flagsDeleteResponse{}, err
		}
		if err := deps.Vault.FlagManager().Delete(ctx, key); err != nil {
			return flagsDeleteResponse{}, deps.mapError("flags.delete", err)
		}
		return flagsDeleteResponse{OK: true, Key: key}, nil
	}
}

// flagsSetEnabledRequest is the wire request for flags.setEnabled.
type flagsSetEnabledRequest struct {
	Key     string `json:"key"`
	Enabled bool   `json:"enabled"`
}

// flagsSetEnabledHandler answers flags.setEnabled for deps.Vault.AppID()
// alone. The manager drops the engine's cache, so a flag turned off stops
// being served on the hot path at once rather than after the cache TTL.
func flagsSetEnabledHandler(deps Deps) func(ctx context.Context, in flagsSetEnabledRequest, p contract.Principal) (flagResponse, error) {
	return func(ctx context.Context, in flagsSetEnabledRequest, _ contract.Principal) (flagResponse, error) {
		key, err := requireKey(in.Key)
		if err != nil {
			return flagResponse{}, err
		}
		def, err := deps.Vault.FlagManager().SetEnabled(ctx, key, in.Enabled)
		if err != nil {
			return flagResponse{}, deps.mapError("flags.setEnabled", err)
		}
		return flagResponse{Flag: projectFlagSummary(def)}, nil
	}
}

// flagRuleRequest is one rule on the wire, in the shape flags.detail returns
// it, so a list read from detail can be sent back unchanged. Fields a rule's
// type does not read are accepted and ignored by the manager, except for
// when_tenant_tag and custom, which keep their config as given. Times are
// RFC3339, "" (or absent) meaning an open end.
type flagRuleRequest struct {
	Type        string         `json:"type"`
	TenantIDs   []string       `json:"tenantIds,omitempty"`
	UserIDs     []string       `json:"userIds,omitempty"`
	Percentage  int            `json:"percentage,omitempty"`
	StartAt     string         `json:"startAt,omitempty"`
	EndAt       string         `json:"endAt,omitempty"`
	TagKey      string         `json:"tagKey,omitempty"`
	TagValue    string         `json:"tagValue,omitempty"`
	Evaluator   string         `json:"evaluator,omitempty"`
	Params      map[string]any `json:"params,omitempty"`
	ReturnValue any            `json:"returnValue"`
}

// flagsSetRulesRequest is the wire request for flags.setRules. Rules is a
// pointer so a request that omits it (or sends null) is refused instead of
// reading as "no rules" and wiping the list; an explicit [] clears it.
type flagsSetRulesRequest struct {
	Key   string             `json:"key"`
	Rules *[]flagRuleRequest `json:"rules"`
}

// flagsSetRulesResponse is the wire response for flags.setRules: the rules
// as stored, in evaluation order.
type flagsSetRulesResponse struct {
	Rules []FlagRuleSummary `json:"rules"`
}

// parseRuleTime parses an optional RFC3339 rule time. "" is absent. The
// error names the field the way the manager's own validation errors do,
// rules[i].startAt.
func parseRuleTime(i int, name, raw string) (*time.Time, error) {
	if raw == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, badRequest(fmt.Sprintf("rules[%d].%s must be an RFC3339 timestamp", i, name))
	}
	return &t, nil
}

// nilIfEmpty returns nil for an empty list. The wire always carries lists as
// [], and a stored config that keeps an empty slice where the original had
// none would not be the config that was read.
func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}

// toRuleInputs converts the wire rules to the manager's inputs.
func toRuleInputs(in []flagRuleRequest) ([]flag.RuleInput, error) {
	out := make([]flag.RuleInput, 0, len(in))
	for i, r := range in {
		start, err := parseRuleTime(i, "startAt", r.StartAt)
		if err != nil {
			return nil, err
		}
		end, err := parseRuleTime(i, "endAt", r.EndAt)
		if err != nil {
			return nil, err
		}
		out = append(out, flag.RuleInput{
			Type: flag.RuleType(r.Type),
			Config: flag.RuleConfig{
				TenantIDs:  nilIfEmpty(r.TenantIDs),
				UserIDs:    nilIfEmpty(r.UserIDs),
				Percentage: r.Percentage,
				StartAt:    start,
				EndAt:      end,
				TagKey:     r.TagKey,
				TagValue:   r.TagValue,
				Evaluator:  r.Evaluator,
				Params:     r.Params,
			},
			ReturnValue: r.ReturnValue,
		})
	}
	return out, nil
}

// flagsSetRulesHandler answers flags.setRules for deps.Vault.AppID() alone.
// The list replaces the flag's rules whole and its order is the priority:
// the first rule wins.
func flagsSetRulesHandler(deps Deps) func(ctx context.Context, in flagsSetRulesRequest, p contract.Principal) (flagsSetRulesResponse, error) {
	return func(ctx context.Context, in flagsSetRulesRequest, _ contract.Principal) (flagsSetRulesResponse, error) {
		key, err := requireKey(in.Key)
		if err != nil {
			return flagsSetRulesResponse{}, err
		}
		if in.Rules == nil {
			return flagsSetRulesResponse{}, badRequest("rules is required; send an empty list to clear them")
		}
		inputs, err := toRuleInputs(*in.Rules)
		if err != nil {
			return flagsSetRulesResponse{}, err
		}
		stored, err := deps.Vault.FlagManager().SetRules(ctx, key, inputs)
		if err != nil {
			return flagsSetRulesResponse{}, deps.mapError("flags.setRules", err)
		}
		rules := make([]FlagRuleSummary, 0, len(stored))
		for _, r := range stored {
			// The manager validated every return value against the flag's
			// type before it wrote, so they all match.
			rules = append(rules, projectFlagRuleMatching(r, true))
		}
		return flagsSetRulesResponse{Rules: rules}, nil
	}
}

// flagsSetTenantOverrideRequest is the wire request for
// flags.setTenantOverride.
type flagsSetTenantOverrideRequest struct {
	Key      string `json:"key"`
	TenantID string `json:"tenantId"`
	Value    any    `json:"value"`
}

// flagsSetTenantOverrideResponse is the wire response for
// flags.setTenantOverride.
type flagsSetTenantOverrideResponse struct {
	Override FlagOverrideSummary `json:"override"`
}

// flagsSetTenantOverrideHandler answers flags.setTenantOverride for
// deps.Vault.AppID() alone. The value must be a value of the flag's type.
func flagsSetTenantOverrideHandler(deps Deps) func(ctx context.Context, in flagsSetTenantOverrideRequest, p contract.Principal) (flagsSetTenantOverrideResponse, error) {
	return func(ctx context.Context, in flagsSetTenantOverrideRequest, _ contract.Principal) (flagsSetTenantOverrideResponse, error) {
		key, err := requireKey(in.Key)
		if err != nil {
			return flagsSetTenantOverrideResponse{}, err
		}
		o, err := deps.Vault.FlagManager().SetTenantOverride(ctx, key, in.TenantID, in.Value)
		if err != nil {
			return flagsSetTenantOverrideResponse{}, deps.mapError("flags.setTenantOverride", err)
		}
		// Validated against the flag's type by the manager before the write.
		return flagsSetTenantOverrideResponse{Override: projectFlagOverrideMatching(o, true)}, nil
	}
}

// flagsDeleteTenantOverrideRequest is the wire request for
// flags.deleteTenantOverride.
type flagsDeleteTenantOverrideRequest struct {
	Key      string `json:"key"`
	TenantID string `json:"tenantId"`
}

// flagsDeleteTenantOverrideResponse is the wire response for
// flags.deleteTenantOverride.
type flagsDeleteTenantOverrideResponse struct {
	OK       bool   `json:"ok"`
	Key      string `json:"key"`
	TenantID string `json:"tenantId"`
}

// flagsDeleteTenantOverrideHandler answers flags.deleteTenantOverride for
// deps.Vault.AppID() alone. A tenant with no override is NOT_FOUND. The
// sentinel behind that is shared with the config overrides, so mapError does
// not map it (a flag's override and a config override would read alike);
// this handler does, because here it can only mean a tenant override.
func flagsDeleteTenantOverrideHandler(deps Deps) func(ctx context.Context, in flagsDeleteTenantOverrideRequest, p contract.Principal) (flagsDeleteTenantOverrideResponse, error) {
	return func(ctx context.Context, in flagsDeleteTenantOverrideRequest, _ contract.Principal) (flagsDeleteTenantOverrideResponse, error) {
		key, err := requireKey(in.Key)
		if err != nil {
			return flagsDeleteTenantOverrideResponse{}, err
		}
		tenantID := strings.TrimSpace(in.TenantID)
		if err := deps.Vault.FlagManager().DeleteTenantOverride(ctx, key, in.TenantID); err != nil {
			if errors.Is(err, vault.ErrOverrideNotFound) {
				return flagsDeleteTenantOverrideResponse{}, &contract.Error{Code: contract.CodeNotFound, Message: "tenant override not found"}
			}
			return flagsDeleteTenantOverrideResponse{}, deps.mapError("flags.deleteTenantOverride", err)
		}
		return flagsDeleteTenantOverrideResponse{OK: true, Key: key, TenantID: tenantID}, nil
	}
}
