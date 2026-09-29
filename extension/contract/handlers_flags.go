package contract

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/xraph/forge/extensions/dashboard/contract"

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
// reaches the client.
type flagsEvaluateResponse struct {
	Value               any             `json:"value"`
	ValueMatchesType    bool            `json:"valueMatchesType"`
	Reason              string          `json:"reason"`
	MatchedRulePriority *int            `json:"matchedRulePriority,omitempty"`
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
		}
		if tenantID != "" {
			b := int(flag.RolloutBucket(tenantID, key))
			out.Bucket = &b
		}
		return out, nil
	}
}
