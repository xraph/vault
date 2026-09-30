package contract

import (
	"context"
	"strings"
	"time"

	"github.com/xraph/forge/extensions/dashboard/contract"

	"github.com/xraph/vault/audit"
	audithook "github.com/xraph/vault/audit_hook"
)

// maxAuditListLimit caps audit.list paging. It is tighter than the other
// lists' cap: an audit row is wider, and the table behind it only grows.
const maxAuditListLimit = 100

// secretReadAction is the action every secret read writes. Reads outnumber
// writes by a wide margin (every confy load and every rotation adds one), so
// the default audit view and the overview's recent activity leave them out.
const secretReadAction = "secret.get"

// readActions are the actions the default audit view excludes.
var readActions = []string{secretReadAction}

// auditListRequest is the wire request for audit.list. Every filter is
// optional and a blank one is no filter. IncludeReads false, the default,
// hides secret reads, but only when no action is named: it matters only for
// a request that names no action, and action "secret.get" alone returns the
// reads.
type auditListRequest struct {
	Resource     string `json:"resource,omitempty"`
	Key          string `json:"key,omitempty"`
	Action       string `json:"action,omitempty"`
	Outcome      string `json:"outcome,omitempty"`
	IncludeReads bool   `json:"includeReads,omitempty"`
	Since        string `json:"since,omitempty"` // RFC3339
	Limit        int    `json:"limit"`
	Offset       int    `json:"offset"`
}

// auditListResponse is the wire response for audit.list. Total counts the
// rows the filters match, whatever the page.
type auditListResponse struct {
	Entries []AuditSummary `json:"entries"`
	Total   int64          `json:"total"`
}

// auditListHandler answers audit.list for deps.Vault.AppID() alone. The
// filters go to the store, which applies them before paging, and the total
// is counted with the same options, so a page and its total always describe
// the same rows. An unknown outcome or an unparseable since is refused
// rather than treated as no filter: a typo must not show every row as if it
// had matched.
func auditListHandler(deps Deps) func(ctx context.Context, in auditListRequest, p contract.Principal) (auditListResponse, error) {
	return func(ctx context.Context, in auditListRequest, _ contract.Principal) (auditListResponse, error) {
		appID := deps.Vault.AppID()

		opts := audit.ListOpts{
			Resource: strings.TrimSpace(in.Resource),
			Key:      strings.TrimSpace(in.Key),
			Action:   strings.TrimSpace(in.Action),
			Outcome:  strings.TrimSpace(in.Outcome),
		}
		switch opts.Outcome {
		case "", audithook.OutcomeSuccess, audithook.OutcomeFailure:
		default:
			return auditListResponse{}, badRequest("outcome must be success or failure")
		}
		if since := strings.TrimSpace(in.Since); since != "" {
			t, err := time.Parse(time.RFC3339, since)
			if err != nil {
				return auditListResponse{}, badRequest("since must be an RFC3339 time")
			}
			opts.Since = t
		}
		// The exclusion is the default view's, not a rule about reads: a
		// caller who names an action has said which rows they want.
		if !in.IncludeReads && opts.Action == "" {
			opts.ExcludeActions = readActions
		}

		limit := in.Limit
		if limit <= 0 {
			limit = defaultListLimit
		}
		if limit > maxAuditListLimit {
			limit = maxAuditListLimit
		}
		offset := in.Offset
		if offset < 0 {
			offset = 0
		}

		st := deps.Vault.Store()
		total, err := st.CountAuditMatching(ctx, appID, opts)
		if err != nil {
			return auditListResponse{}, deps.mapError("audit.list", err)
		}
		opts.Limit, opts.Offset = limit, offset
		rows, err := st.ListAudit(ctx, appID, opts)
		if err != nil {
			return auditListResponse{}, deps.mapError("audit.list", err)
		}

		entries := make([]AuditSummary, 0, len(rows))
		for _, r := range rows {
			entries = append(entries, projectAuditSummary(r))
		}
		return auditListResponse{Entries: entries, Total: total}, nil
	}
}
