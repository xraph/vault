package contract

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/xraph/forge/extensions/dashboard/contract"

	"github.com/xraph/vault"
	"github.com/xraph/vault/audit"
	"github.com/xraph/vault/secret"
)

// defaultListLimit and maxListLimit bound secrets.list paging. A request
// that omits limit gets defaultListLimit; one that asks for more than
// maxListLimit is capped rather than rejected, since a page size is a
// preference, not a contract the client must get exactly right.
const (
	defaultListLimit = 25
	maxListLimit     = 200
)

// recentAuditLimit bounds how many audit entries secrets.detail returns
// alongside a secret. The full history lives behind its own paged read,
// which is out of scope for this slice.
const recentAuditLimit = 10

// secretsListRequest is the wire request for secrets.list.
type secretsListRequest struct {
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

// secretsListResponse is the wire response for secrets.list.
type secretsListResponse struct {
	Secrets []SecretSummary `json:"secrets"`
	Total   int64           `json:"total"`
}

// secretsListHandler answers secrets.list for deps.Vault.AppID() alone; no
// request field ever names a different app.
func secretsListHandler(deps Deps) func(ctx context.Context, in secretsListRequest, p contract.Principal) (secretsListResponse, error) {
	return func(ctx context.Context, in secretsListRequest, _ contract.Principal) (secretsListResponse, error) {
		appID := deps.Vault.AppID()

		limit := in.Limit
		if limit <= 0 {
			limit = defaultListLimit
		}
		if limit > maxListLimit {
			limit = maxListLimit
		}
		offset := in.Offset
		if offset < 0 {
			offset = 0
		}

		metas, err := deps.Vault.Secrets().List(ctx, appID, secret.ListOpts{Limit: limit, Offset: offset})
		if err != nil {
			return secretsListResponse{}, mapError(err)
		}
		total, err := deps.Vault.Store().CountSecrets(ctx, appID)
		if err != nil {
			return secretsListResponse{}, mapError(err)
		}

		summaries := make([]SecretSummary, 0, len(metas))
		for _, m := range metas {
			summaries = append(summaries, projectSecretSummary(m))
		}
		return secretsListResponse{Secrets: summaries, Total: total}, nil
	}
}

// secretsDetailRequest is the wire request for secrets.detail.
type secretsDetailRequest struct {
	Key string `json:"key"`
}

// secretsDetailResponse is the wire response for secrets.detail. Rotation
// has no omitempty: it must reach the client as an explicit null when the
// secret has no policy, not be dropped, so one page can both show and
// create a policy.
type secretsDetailResponse struct {
	Secret      SecretSummary          `json:"secret"`
	Rotation    *RotationPolicySummary `json:"rotation"`
	RecentAudit []AuditSummary         `json:"recentAudit"`
}

// secretsDetailHandler answers secrets.detail for deps.Vault.AppID() alone.
func secretsDetailHandler(deps Deps) func(ctx context.Context, in secretsDetailRequest, p contract.Principal) (secretsDetailResponse, error) {
	return func(ctx context.Context, in secretsDetailRequest, _ contract.Principal) (secretsDetailResponse, error) {
		appID := deps.Vault.AppID()
		key, err := requireKey(in.Key)
		if err != nil {
			return secretsDetailResponse{}, err
		}

		meta, err := deps.Vault.Secrets().GetMeta(ctx, key, appID)
		if err != nil {
			return secretsDetailResponse{}, mapError(err)
		}

		var rotationSummary *RotationPolicySummary
		policy, err := deps.Vault.Store().GetRotationPolicy(ctx, key, appID)
		switch {
		case err == nil:
			rs := projectRotationPolicy(policy, isRotatable(deps.Vault.Rotation().RotatorKeys(), key))
			rotationSummary = &rs
		case errors.Is(err, vault.ErrRotationNotFound):
			// No policy for this secret: rotation stays nil, not an error.
		default:
			return secretsDetailResponse{}, mapError(err)
		}

		entries, err := deps.Vault.Store().ListAuditByKey(ctx, key, appID, audit.ListOpts{Limit: recentAuditLimit})
		if err != nil {
			return secretsDetailResponse{}, mapError(err)
		}
		recentAudit := make([]AuditSummary, 0, len(entries))
		for _, e := range entries {
			recentAudit = append(recentAudit, projectAuditSummary(e))
		}

		return secretsDetailResponse{
			Secret:      projectSecretSummary(meta),
			Rotation:    rotationSummary,
			RecentAudit: recentAudit,
		}, nil
	}
}

// secretsVersionsRequest is the wire request for secrets.versions.
type secretsVersionsRequest struct {
	Key string `json:"key"`
}

// secretsVersionsResponse is the wire response for secrets.versions.
type secretsVersionsResponse struct {
	Versions []SecretVersionSummary `json:"versions"`
}

// secretsVersionsHandler answers secrets.versions for deps.Vault.AppID()
// alone. It checks the secret itself exists before listing, so an orphan
// version row left behind by a deleted secret can never make this answer
// as if the secret were still there.
func secretsVersionsHandler(deps Deps) func(ctx context.Context, in secretsVersionsRequest, p contract.Principal) (secretsVersionsResponse, error) {
	return func(ctx context.Context, in secretsVersionsRequest, _ contract.Principal) (secretsVersionsResponse, error) {
		appID := deps.Vault.AppID()
		key, err := requireKey(in.Key)
		if err != nil {
			return secretsVersionsResponse{}, err
		}

		if _, metaErr := deps.Vault.Secrets().GetMeta(ctx, key, appID); metaErr != nil {
			return secretsVersionsResponse{}, mapError(metaErr)
		}

		versions, err := deps.Vault.Secrets().ListVersions(ctx, key, appID)
		if err != nil {
			return secretsVersionsResponse{}, mapError(err)
		}
		sort.Slice(versions, func(i, j int) bool { return versions[i].Version > versions[j].Version })

		out := make([]SecretVersionSummary, 0, len(versions))
		for _, v := range versions {
			out = append(out, projectSecretVersionSummary(v))
		}
		return secretsVersionsResponse{Versions: out}, nil
	}
}

// parseFutureExpiry parses raw as an RFC3339 timestamp and rejects one that
// is not in the future. Shared by secrets.create and secrets.update, since
// both reject a past expiry the same way.
//
// The returned time is always normalized to UTC. A caller's non-UTC offset
// (e.g. "+02:00") round-trips through the sqlite store's upsert as a
// literal Go-formatted string carrying that offset, which the store's own
// read path cannot parse back; the failure isn't confined to the one row
// either, since it breaks the scan for the whole result set on any query
// that touches it, such as secrets.list. Normalizing here, before the
// value ever reaches Secrets().Set, keeps every stored expiry in the one
// format the store can always read back, the same reason it also strips
// any monotonic clock reading.
func parseFutureExpiry(raw string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, badRequest("expiresAt must be an RFC3339 timestamp")
	}
	if !t.After(time.Now()) {
		return time.Time{}, badRequest("expiresAt must be in the future")
	}
	return t.UTC(), nil
}

// secretsCreateRequest is the wire request for secrets.create. value is
// never logged, never echoed in an error, and never returned: it exists on
// this request type and nowhere else in this file's inputs but
// secretsUpdateRequest.
type secretsCreateRequest struct {
	Key       string `json:"key"`
	Value     string `json:"value"`
	ExpiresAt string `json:"expiresAt,omitempty"`
}

// secretsCreateResponse is the wire response for secrets.create.
type secretsCreateResponse struct {
	Secret SecretSummary `json:"secret"`
}

// secretsCreateHandler answers secrets.create for deps.Vault.AppID() alone.
// It refuses an existing key with CONFLICT, because Secrets().Set would
// otherwise silently add a version to it instead of creating fresh.
func secretsCreateHandler(deps Deps) func(ctx context.Context, in secretsCreateRequest, p contract.Principal) (secretsCreateResponse, error) {
	return func(ctx context.Context, in secretsCreateRequest, _ contract.Principal) (secretsCreateResponse, error) {
		appID := deps.Vault.AppID()
		key, err := requireKey(in.Key)
		if err != nil {
			return secretsCreateResponse{}, err
		}
		if in.Value == "" {
			return secretsCreateResponse{}, badRequest("value is required")
		}

		switch _, metaErr := deps.Vault.Secrets().GetMeta(ctx, key, appID); {
		case metaErr == nil:
			return secretsCreateResponse{}, conflict("a secret with this key already exists; update it instead")
		case !errors.Is(metaErr, vault.ErrSecretNotFound):
			return secretsCreateResponse{}, mapError(metaErr)
		}

		var opts []secret.SetOption
		if in.ExpiresAt != "" {
			t, perr := parseFutureExpiry(in.ExpiresAt)
			if perr != nil {
				return secretsCreateResponse{}, perr
			}
			opts = append(opts, secret.WithExpiresAt(t))
		}

		meta, err := deps.Vault.Secrets().Set(ctx, key, []byte(in.Value), appID, opts...)
		if err != nil {
			return secretsCreateResponse{}, mapError(err)
		}
		return secretsCreateResponse{Secret: projectSecretSummary(meta)}, nil
	}
}

// secretsUpdateRequest is the wire request for secrets.update. ExpiresAt and
// Metadata are pointers so the handler can tell "field absent" (nil) from
// "field present" (non-nil), which is what carrying expiry and metadata
// forward on an untouched update depends on.
type secretsUpdateRequest struct {
	Key       string             `json:"key"`
	Value     string             `json:"value"`
	ExpiresAt *string            `json:"expiresAt,omitempty"`
	Metadata  *map[string]string `json:"metadata,omitempty"`
}

// secretsUpdateResponse is the wire response for secrets.update.
type secretsUpdateResponse struct {
	Secret SecretSummary `json:"secret"`
}

// secretsUpdateHandler answers secrets.update for deps.Vault.AppID() alone.
//
// Secrets().Set always builds a fresh row, and the store backends upsert
// expires_at and metadata from whatever that row carries, so a Set call
// with no options erases both. This handler resolves the expiry and
// metadata this update must end up with (current value carried forward,
// cleared, or replaced) and always passes the result to Set as options, so
// an update that only changes the value never silently erases the other
// two.
func secretsUpdateHandler(deps Deps) func(ctx context.Context, in secretsUpdateRequest, p contract.Principal) (secretsUpdateResponse, error) {
	return func(ctx context.Context, in secretsUpdateRequest, _ contract.Principal) (secretsUpdateResponse, error) {
		appID := deps.Vault.AppID()
		key, err := requireKey(in.Key)
		if err != nil {
			return secretsUpdateResponse{}, err
		}
		if in.Value == "" {
			return secretsUpdateResponse{}, badRequest("value is required")
		}

		existing, err := deps.Vault.Secrets().GetMeta(ctx, key, appID)
		if err != nil {
			return secretsUpdateResponse{}, mapError(err)
		}

		var opts []secret.SetOption

		// expiresAt: absent keeps the current expiry; present "" clears it
		// (by simply not setting a new one, since Set has no "clear" option
		// and a fresh row without WithExpiresAt already has a nil expiry);
		// present with a timestamp sets it, future only.
		switch {
		case in.ExpiresAt == nil:
			if existing.ExpiresAt != nil {
				opts = append(opts, secret.WithExpiresAt(*existing.ExpiresAt))
			}
		case *in.ExpiresAt == "":
			// Clears: no option appended, so the new row's expiry stays nil.
		default:
			t, perr := parseFutureExpiry(*in.ExpiresAt)
			if perr != nil {
				return secretsUpdateResponse{}, perr
			}
			opts = append(opts, secret.WithExpiresAt(t))
		}

		// metadata: absent keeps the current metadata; present replaces it
		// wholesale, including with an empty (but non-nil) map.
		switch in.Metadata {
		case nil:
			if existing.Metadata != nil {
				opts = append(opts, secret.WithMetadata(existing.Metadata))
			}
		default:
			opts = append(opts, secret.WithMetadata(*in.Metadata))
		}

		updated, err := deps.Vault.Secrets().Set(ctx, key, []byte(in.Value), appID, opts...)
		if err != nil {
			return secretsUpdateResponse{}, mapError(err)
		}
		return secretsUpdateResponse{Secret: projectSecretSummary(updated)}, nil
	}
}

// secretsDeleteRequest is the wire request for secrets.delete.
type secretsDeleteRequest struct {
	Key string `json:"key"`
}

// secretsDeleteResponse is the wire response for secrets.delete.
type secretsDeleteResponse struct {
	OK  bool   `json:"ok"`
	Key string `json:"key"`
}

// secretsDeleteHandler answers secrets.delete for deps.Vault.AppID() alone.
// It also removes the secret's rotation policy, if any: an orphaned policy
// left behind would make the rotation loop fail on a missing secret every
// minute, forever.
func secretsDeleteHandler(deps Deps) func(ctx context.Context, in secretsDeleteRequest, p contract.Principal) (secretsDeleteResponse, error) {
	return func(ctx context.Context, in secretsDeleteRequest, _ contract.Principal) (secretsDeleteResponse, error) {
		appID := deps.Vault.AppID()
		key, err := requireKey(in.Key)
		if err != nil {
			return secretsDeleteResponse{}, err
		}

		if err := deps.Vault.Secrets().Delete(ctx, key, appID); err != nil {
			return secretsDeleteResponse{}, mapError(err)
		}

		if err := deps.Vault.Store().DeleteRotationPolicy(ctx, key, appID); err != nil && !errors.Is(err, vault.ErrRotationNotFound) {
			return secretsDeleteResponse{}, mapError(err)
		}

		return secretsDeleteResponse{OK: true, Key: key}, nil
	}
}
