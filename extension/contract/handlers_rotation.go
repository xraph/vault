package contract

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/xraph/forge/extensions/dashboard/contract"

	"github.com/xraph/vault"
	"github.com/xraph/vault/core"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/rotation"
)

// minRotationIntervalSeconds is the shortest interval a rotation policy can
// declare: the rotation loop only ever checks once a minute, so a shorter
// interval can never be honoured.
const minRotationIntervalSeconds = 60

// recentRotationRecordLimit bounds how many rotation records rotation.detail
// returns alongside a policy.
const recentRotationRecordLimit = 50

// rotationPoliciesRequest is the wire request for rotation.policies.
type rotationPoliciesRequest struct {
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

// rotationPoliciesResponse is the wire response for rotation.policies.
type rotationPoliciesResponse struct {
	Policies []RotationPolicySummary `json:"policies"`
	Total    int64                   `json:"total"`
}

// rotationPoliciesHandler answers rotation.policies for deps.Vault.AppID()
// alone. ListRotationPolicies returns every policy for the app with no
// paging of its own, so this handler sorts by secret key, takes the total
// as the full length, and only then applies limit/offset: an exact answer,
// not a post-filter of an already-paged read.
func rotationPoliciesHandler(deps Deps) func(ctx context.Context, in rotationPoliciesRequest, p contract.Principal) (rotationPoliciesResponse, error) {
	return func(ctx context.Context, in rotationPoliciesRequest, _ contract.Principal) (rotationPoliciesResponse, error) {
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

		all, err := deps.Vault.Store().ListRotationPolicies(ctx, appID)
		if err != nil {
			return rotationPoliciesResponse{}, deps.mapError("rotation.policies", err)
		}
		sort.Slice(all, func(i, j int) bool { return all[i].SecretKey < all[j].SecretKey })
		total := int64(len(all))

		start := offset
		if start > len(all) {
			start = len(all)
		}
		end := start + limit
		if end > len(all) {
			end = len(all)
		}
		page := all[start:end]

		rotatorKeys := deps.Vault.Rotation().RotatorKeys()
		summaries := make([]RotationPolicySummary, 0, len(page))
		for _, p := range page {
			summaries = append(summaries, projectRotationPolicy(p, isRotatable(rotatorKeys, p.SecretKey)))
		}
		return rotationPoliciesResponse{Policies: summaries, Total: total}, nil
	}
}

// rotationDetailRequest is the wire request for rotation.detail.
type rotationDetailRequest struct {
	Key string `json:"key"`
}

// rotationDetailResponse is the wire response for rotation.detail. Policy
// has no omitempty: it must reach the client as an explicit null when the
// secret has no policy yet, not be dropped, so one page can both show and
// create a policy.
type rotationDetailResponse struct {
	Policy    *RotationPolicySummary  `json:"policy"`
	Rotatable bool                    `json:"rotatable"`
	Records   []RotationRecordSummary `json:"records"`
}

// rotationDetailHandler answers rotation.detail for deps.Vault.AppID()
// alone. A missing secret is NOT_FOUND; a secret with no policy answers
// with policy: null rather than an error, since that is what lets a single
// page both show and create a policy. Records come back newest first,
// capped at recentRotationRecordLimit.
func rotationDetailHandler(deps Deps) func(ctx context.Context, in rotationDetailRequest, p contract.Principal) (rotationDetailResponse, error) {
	return func(ctx context.Context, in rotationDetailRequest, _ contract.Principal) (rotationDetailResponse, error) {
		appID := deps.Vault.AppID()
		key, err := requireKey(in.Key)
		if err != nil {
			return rotationDetailResponse{}, err
		}

		if _, metaErr := deps.Vault.Secrets().GetMeta(ctx, key, appID); metaErr != nil {
			return rotationDetailResponse{}, deps.mapError("rotation.detail", metaErr)
		}

		rotatable := isRotatable(deps.Vault.Rotation().RotatorKeys(), key)

		var policySummary *RotationPolicySummary
		policy, err := deps.Vault.Store().GetRotationPolicy(ctx, key, appID)
		switch {
		case err == nil:
			ps := projectRotationPolicy(policy, rotatable)
			policySummary = &ps
		case errors.Is(err, vault.ErrRotationNotFound):
			// No policy for this secret yet: policy stays nil, not an error.
		default:
			return rotationDetailResponse{}, deps.mapError("rotation.detail", err)
		}

		records, err := deps.Vault.Store().ListRotationRecords(ctx, key, appID, rotation.ListOpts{Limit: recentRotationRecordLimit})
		if err != nil {
			return rotationDetailResponse{}, deps.mapError("rotation.detail", err)
		}
		out := make([]RotationRecordSummary, 0, len(records))
		for _, r := range records {
			out = append(out, projectRotationRecord(r))
		}

		return rotationDetailResponse{Policy: policySummary, Rotatable: rotatable, Records: out}, nil
	}
}

// rotationSavePolicyRequest is the wire request for rotation.savePolicy.
type rotationSavePolicyRequest struct {
	Key             string `json:"key"`
	IntervalSeconds int64  `json:"intervalSeconds"`
	Enabled         bool   `json:"enabled"`
}

// rotationSavePolicyResponse is the wire response for rotation.savePolicy.
type rotationSavePolicyResponse struct {
	Policy RotationPolicySummary `json:"policy"`
}

// rotationSavePolicyHandler answers rotation.savePolicy for
// deps.Vault.AppID() alone. The secret must already exist. NextRotationAt
// is set to now+interval when the policy is new, when its interval
// changed, when it goes from disabled to enabled, or when it is saved
// enabled with no due time at all; every other save keeps the stored
// value, including LastRotatedAt, unchanged.
func rotationSavePolicyHandler(deps Deps) func(ctx context.Context, in rotationSavePolicyRequest, p contract.Principal) (rotationSavePolicyResponse, error) {
	return func(ctx context.Context, in rotationSavePolicyRequest, _ contract.Principal) (rotationSavePolicyResponse, error) {
		appID := deps.Vault.AppID()
		key, err := requireKey(in.Key)
		if err != nil {
			return rotationSavePolicyResponse{}, err
		}
		if in.IntervalSeconds < minRotationIntervalSeconds {
			return rotationSavePolicyResponse{}, badRequest("intervalSeconds must be at least 60")
		}

		if _, metaErr := deps.Vault.Secrets().GetMeta(ctx, key, appID); metaErr != nil {
			return rotationSavePolicyResponse{}, deps.mapError("rotation.savePolicy", metaErr)
		}

		interval := time.Duration(in.IntervalSeconds) * time.Second
		// now is computed once, in UTC with the monotonic reading stripped,
		// so it round-trips through a sqlite store's read path the same way
		// every other stored time in this package does.
		now := time.Now().UTC()

		var policy *rotation.Policy
		giveNextDueTime := false
		existing, err := deps.Vault.Store().GetRotationPolicy(ctx, key, appID)
		switch {
		case err == nil:
			policy = existing
			intervalChanged := policy.Interval != interval
			reenabled := !policy.Enabled && in.Enabled
			// A policy saved through the Go API never gets a
			// NextRotationAt, so an enabled one without it would never
			// fall due however many times it is saved here.
			enabledWithoutDueTime := in.Enabled && policy.NextRotationAt == nil
			giveNextDueTime = intervalChanged || reenabled || enabledWithoutDueTime
			policy.Interval = interval
			policy.Enabled = in.Enabled
			policy.Touch()
		case errors.Is(err, vault.ErrRotationNotFound):
			giveNextDueTime = true
			policy = &rotation.Policy{
				Entity:    core.NewEntity(),
				ID:        id.NewRotationID(),
				SecretKey: key,
				AppID:     appID,
				Interval:  interval,
				Enabled:   in.Enabled,
			}
		default:
			return rotationSavePolicyResponse{}, deps.mapError("rotation.savePolicy", err)
		}

		if giveNextDueTime {
			next := now.Add(interval)
			policy.NextRotationAt = &next
		}

		if err := deps.Vault.Store().SaveRotationPolicy(ctx, policy); err != nil {
			return rotationSavePolicyResponse{}, deps.mapError("rotation.savePolicy", err)
		}

		rotatable := isRotatable(deps.Vault.Rotation().RotatorKeys(), key)
		return rotationSavePolicyResponse{Policy: projectRotationPolicy(policy, rotatable)}, nil
	}
}

// rotationDeletePolicyRequest is the wire request for rotation.deletePolicy.
type rotationDeletePolicyRequest struct {
	Key string `json:"key"`
}

// rotationDeletePolicyResponse is the wire response for
// rotation.deletePolicy.
type rotationDeletePolicyResponse struct {
	OK  bool   `json:"ok"`
	Key string `json:"key"`
}

// rotationDeletePolicyHandler answers rotation.deletePolicy for
// deps.Vault.AppID() alone. A missing policy maps to NOT_FOUND through
// mapError, the same as every other not-found in this package.
func rotationDeletePolicyHandler(deps Deps) func(ctx context.Context, in rotationDeletePolicyRequest, p contract.Principal) (rotationDeletePolicyResponse, error) {
	return func(ctx context.Context, in rotationDeletePolicyRequest, _ contract.Principal) (rotationDeletePolicyResponse, error) {
		appID := deps.Vault.AppID()
		key, err := requireKey(in.Key)
		if err != nil {
			return rotationDeletePolicyResponse{}, err
		}

		if err := deps.Vault.Store().DeleteRotationPolicy(ctx, key, appID); err != nil {
			return rotationDeletePolicyResponse{}, deps.mapError("rotation.deletePolicy", err)
		}

		return rotationDeletePolicyResponse{OK: true, Key: key}, nil
	}
}

// rotationRotateNowRequest is the wire request for rotation.rotateNow.
type rotationRotateNowRequest struct {
	Key string `json:"key"`
}

// rotationRotateNowResponse is the wire response for rotation.rotateNow.
type rotationRotateNowResponse struct {
	Key        string `json:"key"`
	OldVersion int64  `json:"oldVersion"`
	NewVersion int64  `json:"newVersion"`
}

// rotationRotateNowHandler answers rotation.rotateNow for
// deps.Vault.AppID() alone. A key with no registered rotator is refused
// with BAD_REQUEST before anything is read or written: RotateNow itself
// would fail the same way, but only after Manager.RotateNow's own checks,
// and this handler must refuse before ever calling it.
func rotationRotateNowHandler(deps Deps) func(ctx context.Context, in rotationRotateNowRequest, p contract.Principal) (rotationRotateNowResponse, error) {
	return func(ctx context.Context, in rotationRotateNowRequest, _ contract.Principal) (rotationRotateNowResponse, error) {
		appID := deps.Vault.AppID()
		key, err := requireKey(in.Key)
		if err != nil {
			return rotationRotateNowResponse{}, err
		}

		if !isRotatable(deps.Vault.Rotation().RotatorKeys(), key) {
			return rotationRotateNowResponse{}, badRequest("no rotator is registered for this secret; rotators are registered in application code")
		}

		before, err := deps.Vault.Secrets().GetMeta(ctx, key, appID)
		if err != nil {
			return rotationRotateNowResponse{}, deps.mapError("rotation.rotateNow", err)
		}

		if rotErr := deps.Vault.Rotation().RotateNow(ctx, key, appID); rotErr != nil {
			return rotationRotateNowResponse{}, deps.mapError("rotation.rotateNow", rotErr)
		}

		after, err := deps.Vault.Secrets().GetMeta(ctx, key, appID)
		if err != nil {
			return rotationRotateNowResponse{}, deps.mapError("rotation.rotateNow", err)
		}

		return rotationRotateNowResponse{Key: key, OldVersion: before.Version, NewVersion: after.Version}, nil
	}
}
