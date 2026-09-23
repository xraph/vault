package contract

import (
	"context"
	"errors"
	"testing"
	"time"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"

	"github.com/xraph/vault"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/rotation"
	"github.com/xraph/vault/secret"
)

// --- rotation.policies ---

func TestRotationPolicies_SortPagingAndTotal(t *testing.T) {
	v, st := newTestVault(t)
	ctx := context.Background()

	// Seed out of key order, so a correct handler must sort rather than
	// trust store order.
	for _, key := range []string{"zeta", "alpha", "mid"} {
		if _, err := v.Secrets().Set(ctx, key, []byte("value"), testAppID); err != nil {
			t.Fatalf("seed secret %q: %v", key, err)
		}
		policy := &rotation.Policy{
			Entity: vault.NewEntity(), ID: id.NewRotationID(), SecretKey: key, AppID: testAppID,
			Interval: time.Hour, Enabled: true,
		}
		if err := st.SaveRotationPolicy(ctx, policy); err != nil {
			t.Fatalf("seed policy %q: %v", key, err)
		}
	}

	out, err := rotationPoliciesHandler(Deps{Vault: v})(ctx, rotationPoliciesRequest{Limit: 2, Offset: 0}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("policies: %v", err)
	}
	if out.Total != 3 {
		t.Errorf("total = %d, want 3", out.Total)
	}
	if len(out.Policies) != 2 {
		t.Fatalf("page len = %d, want 2", len(out.Policies))
	}
	if out.Policies[0].SecretKey != "alpha" || out.Policies[1].SecretKey != "mid" {
		t.Errorf("page1 keys = [%s, %s], want [alpha, mid]", out.Policies[0].SecretKey, out.Policies[1].SecretKey)
	}

	page2, err := rotationPoliciesHandler(Deps{Vault: v})(ctx, rotationPoliciesRequest{Limit: 2, Offset: 2}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("policies page2: %v", err)
	}
	if len(page2.Policies) != 1 || page2.Policies[0].SecretKey != "zeta" {
		t.Fatalf("page2 = %+v, want [zeta]", page2.Policies)
	}
	if page2.Total != 3 {
		t.Errorf("page2 total = %d, want 3", page2.Total)
	}
}

func TestRotationPolicies_DefaultLimit(t *testing.T) {
	v, st := newTestVault(t)
	ctx := context.Background()
	if _, err := v.Secrets().Set(ctx, "k", []byte("v"), testAppID); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := st.SaveRotationPolicy(ctx, &rotation.Policy{
		Entity: vault.NewEntity(), ID: id.NewRotationID(), SecretKey: "k", AppID: testAppID,
		Interval: time.Hour, Enabled: true,
	}); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	out, err := rotationPoliciesHandler(Deps{Vault: v})(ctx, rotationPoliciesRequest{}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("policies: %v", err)
	}
	if len(out.Policies) != 1 {
		t.Fatalf("policies = %+v, want 1 with default paging", out.Policies)
	}
}

// --- rotation.detail ---

func TestRotationDetail_MissingSecretIsNotFound(t *testing.T) {
	v, _ := newTestVault(t)
	_, err := rotationDetailHandler(Deps{Vault: v})(context.Background(), rotationDetailRequest{Key: "nope"}, dashcontract.Principal{})
	if code := codeOf(err); code != dashcontract.CodeNotFound {
		t.Fatalf("detail of a missing secret: code %q, err %v; want NOT_FOUND", code, err)
	}
}

func TestRotationDetail_PolicyNullWithoutPolicy(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	if _, err := v.Secrets().Set(ctx, "no-policy", []byte("v"), testAppID); err != nil {
		t.Fatalf("seed: %v", err)
	}

	out, err := rotationDetailHandler(Deps{Vault: v})(ctx, rotationDetailRequest{Key: "no-policy"}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("detail: %v", err)
	}
	if out.Policy != nil {
		t.Errorf("policy = %+v, want nil", out.Policy)
	}
	if out.Records == nil {
		t.Error("records = nil, want an empty (non-nil) slice or at least a JSON-safe value")
	}
}

func TestRotationDetail_RecordsNewestFirstAndRotatable(t *testing.T) {
	v, st := newTestVault(t)
	ctx := context.Background()
	const key = "rotatable-key"
	if _, err := v.Secrets().Set(ctx, key, []byte("v"), testAppID); err != nil {
		t.Fatalf("seed secret: %v", err)
	}
	v.Rotation().RegisterRotator(key, func(_ context.Context, current []byte) ([]byte, error) { return current, nil })

	policy := &rotation.Policy{
		Entity: vault.NewEntity(), ID: id.NewRotationID(), SecretKey: key, AppID: testAppID,
		Interval: time.Hour, Enabled: true,
	}
	if err := st.SaveRotationPolicy(ctx, policy); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	base := time.Now().UTC().Add(-time.Hour)
	for i := 0; i < 3; i++ {
		rec := &rotation.Record{
			ID: id.NewRotationID(), SecretKey: key, AppID: testAppID,
			OldVersion: int64(i + 1), NewVersion: int64(i + 2),
			RotatedBy: "test", RotatedAt: base.Add(time.Duration(i) * time.Minute),
		}
		if err := st.RecordRotation(ctx, rec); err != nil {
			t.Fatalf("seed record %d: %v", i, err)
		}
	}

	out, err := rotationDetailHandler(Deps{Vault: v})(ctx, rotationDetailRequest{Key: key}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("detail: %v", err)
	}
	if out.Policy == nil {
		t.Fatal("policy = nil, want the saved policy")
	}
	if !out.Rotatable {
		t.Error("rotatable = false, want true: a rotator is registered")
	}
	if !out.Policy.Rotatable {
		t.Error("policy.rotatable = false, want true")
	}
	if len(out.Records) != 3 {
		t.Fatalf("records len = %d, want 3", len(out.Records))
	}
	for i := 0; i < len(out.Records)-1; i++ {
		if out.Records[i].RotatedAt < out.Records[i+1].RotatedAt {
			t.Fatalf("records not newest-first: %+v", out.Records)
		}
	}
}

// --- rotation.savePolicy ---

func TestRotationSavePolicy_SecretMustExist(t *testing.T) {
	v, _ := newTestVault(t)
	_, err := rotationSavePolicyHandler(Deps{Vault: v})(context.Background(), rotationSavePolicyRequest{
		Key: "nope", IntervalSeconds: 120, Enabled: true,
	}, dashcontract.Principal{})
	if code := codeOf(err); code != dashcontract.CodeNotFound {
		t.Fatalf("savePolicy for a missing secret: code %q, err %v; want NOT_FOUND", code, err)
	}
}

func TestRotationSavePolicy_IntervalTooShortIsBadRequest(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	if _, err := v.Secrets().Set(ctx, "short", []byte("v"), testAppID); err != nil {
		t.Fatalf("seed: %v", err)
	}

	_, err := rotationSavePolicyHandler(Deps{Vault: v})(ctx, rotationSavePolicyRequest{
		Key: "short", IntervalSeconds: 59, Enabled: true,
	}, dashcontract.Principal{})
	if code := codeOf(err); code != dashcontract.CodeBadRequest {
		t.Fatalf("savePolicy with intervalSeconds=59: code %q, err %v; want BAD_REQUEST", code, err)
	}

	if _, getErr := v.Store().GetRotationPolicy(ctx, "short", testAppID); !errors.Is(getErr, vault.ErrRotationNotFound) {
		t.Errorf("a rejected savePolicy must not create anything; GetRotationPolicy err = %v", getErr)
	}
}

// TestRotationSavePolicy_NextRotationAtRules table-tests the four cases
// from the plan: new, interval changed, disabled-to-enabled, and
// unchanged. Each sets up its own secret and starting policy state (where
// one exists), calls savePolicy, and checks whether NextRotationAt moved.
func TestRotationSavePolicy_NextRotationAtRules(t *testing.T) {
	cases := []struct {
		name            string
		seedPolicy      bool
		seedInterval    time.Duration
		seedEnabled     bool
		seedNext        *time.Time // nil means "no NextRotationAt stored"
		reqInterval     int64      // seconds
		reqEnabled      bool
		wantNextChanges bool
	}{
		{
			name:            "new policy always gets a next due time",
			seedPolicy:      false,
			reqInterval:     120,
			reqEnabled:      true,
			wantNextChanges: true,
		},
		{
			name:            "new disabled policy still gets a next due time",
			seedPolicy:      false,
			reqInterval:     120,
			reqEnabled:      false,
			wantNextChanges: true,
		},
		{
			name:            "interval changed",
			seedPolicy:      true,
			seedInterval:    time.Hour,
			seedEnabled:     true,
			seedNext:        timePtr(time.Now().UTC().Add(2 * time.Hour)),
			reqInterval:     7200, // 2h, different from the seeded 1h
			reqEnabled:      true,
			wantNextChanges: true,
		},
		{
			name:            "disabled to enabled",
			seedPolicy:      true,
			seedInterval:    time.Hour,
			seedEnabled:     false,
			seedNext:        timePtr(time.Now().UTC().Add(2 * time.Hour)),
			reqInterval:     3600, // same interval, 1h
			reqEnabled:      true,
			wantNextChanges: true,
		},
		{
			name:            "unchanged: same interval, stays enabled",
			seedPolicy:      true,
			seedInterval:    time.Hour,
			seedEnabled:     true,
			seedNext:        timePtr(time.Now().UTC().Add(2 * time.Hour)),
			reqInterval:     3600,
			reqEnabled:      true,
			wantNextChanges: false,
		},
		{
			name:            "unchanged: enabled to disabled keeps the stored value",
			seedPolicy:      true,
			seedInterval:    time.Hour,
			seedEnabled:     true,
			seedNext:        timePtr(time.Now().UTC().Add(2 * time.Hour)),
			reqInterval:     3600,
			reqEnabled:      false,
			wantNextChanges: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, st := newTestVault(t)
			ctx := context.Background()
			const key = "policy-key"
			if _, err := v.Secrets().Set(ctx, key, []byte("v"), testAppID); err != nil {
				t.Fatalf("seed secret: %v", err)
			}

			var lastRotated *time.Time
			var seededNext *time.Time
			if tc.seedPolicy {
				lastRotated = timePtr(time.Now().UTC().Add(-24 * time.Hour))
				seededNext = tc.seedNext
				if err := st.SaveRotationPolicy(ctx, &rotation.Policy{
					Entity: vault.NewEntity(), ID: id.NewRotationID(), SecretKey: key, AppID: testAppID,
					Interval: tc.seedInterval, Enabled: tc.seedEnabled,
					LastRotatedAt: lastRotated, NextRotationAt: tc.seedNext,
				}); err != nil {
					t.Fatalf("seed policy: %v", err)
				}
			}

			before := time.Now().UTC()
			_, err := rotationSavePolicyHandler(Deps{Vault: v})(ctx, rotationSavePolicyRequest{
				Key: key, IntervalSeconds: tc.reqInterval, Enabled: tc.reqEnabled,
			}, dashcontract.Principal{})
			if err != nil {
				t.Fatalf("savePolicy: %v", err)
			}
			after := time.Now().UTC()

			stored, err := st.GetRotationPolicy(ctx, key, testAppID)
			if err != nil {
				t.Fatalf("GetRotationPolicy: %v", err)
			}

			// LastRotatedAt must never move here: savePolicy doesn't rotate
			// anything.
			if tc.seedPolicy {
				if stored.LastRotatedAt == nil || !stored.LastRotatedAt.Equal(*lastRotated) {
					t.Errorf("lastRotatedAt = %v, want it kept at %v", stored.LastRotatedAt, lastRotated)
				}
			}

			if tc.wantNextChanges {
				if stored.NextRotationAt == nil {
					t.Fatal("nextRotationAt = nil, want now+interval")
				}
				wantInterval := time.Duration(tc.reqInterval) * time.Second
				lowerBound := before.Add(wantInterval)
				upperBound := after.Add(wantInterval)
				if stored.NextRotationAt.Before(lowerBound) || stored.NextRotationAt.After(upperBound) {
					t.Errorf("nextRotationAt = %v, want between %v and %v (now+interval)", stored.NextRotationAt, lowerBound, upperBound)
				}
				if seededNext != nil && stored.NextRotationAt.Equal(*seededNext) {
					t.Errorf("nextRotationAt = %v, want it to have moved off the seeded value", stored.NextRotationAt)
				}
			} else {
				if seededNext == nil {
					if stored.NextRotationAt != nil {
						t.Errorf("nextRotationAt = %v, want nil (kept unset)", stored.NextRotationAt)
					}
				} else if stored.NextRotationAt == nil || !stored.NextRotationAt.Equal(*seededNext) {
					t.Errorf("nextRotationAt = %v, want it kept at the seeded %v", stored.NextRotationAt, seededNext)
				}
			}
		})
	}
}

func timePtr(t time.Time) *time.Time { return &t }

func TestRotationSavePolicy_ThenDetailShowsIt(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	const key = "detail-after-save"
	if _, err := v.Secrets().Set(ctx, key, []byte("v"), testAppID); err != nil {
		t.Fatalf("seed: %v", err)
	}

	out, err := rotationSavePolicyHandler(Deps{Vault: v})(ctx, rotationSavePolicyRequest{
		Key: key, IntervalSeconds: 120, Enabled: true,
	}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("savePolicy: %v", err)
	}
	if out.Policy.SecretKey != key {
		t.Errorf("policy.secretKey = %q, want %q", out.Policy.SecretKey, key)
	}
	if out.Policy.IntervalSeconds != 120 {
		t.Errorf("policy.intervalSeconds = %d, want 120", out.Policy.IntervalSeconds)
	}

	detail, err := rotationDetailHandler(Deps{Vault: v})(ctx, rotationDetailRequest{Key: key}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("detail: %v", err)
	}
	if detail.Policy == nil || detail.Policy.IntervalSeconds != 120 {
		t.Errorf("detail policy = %+v, want intervalSeconds=120", detail.Policy)
	}
}

// --- rotation.deletePolicy ---

func TestRotationDeletePolicy_RemovesPolicy(t *testing.T) {
	v, st := newTestVault(t)
	ctx := context.Background()
	const key = "to-delete"
	if _, err := v.Secrets().Set(ctx, key, []byte("v"), testAppID); err != nil {
		t.Fatalf("seed secret: %v", err)
	}
	if err := st.SaveRotationPolicy(ctx, &rotation.Policy{
		Entity: vault.NewEntity(), ID: id.NewRotationID(), SecretKey: key, AppID: testAppID,
		Interval: time.Hour, Enabled: true,
	}); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	out, err := rotationDeletePolicyHandler(Deps{Vault: v})(ctx, rotationDeletePolicyRequest{Key: key}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("deletePolicy: %v", err)
	}
	if !out.OK || out.Key != key {
		t.Errorf("deletePolicy response = %+v, want ok=true key=%q", out, key)
	}
	if _, getErr := st.GetRotationPolicy(ctx, key, testAppID); !errors.Is(getErr, vault.ErrRotationNotFound) {
		t.Errorf("policy still exists after deletePolicy: %v", getErr)
	}
}

func TestRotationDeletePolicy_MissingIsNotFound(t *testing.T) {
	v, _ := newTestVault(t)
	_, err := rotationDeletePolicyHandler(Deps{Vault: v})(context.Background(), rotationDeletePolicyRequest{Key: "nope"}, dashcontract.Principal{})
	if code := codeOf(err); code != dashcontract.CodeNotFound {
		t.Fatalf("deletePolicy for a missing policy: code %q, err %v; want NOT_FOUND", code, err)
	}
}

// --- rotation.rotateNow ---

func TestRotationRotateNow_NotRotatableIsBadRequestAndWritesNothing(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	const key = "no-rotator"
	if _, err := v.Secrets().Set(ctx, key, []byte("v1"), testAppID); err != nil {
		t.Fatalf("seed: %v", err)
	}

	_, err := rotationRotateNowHandler(Deps{Vault: v})(ctx, rotationRotateNowRequest{Key: key}, dashcontract.Principal{})
	if code := codeOf(err); code != dashcontract.CodeBadRequest {
		t.Fatalf("rotateNow with no registered rotator: code %q, err %v; want BAD_REQUEST", code, err)
	}
	var ce *dashcontract.Error
	if errors.As(err, &ce) && ce.Message != "no rotator is registered for this secret; rotators are registered in application code" {
		t.Errorf("message = %q, want the exact refusal text", ce.Message)
	}

	meta, getErr := v.Secrets().GetMeta(ctx, key, testAppID)
	if getErr != nil {
		t.Fatalf("GetMeta: %v", getErr)
	}
	if meta.Version != 1 {
		t.Errorf("version = %d after a refused rotateNow, want 1 (nothing written)", meta.Version)
	}
}

func TestRotationRotateNow_BumpsVersionAndKeepsExpiry(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	const key = "rotate-me"
	// Round(0) strips the monotonic clock reading time.Now() carries, the
	// same reason the sqlite suite in this package does it: a real request
	// never has one (expiresAt always arrives as an RFC3339 string and
	// goes through time.Parse), and comparing a monotonic-tainted value
	// with Equal after it round-trips through the store would only add
	// noise unrelated to what this test checks.
	expiry := time.Now().Add(24 * time.Hour).Round(0)
	if _, err := v.Secrets().Set(ctx, key, []byte("v1"), testAppID, secret.WithExpiresAt(expiry)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	v.Rotation().RegisterRotator(key, func(_ context.Context, current []byte) ([]byte, error) {
		// A no-op rotator: it returns the same bytes, but Set still
		// allocates a fresh version for them.
		return current, nil
	})

	out, err := rotationRotateNowHandler(Deps{Vault: v})(ctx, rotationRotateNowRequest{Key: key}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("rotateNow: %v", err)
	}
	if out.Key != key {
		t.Errorf("key = %q, want %q", out.Key, key)
	}
	if out.OldVersion != 1 {
		t.Errorf("oldVersion = %d, want 1", out.OldVersion)
	}
	if out.NewVersion != 2 {
		t.Errorf("newVersion = %d, want 2", out.NewVersion)
	}

	meta, err := v.Secrets().GetMeta(ctx, key, testAppID)
	if err != nil {
		t.Fatalf("GetMeta after rotate: %v", err)
	}
	if meta.Version != 2 {
		t.Errorf("stored version = %d, want 2", meta.Version)
	}
	if meta.ExpiresAt == nil {
		t.Fatal("expiresAt = nil after rotateNow, want it carried forward")
	}
	if !meta.ExpiresAt.Equal(expiry) {
		t.Errorf("expiresAt = %v, want %v", meta.ExpiresAt, expiry)
	}
}

func TestRotationRotateNow_MissingSecretIsNotFound(t *testing.T) {
	v, _ := newTestVault(t)
	const key = "ghost"
	// Register a rotator for a key with no secret at all: rotatable but
	// GetMeta must still fail before RotateNow ever runs.
	v.Rotation().RegisterRotator(key, func(_ context.Context, current []byte) ([]byte, error) { return current, nil })

	_, err := rotationRotateNowHandler(Deps{Vault: v})(context.Background(), rotationRotateNowRequest{Key: key}, dashcontract.Principal{})
	if code := codeOf(err); code != dashcontract.CodeNotFound {
		t.Fatalf("rotateNow for a rotatable key with no secret: code %q, err %v; want NOT_FOUND", code, err)
	}
}
