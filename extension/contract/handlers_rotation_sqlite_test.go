package contract

import (
	"context"
	"testing"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// TestRotationSavePolicy_SQLite_ThenListAndDetailSucceed is the regression
// test for the "computes NextRotationAt from a non-UTC or monotonic-tainted
// time.Now()" bug against a real backend: the sqlite store cannot read back
// a time with a non-UTC location or a monotonic clock reading, and one bad
// row makes list reads fail for the whole app, not just the row itself.
// newSQLiteTestVault and testSQLiteStore are defined in
// handlers_secrets_sqlite_test.go and shared across this package's sqlite
// suites.
func TestRotationSavePolicy_SQLite_ThenListAndDetailSucceed(t *testing.T) {
	v := newSQLiteTestVault(t)
	ctx := context.Background()
	const key = "sqlite-policy"

	if _, err := v.Secrets().Set(ctx, key, []byte("v1"), testAppID); err != nil {
		t.Fatalf("seed secret: %v", err)
	}

	saveOut, err := rotationSavePolicyHandler(Deps{Vault: v})(ctx, rotationSavePolicyRequest{
		Key: key, IntervalSeconds: 300, Enabled: true,
	}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("savePolicy: %v", err)
	}
	if saveOut.Policy.NextRotationAt == nil {
		t.Fatal("savePolicy response nextRotationAt = nil, want a value for a new enabled policy")
	}

	// The regression: a NextRotationAt computed from a raw time.Now().Add()
	// (non-UTC location, monotonic reading) fails to read back from
	// sqlite, and that failure poisons the whole app's list scan, not just
	// this one row.
	listOut, err := rotationPoliciesHandler(Deps{Vault: v})(ctx, rotationPoliciesRequest{}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("rotation.policies after a sqlite savePolicy: %v", err)
	}
	found := false
	for _, p := range listOut.Policies {
		if p.SecretKey == key {
			found = true
		}
	}
	if !found {
		t.Fatalf("rotation.policies did not include %q: %+v", key, listOut.Policies)
	}

	detailOut, err := rotationDetailHandler(Deps{Vault: v})(ctx, rotationDetailRequest{Key: key}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("rotation.detail after a sqlite savePolicy: %v", err)
	}
	if detailOut.Policy == nil {
		t.Fatal("rotation.detail policy = nil, want the saved policy")
	}
	if detailOut.Policy.IntervalSeconds != 300 {
		t.Errorf("intervalSeconds = %d, want 300", detailOut.Policy.IntervalSeconds)
	}

	// Re-saving with a changed interval recomputes NextRotationAt again;
	// confirm that path is also readable back.
	save2, err := rotationSavePolicyHandler(Deps{Vault: v})(ctx, rotationSavePolicyRequest{
		Key: key, IntervalSeconds: 600, Enabled: true,
	}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("second savePolicy: %v", err)
	}
	if save2.Policy.NextRotationAt == nil {
		t.Fatal("second savePolicy nextRotationAt = nil, want a value (interval changed)")
	}

	if _, err := rotationPoliciesHandler(Deps{Vault: v})(ctx, rotationPoliciesRequest{}, dashcontract.Principal{}); err != nil {
		t.Fatalf("rotation.policies after a second sqlite savePolicy: %v", err)
	}
}
