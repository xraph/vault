package memory_test

import (
	"testing"
	"time"

	"github.com/xraph/vault"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/rotation"
)

// ClaimDueRotation is what stops two replicas both rotating the same due
// policy. Each case seeds one policy (or none), claims it once at a fixed
// now, and checks both the answer and what the claim left in the store.
func TestClaimDueRotation(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	until := now.Add(5 * time.Minute)
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	cases := []struct {
		name     string
		seed     *rotation.Policy // nil seeds nothing
		want     bool
		wantNext *time.Time // NextRotationAt after the claim; nil means unset
	}{
		{"due", claimPolicy(true, &past), true, &until},
		{"not due yet", claimPolicy(true, &future), false, &future},
		{"due exactly now is not due", claimPolicy(true, &now), false, &now},
		{"disabled", claimPolicy(false, &past), false, &past},
		{"no due time", claimPolicy(true, nil), false, nil},
		{"missing policy", nil, false, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newStore()
			if tc.seed != nil {
				if err := s.SaveRotationPolicy(bg(), tc.seed); err != nil {
					t.Fatalf("SaveRotationPolicy: %v", err)
				}
			}

			got, err := s.ClaimDueRotation(bg(), "db-password", testApp, now, until)
			if err != nil {
				t.Fatalf("ClaimDueRotation: %v", err)
			}
			if got != tc.want {
				t.Fatalf("claimed: got %v, want %v", got, tc.want)
			}
			if tc.seed == nil {
				return
			}

			p, err := s.GetRotationPolicy(bg(), "db-password", testApp)
			if err != nil {
				t.Fatalf("GetRotationPolicy: %v", err)
			}
			assertNext(t, p.NextRotationAt, tc.wantNext)
		})
	}
}

// A second claim at the same now finds the due time already moved to the
// lease end, so only the first caller wins.
func TestClaimDueRotationOnlyOnce(t *testing.T) {
	s := newStore()
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)
	until := now.Add(5 * time.Minute)
	if err := s.SaveRotationPolicy(bg(), claimPolicy(true, &past)); err != nil {
		t.Fatalf("SaveRotationPolicy: %v", err)
	}

	first, err := s.ClaimDueRotation(bg(), "db-password", testApp, now, until)
	if err != nil || !first {
		t.Fatalf("first claim: got %v, %v; want true, nil", first, err)
	}
	second, err := s.ClaimDueRotation(bg(), "db-password", testApp, now, until)
	if err != nil || second {
		t.Fatalf("second claim: got %v, %v; want false, nil", second, err)
	}
}

func claimPolicy(enabled bool, next *time.Time) *rotation.Policy {
	return &rotation.Policy{
		Entity:         vault.NewEntity(),
		ID:             id.NewRotationID(),
		SecretKey:      "db-password",
		AppID:          testApp,
		Interval:       time.Hour,
		Enabled:        enabled,
		NextRotationAt: next,
	}
}

func assertNext(t *testing.T, got, want *time.Time) {
	t.Helper()
	switch {
	case want == nil && got != nil:
		t.Errorf("NextRotationAt: got %v, want unset", *got)
	case want != nil && got == nil:
		t.Errorf("NextRotationAt: got unset, want %v", *want)
	case want != nil && !got.Equal(*want):
		t.Errorf("NextRotationAt: got %v, want %v", *got, *want)
	}
}
