package sqlite_test

import (
	"sync"
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
			s := testStore(t)
			if tc.seed != nil {
				if err := s.SaveRotationPolicy(bg(), tc.seed); err != nil {
					t.Fatalf("SaveRotationPolicy: %v", err)
				}
			}

			got, err := s.ClaimDueRotation(bg(), "db-password", "app1", now, until)
			if err != nil {
				t.Fatalf("ClaimDueRotation: %v", err)
			}
			if got != tc.want {
				t.Fatalf("claimed: got %v, want %v", got, tc.want)
			}
			if tc.seed == nil {
				return
			}

			p, err := s.GetRotationPolicy(bg(), "db-password", "app1")
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
	s := testStore(t)
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)
	until := now.Add(5 * time.Minute)
	if err := s.SaveRotationPolicy(bg(), claimPolicy(true, &past)); err != nil {
		t.Fatalf("SaveRotationPolicy: %v", err)
	}

	first, err := s.ClaimDueRotation(bg(), "db-password", "app1", now, until)
	if err != nil || !first {
		t.Fatalf("first claim: got %v, %v; want true, nil", first, err)
	}
	second, err := s.ClaimDueRotation(bg(), "db-password", "app1", now, until)
	if err != nil || second {
		t.Fatalf("second claim: got %v, %v; want false, nil", second, err)
	}
}

// Many callers claiming the same due time at once, over one file database
// and the driver's connection pool, must produce exactly one winner. The
// round repeats so a race that only loses some of the time still shows.
func TestClaimDueRotationConcurrentOneWinner(t *testing.T) {
	s := testStore(t)
	const (
		rounds  = 20
		callers = 16
	)

	for round := range rounds {
		now := time.Date(2026, 9, 29, 12, round, 0, 0, time.UTC)
		past := now.Add(-time.Hour)
		until := now.Add(5 * time.Minute)
		if err := s.SaveRotationPolicy(bg(), claimPolicy(true, &past)); err != nil {
			t.Fatalf("round %d: SaveRotationPolicy: %v", round, err)
		}

		var (
			start sync.WaitGroup
			done  sync.WaitGroup
			mu    sync.Mutex
			wins  int
			errs  []error
		)
		start.Add(1)
		for range callers {
			done.Add(1)
			go func() {
				defer done.Done()
				start.Wait()
				ok, err := s.ClaimDueRotation(bg(), "db-password", "app1", now, until)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					errs = append(errs, err)
				}
				if ok {
					wins++
				}
			}()
		}
		start.Done()
		done.Wait()

		if len(errs) > 0 {
			t.Fatalf("round %d: %d callers failed, first: %v", round, len(errs), errs[0])
		}
		if wins != 1 {
			t.Fatalf("round %d: %d callers claimed the same due time, want exactly 1", round, wins)
		}

		p, err := s.GetRotationPolicy(bg(), "db-password", "app1")
		if err != nil {
			t.Fatalf("round %d: GetRotationPolicy: %v", round, err)
		}
		assertNext(t, p.NextRotationAt, &until)
	}
}

func claimPolicy(enabled bool, next *time.Time) *rotation.Policy {
	return &rotation.Policy{
		Entity:         vault.NewEntity(),
		ID:             id.NewRotationID(),
		SecretKey:      "db-password",
		AppID:          "app1",
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
