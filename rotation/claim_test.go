package rotation_test

import (
	"context"
	"crypto/rand"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/sqlitedriver"

	// Registers the "sqlite" migration executor the sqlite store migrates with.
	_ "github.com/xraph/grove/drivers/sqlitedriver/sqlitemigrate"

	"github.com/xraph/vault"
	"github.com/xraph/vault/crypto"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/rotation"
	"github.com/xraph/vault/secret"
	"github.com/xraph/vault/store/memory"
	sqlitestore "github.com/xraph/vault/store/sqlite"
)

// sharedStore is what two replicas point at: one database holding both the
// secrets and the rotation policies.
type sharedStore interface {
	secret.Store
	rotation.Store
}

// listBarrier makes every manager over it finish listing policies before any
// of them goes on to act on the list. Without it one replica could finish a
// whole rotation before the other lists, and the test would pass with no
// claim at all. With it both replicas always see the same due policy, which
// is the window a claim has to close.
type listBarrier struct {
	rotation.Store
	listed *sync.WaitGroup
}

func (b listBarrier) ListRotationPolicies(ctx context.Context, appID string) ([]*rotation.Policy, error) {
	ps, err := b.Store.ListRotationPolicies(ctx, appID)
	b.listed.Done()
	waited := make(chan struct{})
	go func() { b.listed.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(5 * time.Second):
	}
	return ps, err
}

// Two replicas run the scheduled loop over one store with the same rotator
// registered. A due policy must be rotated once, not once per replica: a
// second rotation overwrites the first value, and any app that already
// picked up the first is left holding a dead one.
func TestScheduledRotationRunsOnceAcrossReplicas(t *testing.T) {
	backends := map[string]func(t *testing.T) sharedStore{
		"memory": func(*testing.T) sharedStore { return memory.New() },
		"sqlite": openSQLite,
	}

	for name, open := range backends {
		t.Run(name, func(t *testing.T) {
			st := open(t)
			svc := secretService(t, st)
			if _, err := svc.Set(bg(), "db-password", []byte("v1"), ""); err != nil {
				t.Fatalf("seed secret: %v", err)
			}
			past := time.Now().UTC().Add(-time.Hour)
			if err := st.SaveRotationPolicy(bg(), &rotation.Policy{
				Entity:         vault.NewEntity(),
				ID:             id.NewRotationID(),
				SecretKey:      "db-password",
				AppID:          testApp,
				Interval:       24 * time.Hour,
				Enabled:        true,
				NextRotationAt: &past,
			}); err != nil {
				t.Fatalf("seed policy: %v", err)
			}

			var calls atomic.Int32
			rotator := func(_ context.Context, _ []byte) ([]byte, error) {
				calls.Add(1)
				return []byte("v2"), nil
			}

			var listed sync.WaitGroup
			listed.Add(2)
			replicas := make([]*rotation.Manager, 2)
			for i := range replicas {
				m := rotation.NewManager(listBarrier{Store: st, listed: &listed}, svc, rotation.WithAppID(testApp))
				m.RegisterRotator("db-password", rotator)
				replicas[i] = m
			}

			var run sync.WaitGroup
			for _, m := range replicas {
				run.Add(1)
				go func() {
					defer run.Done()
					m.CheckDuePoliciesForTest(bg())
				}()
			}
			run.Wait()

			if got := calls.Load(); got != 1 {
				t.Errorf("rotator called %d times across two replicas, want 1", got)
			}
			versions, err := st.ListSecretVersions(bg(), "db-password", testApp)
			if err != nil {
				t.Fatalf("ListSecretVersions: %v", err)
			}
			if len(versions) != 2 {
				t.Errorf("secret has %d versions after one due rotation, want 2 (the seed and one new value)", len(versions))
			}
		})
	}
}

func secretService(t *testing.T, s secret.Store) *secret.Service {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	enc, err := crypto.NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}
	return secret.NewService(s, enc, secret.WithAppID(testApp))
}

func openSQLite(t *testing.T) sharedStore {
	t.Helper()
	sdb := sqlitedriver.New()
	if err := sdb.Open(bg(), filepath.Join(t.TempDir(), "vault_claim.db")); err != nil {
		t.Fatalf("sqlitedriver open: %v", err)
	}
	db, err := grove.Open(sdb)
	if err != nil {
		t.Fatalf("grove open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s := sqlitestore.New(db)
	if err := s.Migrate(bg()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return s
}

// A replica with no rotator for a due key must leave the policy alone. If it
// claimed first and then failed to rotate, it would push the due time out
// by a lease on every pass, forever on its own, and ahead of a replica that
// does have the rotator when several share the store.
func TestScheduledLoopDoesNotClaimWithoutRotator(t *testing.T) {
	s := memory.New()
	svc := setupSecretService(t, s)
	seedSecret(t, svc, "db-password", []byte("v1"))
	past := time.Now().UTC().Add(-time.Hour)
	seedPolicy(t, s, "db-password", 24*time.Hour, past)

	without := rotation.NewManager(s, svc, rotation.WithAppID(testApp))
	without.CheckDuePoliciesForTest(bg())

	p, err := s.GetRotationPolicy(bg(), "db-password", testApp)
	if err != nil {
		t.Fatalf("GetRotationPolicy: %v", err)
	}
	if p.NextRotationAt == nil || !p.NextRotationAt.Equal(past) {
		t.Fatalf("NextRotationAt after a pass with no rotator: got %v, want unchanged %v", p.NextRotationAt, past)
	}

	// A replica that has the rotator still finds it due and rotates it.
	var calls atomic.Int32
	with := rotation.NewManager(s, svc, rotation.WithAppID(testApp))
	with.RegisterRotator("db-password", func(_ context.Context, _ []byte) ([]byte, error) {
		calls.Add(1)
		return []byte("v2"), nil
	})
	with.CheckDuePoliciesForTest(bg())
	if got := calls.Load(); got != 1 {
		t.Errorf("rotator on the replica that has it ran %d times, want 1", got)
	}
}

// While one replica is mid-rotation its lease is live, and a second replica
// passing over the same policy in that window must not rotate it too.
func TestScheduledRotationLeaseHoldsMidRotation(t *testing.T) {
	s := memory.New()
	svc := setupSecretService(t, s)
	seedSecret(t, svc, "db-password", []byte("v1"))
	seedPolicy(t, s, "db-password", 24*time.Hour, time.Now().UTC().Add(-time.Hour))

	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	blocking := func(_ context.Context, _ []byte) ([]byte, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
		return []byte("v2"), nil
	}

	a := rotation.NewManager(s, svc, rotation.WithAppID(testApp))
	a.RegisterRotator("db-password", blocking)
	b := rotation.NewManager(s, svc, rotation.WithAppID(testApp))
	b.RegisterRotator("db-password", blocking)

	aDone := make(chan struct{})
	go func() {
		defer close(aDone)
		a.CheckDuePoliciesForTest(bg())
	}()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("replica A never reached its rotator")
	}
	b.CheckDuePoliciesForTest(bg())
	close(release)
	<-aDone

	if got := calls.Load(); got != 1 {
		t.Errorf("rotator ran %d times across two replicas, want 1", got)
	}
}

// claimRecorder notes the now each claim was made with.
type claimRecorder struct {
	rotation.Store
	mu   sync.Mutex
	nows map[string]time.Time
}

func (c *claimRecorder) ClaimDueRotation(ctx context.Context, key, appID string, now, until time.Time) (bool, error) {
	c.mu.Lock()
	c.nows[key] = now
	c.mu.Unlock()
	return c.Store.ClaimDueRotation(ctx, key, appID, now, until)
}

// Rotations in one pass run one after another, so each claim must be made
// at the time it is taken. A now read once at the top of the pass would
// start a later policy's lease in the past, shortened or already over by
// the time that policy is claimed.
func TestScheduledLoopClaimsWithFreshTime(t *testing.T) {
	s := memory.New()
	svc := setupSecretService(t, s)
	past := time.Now().UTC().Add(-time.Hour)
	for _, k := range []string{"a-slow", "b-next"} {
		seedSecret(t, svc, k, []byte("v1"))
		seedPolicy(t, s, k, 24*time.Hour, past)
	}

	rec := &claimRecorder{Store: s, nows: map[string]time.Time{}}
	m := rotation.NewManager(rec, svc, rotation.WithAppID(testApp))
	var slowDone time.Time
	m.RegisterRotator("a-slow", func(_ context.Context, _ []byte) ([]byte, error) {
		time.Sleep(50 * time.Millisecond)
		slowDone = time.Now().UTC()
		return []byte("v2"), nil
	})
	m.RegisterRotator("b-next", func(_ context.Context, _ []byte) ([]byte, error) {
		return []byte("v2"), nil
	})

	m.CheckDuePoliciesForTest(bg())

	got, ok := rec.nows["b-next"]
	if !ok {
		t.Fatal("b-next was never claimed")
	}
	if got.Before(slowDone) {
		t.Errorf("b-next claimed with now %v, before a-slow finished rotating at %v; the claim time is stale", got, slowDone)
	}
}
