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
