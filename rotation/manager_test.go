package rotation_test

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/xraph/vault"
	"github.com/xraph/vault/crypto"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/rotation"
	"github.com/xraph/vault/secret"
	"github.com/xraph/vault/store/memory"
)

const testApp = "app1"

func bg() context.Context { return context.Background() }

func setupSecretService(t *testing.T, s *memory.Store) *secret.Service {
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

func seedSecret(t *testing.T, svc *secret.Service, key string, value []byte) {
	t.Helper()
	_, err := svc.Set(bg(), key, value, "")
	if err != nil {
		t.Fatalf("secret.Set(%q): %v", key, err)
	}
}

func seedPolicy(t *testing.T, s *memory.Store, key string, interval time.Duration, nextAt time.Time) {
	t.Helper()
	err := s.SaveRotationPolicy(bg(), &rotation.Policy{
		Entity:         vault.NewEntity(),
		ID:             id.NewRotationID(),
		SecretKey:      key,
		AppID:          testApp,
		Interval:       interval,
		Enabled:        true,
		NextRotationAt: &nextAt,
	})
	if err != nil {
		t.Fatalf("SaveRotationPolicy(%q): %v", key, err)
	}
}

func TestRotateNow(t *testing.T) {
	s := memory.New()
	svc := setupSecretService(t, s)
	seedSecret(t, svc, "db-password", []byte("old-password"))

	// Create a policy so timestamps can be updated.
	next := time.Now().UTC().Add(-1 * time.Hour)
	seedPolicy(t, s, "db-password", 24*time.Hour, next)

	mgr := rotation.NewManager(s, svc, rotation.WithAppID(testApp))
	mgr.RegisterRotator("db-password", func(_ context.Context, current []byte) ([]byte, error) {
		return []byte("new-password-" + string(current)), nil
	})

	err := mgr.RotateNow(bg(), "db-password", "")
	if err != nil {
		t.Fatal(err)
	}

	// Verify new secret value.
	sec, err := svc.Get(bg(), "db-password", "")
	if err != nil {
		t.Fatal(err)
	}
	if string(sec.Value) != "new-password-old-password" {
		t.Errorf("got %q, want %q", string(sec.Value), "new-password-old-password")
	}
	if sec.Version != 2 {
		t.Errorf("version: got %d, want 2", sec.Version)
	}
}

// A rotation must not silently erase the expiry and metadata that were set
// on the secret before it: secret.Service.Set builds a fresh row, and
// without carrying these forward, the backends upsert empty values for
// both. This must fail against today's code.
func TestRotateNowPreservesExpiryAndMetadata(t *testing.T) {
	s := memory.New()
	svc := setupSecretService(t, s)

	expiresAt := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second)
	metadata := map[string]string{"owner": "payments-team"}
	if _, err := svc.Set(bg(), "rotating-secret", []byte("old-value"), "",
		secret.WithExpiresAt(expiresAt),
		secret.WithMetadata(metadata),
	); err != nil {
		t.Fatalf("secret.Set: %v", err)
	}

	mgr := rotation.NewManager(s, svc, rotation.WithAppID(testApp))
	mgr.RegisterRotator("rotating-secret", func(_ context.Context, _ []byte) ([]byte, error) {
		return []byte("new-value"), nil
	})

	if err := mgr.RotateNow(bg(), "rotating-secret", ""); err != nil {
		t.Fatal(err)
	}

	meta, err := svc.GetMeta(bg(), "rotating-secret", "")
	if err != nil {
		t.Fatal(err)
	}
	if meta.Version != 2 {
		t.Errorf("version: got %d, want 2", meta.Version)
	}
	if meta.ExpiresAt == nil {
		t.Fatal("ExpiresAt is nil after rotation, want it carried forward")
	}
	if !meta.ExpiresAt.Equal(expiresAt) {
		t.Errorf("ExpiresAt: got %v, want %v", meta.ExpiresAt, expiresAt)
	}
	if meta.Metadata["owner"] != "payments-team" {
		t.Errorf("Metadata[owner]: got %q, want %q", meta.Metadata["owner"], "payments-team")
	}
}

func TestRotateNowCreatesRecord(t *testing.T) {
	s := memory.New()
	svc := setupSecretService(t, s)
	seedSecret(t, svc, "api-key", []byte("v1"))

	next := time.Now().UTC().Add(-1 * time.Hour)
	seedPolicy(t, s, "api-key", 1*time.Hour, next)

	mgr := rotation.NewManager(s, svc, rotation.WithAppID(testApp))
	mgr.RegisterRotator("api-key", func(_ context.Context, _ []byte) ([]byte, error) {
		return []byte("v2"), nil
	})

	_ = mgr.RotateNow(bg(), "api-key", "")

	records, err := s.ListRotationRecords(bg(), "api-key", testApp, rotation.ListOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}

	rec := records[0]
	if rec.OldVersion != 1 {
		t.Errorf("old version: got %d, want 1", rec.OldVersion)
	}
	if rec.NewVersion != 2 {
		t.Errorf("new version: got %d, want 2", rec.NewVersion)
	}
	if rec.SecretKey != "api-key" {
		t.Errorf("secret key: got %q, want %q", rec.SecretKey, "api-key")
	}
	if rec.RotatedBy != "rotation-manager" {
		t.Errorf("rotated by: got %q, want %q", rec.RotatedBy, "rotation-manager")
	}
}

func TestRotateNowUpdatesPolicyTimestamps(t *testing.T) {
	s := memory.New()
	svc := setupSecretService(t, s)
	seedSecret(t, svc, "token", []byte("tok"))

	next := time.Now().UTC().Add(-1 * time.Hour)
	seedPolicy(t, s, "token", 6*time.Hour, next)

	mgr := rotation.NewManager(s, svc, rotation.WithAppID(testApp))
	mgr.RegisterRotator("token", func(_ context.Context, _ []byte) ([]byte, error) {
		return []byte("tok2"), nil
	})

	before := time.Now().UTC()
	_ = mgr.RotateNow(bg(), "token", "")
	after := time.Now().UTC()

	policy, err := s.GetRotationPolicy(bg(), "token", testApp)
	if err != nil {
		t.Fatal(err)
	}

	if policy.LastRotatedAt == nil {
		t.Fatal("LastRotatedAt is nil")
	}
	if policy.LastRotatedAt.Before(before) || policy.LastRotatedAt.After(after) {
		t.Errorf("LastRotatedAt out of range: %v", policy.LastRotatedAt)
	}

	if policy.NextRotationAt == nil {
		t.Fatal("NextRotationAt is nil")
	}
	expectedNext := policy.LastRotatedAt.Add(6 * time.Hour)
	if !policy.NextRotationAt.Equal(expectedNext) {
		t.Errorf("NextRotationAt: got %v, want %v", policy.NextRotationAt, expectedNext)
	}
}

func TestRotateNowNoRotator(t *testing.T) {
	s := memory.New()
	svc := setupSecretService(t, s)
	seedSecret(t, svc, "norot", []byte("val"))

	mgr := rotation.NewManager(s, svc, rotation.WithAppID(testApp))

	err := mgr.RotateNow(bg(), "norot", "")
	if err == nil {
		t.Fatal("expected error for unregistered rotator")
	}
}

func TestRotateNowRotatorError(t *testing.T) {
	s := memory.New()
	svc := setupSecretService(t, s)
	seedSecret(t, svc, "fail-key", []byte("val"))

	next := time.Now().UTC().Add(-1 * time.Hour)
	seedPolicy(t, s, "fail-key", 1*time.Hour, next)

	mgr := rotation.NewManager(s, svc, rotation.WithAppID(testApp))
	mgr.RegisterRotator("fail-key", func(_ context.Context, _ []byte) ([]byte, error) {
		return nil, errors.New("external provider down")
	})

	err := mgr.RotateNow(bg(), "fail-key", "")
	if err == nil {
		t.Fatal("expected error when rotator fails")
	}

	// Verify no rotation record was created.
	records, _ := s.ListRotationRecords(bg(), "fail-key", testApp, rotation.ListOpts{})
	if len(records) != 0 {
		t.Errorf("got %d records, want 0 (rotator failed)", len(records))
	}

	// Verify secret value unchanged.
	sec, _ := svc.Get(bg(), "fail-key", "")
	if string(sec.Value) != "val" {
		t.Errorf("value changed to %q, want %q (unchanged)", string(sec.Value), "val")
	}
}

func TestScheduledRotationFires(t *testing.T) {
	s := memory.New()
	svc := setupSecretService(t, s)
	seedSecret(t, svc, "sched-key", []byte("orig"))

	// Set NextRotationAt to the past so it's due immediately.
	past := time.Now().UTC().Add(-1 * time.Minute)
	seedPolicy(t, s, "sched-key", 1*time.Hour, past)

	mgr := rotation.NewManager(s, svc,
		rotation.WithAppID(testApp),
		rotation.WithCheckInterval(50*time.Millisecond),
	)
	mgr.RegisterRotator("sched-key", func(_ context.Context, _ []byte) ([]byte, error) {
		return []byte("rotated"), nil
	})

	_ = mgr.Start(bg())

	// Wait for the check to fire.
	time.Sleep(200 * time.Millisecond)

	_ = mgr.Stop(bg())

	sec, err := svc.Get(bg(), "sched-key", "")
	if err != nil {
		t.Fatal(err)
	}
	if string(sec.Value) != "rotated" {
		t.Errorf("got %q, want %q (scheduled rotation)", string(sec.Value), "rotated")
	}
}

// TestScheduledRotationRunsWhileStarted is the Manager-level proof that
// Start actually runs the rotation loop, not just that Start and Stop
// return without hanging. It polls up to 2s for the secret's version to
// increment rather than sleeping a fixed duration, so it fails cleanly if
// the loop never runs instead of only being fast when it does.
func TestScheduledRotationRunsWhileStarted(t *testing.T) {
	s := memory.New()
	svc := setupSecretService(t, s)
	seedSecret(t, svc, "loop-key", []byte("v1"))

	past := time.Now().UTC().Add(-1 * time.Hour)
	seedPolicy(t, s, "loop-key", 1*time.Hour, past)

	mgr := rotation.NewManager(s, svc,
		rotation.WithAppID(testApp),
		rotation.WithCheckInterval(5*time.Millisecond),
	)
	mgr.RegisterRotator("loop-key", func(_ context.Context, _ []byte) ([]byte, error) {
		return []byte("v2"), nil
	})

	if err := mgr.Start(bg()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mgr.Stop(bg()) }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		sec, err := svc.Get(bg(), "loop-key", "")
		if err != nil {
			t.Fatal(err)
		}
		if sec.Version == 2 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("scheduled rotation did not run within 2s; version is still %d", sec.Version)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestStopCancelsGoroutineCleanly(t *testing.T) {
	s := memory.New()
	svc := setupSecretService(t, s)

	mgr := rotation.NewManager(s, svc,
		rotation.WithAppID(testApp),
		rotation.WithCheckInterval(10*time.Millisecond),
	)

	_ = mgr.Start(bg())

	// Allow some ticks.
	time.Sleep(50 * time.Millisecond)

	err := mgr.Stop(bg())
	if err != nil {
		t.Errorf("Stop returned error: %v", err)
	}

	// Calling Stop again should be safe.
	err = mgr.Stop(bg())
	if err != nil {
		t.Errorf("second Stop returned error: %v", err)
	}
}

func TestMultipleRotationsIncrementsVersions(t *testing.T) {
	s := memory.New()
	svc := setupSecretService(t, s)
	seedSecret(t, svc, "multi-rot", []byte("v1"))

	next := time.Now().UTC().Add(-1 * time.Hour)
	seedPolicy(t, s, "multi-rot", 1*time.Hour, next)

	mgr := rotation.NewManager(s, svc, rotation.WithAppID(testApp))
	counter := 1
	mgr.RegisterRotator("multi-rot", func(_ context.Context, _ []byte) ([]byte, error) {
		counter++
		return []byte("v" + string(rune('0'+counter))), nil
	})

	_ = mgr.RotateNow(bg(), "multi-rot", "")
	_ = mgr.RotateNow(bg(), "multi-rot", "")

	sec, _ := svc.Get(bg(), "multi-rot", "")
	if sec.Version != 3 {
		t.Errorf("version: got %d, want 3", sec.Version)
	}

	records, _ := s.ListRotationRecords(bg(), "multi-rot", testApp, rotation.ListOpts{})
	if len(records) != 2 {
		t.Errorf("records: got %d, want 2", len(records))
	}
}

func TestRotatorKeysListsRegisteredRotatorsSorted(t *testing.T) {
	s := memory.New()
	m := rotation.NewManager(s, nil)

	if got := m.RotatorKeys(); len(got) != 0 {
		t.Errorf("with nothing registered: got %v, want empty", got)
	}

	noop := func(_ context.Context, cur []byte) ([]byte, error) { return cur, nil }
	m.RegisterRotator("zeta", noop)
	m.RegisterRotator("alpha", noop)

	got := m.RotatorKeys()
	want := []string{"alpha", "zeta"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v (sorted)", got, want)
		}
	}
}
