package rotation_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/xraph/vault"
	"github.com/xraph/vault/audit"
	"github.com/xraph/vault/rotation"
	"github.com/xraph/vault/store/memory"
)

type rotateCall struct {
	key, appID string
	err        error
}

// A successful rotation calls the hook once, with a nil error, after the
// rotation record exists.
func TestWithOnRotateSuccessCallsHookOnceAfterRecord(t *testing.T) {
	s := memory.New()
	svc := setupSecretService(t, s)
	seedSecret(t, svc, "k", []byte("v1"))

	var calls []rotateCall
	var recordsAtHook int
	mgr := rotation.NewManager(s, svc, rotation.WithAppID(testApp),
		rotation.WithOnRotate(func(ctx context.Context, key, appID string, err error) {
			calls = append(calls, rotateCall{key, appID, err})
			recs, lErr := s.ListRotationRecords(ctx, key, appID, rotation.ListOpts{Limit: 10})
			if lErr != nil {
				t.Errorf("list records: %v", lErr)
			}
			recordsAtHook = len(recs)
		}))
	mgr.RegisterRotator("k", func(context.Context, []byte) ([]byte, error) { return []byte("v2"), nil })

	if err := mgr.RotateNow(bg(), "k", ""); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 {
		t.Fatalf("hook calls = %d, want 1", len(calls))
	}
	if calls[0].err != nil || calls[0].key != "k" || calls[0].appID != testApp {
		t.Errorf("hook call = %+v", calls[0])
	}
	if recordsAtHook != 1 {
		t.Errorf("records visible to the hook = %d, want 1 (hook must run after the record is written)", recordsAtHook)
	}
}

// Every failure past the rotator lookup reaches the hook with the error.
func TestWithOnRotateFailuresCallHook(t *testing.T) {
	boom := errors.New("boom")
	cases := []struct {
		name string
		run  func(mgr *rotation.Manager) error
	}{
		{"no rotator", func(mgr *rotation.Manager) error {
			return mgr.RotateNow(bg(), "missing", "")
		}},
		{"rotator error", func(mgr *rotation.Manager) error {
			mgr.RegisterRotator("k", func(context.Context, []byte) ([]byte, error) { return nil, boom })
			return mgr.RotateNow(bg(), "k", "")
		}},
		{"secret gone", func(mgr *rotation.Manager) error {
			mgr.RegisterRotator("nosecret", func(context.Context, []byte) ([]byte, error) { return []byte("x"), nil })
			return mgr.RotateNow(bg(), "nosecret", "")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := memory.New()
			svc := setupSecretService(t, s)
			seedSecret(t, svc, "k", []byte("v1"))
			var calls []rotateCall
			mgr := rotation.NewManager(s, svc, rotation.WithAppID(testApp),
				rotation.WithOnRotate(func(_ context.Context, key, appID string, err error) {
					calls = append(calls, rotateCall{key, appID, err})
				}))
			got := tc.run(mgr)
			if got == nil {
				t.Fatal("RotateNow succeeded, want an error")
			}
			if len(calls) != 1 {
				t.Fatalf("hook calls = %d, want 1", len(calls))
			}
			if calls[0].err == nil || calls[0].err.Error() != got.Error() {
				t.Errorf("hook err = %v, want %v", calls[0].err, got)
			}
		})
	}
}

func failureRows(t *testing.T, v *vault.Vault) []*audit.Entry {
	t.Helper()
	rows, err := v.Store().ListAudit(bg(), testApp, audit.ListOpts{Limit: 50, Action: "secret.rotated", Outcome: "failure"})
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func newAuditedVault(t *testing.T) *vault.Vault {
	t.Helper()
	v, err := vault.New(vault.WithStore(memory.New()), vault.WithAppID(testApp), vault.WithEncryptionKey([]byte(strings.Repeat("k", 32))))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// A scheduled rotation whose rotator fails leaves a failure row an operator
// can find, with the error text and no user.
func TestScheduledRotationFailureWritesFailureRowWithNoUser(t *testing.T) {
	v := newAuditedVault(t)
	if _, err := v.Secrets().Set(bg(), "sched", []byte("v1"), testApp); err != nil {
		t.Fatal(err)
	}
	past := time.Now().UTC().Add(-time.Hour)
	if err := v.Store().SaveRotationPolicy(bg(), &rotation.Policy{
		Entity: vault.NewEntity(), SecretKey: "sched", AppID: testApp,
		Interval: time.Hour, Enabled: true, NextRotationAt: &past,
	}); err != nil {
		t.Fatal(err)
	}
	v.Rotation().RegisterRotator("sched", func(context.Context, []byte) ([]byte, error) {
		return nil, errors.New("upstream said no")
	})

	v.Rotation().CheckDuePoliciesForTest(bg())

	rows := failureRows(t, v)
	if len(rows) != 1 {
		t.Fatalf("failure rows = %d, want 1", len(rows))
	}
	r := rows[0]
	if r.Key != "sched" || r.Resource != "secret" || r.AppID != testApp {
		t.Errorf("row = %+v", r)
	}
	if r.UserID != "" {
		t.Errorf("UserID = %q, want empty for a scheduled rotation", r.UserID)
	}
	if msg, _ := r.Metadata["error"].(string); !strings.Contains(msg, "upstream said no") {
		t.Errorf("metadata error = %v, want the rotator's error text", r.Metadata)
	}
}

// A manual rotation with no rotator registered is still an attempt.
func TestNoRotatorRotateNowWritesFailureRow(t *testing.T) {
	v := newAuditedVault(t)
	if _, err := v.Secrets().Set(bg(), "norot", []byte("v1"), testApp); err != nil {
		t.Fatal(err)
	}
	if err := v.Rotation().RotateNow(bg(), "norot", testApp); err == nil {
		t.Fatal("want an error")
	}
	rows := failureRows(t, v)
	if len(rows) != 1 || rows[0].Key != "norot" {
		t.Fatalf("failure rows = %+v, want one for norot", rows)
	}
}

// A successful rotation writes secret.rotated success.
func TestSuccessfulRotationWritesRotatedRow(t *testing.T) {
	v := newAuditedVault(t)
	if _, err := v.Secrets().Set(bg(), "ok", []byte("v1"), testApp); err != nil {
		t.Fatal(err)
	}
	v.Rotation().RegisterRotator("ok", func(context.Context, []byte) ([]byte, error) { return []byte("v2"), nil })
	if err := v.Rotation().RotateNow(bg(), "ok", testApp); err != nil {
		t.Fatal(err)
	}
	rows, err := v.Store().ListAudit(bg(), testApp, audit.ListOpts{Limit: 50, Action: "secret.rotated", Outcome: "success"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Key != "ok" || rows[0].Resource != "secret" {
		t.Fatalf("rows = %+v", rows)
	}
	if len(failureRows(t, v)) != 0 {
		t.Error("a successful rotation wrote a failure row")
	}
}
