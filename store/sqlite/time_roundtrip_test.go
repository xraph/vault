package sqlite_test

import (
	"context"
	"testing"
	"time"

	"github.com/xraph/vault/audit"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/rotation"
	"github.com/xraph/vault/secret"
)

// roundTripTimes are the caller-supplied timestamp shapes the store has to
// read back. modernc/sqlite writes a time.Time argument with t.String()
// unless the DSN sets _time_format, and the store doesn't own the DSN. That
// string carries a " m=+..." suffix when the value still has a monotonic
// clock reading, and a "+0200 +0200" zone when the offset has no name.
// Grove's scanner can parse neither, so the row becomes unreadable.
func roundTripTimes() map[string]time.Time {
	return map[string]time.Time{
		"monotonic":   time.Now().Add(24 * time.Hour),
		"non-UTC":     time.Date(2031, 3, 4, 5, 6, 7, 0, time.FixedZone("", 2*60*60)),
		"named local": time.Now().Add(48 * time.Hour).Round(0).In(time.FixedZone("CDT", -5*60*60)),
	}
}

func TestSecretExpiresAtRoundTrips(t *testing.T) {
	for name, ts := range roundTripTimes() {
		t.Run(name, func(t *testing.T) {
			s := testStore(t)
			ctx := context.Background()

			sec := &secret.Secret{
				ID: id.NewSecretID(), Key: "db-password", AppID: "app1",
				EncryptedValue: []byte("ct"), ExpiresAt: &ts,
			}
			if err := s.SetSecret(ctx, sec); err != nil {
				t.Fatalf("SetSecret: %v", err)
			}

			got, err := s.GetSecret(ctx, "db-password", "app1", "")
			if err != nil {
				t.Fatalf("GetSecret: %v", err)
			}
			if got.ExpiresAt == nil || !got.ExpiresAt.Equal(ts) {
				t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, ts)
			}

			metas, err := s.ListSecrets(ctx, "app1", secret.ListOpts{})
			if err != nil {
				t.Fatalf("ListSecrets: %v", err)
			}
			if len(metas) != 1 || metas[0].ExpiresAt == nil || !metas[0].ExpiresAt.Equal(ts) {
				t.Errorf("ListSecrets expiry did not round-trip: %+v", metas)
			}
		})
	}
}

func TestRotationPolicyTimesRoundTrip(t *testing.T) {
	for name, ts := range roundTripTimes() {
		t.Run(name, func(t *testing.T) {
			s := testStore(t)
			ctx := context.Background()

			last := ts.Add(-time.Hour)
			p := &rotation.Policy{
				ID: id.NewRotationID(), SecretKey: "db-password", AppID: "app1",
				Interval: time.Hour, Enabled: true,
				LastRotatedAt: &last, NextRotationAt: &ts,
			}
			if err := s.SaveRotationPolicy(ctx, p); err != nil {
				t.Fatalf("SaveRotationPolicy: %v", err)
			}

			got, err := s.GetRotationPolicy(ctx, "db-password", "app1")
			if err != nil {
				t.Fatalf("GetRotationPolicy: %v", err)
			}
			if got.LastRotatedAt == nil || !got.LastRotatedAt.Equal(last) {
				t.Errorf("LastRotatedAt = %v, want %v", got.LastRotatedAt, last)
			}
			if got.NextRotationAt == nil || !got.NextRotationAt.Equal(ts) {
				t.Errorf("NextRotationAt = %v, want %v", got.NextRotationAt, ts)
			}
		})
	}
}

func TestRotationRecordTimeRoundTrips(t *testing.T) {
	for name, ts := range roundTripTimes() {
		t.Run(name, func(t *testing.T) {
			s := testStore(t)
			ctx := context.Background()

			r := &rotation.Record{
				ID: id.NewRotationID(), SecretKey: "db-password", AppID: "app1",
				OldVersion: 1, NewVersion: 2, RotatedBy: "test", RotatedAt: ts,
			}
			if err := s.RecordRotation(ctx, r); err != nil {
				t.Fatalf("RecordRotation: %v", err)
			}

			got, err := s.ListRotationRecords(ctx, "db-password", "app1", rotation.ListOpts{})
			if err != nil {
				t.Fatalf("ListRotationRecords: %v", err)
			}
			if len(got) != 1 || !got[0].RotatedAt.Equal(ts) {
				t.Errorf("RotatedAt did not round-trip: %+v", got)
			}
		})
	}
}

func TestAuditTimeRoundTrips(t *testing.T) {
	for name, ts := range roundTripTimes() {
		t.Run(name, func(t *testing.T) {
			s := testStore(t)
			ctx := context.Background()

			e := &audit.Entry{
				ID: id.NewAuditID(), Action: "secret.set", Resource: "secret",
				Key: "db-password", AppID: "app1", Outcome: "success", CreatedAt: ts,
			}
			if err := s.RecordAudit(ctx, e); err != nil {
				t.Fatalf("RecordAudit: %v", err)
			}

			got, err := s.ListAudit(ctx, "app1", audit.ListOpts{})
			if err != nil {
				t.Fatalf("ListAudit: %v", err)
			}
			if len(got) != 1 || !got[0].CreatedAt.Equal(ts) {
				t.Errorf("CreatedAt did not round-trip: %+v", got)
			}
		})
	}
}
