package contract

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"

	"github.com/xraph/vault"
	"github.com/xraph/vault/audit"
	"github.com/xraph/vault/core"
	"github.com/xraph/vault/flag"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/rotation"
	"github.com/xraph/vault/store"
	"github.com/xraph/vault/store/memory"
)

func seedPolicy(t *testing.T, v *vault.Vault, key string, enabled bool, next *time.Time) {
	t.Helper()
	if err := v.Store().SaveRotationPolicy(context.Background(), &rotation.Policy{
		Entity: core.NewEntity(), ID: id.NewRotationID(), SecretKey: key, AppID: testAppID,
		Interval: time.Hour, Enabled: enabled, NextRotationAt: next,
	}); err != nil {
		t.Fatalf("seed policy %q: %v", key, err)
	}
}

func noopRotator(_ context.Context, cur []byte) ([]byte, error) { return cur, nil }

// seedOverviewVault builds a vault where every stat has a distinct,
// non-zero answer:
//
//	secrets 4 (3 encrypted, 1 written by a vault with no key)
//	flags 2, config entries 3, config overrides 2
//	policies 4: ok (enabled, rotatable, due later), overdue (enabled,
//	rotatable, due before now), bare (enabled, no rotator, due before now),
//	off (disabled, rotatable, due before now)
//	secret.rotated failures: one 1h old, one 30h old; a success 1h old and
//	a flag failure 1h old, neither of which counts
func seedOverviewVault(t *testing.T) *vault.Vault {
	t.Helper()
	v, st := newTestVault(t)
	ctx := context.Background()
	for _, k := range []string{"e1", "e2", "e3"} {
		if _, err := v.Secrets().Set(ctx, k, []byte("v"), testAppID); err != nil {
			t.Fatal(err)
		}
	}
	plain, err := vault.New(vault.WithStore(st), vault.WithAppID(testAppID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plain.Secrets().Set(ctx, "clear", []byte("v"), testAppID); err != nil {
		t.Fatal(err)
	}

	seedFlag(t, v, "f1", flag.TypeBool, false, true)
	seedFlag(t, v, "f2", flag.TypeBool, false, false)
	seedConfig(t, v, "c1", "string", "a")
	seedConfig(t, v, "c2", "string", "b")
	seedConfig(t, v, "c3", "string", "c")
	seedOverride(t, v, "c1", "acme", "x")
	seedOverride(t, v, "c2", "acme", "y")

	now := time.Now().UTC()
	past, future := now.Add(-time.Hour), now.Add(time.Hour)
	seedPolicy(t, v, "e1", true, &future)
	seedPolicy(t, v, "e2", true, &past)
	seedPolicy(t, v, "e3", true, &past)
	seedPolicy(t, v, "clear", false, &past)
	v.Rotation().RegisterRotator("e1", noopRotator)
	v.Rotation().RegisterRotator("e2", noopRotator)
	v.Rotation().RegisterRotator("clear", noopRotator)

	seedAuditRows(t, v, []auditSeed{
		{action: "secret.rotated", resource: "secret", key: "e2", outcome: "failure", errText: "boom", age: time.Hour},
		{action: "secret.rotated", resource: "secret", key: "e2", outcome: "failure", errText: "old boom", age: 30 * time.Hour},
		{action: "secret.rotated", resource: "secret", key: "e1", age: time.Hour},
		{action: "flag.created", resource: "flag", key: "f1", outcome: "failure", age: time.Hour},
	})
	return v
}

func TestOverviewStats_EveryStatOnASeededVault(t *testing.T) {
	v := seedOverviewVault(t)
	out, err := overviewStatsHandler(Deps{Vault: v})(context.Background(), overviewStatsRequest{}, dashcontract.Principal{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][2]int64{
		"secrets":                {out.Secrets, 4},
		"unencryptedSecrets":     {out.UnencryptedSecrets, 1},
		"flags":                  {out.Flags, 2},
		"configEntries":          {out.ConfigEntries, 3},
		"configOverrides":        {out.ConfigOverrides, 2},
		"rotationPolicies":       {out.RotationPolicies, 4},
		"rotationEnabled":        {out.RotationEnabled, 3},
		"rotationOverdue":        {out.RotationOverdue, 1},
		"rotationWithoutRotator": {out.RotationWithoutRotator, 1},
		"rotationFailures24h":    {out.RotationFailures24h, 1},
	}
	for name, p := range want {
		if p[0] != p[1] {
			t.Errorf("%s = %d, want %d", name, p[0], p[1])
		}
	}
	if !out.EncryptionEnabled || out.EncryptionAlgorithm != "AES-256-GCM" {
		t.Errorf("encryption = %v %q, want true AES-256-GCM", out.EncryptionEnabled, out.EncryptionAlgorithm)
	}
}

// A vault with no key says so, and an empty one answers zeros and an empty
// (not null) activity list.
func TestOverviewStats_NoKeyAndEmpty(t *testing.T) {
	v, err := vault.New(vault.WithStore(memory.New()), vault.WithAppID(testAppID))
	if err != nil {
		t.Fatal(err)
	}
	out, err := overviewStatsHandler(Deps{Vault: v})(context.Background(), overviewStatsRequest{}, dashcontract.Principal{})
	if err != nil {
		t.Fatal(err)
	}
	if out.EncryptionEnabled || out.EncryptionAlgorithm != "" {
		t.Errorf("encryption = %v %q, want false and empty", out.EncryptionEnabled, out.EncryptionAlgorithm)
	}
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"recentActivity":[]`) || !strings.Contains(string(raw), `"encryptionAlgorithm":""`) {
		t.Errorf("wire = %s", raw)
	}
	if out.Secrets != 0 || out.RotationPolicies != 0 || out.RotationFailures24h != 0 {
		t.Errorf("empty vault stats = %+v", out)
	}

	// Plaintext secrets on a vault with no key are all unencrypted.
	if _, setErr := v.Secrets().Set(context.Background(), "p", []byte("v"), testAppID); setErr != nil {
		t.Fatal(setErr)
	}
	out, err = overviewStatsHandler(Deps{Vault: v})(context.Background(), overviewStatsRequest{}, dashcontract.Principal{})
	if err != nil || out.Secrets != 1 || out.UnencryptedSecrets != 1 {
		t.Errorf("secrets %d unencrypted %d, err %v", out.Secrets, out.UnencryptedSecrets, err)
	}
}

// A policy due exactly now, or with no due time, is not overdue; a disabled
// or rotator-less policy is not overdue either.
func TestOverviewStats_OverdueNeedsEnabledRotatableAndPastDue(t *testing.T) {
	v, _ := newTestVault(t)
	ctx := context.Background()
	for _, k := range []string{"a", "b", "c"} {
		if _, err := v.Secrets().Set(ctx, k, []byte("v"), testAppID); err != nil {
			t.Fatal(err)
		}
		v.Rotation().RegisterRotator(k, noopRotator)
	}
	past := time.Now().UTC().Add(-time.Minute)
	future := time.Now().UTC().Add(time.Minute)
	seedPolicy(t, v, "a", true, nil)
	seedPolicy(t, v, "b", true, &future)
	seedPolicy(t, v, "c", true, &past)
	out, err := overviewStatsHandler(Deps{Vault: v})(ctx, overviewStatsRequest{}, dashcontract.Principal{})
	if err != nil {
		t.Fatal(err)
	}
	if out.RotationOverdue != 1 || out.RotationWithoutRotator != 0 || out.RotationEnabled != 3 {
		t.Errorf("overdue %d withoutRotator %d enabled %d, want 1 0 3", out.RotationOverdue, out.RotationWithoutRotator, out.RotationEnabled)
	}
}

// Recent activity is the ten newest rows, reads excluded, newest first.
func TestOverviewStats_RecentActivityIsTenNewestWithoutReads(t *testing.T) {
	v, _ := newTestVault(t)
	rows := []auditSeed{{action: "secret.get", resource: "secret", key: "read", age: 0}}
	for i := 1; i <= 12; i++ {
		rows = append(rows, auditSeed{action: "config.set", resource: "config", key: string(rune('a' + i)), age: time.Duration(i) * time.Minute})
	}
	seedAuditRows(t, v, rows)
	out, err := overviewStatsHandler(Deps{Vault: v})(context.Background(), overviewStatsRequest{}, dashcontract.Principal{})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.RecentActivity) != 10 {
		t.Fatalf("recent activity = %d rows, want 10", len(out.RecentActivity))
	}
	for i, e := range out.RecentActivity {
		if e.Action == "secret.get" {
			t.Errorf("row %d is a read", i)
		}
		if e.Key != string(rune('a'+i+1)) {
			t.Errorf("row %d key = %q, want %q (newest first)", i, e.Key, string(rune('a'+i+1)))
		}
	}
}

// failingStore fails the named store methods and passes the rest through.
type failingStore struct {
	store.Store
	fail string
}

func (s failingStore) boom(name string) error {
	if s.fail == name {
		return errStoreBoom
	}
	return nil
}

func (s failingStore) CountSecrets(ctx context.Context, appID string) (int64, error) {
	if err := s.boom("CountSecrets"); err != nil {
		return 0, err
	}
	return s.Store.CountSecrets(ctx, appID)
}

func (s failingStore) CountSecretsUnencrypted(ctx context.Context, appID string) (int64, error) {
	if err := s.boom("CountSecretsUnencrypted"); err != nil {
		return 0, err
	}
	return s.Store.CountSecretsUnencrypted(ctx, appID)
}

func (s failingStore) CountFlagDefinitions(ctx context.Context, appID string) (int64, error) {
	if err := s.boom("CountFlagDefinitions"); err != nil {
		return 0, err
	}
	return s.Store.CountFlagDefinitions(ctx, appID)
}

func (s failingStore) CountConfig(ctx context.Context, appID string) (int64, error) {
	if err := s.boom("CountConfig"); err != nil {
		return 0, err
	}
	return s.Store.CountConfig(ctx, appID)
}

func (s failingStore) CountOverrides(ctx context.Context, appID string) (int64, error) {
	if err := s.boom("CountOverrides"); err != nil {
		return 0, err
	}
	return s.Store.CountOverrides(ctx, appID)
}

func (s failingStore) ListRotationPolicies(ctx context.Context, appID string) ([]*rotation.Policy, error) {
	if err := s.boom("ListRotationPolicies"); err != nil {
		return nil, err
	}
	return s.Store.ListRotationPolicies(ctx, appID)
}

func (s failingStore) CountAuditMatching(ctx context.Context, appID string, opts audit.ListOpts) (int64, error) {
	if err := s.boom("CountAuditMatching"); err != nil {
		return 0, err
	}
	return s.Store.CountAuditMatching(ctx, appID, opts)
}

func (s failingStore) ListAudit(ctx context.Context, appID string, opts audit.ListOpts) ([]*audit.Entry, error) {
	if err := s.boom("ListAudit"); err != nil {
		return nil, err
	}
	return s.Store.ListAudit(ctx, appID, opts)
}

// Any one failing read fails the whole query: no 0 stands in for an error.
func TestOverviewStats_AnyStoreErrorFailsTheQuery(t *testing.T) {
	for _, fail := range []string{
		"CountSecrets", "CountSecretsUnencrypted", "CountFlagDefinitions", "CountConfig", "CountOverrides",
		"ListRotationPolicies", "CountAuditMatching", "ListAudit",
	} {
		t.Run(fail, func(t *testing.T) {
			v, err := vault.New(vault.WithStore(failingStore{Store: memory.New(), fail: fail}), vault.WithAppID(testAppID), vault.WithEncryptionKey(testEncryptionKey))
			if err != nil {
				t.Fatal(err)
			}
			out, err := overviewStatsHandler(Deps{Vault: v})(context.Background(), overviewStatsRequest{}, dashcontract.Principal{})
			if codeOf(err) != dashcontract.CodeInternal {
				t.Errorf("code = %q (%v), want INTERNAL", codeOf(err), err)
			}
			if out.RecentActivity != nil || out.Secrets != 0 {
				t.Errorf("a failed query returned data: %+v", out)
			}
		})
	}
}
