package storetest

import (
	"slices"
	"testing"
	"time"

	"github.com/xraph/vault/core"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/secret"
)

// ExpiryFactory returns a fresh, empty secret store.
type ExpiryFactory func(t *testing.T) secret.Store

func putExpiring(t *testing.T, s secret.Store, app, key string, at *time.Time) {
	t.Helper()
	sec := &secret.Secret{
		Entity: core.NewEntity(), ID: id.NewSecretID(),
		Key: key, AppID: app, EncryptedValue: []byte("bytes-" + key), ExpiresAt: at,
	}
	if err := s.SetSecret(t.Context(), sec); err != nil {
		t.Fatalf("SetSecret(%s): %v", key, err)
	}
}

func metaKeys(ms []*secret.Meta) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = m.Key
	}
	return out
}

// RunSecretExpiry runs the expiry-filter conformance tests against the store
// newStore builds. One store is seeded once and every case reads from it.
func RunSecretExpiry(t *testing.T, newStore ExpiryFactory) {
	t.Helper()

	// Whole seconds: every backend keeps at least that much of a timestamp, so
	// "exactly at now" is exactly representable everywhere.
	now := time.Now().UTC().Truncate(time.Second)
	day := 24 * time.Hour
	at := func(d time.Duration) *time.Time { v := now.Add(d); return &v }

	s := newStore(t)
	// zone is now+5d written with a numeric offset and no zone name, the shape
	// that breaks a store comparing times as text.
	zone := now.Add(5 * day).In(time.FixedZone("", 2*3600))
	for _, seed := range []struct {
		key string
		at  *time.Time
	}{
		{"none", nil},
		{"past", at(-time.Hour)},
		{"now", at(0)},
		{"d03", at(3 * day)},
		{"zone5", &zone},
		{"tie-b", at(10 * day)},
		{"tie-a", at(10 * day)},
		{"d20", at(20 * day)},
		{"edge30", at(30 * day)},
		{"d60", at(60 * day)},
	} {
		putExpiring(t, s, "app", seed.key, seed.at)
	}
	// Another app's secret that would match every bound.
	putExpiring(t, s, "other", "other-d03", at(3*day))

	allByKey := []string{"d03", "d20", "d60", "edge30", "none", "now", "past", "tie-a", "tie-b", "zone5"}

	cases := []struct {
		name string
		opts secret.ListOpts
		want []string
	}{
		{"no filter lists everything by key", secret.ListOpts{}, allByKey},
		{"expired is before-or-at now, oldest first", secret.ListOpts{ExpiresBefore: &now}, []string{"past", "now"}},
		{"expiring in 7 days excludes the one at now", secret.ListOpts{ExpiresAfter: &now, ExpiresBefore: at(7 * day)},
			[]string{"d03", "zone5"}},
		{"expiring in 30 days includes the one at exactly 30 days, ties by key",
			secret.ListOpts{ExpiresAfter: &now, ExpiresBefore: at(30 * day)},
			[]string{"d03", "zone5", "tie-a", "tie-b", "d20", "edge30"}},
		{"an after bound alone drops the expired and the unset", secret.ListOpts{ExpiresAfter: &now},
			[]string{"d03", "zone5", "tie-a", "tie-b", "d20", "edge30", "d60"}},
		{"a bound with nothing in it", secret.ListOpts{ExpiresAfter: at(90 * day)}, []string{}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := s.ListSecrets(t.Context(), "app", c.opts)
			if err != nil {
				t.Fatalf("ListSecrets: %v", err)
			}
			if keys := metaKeys(got); !slices.Equal(keys, c.want) {
				t.Errorf("ListSecrets keys = %v, want %v", keys, c.want)
			}
			n, err := s.CountSecretsMatching(t.Context(), "app", c.opts)
			if err != nil {
				t.Fatalf("CountSecretsMatching: %v", err)
			}
			if n != int64(len(c.want)) {
				t.Errorf("CountSecretsMatching = %d, want %d (the unpaged list)", n, len(c.want))
			}
			if slices.Contains(metaKeys(got), "none") && c.opts.HasExpiryBound() {
				t.Error("a secret with no expiry appeared under an expiry bound")
			}
		})
	}

	t.Run("paging a bounded list returns the right slice and the full count", func(t *testing.T) {
		opts := secret.ListOpts{ExpiresAfter: &now, ExpiresBefore: at(30 * day), Limit: 2, Offset: 1}
		got, err := s.ListSecrets(t.Context(), "app", opts)
		if err != nil {
			t.Fatal(err)
		}
		if keys := metaKeys(got); !slices.Equal(keys, []string{"zone5", "tie-a"}) {
			t.Errorf("page = %v, want [zone5 tie-a]", keys)
		}
		n, err := s.CountSecretsMatching(t.Context(), "app", opts)
		if err != nil {
			t.Fatal(err)
		}
		if n != 6 {
			t.Errorf("count = %d, want 6: paging must not change the total", n)
		}
	})

	t.Run("paging an unbounded list", func(t *testing.T) {
		got, err := s.ListSecrets(t.Context(), "app", secret.ListOpts{Limit: 3, Offset: 2})
		if err != nil {
			t.Fatal(err)
		}
		if keys := metaKeys(got); !slices.Equal(keys, []string{"d60", "edge30", "none"}) {
			t.Errorf("page = %v, want [d60 edge30 none]", keys)
		}
	})

	t.Run("the offset-written secret compares by instant", func(t *testing.T) {
		// zone5 is now+5d. A bound one second either side of it must tell
		// them apart, whatever offset the row was written with.
		// The bounds carry the same nameless offset, so binding them is under
		// test as well.
		just := now.Add(5 * day).In(zone.Location())
		before := just.Add(-time.Second)
		for _, c := range []struct {
			name string
			opts secret.ListOpts
			want bool
		}{
			{"after a second earlier", secret.ListOpts{ExpiresAfter: &before, ExpiresBefore: &just}, true},
			{"after the instant itself", secret.ListOpts{ExpiresAfter: &just, ExpiresBefore: at(6 * day)}, false},
			{"before the instant", secret.ListOpts{ExpiresAfter: &now, ExpiresBefore: &before}, false},
		} {
			got, err := s.ListSecrets(t.Context(), "app", c.opts)
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			if has := slices.Contains(metaKeys(got), "zone5"); has != c.want {
				t.Errorf("%s: zone5 listed = %v, want %v (got %v)", c.name, has, c.want, metaKeys(got))
			}
		}
	})

	t.Run("another app is never counted or listed", func(t *testing.T) {
		opts := secret.ListOpts{ExpiresAfter: &now, ExpiresBefore: at(7 * day)}
		got, err := s.ListSecrets(t.Context(), "other", opts)
		if err != nil {
			t.Fatal(err)
		}
		if keys := metaKeys(got); !slices.Equal(keys, []string{"other-d03"}) {
			t.Errorf("other app keys = %v, want [other-d03]", keys)
		}
		n, err := s.CountSecretsMatching(t.Context(), "other", opts)
		if err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Errorf("other app count = %d, want 1", n)
		}
	})

	t.Run("removing the expiry takes a secret out of every bound", func(t *testing.T) {
		putExpiring(t, s, "app", "d03", nil)
		opts := secret.ListOpts{ExpiresAfter: &now, ExpiresBefore: at(7 * day)}
		got, err := s.ListSecrets(t.Context(), "app", opts)
		if err != nil {
			t.Fatal(err)
		}
		if keys := metaKeys(got); !slices.Equal(keys, []string{"zone5"}) {
			t.Errorf("keys = %v, want [zone5]", keys)
		}
	})
}
