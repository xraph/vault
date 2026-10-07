// Package storetest holds store conformance tests shared by every backend, so
// the memory, SQLite, Postgres and MongoDB stores are held to one behavior.
package storetest

import (
	"slices"
	"testing"

	"github.com/xraph/vault/core"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/secret"
)

// Alg is the algorithm name the version tests record for an encrypted row.
const Alg = secret.EncryptionAlgorithm

// VersionEncryptionFactory returns a fresh, empty store plus a legacy
// function. legacy rewrites one version row the way a row written before the
// encryption_alg column looks: its algorithm unset (NULL or absent), not "".
type VersionEncryptionFactory func(t *testing.T) (s secret.Store, legacy func(key, appID string, version int64))

func put(t *testing.T, s secret.Store, app, key, alg string) {
	t.Helper()
	sec := &secret.Secret{
		Entity: core.NewEntity(), ID: id.NewSecretID(),
		Key: key, AppID: app, EncryptedValue: []byte("bytes-" + key), EncryptionAlg: alg,
	}
	if err := s.SetSecret(t.Context(), sec); err != nil {
		t.Fatalf("SetSecret(%s, %q): %v", key, alg, err)
	}
}

func versionsOf(t *testing.T, s secret.Store) []*secret.Version {
	t.Helper()
	vs, err := s.ListSecretVersions(t.Context(), "k", "app")
	if err != nil {
		t.Fatalf("ListSecretVersions: %v", err)
	}
	return vs
}

func algOf(v *secret.Version) string {
	if v.EncryptionAlg == nil {
		return "<nil>"
	}
	return "\"" + *v.EncryptionAlg + "\""
}

func ids(vs []*secret.Version) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = v.ID.String()
	}
	return out
}

// RunVersionEncryption runs the version-encryption conformance tests against
// the store newStore builds.
func RunVersionEncryption(t *testing.T, newStore VersionEncryptionFactory) {
	t.Helper()

	t.Run("SetSecretRecordsTheSecretsAlgorithm", func(t *testing.T) {
		for _, alg := range []string{Alg, ""} {
			s, _ := newStore(t)
			put(t, s, "app", "k", alg)
			vs := versionsOf(t, s)
			if len(vs) != 1 {
				t.Fatalf("alg %q: got %d versions, want 1", alg, len(vs))
			}
			if vs[0].EncryptionAlg == nil || *vs[0].EncryptionAlg != alg {
				t.Errorf("alg %q: version records %s", alg, algOf(vs[0]))
			}
		}
	})

	t.Run("GetSecretVersionReturnsTheVersionsOwnAlgorithm", func(t *testing.T) {
		s, _ := newStore(t)
		put(t, s, "app", "k", "")
		put(t, s, "app", "k", Alg)

		v1, err := s.GetSecretVersion(t.Context(), "k", "app", 1)
		if err != nil {
			t.Fatal(err)
		}
		if v1.EncryptionAlg != "" {
			t.Errorf("v1 alg = %q, want \"\" (the current row says %q)", v1.EncryptionAlg, Alg)
		}
		v2, err := s.GetSecretVersion(t.Context(), "k", "app", 2)
		if err != nil {
			t.Fatal(err)
		}
		if v2.EncryptionAlg != Alg {
			t.Errorf("v2 alg = %q, want %q", v2.EncryptionAlg, Alg)
		}

		// And the other direction: an encrypted v1 under a current row that
		// was written with no key.
		put(t, s, "app", "j", Alg)
		put(t, s, "app", "j", "")
		j1, err := s.GetSecretVersion(t.Context(), "j", "app", 1)
		if err != nil {
			t.Fatal(err)
		}
		if j1.EncryptionAlg != Alg {
			t.Errorf("j v1 alg = %q, want %q", j1.EncryptionAlg, Alg)
		}
	})

	t.Run("AnUnrecordedVersionReadsAsTheCurrentRow", func(t *testing.T) {
		s, legacy := newStore(t)
		put(t, s, "app", "k", "")
		put(t, s, "app", "k", Alg)
		legacy("k", "app", 1)

		vs := versionsOf(t, s)
		if vs[0].EncryptionAlg != nil {
			t.Fatalf("legacy v1 records %s, want <nil>", algOf(vs[0]))
		}
		got, err := s.GetSecretVersion(t.Context(), "k", "app", 1)
		if err != nil {
			t.Fatal(err)
		}
		if got.EncryptionAlg != Alg {
			t.Errorf("legacy v1 alg = %q, want the current row's %q", got.EncryptionAlg, Alg)
		}
	})

	t.Run("ListUnrecordedVersions", func(t *testing.T) {
		s, legacy := newStore(t)
		got, err := s.ListUnrecordedVersions(t.Context(), "app", "", 10)
		if err != nil {
			t.Fatal(err)
		}
		if got == nil || len(got) != 0 {
			t.Fatalf("empty store: got %v, want a non-nil empty slice", got)
		}

		for _, k := range []string{"a", "b", "c", "d"} {
			put(t, s, "app", k, Alg)
		}
		put(t, s, "other", "z", Alg)
		legacy("a", "app", 1)
		legacy("b", "app", 1)
		legacy("d", "app", 1)
		legacy("z", "other", 1)

		all, err := s.ListUnrecordedVersions(t.Context(), "app", "", 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(all) != 3 {
			t.Fatalf("got %d unrecorded, want 3 (c is recorded, z is another app)", len(all))
		}
		for _, v := range all {
			if v.EncryptionAlg != nil {
				t.Errorf("version %s is returned but records %s", v.ID, algOf(v))
			}
			if v.AppID != "app" {
				t.Errorf("version %s belongs to %q", v.ID, v.AppID)
			}
			if string(v.EncryptedValue) != "bytes-"+v.SecretKey {
				t.Errorf("version %s lost its bytes: %q", v.ID, v.EncryptedValue)
			}
		}
		if !slices.IsSorted(ids(all)) {
			t.Errorf("not in id order: %v", ids(all))
		}

		first, err := s.ListUnrecordedVersions(t.Context(), "app", "", 2)
		if err != nil {
			t.Fatal(err)
		}
		if len(first) != 2 || first[0].ID != all[0].ID || first[1].ID != all[1].ID {
			t.Fatalf("limit 2: got %v, want the first two of %v", ids(first), ids(all))
		}
		rest, err := s.ListUnrecordedVersions(t.Context(), "app", first[1].ID.String(), 2)
		if err != nil {
			t.Fatal(err)
		}
		if len(rest) != 1 || rest[0].ID != all[2].ID {
			t.Fatalf("after cursor: got %v, want [%s]", ids(rest), all[2].ID)
		}
		end, err := s.ListUnrecordedVersions(t.Context(), "app", all[2].ID.String(), 2)
		if err != nil {
			t.Fatal(err)
		}
		if end == nil || len(end) != 0 {
			t.Errorf("past the last id: got %v, want a non-nil empty slice", end)
		}
	})

	t.Run("SetVersionEncryption", func(t *testing.T) {
		s, legacy := newStore(t)
		put(t, s, "app", "k", Alg)
		put(t, s, "app", "k", Alg)
		legacy("k", "app", 1)
		legacy("k", "app", 2)

		vs := versionsOf(t, s)
		if err := s.SetVersionEncryption(t.Context(), vs[0].ID, ""); err != nil {
			t.Fatal(err)
		}
		vs = versionsOf(t, s)
		if vs[0].EncryptionAlg == nil || *vs[0].EncryptionAlg != "" {
			t.Errorf("v1 records %s, want \"\"", algOf(vs[0]))
		}
		if vs[1].EncryptionAlg != nil {
			t.Errorf("v2 records %s, want it untouched", algOf(vs[1]))
		}
		if err := s.SetVersionEncryption(t.Context(), vs[1].ID, Alg); err != nil {
			t.Fatal(err)
		}
		vs = versionsOf(t, s)
		if vs[1].EncryptionAlg == nil || *vs[1].EncryptionAlg != Alg {
			t.Errorf("v2 records %s, want %q", algOf(vs[1]), Alg)
		}

		if err := s.SetVersionEncryption(t.Context(), id.NewVersionID(), Alg); err != nil {
			t.Errorf("unknown id: got %v, want nil", err)
		}
	})

	t.Run("CountVersionEncryption", func(t *testing.T) {
		s, legacy := newStore(t)
		zero, err := s.CountVersionEncryption(t.Context(), "app")
		if err != nil {
			t.Fatal(err)
		}
		if zero != (secret.VersionEncryptionCounts{}) {
			t.Fatalf("empty store: got %+v", zero)
		}

		put(t, s, "app", "plain", "") // v1 earlier, counted
		put(t, s, "app", "plain", "") // v2 current, not counted
		put(t, s, "app", "only", "")  // current, not counted
		put(t, s, "app", "upgraded", "")
		put(t, s, "app", "upgraded", Alg) // v1 plaintext under encrypted v2
		put(t, s, "app", "sealed", Alg)
		put(t, s, "app", "old", Alg)
		put(t, s, "app", "old", Alg)
		put(t, s, "app", "older", Alg)
		legacy("old", "app", 1)   // earlier, counted
		legacy("older", "app", 1) // current, not counted
		// The other app's "plain" has one more version, so a count that
		// matched current rows by key alone would drop its v2.
		put(t, s, "other", "plain", "")
		put(t, s, "other", "plain", "")
		put(t, s, "other", "plain", "")
		put(t, s, "other", "old", Alg)
		put(t, s, "other", "old", Alg)
		legacy("old", "other", 1)

		got, err := s.CountVersionEncryption(t.Context(), "app")
		if err != nil {
			t.Fatal(err)
		}
		want := secret.VersionEncryptionCounts{Plaintext: 2, Unrecorded: 1}
		if got != want {
			t.Errorf("app: got %+v, want %+v", got, want)
		}
		other, err := s.CountVersionEncryption(t.Context(), "other")
		if err != nil {
			t.Fatal(err)
		}
		if other != (secret.VersionEncryptionCounts{Plaintext: 2, Unrecorded: 1}) {
			t.Errorf("other: got %+v", other)
		}
	})

	t.Run("CountVersionEncryption leaves out the current version", func(t *testing.T) {
		s, _ := newStore(t)
		put(t, s, "app", "k", "")
		got, err := s.CountVersionEncryption(t.Context(), "app")
		if err != nil {
			t.Fatal(err)
		}
		if got != (secret.VersionEncryptionCounts{}) {
			t.Errorf("only version plaintext: got %+v, want zero", got)
		}

		put(t, s, "app", "k", Alg)
		got, err = s.CountVersionEncryption(t.Context(), "app")
		if err != nil {
			t.Fatal(err)
		}
		if got != (secret.VersionEncryptionCounts{Plaintext: 1}) {
			t.Errorf("plaintext v1 under encrypted v2: got %+v, want Plaintext 1", got)
		}
	})
}
