package secret_test

import (
	"context"
	"sort"
	"testing"

	"github.com/xraph/vault/id"
	"github.com/xraph/vault/secret"
	"github.com/xraph/vault/store/memory"
)

// legacyStore wraps a real store and overrides the three version-encryption
// methods over a fixed set of version rows, so the backfill can be driven with
// rows no live service could write (a row of unknown provenance), and its
// store calls counted.
type legacyStore struct {
	secret.Store
	versions  []*secret.Version // every legacy row, algorithm unset
	recorded  map[id.ID]string
	listCalls int
	setCalls  int
}

func newLegacyStore() *legacyStore {
	return &legacyStore{Store: memory.New(), recorded: map[id.ID]string{}}
}

func (l *legacyStore) add(app string, value []byte) *secret.Version {
	v := &secret.Version{ID: id.NewVersionID(), SecretKey: "k", AppID: app, Version: int64(len(l.versions) + 1), EncryptedValue: value}
	l.versions = append(l.versions, v)
	return v
}

func (l *legacyStore) ListUnrecordedVersions(_ context.Context, appID, after string, limit int) ([]*secret.Version, error) {
	l.listCalls++
	out := make([]*secret.Version, 0)
	for _, v := range l.versions {
		if _, done := l.recorded[v.ID]; done || v.AppID != appID || v.ID.String() <= after {
			continue
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID.String() < out[j].ID.String() })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (l *legacyStore) SetVersionEncryption(_ context.Context, versionID id.ID, alg string) error {
	l.setCalls++
	l.recorded[versionID] = alg
	return nil
}

func TestBackfillMarksOnlyWhatTheConfiguredKeyDecrypts(t *testing.T) {
	configured := encryptorWithKey(t, 1)
	other := encryptorWithKey(t, 2)
	st := newLegacyStore()

	sealedWithOurs, err := configured.Encrypt([]byte("ours"))
	if err != nil {
		t.Fatal(err)
	}
	sealedWithOther, err := other.Encrypt([]byte("theirs"))
	if err != nil {
		t.Fatal(err)
	}
	ours := st.add("app1", sealedWithOurs)
	plain := st.add("app1", []byte("just plaintext"))
	theirs := st.add("app1", sealedWithOther)
	elsewhere := st.add("app2", sealedWithOurs)

	svc := secret.NewService(st, configured, secret.WithAppID("app1"))
	marked, err := svc.BackfillVersionEncryption(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if marked != 1 {
		t.Errorf("marked = %d, want 1", marked)
	}
	if got := st.recorded[ours.ID]; got != secret.EncryptionAlgorithm {
		t.Errorf("our row recorded %q, want %q", got, secret.EncryptionAlgorithm)
	}
	for name, v := range map[string]*secret.Version{"plaintext": plain, "other key": theirs, "other app": elsewhere} {
		if alg, ok := st.recorded[v.ID]; ok {
			t.Errorf("%s row was marked %q; the backfill must leave it alone", name, alg)
		}
	}

	again, err := svc.BackfillVersionEncryption(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if again != 0 {
		t.Errorf("second run marked %d, want 0", again)
	}
}

func TestBackfillWithNoKeyReadsNothing(t *testing.T) {
	st := newLegacyStore()
	st.add("app1", []byte("anything"))

	svc := secret.NewService(st, nil, secret.WithAppID("app1"))
	marked, err := svc.BackfillVersionEncryption(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if marked != 0 {
		t.Errorf("marked = %d, want 0", marked)
	}
	if st.listCalls != 0 || st.setCalls != 0 {
		t.Errorf("store touched: %d list calls, %d set calls, want none", st.listCalls, st.setCalls)
	}
}

// Rows the key cannot decrypt stay unrecorded forever, so the backfill must
// move a cursor past them rather than ask for the same page again.
func TestBackfillFinishesWhenRowsStayUnrecorded(t *testing.T) {
	st := newLegacyStore()
	for range 1200 {
		st.add("app1", []byte("not ciphertext"))
	}

	svc := secret.NewService(st, encryptorWithKey(t, 1), secret.WithAppID("app1"))
	marked, err := svc.BackfillVersionEncryption(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if marked != 0 {
		t.Errorf("marked = %d, want 0", marked)
	}
	if st.listCalls != 3 {
		t.Errorf("list calls = %d, want 3 pages (500, 500, 200)", st.listCalls)
	}
	if st.setCalls != 0 {
		t.Errorf("set calls = %d, want 0", st.setCalls)
	}
}

func TestBackfillMarksAcrossPages(t *testing.T) {
	configured := encryptorWithKey(t, 1)
	st := newLegacyStore()
	for i := range 1100 {
		value := []byte("plain")
		if i%2 == 0 {
			var err error
			if value, err = configured.Encrypt([]byte("v")); err != nil {
				t.Fatal(err)
			}
		}
		st.add("app1", value)
	}

	svc := secret.NewService(st, configured, secret.WithAppID("app1"))
	marked, err := svc.BackfillVersionEncryption(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if marked != 550 {
		t.Errorf("marked = %d, want 550", marked)
	}
}
