package extension

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xraph/forge"

	"github.com/xraph/vault"
	"github.com/xraph/vault/crypto"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/secret"
	"github.com/xraph/vault/store/memory"
)

// testKeyHex is a valid 32-byte AES-256-GCM key, matching the fixture the
// vault package itself uses in vault_test.go.
const testKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

func mustTestKey(t *testing.T) []byte {
	t.Helper()
	key, err := hex.DecodeString(testKeyHex)
	if err != nil {
		t.Fatalf("decode test key: %v", err)
	}
	return key
}

// TestBuildVaultKeepsAKeyPassedAsAVaultOption pins the regression that
// vault.WithConfig's overlay semantics fixed: a key passed through
// extension.WithVaultOption(vault.WithEncryptionKey(...)) must survive the
// extension's own WithConfig call, which runs later in buildVault's option
// sequence whenever FlagCacheTTL is set. Before the overlay fix, WithConfig
// clobbered the key with a zero value and this test would fail with
// EncryptionEnabled() == false.
func TestBuildVaultKeepsAKeyPassedAsAVaultOption(t *testing.T) {
	key := mustTestKey(t)
	e := &Extension{
		config: Config{
			FlagCacheTTL: 30 * time.Second,
		},
		store:     memory.New(),
		vaultOpts: []vault.Option{vault.WithEncryptionKey(key)},
	}

	v, err := e.buildVault()
	if err != nil {
		t.Fatalf("buildVault() returned an error: %v", err)
	}
	if !v.EncryptionEnabled() {
		t.Error("EncryptionEnabled() is false: the extension's WithConfig call dropped the key passed via WithVaultOption")
	}
}

// TestBuildVaultWithoutAKeyIsUnencryptedNotAnError confirms the documented
// keyless fallback: no encryption key anywhere still produces a usable
// Vault, just an unencrypted one. buildVault itself must not error or warn;
// the warning is Register's job.
func TestBuildVaultWithoutAKeyIsUnencryptedNotAnError(t *testing.T) {
	e := &Extension{
		store: memory.New(),
	}

	v, err := e.buildVault()
	if err != nil {
		t.Fatalf("buildVault() returned an error: %v", err)
	}
	if v.EncryptionEnabled() {
		t.Error("EncryptionEnabled() is true with no key configured anywhere")
	}
}

// TestBuildVaultWithoutAStoreSaysHowToConfigureOne checks the error a
// missing store now produces: it still satisfies errors.Is(err,
// vault.ErrNoStore) for callers that check the sentinel, but its text
// names the three ways to supply a store instead of the doubled-up
// "vault: vault: no store configured" that a naive %w wrap produced.
func TestBuildVaultWithoutAStoreSaysHowToConfigureOne(t *testing.T) {
	e := &Extension{}

	_, err := e.buildVault()
	if err == nil {
		t.Fatal("expected an error with no store configured")
	}
	if !errors.Is(err, vault.ErrNoStore) {
		t.Errorf("error does not satisfy errors.Is(err, vault.ErrNoStore): %v", err)
	}
	if !strings.Contains(err.Error(), "WithStore") {
		t.Errorf("error does not mention WithStore: %q", err)
	}
	if strings.Contains(err.Error(), "vault: vault:") {
		t.Errorf("error has a doubled-up prefix: %q", err)
	}
}

// TestStartAndStopReturnPromptly proves only what it says: the extension's
// Start and Stop, which now delegate to the rotation manager's loop,
// return without hanging. It does not and cannot prove the loop ever runs
// a rotation, since it passes whether or not that loop actually starts;
// rotation.TestScheduledRotationRunsWhileStarted is the test that proves
// scheduled rotation really fires. The test here is bounded so a
// regression that makes Stop hang fails the test instead of the suite.
func TestStartAndStopReturnPromptly(t *testing.T) {
	e := &Extension{
		BaseExtension: forge.NewBaseExtension(ExtensionName, ExtensionVersion, ExtensionDescription),
		store:         memory.New(),
	}
	v, err := e.buildVault()
	if err != nil {
		t.Fatalf("buildVault() returned an error: %v", err)
	}
	e.v = v

	done := make(chan error, 1)
	go func() {
		if startErr := e.Start(context.Background()); startErr != nil {
			done <- startErr
			return
		}
		done <- e.Stop(context.Background())
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Start/Stop returned an error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start/Stop did not return within 5s; the rotation loop may be hanging Stop")
	}
}

// TestAuditIsOnEvenWhenEnableAuditIsFalse confirms that auditing is always
// on regardless of the EnableAudit configuration setting. This proves the
// setting is now a no-op and can be safely ignored.
func TestAuditIsOnEvenWhenEnableAuditIsFalse(t *testing.T) {
	e := &Extension{
		config: Config{
			EnableAudit: false,
		},
		store: memory.New(),
	}

	v, err := e.buildVault()
	if err != nil {
		t.Fatalf("buildVault() returned an error: %v", err)
	}

	ctx := context.Background()
	appID := "test-app"
	_, err = v.Secrets().Set(ctx, "test-key", []byte("test-value"), appID)
	if err != nil {
		t.Fatalf("Secrets().Set() returned an error: %v", err)
	}

	count, err := v.Store().CountAudit(ctx, appID)
	if err != nil {
		t.Fatalf("CountAudit() returned an error: %v", err)
	}
	if count == 0 {
		t.Error("expected audit entries to exist, but CountAudit returned 0; auditing should always be on")
	}
}

// legacyRowStore reports one version row whose algorithm was never recorded
// and remembers the algorithm the backfill records for it, standing in for a
// row written before versions carried one. Every other call passes through to
// the embedded memory store.
type legacyRowStore struct {
	*memory.Store
	row *secret.Version

	mu       sync.Mutex
	recorded string
}

func (l *legacyRowStore) ListUnrecordedVersions(_ context.Context, _, after string, _ int) ([]*secret.Version, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.recorded != "" || l.row.ID.String() <= after {
		return []*secret.Version{}, nil
	}
	return []*secret.Version{l.row}, nil
}

func (l *legacyRowStore) SetVersionEncryption(_ context.Context, _ id.ID, alg string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.recorded = alg
	return nil
}

func (l *legacyRowStore) recordedAlg() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.recorded
}

// TestStartBackfillsVersionEncryption proves Start classifies a legacy row the
// configured key decrypts, without Start itself waiting on it.
func TestStartBackfillsVersionEncryption(t *testing.T) {
	key := mustTestKey(t)
	enc, err := crypto.NewEncryptor(key)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := enc.Encrypt([]byte("legacy"))
	if err != nil {
		t.Fatal(err)
	}
	st := &legacyRowStore{
		Store: memory.New(),
		row:   &secret.Version{ID: id.NewVersionID(), SecretKey: "old", AppID: "app1", Version: 1, EncryptedValue: sealed},
	}
	e := &Extension{
		BaseExtension: forge.NewBaseExtension(ExtensionName, ExtensionVersion, ExtensionDescription),
		config:        Config{AppID: "app1"},
		store:         st,
		vaultOpts:     []vault.Option{vault.WithEncryptionKey(key)},
	}
	v, err := e.buildVault()
	if err != nil {
		t.Fatalf("buildVault() returned an error: %v", err)
	}
	e.v = v

	if err := e.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for st.recordedAlg() == "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := st.recordedAlg(); got != secret.EncryptionAlgorithm {
		t.Errorf("recorded algorithm = %q after Start, want %q", got, secret.EncryptionAlgorithm)
	}
	if err := e.Stop(context.Background()); err != nil {
		t.Errorf("Stop: %v", err)
	}
}

// TestStartWithoutAKeyMarksNothing: with no key the backfill proves nothing,
// so it records nothing.
func TestStartWithoutAKeyMarksNothing(t *testing.T) {
	st := &legacyRowStore{
		Store: memory.New(),
		row:   &secret.Version{ID: id.NewVersionID(), SecretKey: "old", AppID: "app1", Version: 1, EncryptedValue: []byte("plain")},
	}
	e := &Extension{
		BaseExtension: forge.NewBaseExtension(ExtensionName, ExtensionVersion, ExtensionDescription),
		config:        Config{AppID: "app1"},
		store:         st,
	}
	v, err := e.buildVault()
	if err != nil {
		t.Fatal(err)
	}
	e.v = v
	if err := e.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := e.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := st.recordedAlg(); got != "" {
		t.Errorf("recorded %q with no key configured, want nothing", got)
	}
}
