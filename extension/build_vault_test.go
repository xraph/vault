package extension

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/xraph/forge"

	"github.com/xraph/vault"
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

// TestStartStopRunsTheRotationLoopWithoutHanging pins that the extension's
// Start begins the rotation manager's loop and Stop stops it cleanly.
// Nothing in the repository ever called rotation.Manager.Start before this
// fix, so a policy's scheduled rotation never ran. The test is bounded so a
// regression that makes Stop hang fails the test instead of the suite.
func TestStartStopRunsTheRotationLoopWithoutHanging(t *testing.T) {
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
