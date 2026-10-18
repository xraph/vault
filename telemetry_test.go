package vault_test

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/xraph/vault"
	"github.com/xraph/vault/flag"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/internal/telemetry"
	"github.com/xraph/vault/internal/telemetrytest"
	"github.com/xraph/vault/scope"
	"github.com/xraph/vault/store/memory"
)

// TestTelemetryNeverCarriesSecretMaterial pushes a recognisable secret name
// and value through Set, Get, GetVersion and a rotation (one that succeeds
// and one whose rotator quotes both in its error), plus a tenant-scoped flag
// evaluation, then checks that none of it reached a span or a metric label.
func TestTelemetryNeverCarriesSecretMaterial(t *testing.T) {
	const (
		secretName  = "prod-postgres-root-password-61c9"
		secretValue = "Tr0ub4dor-and-3-6f0a1b"
		rotated     = "Tr0ub4dor-rotated-8d2e7c"
		appID       = "app-billing-3f11"
		tenantID    = "tenant-globex-a4e2"
		userID      = "alice@example.com"
		flagKey     = "beta-ledger-export-77b0"
	)
	key, err := hex.DecodeString(testKeyHex)
	if err != nil {
		t.Fatal(err)
	}

	rec := telemetrytest.Spans(t)
	sink := telemetrytest.NewSink()
	st := memory.New()
	v, err := vault.New(
		vault.WithStore(st),
		vault.WithAppID(appID),
		vault.WithEncryptionKey(key),
		vault.WithMetrics(sink),
	)
	if err != nil {
		t.Fatal(err)
	}

	ctx := scope.WithScope(t.Context(), appID, "", userID, "203.0.113.7")
	if _, err := v.Secrets().Set(ctx, secretName, []byte(secretValue), ""); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, err := v.Secrets().Get(ctx, secretName, ""); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := v.Secrets().GetVersion(ctx, secretName, "", 1); err != nil {
		t.Fatalf("GetVersion: %v", err)
	}

	v.Rotation().RegisterRotator(secretName, func(_ context.Context, _ []byte) ([]byte, error) {
		return []byte(rotated), nil
	})
	if err := v.Rotation().RotateNow(ctx, secretName, ""); err != nil {
		t.Fatalf("RotateNow: %v", err)
	}
	v.Rotation().RegisterRotator(secretName, func(_ context.Context, current []byte) ([]byte, error) {
		return nil, errors.New("upstream rejected " + secretName + "=" + string(current))
	})
	if err := v.Rotation().RotateNow(ctx, secretName, ""); err == nil {
		t.Fatal("RotateNow succeeded with a failing rotator")
	}

	if err := st.DefineFlag(ctx, &flag.Definition{
		Entity: vault.NewEntity(), ID: id.NewFlagID(), Key: flagKey, Type: flag.TypeBool,
		DefaultValue: false, Enabled: true, AppID: appID,
	}); err != nil {
		t.Fatal(err)
	}
	flagCtx := scope.WithTenantID(ctx, tenantID)
	if _, err := v.FlagEngine().Evaluate(flagCtx, flagKey, appID); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}

	// The work above went through every span vault starts on this path.
	for _, name := range []string{"set secret", "get secret", "get secret version", "rotate secret", "evaluate flag"} {
		if len(telemetrytest.Named(rec, name)) == 0 {
			t.Errorf("no %q span recorded", name)
		}
	}
	for _, name := range []string{
		telemetry.MetricSecretOperations, telemetry.MetricCryptoOperations,
		telemetry.MetricRotations, telemetry.MetricRotationDuration, telemetry.MetricFlagEvaluations,
	} {
		if len(sink.LabelSets(name)) == 0 {
			t.Errorf("vault.WithMetrics did not reach %s", name)
		}
	}

	needles := []string{
		secretName, secretValue, rotated, testKeyHex, string(key),
		appID, tenantID, userID, "203.0.113.7", flagKey, "upstream rejected",
	}
	telemetrytest.AssertNoLeak(t, rec, needles...)
	sink.AssertNoLeak(t, needles...)
}
