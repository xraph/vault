package scope_test

import (
	"context"
	"testing"

	"github.com/xraph/vault/flag"
	"github.com/xraph/vault/override"
	"github.com/xraph/vault/scope"
)

func bg() context.Context { return context.Background() }

func TestFromContextAllPresent(t *testing.T) {
	ctx := scope.WithScope(bg(), "app1", "tenant1", "user1", "10.0.0.1")

	appID, tenantID, userID, ip := scope.FromContext(ctx)
	if appID != "app1" {
		t.Errorf("appID: got %q, want %q", appID, "app1")
	}
	if tenantID != "tenant1" {
		t.Errorf("tenantID: got %q, want %q", tenantID, "tenant1")
	}
	if userID != "user1" {
		t.Errorf("userID: got %q, want %q", userID, "user1")
	}
	if ip != "10.0.0.1" {
		t.Errorf("ip: got %q, want %q", ip, "10.0.0.1")
	}
}

func TestFromContextEmpty(t *testing.T) {
	appID, tenantID, userID, ip := scope.FromContext(bg())
	if appID != "" || tenantID != "" || userID != "" || ip != "" {
		t.Errorf("expected empty strings, got %q %q %q %q", appID, tenantID, userID, ip)
	}
}

func TestFromContextPartial(t *testing.T) {
	ctx := scope.WithTenantID(bg(), "t-only")

	appID, tenantID, userID, ip := scope.FromContext(ctx)
	if appID != "" {
		t.Errorf("appID: got %q, want empty", appID)
	}
	if tenantID != "t-only" {
		t.Errorf("tenantID: got %q, want %q", tenantID, "t-only")
	}
	if userID != "" {
		t.Errorf("userID: got %q, want empty", userID)
	}
	if ip != "" {
		t.Errorf("ip: got %q, want empty", ip)
	}
}

func TestWithAppID(t *testing.T) {
	ctx := scope.WithAppID(bg(), "myapp")
	appID, _, _, _ := scope.FromContext(ctx)
	if appID != "myapp" {
		t.Errorf("got %q, want %q", appID, "myapp")
	}
}

func TestWithTenantID(t *testing.T) {
	ctx := scope.WithTenantID(bg(), "t-1")
	_, tenantID, _, _ := scope.FromContext(ctx)
	if tenantID != "t-1" {
		t.Errorf("got %q, want %q", tenantID, "t-1")
	}
}

func TestWithUserID(t *testing.T) {
	ctx := scope.WithUserID(bg(), "u-1")
	_, _, userID, _ := scope.FromContext(ctx)
	if userID != "u-1" {
		t.Errorf("got %q, want %q", userID, "u-1")
	}
}

func TestWithIP(t *testing.T) {
	ctx := scope.WithIP(bg(), "192.168.1.1")
	_, _, _, ip := scope.FromContext(ctx)
	if ip != "192.168.1.1" {
		t.Errorf("got %q, want %q", ip, "192.168.1.1")
	}
}

func TestWithScopeBuildsAll(t *testing.T) {
	ctx := scope.WithScope(bg(), "a", "b", "c", "d")
	appID, tenantID, userID, ip := scope.FromContext(ctx)

	if appID != "a" {
		t.Errorf("appID: got %q", appID)
	}
	if tenantID != "b" {
		t.Errorf("tenantID: got %q", tenantID)
	}
	if userID != "c" {
		t.Errorf("userID: got %q", userID)
	}
	if ip != "d" {
		t.Errorf("ip: got %q", ip)
	}
}

func TestContextKeyMatchesFlagPackage(t *testing.T) {
	// Verify scope and flag use the same key type via the same string constants.
	// scope.ContextKey and flag.ContextKey are distinct Go types, so values set
	// by scope.WithTenantID are NOT directly readable via flag.ContextKeyTenantID.
	// This test confirms they use the same underlying string so an adapter (scope → flag)
	// or a unified key approach can be built.
	if string(scope.KeyTenantID) != string(flag.ContextKeyTenantID) {
		t.Errorf("scope.KeyTenantID=%q != flag.ContextKeyTenantID=%q",
			scope.KeyTenantID, flag.ContextKeyTenantID)
	}
	if string(scope.KeyUserID) != string(flag.ContextKeyUserID) {
		t.Errorf("scope.KeyUserID=%q != flag.ContextKeyUserID=%q",
			scope.KeyUserID, flag.ContextKeyUserID)
	}
}

func TestContextKeyMatchesOverridePackage(t *testing.T) {
	if string(scope.KeyTenantID) != string(override.ContextKeyTenantID) {
		t.Errorf("scope.KeyTenantID=%q != override.ContextKeyTenantID=%q",
			scope.KeyTenantID, override.ContextKeyTenantID)
	}
}
