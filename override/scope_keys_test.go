package override_test

import (
	"testing"

	"github.com/xraph/vault/override"
	"github.com/xraph/vault/scope"
	"github.com/xraph/vault/store/memory"
)

// A tenant placed on the context with scope.WithTenantID must be visible to
// the resolver. Before the fix, override.contextKey was a distinct defined
// type from scope.ContextKey, so the resolver never saw a tenant set through
// the documented scope helpers and silently fell back to the app default.
func TestScopeTenantReachesTheResolver(t *testing.T) {
	s := memory.New()
	setConfig(t, s, "db.pool_size", float64(10))
	setOverride(t, s, "db.pool_size", "t-9", float64(50))

	r := override.NewResolver(s, s)
	ctx := scope.WithTenantID(bg(), "t-9")

	val, err := r.Resolve(ctx, "db.pool_size", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if val != float64(50) {
		t.Errorf("got %v, want 50 (tenant override reached via scope.WithTenantID)", val)
	}
}
