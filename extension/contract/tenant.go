package contract

import (
	"context"

	"github.com/xraph/vault/scope"
)

// The secrets intents answer for the tenant the request context carries, if
// any: Secrets() reads it from the context, so a request scoped to a tenant
// lists, reads, creates, changes and deletes that tenant's secrets only, and
// a request with no tenant works on the app-level secrets. Nothing on the
// wire names a tenant; a host that wants a tenant-scoped dashboard puts the
// tenant in the context with scope.WithTenantID, the way it does for every
// other vault call.
//
// Rotation is the exception. Policies and records carry no tenant, and the
// rotation manager only ever rotates the app-level secret under a policy's
// key, so the rotation intents work on that secret whatever tenant the
// request carries, and the secrets intents leave rotation alone for a
// tenant's secret.

// tenantOf returns the tenant ctx carries, or "" for none.
func tenantOf(ctx context.Context) string {
	_, tenantID, _, _ := scope.FromContext(ctx)
	return tenantID
}

// appLevel returns ctx scoped to the app-level secrets, with every other
// scope value (app, user, IP) kept.
func appLevel(ctx context.Context) context.Context {
	return scope.WithTenantID(ctx, "")
}
