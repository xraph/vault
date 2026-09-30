package contract

import (
	"context"

	"github.com/xraph/forge/extensions/dashboard/contract"

	"github.com/xraph/vault/scope"
)

// withOperator returns ctx carrying the dashboard operator's subject as the
// scope user, so the audit rows a command writes name who ran it. A
// principal with no user or an empty subject leaves ctx untouched: an
// unattributed write shows no user rather than a wrong one.
//
// Command handlers call it on the context they hand to writes. Queries must
// not: a read carries no operator, and flags.evaluate and config.resolve
// build fresh contexts of their own.
func withOperator(ctx context.Context, p contract.Principal) context.Context {
	if p.User == nil || p.User.Subject == "" {
		return ctx
	}
	return scope.WithUserID(ctx, p.User.Subject)
}
