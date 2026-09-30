package contract

import (
	"context"
	"strings"

	"github.com/xraph/forge/extensions/dashboard/contract"

	"github.com/xraph/vault/scope"
)

// withOperator returns ctx carrying the dashboard operator's subject as the
// scope user, so the audit rows a command writes name who ran it. A
// principal with no user, or a subject that is empty once trimmed, leaves
// ctx untouched: an unattributed write shows no user rather than a wrong
// one. The subject is recorded trimmed.
//
// Command handlers call it on the context they hand to writes. Queries must
// not: a read carries no operator, and flags.evaluate and config.resolve
// build fresh contexts of their own.
func withOperator(ctx context.Context, p contract.Principal) context.Context {
	if p.User == nil {
		return ctx
	}
	subject := strings.TrimSpace(p.User.Subject)
	if subject == "" {
		return ctx
	}
	return scope.WithUserID(ctx, subject)
}
