package contract

import (
	"errors"
	"strings"

	"github.com/xraph/forge/extensions/dashboard/contract"

	"github.com/xraph/vault"
)

// mapError translates a Vault domain error into a *contract.Error the
// dashboard client can branch on. An error that is not one of the domain
// sentinels below becomes CodeInternal with a generic message: the
// underlying error's own text never reaches the client, and nothing here
// logs it either, because it can carry a secret's key or worse.
func mapError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, vault.ErrSecretNotFound):
		return &contract.Error{Code: contract.CodeNotFound, Message: "secret not found"}
	case errors.Is(err, vault.ErrRotationNotFound):
		return &contract.Error{Code: contract.CodeNotFound, Message: "rotation policy not found"}
	case errors.Is(err, vault.ErrDecryptionFailed):
		return &contract.Error{
			Code:    contract.CodeUnavailable,
			Message: "this secret is encrypted and the vault has no key configured",
		}
	default:
		return &contract.Error{Code: contract.CodeInternal, Message: "an internal error occurred"}
	}
}

// badRequest builds a CodeBadRequest contract error.
func badRequest(msg string) error {
	return &contract.Error{Code: contract.CodeBadRequest, Message: msg}
}

// conflict builds a CodeConflict contract error.
func conflict(msg string) error {
	return &contract.Error{Code: contract.CodeConflict, Message: msg}
}

// requireKey validates that key is present, returning it trimmed. Every
// keyed handler in this package calls it first, so a missing key reads the
// same message wherever a client sees it.
func requireKey(key string) (string, error) {
	trimmed := strings.TrimSpace(key)
	if trimmed == "" {
		return "", badRequest("key is required")
	}
	return trimmed, nil
}
