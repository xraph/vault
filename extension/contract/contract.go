// Package contract wires Vault into the Forge dashboard's contract path. It
// registers the `vault` contributor with the dashboard's contract registry
// and answers its intents from the live Vault instance.
//
// Vault's templ dashboard still renders server-side for now. This package is
// the parallel surface the React shell reads, and it will outlive the templ
// one.
package contract

import (
	"bytes"
	_ "embed"
	"fmt"

	"github.com/xraph/forge/extensions/dashboard/contract"
	"github.com/xraph/forge/extensions/dashboard/contract/dispatcher"
	"github.com/xraph/forge/extensions/dashboard/contract/loader"

	"github.com/xraph/vault"
)

//go:embed manifest.yaml
var manifestYAML []byte

// ContributorName is the join key between this contract and
// packages/plugin-vault's `extension` field, and matches
// extension.ExtensionName. A mismatch hides the React plugin with no error
// anywhere, because that is what an uninstalled extension looks like.
const ContributorName = "vault"

// Deps bundles what the contract handlers need at registration time.
type Deps struct {
	// Vault is the composed vault. Required. Every handler operates on
	// Vault.AppID() and nothing else: no request carries an app id.
	Vault *vault.Vault
}

// Register loads the embedded manifest, validates it, registers the `vault`
// contributor with reg, and binds the handlers against deps.
func Register(
	d *dispatcher.Dispatcher,
	reg contract.Registry,
	wreg contract.WardenRegistry,
	deps Deps,
) error {
	if deps.Vault == nil {
		return fmt.Errorf("vault/contract: Vault is required")
	}

	m, err := loader.Load(bytes.NewReader(manifestYAML), "vault/contract/manifest.yaml")
	if err != nil {
		return fmt.Errorf("vault/contract: load manifest: %w", err)
	}
	if err := loader.Validate(m, wreg); err != nil {
		return fmt.Errorf("vault/contract: validate manifest: %w", err)
	}
	if err := reg.Register(m); err != nil {
		return fmt.Errorf("vault/contract: register manifest: %w", err)
	}

	c := ContributorName
	for _, bind := range []struct {
		intent string
		fn     func() error
	}{
		{"secrets.list", func() error {
			return dispatcher.RegisterQuery(d, c, "secrets.list", 1, secretsListHandler(deps))
		}},
		{"secrets.detail", func() error {
			return dispatcher.RegisterQuery(d, c, "secrets.detail", 1, secretsDetailHandler(deps))
		}},
		{"secrets.versions", func() error {
			return dispatcher.RegisterQuery(d, c, "secrets.versions", 1, secretsVersionsHandler(deps))
		}},
		{"secrets.create", func() error {
			return dispatcher.RegisterCommand(d, c, "secrets.create", 1, secretsCreateHandler(deps))
		}},
		{"secrets.update", func() error {
			return dispatcher.RegisterCommand(d, c, "secrets.update", 1, secretsUpdateHandler(deps))
		}},
		{"secrets.delete", func() error {
			return dispatcher.RegisterCommand(d, c, "secrets.delete", 1, secretsDeleteHandler(deps))
		}},
	} {
		if err := bind.fn(); err != nil {
			return fmt.Errorf("vault/contract: register %s: %w", bind.intent, err)
		}
	}
	return nil
}
