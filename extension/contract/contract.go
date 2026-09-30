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

	"github.com/xraph/forge"
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

	// Logger receives an Error-level entry for every error a handler maps
	// to CodeInternal, so an operator can find out why a dashboard request
	// failed. Optional: nil means nothing is logged.
	Logger forge.Logger
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
		{"flags.list", func() error {
			return dispatcher.RegisterQuery(d, c, "flags.list", 1, flagsListHandler(deps))
		}},
		{"flags.detail", func() error {
			return dispatcher.RegisterQuery(d, c, "flags.detail", 1, flagsDetailHandler(deps))
		}},
		{"flags.evaluate", func() error {
			return dispatcher.RegisterQuery(d, c, "flags.evaluate", 1, flagsEvaluateHandler(deps))
		}},
		{"flags.create", func() error {
			return dispatcher.RegisterCommand(d, c, "flags.create", 1, flagsCreateHandler(deps))
		}},
		{"flags.update", func() error {
			return dispatcher.RegisterCommand(d, c, "flags.update", 1, flagsUpdateHandler(deps))
		}},
		{"flags.delete", func() error {
			return dispatcher.RegisterCommand(d, c, "flags.delete", 1, flagsDeleteHandler(deps))
		}},
		{"flags.setEnabled", func() error {
			return dispatcher.RegisterCommand(d, c, "flags.setEnabled", 1, flagsSetEnabledHandler(deps))
		}},
		{"flags.setRules", func() error {
			return dispatcher.RegisterCommand(d, c, "flags.setRules", 1, flagsSetRulesHandler(deps))
		}},
		{"flags.setTenantOverride", func() error {
			return dispatcher.RegisterCommand(d, c, "flags.setTenantOverride", 1, flagsSetTenantOverrideHandler(deps))
		}},
		{"flags.deleteTenantOverride", func() error {
			return dispatcher.RegisterCommand(d, c, "flags.deleteTenantOverride", 1, flagsDeleteTenantOverrideHandler(deps))
		}},
		{"config.list", func() error {
			return dispatcher.RegisterQuery(d, c, "config.list", 1, configListHandler(deps))
		}},
		{"config.detail", func() error {
			return dispatcher.RegisterQuery(d, c, "config.detail", 1, configDetailHandler(deps))
		}},
		{"config.versions", func() error {
			return dispatcher.RegisterQuery(d, c, "config.versions", 1, configVersionsHandler(deps))
		}},
		{"config.resolve", func() error {
			return dispatcher.RegisterQuery(d, c, "config.resolve", 1, configResolveHandler(deps))
		}},
		{"overrides.list", func() error {
			return dispatcher.RegisterQuery(d, c, "overrides.list", 1, overridesListHandler(deps))
		}},
		{"config.create", func() error {
			return dispatcher.RegisterCommand(d, c, "config.create", 1, configCreateHandler(deps))
		}},
		{"config.update", func() error {
			return dispatcher.RegisterCommand(d, c, "config.update", 1, configUpdateHandler(deps))
		}},
		{"config.delete", func() error {
			return dispatcher.RegisterCommand(d, c, "config.delete", 1, configDeleteHandler(deps))
		}},
		{"config.rollback", func() error {
			return dispatcher.RegisterCommand(d, c, "config.rollback", 1, configRollbackHandler(deps))
		}},
		{"overrides.set", func() error {
			return dispatcher.RegisterCommand(d, c, "overrides.set", 1, overridesSetHandler(deps))
		}},
		{"overrides.delete", func() error {
			return dispatcher.RegisterCommand(d, c, "overrides.delete", 1, overridesDeleteHandler(deps))
		}},
		{"rotation.policies", func() error {
			return dispatcher.RegisterQuery(d, c, "rotation.policies", 1, rotationPoliciesHandler(deps))
		}},
		{"rotation.detail", func() error {
			return dispatcher.RegisterQuery(d, c, "rotation.detail", 1, rotationDetailHandler(deps))
		}},
		{"rotation.savePolicy", func() error {
			return dispatcher.RegisterCommand(d, c, "rotation.savePolicy", 1, rotationSavePolicyHandler(deps))
		}},
		{"rotation.deletePolicy", func() error {
			return dispatcher.RegisterCommand(d, c, "rotation.deletePolicy", 1, rotationDeletePolicyHandler(deps))
		}},
		{"rotation.rotateNow", func() error {
			return dispatcher.RegisterCommand(d, c, "rotation.rotateNow", 1, rotationRotateNowHandler(deps))
		}},
	} {
		if err := bind.fn(); err != nil {
			return fmt.Errorf("vault/contract: register %s: %w", bind.intent, err)
		}
	}
	return nil
}
