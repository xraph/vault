package contract

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
	"github.com/xraph/forge/extensions/dashboard/contract/dispatcher"
	"github.com/xraph/forge/extensions/dashboard/contract/loader"
)

// TestRegister_NilVaultErrors checks the guard at the top of Register: a nil
// Vault must fail loudly here rather than panic the first time a handler
// runs against it.
func TestRegister_NilVaultErrors(t *testing.T) {
	d := dispatcher.New(nil)
	err := Register(d, dashcontract.NewRegistry(), dashcontract.NewWardenRegistry(), Deps{})
	if err == nil {
		t.Fatal("Register with a nil Vault: want an error, got nil")
	}
}

// TestEveryDeclaredIntentIsRegistered registers the vault contributor
// against a real dispatcher.Dispatcher and contract registries, then
// dispatches a request for every intent the embedded manifest declares. It
// asserts the dispatcher found a bound handler, not that the handler
// succeeds: a NOT_FOUND or BAD_REQUEST from the handler itself (an empty
// payload rarely satisfies one) is fine. What must never happen is the
// dispatcher not knowing the intent at all, which is what a manifest entry
// with no matching dispatcher.Register* call looks like, and would
// otherwise only surface as a 404 in the browser.
func TestEveryDeclaredIntentIsRegistered(t *testing.T) {
	v, _ := newTestVault(t)

	d := dispatcher.New(nil)
	if err := Register(d, dashcontract.NewRegistry(), dashcontract.NewWardenRegistry(), Deps{Vault: v}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	m, err := loader.Load(bytes.NewReader(manifestYAML), "vault/contract/manifest.yaml")
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	if len(m.Intents) == 0 {
		t.Fatal("manifest declares no intents")
	}

	for _, intent := range m.Intents {
		kind := dashcontract.KindQuery
		if intent.Kind == dashcontract.IntentKindCommand {
			kind = dashcontract.KindCommand
		}
		req := dashcontract.Request{
			Envelope:      "v1",
			Kind:          kind,
			Contributor:   ContributorName,
			Intent:        intent.Name,
			IntentVersion: 1,
		}
		if kind == dashcontract.KindQuery {
			req.Params = map[string]any{}
		} else {
			req.Payload = json.RawMessage(`{}`)
		}

		_, _, dispatchErr := d.Dispatch(context.Background(), req, dashcontract.Principal{})
		if dispatchErr != nil && strings.Contains(strings.ToLower(dispatchErr.Error()), "not registered") {
			t.Errorf("%s is not registered: %v", intent.Name, dispatchErr)
		}
	}
}
