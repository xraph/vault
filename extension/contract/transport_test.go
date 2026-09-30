package contract

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
	"github.com/xraph/forge/extensions/dashboard/contract/dispatcher"
	"github.com/xraph/forge/extensions/dashboard/contract/loader"
	"github.com/xraph/forge/extensions/dashboard/contract/transport"

	"github.com/xraph/vault/flag"
)

// TestCommandInvalidatesReachTheClient sends a real command through forge's
// HTTP transport and checks the response meta carries the manifest's
// invalidates. The handlers return none of their own, so the client learns
// what to refetch only if the transport merges the manifest's list in.
// forge v1.10.0 did not, and against it no dashboard write refreshed any
// read; this test pins the forge version that does. It runs one command from
// each of secrets, flags and config, so every part of the manifest is held
// to it.
func TestCommandInvalidatesReachTheClient(t *testing.T) {
	tests := []struct {
		intent  string
		payload string
	}{
		{"secrets.create", `{"key":"transport/check","value":"v1"}`},
		{"flags.setEnabled", `{"key":"transport-flag","enabled":false}`},
		{"overrides.delete", `{"key":"transport-cfg","tenantId":"acme"}`},
	}
	for _, tt := range tests {
		t.Run(tt.intent, func(t *testing.T) {
			v, _ := newTestVault(t)
			seedFlag(t, v, "transport-flag", flag.TypeBool, false, true)
			seedConfig(t, v, "transport-cfg", "string", "app")
			seedOverride(t, v, "transport-cfg", "acme", "tenant")

			reg := dashcontract.NewRegistry()
			wreg := dashcontract.NewWardenRegistry()
			d := dispatcher.New(nil)
			if err := Register(d, reg, wreg, Deps{Vault: v}); err != nil {
				t.Fatalf("Register: %v", err)
			}

			m, err := loader.Load(bytes.NewReader(manifestYAML), "vault/contract/manifest.yaml")
			if err != nil {
				t.Fatalf("load manifest: %v", err)
			}
			var want []string
			for _, intent := range m.Intents {
				if intent.Name == tt.intent {
					want = intent.Invalidates
				}
			}
			if len(want) == 0 {
				t.Fatalf("the manifest declares no invalidates for %s", tt.intent)
			}

			body := `{"envelope":"v1","kind":"command","contributor":"vault","intent":"` + tt.intent + `",` +
				`"csrf":"test","idempotencyKey":"test","payload":` + tt.payload + `}`
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/dashboard/v1", strings.NewReader(body))
			rec := httptest.NewRecorder()
			transport.NewHandler(reg, wreg, d, nil).ServeHTTP(rec, req)

			var resp dashcontract.Response
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode response: %v (%s)", err, rec.Body)
			}
			if !resp.OK {
				t.Fatalf("%s failed: %s", tt.intent, rec.Body)
			}
			if !reflect.DeepEqual(resp.Meta.Invalidates, want) {
				t.Fatalf("meta.invalidates = %v, want the manifest's %v", resp.Meta.Invalidates, want)
			}
		})
	}
}
