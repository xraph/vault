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
)

// TestCommandInvalidatesReachTheClient sends a real command through forge's
// HTTP transport and checks the response meta carries the manifest's
// invalidates. The handlers return none of their own, so the client learns
// what to refetch only if the transport merges the manifest's list in.
// forge v1.10.0 did not, and against it no dashboard write refreshed any
// read; this test pins the forge version that does.
func TestCommandInvalidatesReachTheClient(t *testing.T) {
	v, _ := newTestVault(t)

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
		if intent.Name == "secrets.create" {
			want = intent.Invalidates
		}
	}
	if len(want) == 0 {
		t.Fatal("the manifest declares no invalidates for secrets.create")
	}

	body := `{"envelope":"v1","kind":"command","contributor":"vault","intent":"secrets.create",` +
		`"csrf":"test","idempotencyKey":"test","payload":{"key":"transport/check","value":"v1"}}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/dashboard/v1", strings.NewReader(body))
	rec := httptest.NewRecorder()
	transport.NewHandler(reg, wreg, d, nil).ServeHTTP(rec, req)

	var resp dashcontract.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (%s)", err, rec.Body)
	}
	if !resp.OK {
		t.Fatalf("secrets.create failed: %s", rec.Body)
	}
	if !reflect.DeepEqual(resp.Meta.Invalidates, want) {
		t.Fatalf("meta.invalidates = %v, want the manifest's %v", resp.Meta.Invalidates, want)
	}
}
