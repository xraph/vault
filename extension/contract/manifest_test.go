package contract

import (
	"strings"
	"testing"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
	"github.com/xraph/forge/extensions/dashboard/contract/loader"
)

func TestManifest_Loads(t *testing.T) {
	m, err := loader.Load(strings.NewReader(string(manifestYAML)), "vault/contract/manifest.yaml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if m.Contributor.Name != "vault" {
		t.Errorf("contributor name = %q, want vault", m.Contributor.Name)
	}
	// secrets.list, secrets.detail, secrets.versions. Later tasks append
	// commands and rotation intents; bump this count in each one.
	if got := len(m.Intents); got != 3 {
		t.Errorf("intents = %d, want 3", got)
	}
}

func TestManifest_Validates(t *testing.T) {
	m, err := loader.Load(strings.NewReader(string(manifestYAML)), "vault/contract/manifest.yaml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := loader.Validate(m, dashcontract.NewWardenRegistry()); err != nil {
		t.Errorf("validate: %v", err)
	}
}

func TestManifest_RegistersWithRegistry(t *testing.T) {
	reg := dashcontract.NewRegistry()
	m, err := loader.Load(strings.NewReader(string(manifestYAML)), "vault/contract/manifest.yaml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := reg.Register(m); err != nil {
		t.Fatalf("register: %v", err)
	}
	for _, name := range []string{"secrets.list", "secrets.detail", "secrets.versions"} {
		intent, ok := reg.Intent("vault", name, 1)
		if !ok {
			t.Fatalf("expected %s to be registered", name)
		}
		if intent.Kind != "query" {
			t.Errorf("%s kind = %q, want query", name, intent.Kind)
		}
	}
}
