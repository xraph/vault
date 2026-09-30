package contract

import (
	"reflect"
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
	// secrets.list, secrets.detail, secrets.versions, secrets.create,
	// secrets.update, secrets.delete, rotation.policies, rotation.detail,
	// rotation.savePolicy, rotation.deletePolicy, rotation.rotateNow, flags.list,
	// flags.detail, flags.evaluate, flags.create, flags.update, flags.delete,
	// flags.setEnabled, flags.setRules, flags.setTenantOverride,
	// flags.deleteTenantOverride, config.list, config.detail, config.versions,
	// config.resolve, overrides.list, config.create, config.update,
	// config.delete, config.rollback, overrides.set, overrides.delete.
	if got := len(m.Intents); got != 32 {
		t.Errorf("intents = %d, want 32", got)
	}
}

// The config commands must refresh exactly the reads they can change: a
// delete or create also moves the overrides list, an update or rollback does
// not, and an override write moves the entry's detail and resolve.
func TestManifest_ConfigCommandInvalidates(t *testing.T) {
	m, err := loader.Load(strings.NewReader(string(manifestYAML)), "vault/contract/manifest.yaml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	want := map[string][]string{
		"config.create":    {"config.list", "config.detail", "config.versions", "config.resolve", "overrides.list"},
		"config.update":    {"config.list", "config.detail", "config.versions", "config.resolve"},
		"config.delete":    {"config.list", "config.detail", "config.versions", "config.resolve", "overrides.list"},
		"config.rollback":  {"config.list", "config.detail", "config.versions", "config.resolve"},
		"overrides.set":    {"config.detail", "config.resolve", "overrides.list"},
		"overrides.delete": {"config.detail", "config.resolve", "overrides.list"},
	}
	seen := 0
	for _, intent := range m.Intents {
		if w, ok := want[intent.Name]; ok {
			seen++
			if !reflect.DeepEqual(intent.Invalidates, w) {
				t.Errorf("%s invalidates = %v, want %v", intent.Name, intent.Invalidates, w)
			}
		}
	}
	if seen != len(want) {
		t.Errorf("found %d of %d config commands in the manifest", seen, len(want))
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
	queries := []string{"secrets.list", "secrets.detail", "secrets.versions", "rotation.policies", "rotation.detail", "flags.list", "flags.detail", "flags.evaluate",
		"config.list", "config.detail", "config.versions", "config.resolve", "overrides.list"}
	commands := []string{"secrets.create", "secrets.update", "secrets.delete", "rotation.savePolicy", "rotation.deletePolicy", "rotation.rotateNow",
		"flags.create", "flags.update", "flags.delete", "flags.setEnabled", "flags.setRules", "flags.setTenantOverride", "flags.deleteTenantOverride",
		"config.create", "config.update", "config.delete", "config.rollback", "overrides.set", "overrides.delete"}
	for _, name := range queries {
		intent, ok := reg.Intent("vault", name, 1)
		if !ok {
			t.Fatalf("expected %s to be registered", name)
		}
		if intent.Kind != "query" {
			t.Errorf("%s kind = %q, want query", name, intent.Kind)
		}
	}
	for _, name := range commands {
		intent, ok := reg.Intent("vault", name, 1)
		if !ok {
			t.Fatalf("expected %s to be registered", name)
		}
		if intent.Kind != "command" {
			t.Errorf("%s kind = %q, want command", name, intent.Kind)
		}
	}
}
