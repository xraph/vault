package flag_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/sqlitedriver"

	// Registers the "sqlite" migration executor; vault leaves this to the
	// consumer.
	_ "github.com/xraph/grove/drivers/sqlitedriver/sqlitemigrate"

	"github.com/xraph/vault"
	"github.com/xraph/vault/audit"
	audithook "github.com/xraph/vault/audit_hook"
	"github.com/xraph/vault/flag"
	"github.com/xraph/vault/store"
	"github.com/xraph/vault/store/memory"
	sqlitestore "github.com/xraph/vault/store/sqlite"
)

const mgrApp = "mgr-app"

// backends runs fn once per store backend the manager must behave the same
// on. Both are built through vault.New with a long cache TTL, so a test that
// depends on invalidation cannot pass by the cache expiring.
func backends(t *testing.T, fn func(t *testing.T, v *vault.Vault)) {
	t.Helper()
	t.Run("memory", func(t *testing.T) {
		fn(t, newMgrVault(t, memory.New()))
	})
	t.Run("sqlite", func(t *testing.T) {
		fn(t, newMgrVault(t, newSQLiteStore(t)))
	})
}

func newMgrVault(t *testing.T, st store.Store) *vault.Vault {
	t.Helper()
	v, err := vault.New(
		vault.WithStore(st),
		vault.WithAppID(mgrApp),
		vault.WithConfig(vault.Config{FlagCacheTTL: time.Hour}),
	)
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	return v
}

// newSQLiteStore builds a migrated store on a temp-file database. It is a
// copy of the helper in extension/contract: test helpers cannot be shared
// across packages.
func newSQLiteStore(t *testing.T) *sqlitestore.Store {
	t.Helper()
	sdb := sqlitedriver.New()
	dsn := filepath.Join(t.TempDir(), "flags_test.db")
	if err := sdb.Open(context.Background(), dsn); err != nil {
		t.Fatalf("sqlitedriver open: %v", err)
	}
	db, err := grove.Open(sdb)
	if err != nil {
		t.Fatalf("grove open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	s := sqlitestore.New(db)
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return s
}

func mustCreate(t *testing.T, v *vault.Vault, in flag.CreateInput) *flag.Definition {
	t.Helper()
	def, err := v.FlagManager().Create(bg(), in)
	if err != nil {
		t.Fatalf("Create(%q): %v", in.Key, err)
	}
	return def
}

// wantValidation asserts err is a *flag.ValidationError naming field.
func wantValidation(t *testing.T, err error, field string) {
	t.Helper()
	var ve *flag.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v (%T), want *flag.ValidationError for %q", err, err, field)
	}
	if ve.Field != field {
		t.Errorf("ValidationError.Field = %q, want %q (message %q)", ve.Field, field, ve.Message)
	}
}

func flagAudit(t *testing.T, v *vault.Vault) []*audit.Entry {
	t.Helper()
	entries, err := v.Store().ListAudit(bg(), mgrApp, audit.ListOpts{Resource: audithook.ResourceFlag})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	return entries
}

func TestManagerCreateTwiceIsExists(t *testing.T) {
	backends(t, func(t *testing.T, v *vault.Vault) {
		mustCreate(t, v, flag.CreateInput{Key: "dup", Type: flag.TypeInt, DefaultValue: 1.0, Enabled: true})

		_, err := v.FlagManager().Create(bg(), flag.CreateInput{Key: "dup", Type: flag.TypeString, DefaultValue: "x"})
		if !errors.Is(err, vault.ErrFlagExists) {
			t.Fatalf("second Create err = %v, want ErrFlagExists", err)
		}

		got, err := v.Store().GetFlagDefinition(bg(), "dup", mgrApp)
		if err != nil {
			t.Fatal(err)
		}
		if got.Type != flag.TypeInt {
			t.Errorf("stored type = %q after a refused create, want int", got.Type)
		}
	})
}

func TestManagerCreateTwoFlagsWithoutIDs(t *testing.T) {
	backends(t, func(t *testing.T, v *vault.Vault) {
		a := mustCreate(t, v, flag.CreateInput{Key: "one", Type: flag.TypeBool, DefaultValue: false})
		b := mustCreate(t, v, flag.CreateInput{Key: "two", Type: flag.TypeBool, DefaultValue: false})
		if a.ID.String() == "" || b.ID.String() == "" || a.ID.String() == b.ID.String() {
			t.Errorf("ids = %q, %q, want two distinct non-empty ids", a.ID, b.ID)
		}
		if a.Tags == nil {
			t.Error("nil tags must come back as [], not nil")
		}
	})
}

func TestManagerCreateClearsOrphans(t *testing.T) {
	backends(t, func(t *testing.T, v *vault.Vault) {
		st := v.Store()
		// A rule and an override for a key that has no flag: the shape a
		// partly failed delete leaves behind on mongo, and what
		// SetFlagTenantOverride writes on every backend for a missing flag.
		// On memory SetFlagRules refuses a missing flag, so seed the rule
		// through a flag that is then deleted out from under its rules only
		// where the backend allows it.
		if err := st.SetFlagTenantOverride(bg(), "ghost", mgrApp, "t1", true); err != nil {
			t.Fatal(err)
		}
		if err := st.SetFlagRules(bg(), "ghost", mgrApp, []*flag.Rule{flag.WhenTenant("t1").Return(true)}); err != nil {
			t.Logf("backend refuses rules for a missing flag (%v); orphan override only", err)
		}

		mustCreate(t, v, flag.CreateInput{Key: "ghost", Type: flag.TypeBool, DefaultValue: false, Enabled: true})

		rules, err := st.GetFlagRules(bg(), "ghost", mgrApp)
		if err != nil {
			t.Fatal(err)
		}
		if len(rules) != 0 {
			t.Errorf("new flag inherited %d rules, want 0", len(rules))
		}
		ovs, err := st.ListFlagTenantOverrides(bg(), "ghost", mgrApp)
		if err != nil {
			t.Fatal(err)
		}
		if len(ovs) != 0 {
			t.Errorf("new flag inherited %d overrides, want 0", len(ovs))
		}
	})
}

func TestManagerUpdateKeepsUntouchedFields(t *testing.T) {
	backends(t, func(t *testing.T, v *vault.Vault) {
		created := mustCreate(t, v, flag.CreateInput{Key: "keep", Type: flag.TypeString, DefaultValue: "a", Description: "old", Tags: []string{"x"}, Enabled: true})

		// Variants and Metadata are not part of the manager's inputs, so
		// seed them straight through the store.
		seeded, err := v.Store().GetFlagDefinition(bg(), "keep", mgrApp)
		if err != nil {
			t.Fatal(err)
		}
		seeded.Variants = []flag.Variant{{Value: "b", Description: "the b variant"}}
		seeded.Metadata = map[string]string{"owner": "growth"}
		if err = v.Store().DefineFlag(bg(), seeded); err != nil {
			t.Fatal(err)
		}
		before, err := v.Store().GetFlagDefinition(bg(), "keep", mgrApp)
		if err != nil {
			t.Fatal(err)
		}

		desc := "new"
		after, err := v.FlagManager().Update(bg(), "keep", flag.UpdateInput{Description: &desc})
		if err != nil {
			t.Fatal(err)
		}

		if after.Description != "new" {
			t.Errorf("Description = %q, want new", after.Description)
		}
		if len(after.Variants) != 1 || after.Variants[0].Description != "the b variant" {
			t.Errorf("Variants = %+v, want the seeded variant", after.Variants)
		}
		if after.Metadata["owner"] != "growth" {
			t.Errorf("Metadata = %v, want owner=growth", after.Metadata)
		}
		if after.ID.String() != created.ID.String() {
			t.Errorf("ID = %s, want %s", after.ID, created.ID)
		}
		if !after.CreatedAt.Equal(before.CreatedAt) {
			t.Errorf("CreatedAt = %v, want %v", after.CreatedAt, before.CreatedAt)
		}
		if after.DefaultValue != "a" || len(after.Tags) != 1 || !after.Enabled {
			t.Errorf("untouched fields changed: default=%v tags=%v enabled=%v", after.DefaultValue, after.Tags, after.Enabled)
		}
	})
}

func TestManagerUpdateTagsAndDefault(t *testing.T) {
	backends(t, func(t *testing.T, v *vault.Vault) {
		mustCreate(t, v, flag.CreateInput{Key: "u", Type: flag.TypeInt, DefaultValue: 1.0, Tags: []string{"a"}, Enabled: true})
		var def any = 7.0
		tags := []string{}
		got, err := v.FlagManager().Update(bg(), "u", flag.UpdateInput{DefaultValue: &def, Tags: &tags})
		if err != nil {
			t.Fatal(err)
		}
		if got.DefaultValue != 7.0 {
			t.Errorf("DefaultValue = %v, want 7", got.DefaultValue)
		}
		if got.Tags == nil || len(got.Tags) != 0 {
			t.Errorf("Tags = %#v, want []", got.Tags)
		}

		var bad any = "7"
		_, err = v.FlagManager().Update(bg(), "u", flag.UpdateInput{DefaultValue: &bad})
		wantValidation(t, err, "defaultValue")

		_, err = v.FlagManager().Update(bg(), "missing", flag.UpdateInput{})
		if !errors.Is(err, vault.ErrFlagNotFound) {
			t.Errorf("Update missing err = %v, want ErrFlagNotFound", err)
		}
	})
}

func TestManagerUpdateDropsTheCachedDefault(t *testing.T) {
	backends(t, func(t *testing.T, v *vault.Vault) {
		mustCreate(t, v, flag.CreateInput{Key: "cached", Type: flag.TypeBool, DefaultValue: true, Enabled: true})
		eng := v.FlagEngine()

		got, err := eng.Evaluate(bg(), "cached", mgrApp)
		if err != nil || got != true {
			t.Fatalf("Evaluate = %v, %v, want true", got, err)
		}
		var def any = false
		if _, err = v.FlagManager().Update(bg(), "cached", flag.UpdateInput{DefaultValue: &def}); err != nil {
			t.Fatal(err)
		}
		got, err = eng.Evaluate(bg(), "cached", mgrApp)
		if err != nil || got != false {
			t.Fatalf("Evaluate after update = %v, %v, want false at once", got, err)
		}
	})
}

// disabling must hand back the default rather than a rule's cached value.
func TestManagerDisableStopsServingCachedRuleValue(t *testing.T) {
	backends(t, func(t *testing.T, v *vault.Vault) {
		mustCreate(t, v, flag.CreateInput{Key: "gated", Type: flag.TypeBool, DefaultValue: false, Enabled: true})
		if _, err := v.FlagManager().SetRules(bg(), "gated", []flag.RuleInput{
			{Type: flag.RuleWhenTenant, Config: flag.RuleConfig{TenantIDs: []string{"t1"}}, ReturnValue: true},
		}); err != nil {
			t.Fatal(err)
		}
		ctx := context.WithValue(bg(), flag.ContextKeyTenantID, "t1")
		eng := v.FlagEngine()
		got, err := eng.Evaluate(ctx, "gated", mgrApp)
		if err != nil || got != true {
			t.Fatalf("Evaluate = %v, %v, want true from the rule", got, err)
		}
		if _, err = v.FlagManager().SetEnabled(bg(), "gated", false); err != nil {
			t.Fatal(err)
		}
		got, err = eng.Evaluate(ctx, "gated", mgrApp)
		if err != nil || got != false {
			t.Fatalf("Evaluate after disable = %v, %v, want the default false at once", got, err)
		}
	})
}

func TestManagerValueValidationNamesTheField(t *testing.T) {
	backends(t, func(t *testing.T, v *vault.Vault) {
		m := v.FlagManager()

		_, err := m.Create(bg(), flag.CreateInput{Key: "b", Type: flag.TypeBool, DefaultValue: "true"})
		wantValidation(t, err, "defaultValue")
		if _, gerr := v.Store().GetFlagDefinition(bg(), "b", mgrApp); !errors.Is(gerr, vault.ErrFlagNotFound) {
			t.Errorf("a refused create left a row behind (%v)", gerr)
		}

		mustCreate(t, v, flag.CreateInput{Key: "b", Type: flag.TypeBool, DefaultValue: false, Enabled: true})

		_, err = m.SetRules(bg(), "b", []flag.RuleInput{
			{Type: flag.RuleWhenTenant, Config: flag.RuleConfig{TenantIDs: []string{"t"}}, ReturnValue: "true"},
		})
		wantValidation(t, err, "rules[0].returnValue")

		_, err = m.SetTenantOverride(bg(), "b", "t1", "true")
		wantValidation(t, err, "value")
	})
}

func TestManagerCreateValidatesKeyAndType(t *testing.T) {
	backends(t, func(t *testing.T, v *vault.Vault) {
		long := make([]byte, 257)
		for i := range long {
			long[i] = 'k'
		}
		cases := []struct {
			name  string
			in    flag.CreateInput
			field string
		}{
			{"empty key", flag.CreateInput{Key: "  ", Type: flag.TypeBool, DefaultValue: true}, "key"},
			{"leading space", flag.CreateInput{Key: " k", Type: flag.TypeBool, DefaultValue: true}, "key"},
			{"trailing space", flag.CreateInput{Key: "k ", Type: flag.TypeBool, DefaultValue: true}, "key"},
			{"too long", flag.CreateInput{Key: string(long), Type: flag.TypeBool, DefaultValue: true}, "key"},
			{"unknown type", flag.CreateInput{Key: "k", Type: "yaml", DefaultValue: "x"}, "type"},
			{"empty type", flag.CreateInput{Key: "k", DefaultValue: "x"}, "type"},
			{"nil default", flag.CreateInput{Key: "k", Type: flag.TypeString}, "defaultValue"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := v.FlagManager().Create(bg(), tc.in)
				wantValidation(t, err, tc.field)
			})
		}
		// A key of exactly 256 bytes is fine.
		mustCreate(t, v, flag.CreateInput{Key: string(long[:256]), Type: flag.TypeBool, DefaultValue: true})
	})
}

func TestManagerIntAndJSONValues(t *testing.T) {
	backends(t, func(t *testing.T, v *vault.Vault) {
		m := v.FlagManager()
		_, err := m.Create(bg(), flag.CreateInput{Key: "i", Type: flag.TypeInt, DefaultValue: 1.5})
		wantValidation(t, err, "defaultValue")

		mustCreate(t, v, flag.CreateInput{Key: "i", Type: flag.TypeInt, DefaultValue: 2.0})
		mustCreate(t, v, flag.CreateInput{Key: "j", Type: flag.TypeJSON, DefaultValue: nil})
	})
}

func TestManagerSetRulesRefusals(t *testing.T) {
	backends(t, func(t *testing.T, v *vault.Vault) {
		mustCreate(t, v, flag.CreateInput{Key: "r", Type: flag.TypeBool, DefaultValue: false, Enabled: true})
		m := v.FlagManager()

		t1 := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
		t0 := t1.Add(-time.Hour)

		cases := []struct {
			name  string
			rule  flag.RuleInput
			field string
		}{
			{"rollout over 100", flag.RuleInput{Type: flag.RuleRollout, Config: flag.RuleConfig{Percentage: 101}, ReturnValue: true}, "rules[0].config.percentage"},
			{"rollout under 0", flag.RuleInput{Type: flag.RuleRollout, Config: flag.RuleConfig{Percentage: -1}, ReturnValue: true}, "rules[0].config.percentage"},
			{"schedule start after end", flag.RuleInput{Type: flag.RuleSchedule, Config: flag.RuleConfig{StartAt: &t1, EndAt: &t0}, ReturnValue: true}, "rules[0].config.endAt"},
			{"schedule start equals end", flag.RuleInput{Type: flag.RuleSchedule, Config: flag.RuleConfig{StartAt: &t1, EndAt: &t1}, ReturnValue: true}, "rules[0].config.endAt"},
			{"schedule neither", flag.RuleInput{Type: flag.RuleSchedule, ReturnValue: true}, "rules[0].config"},
			{"empty tenant list", flag.RuleInput{Type: flag.RuleWhenTenant, ReturnValue: true}, "rules[0].config.tenantIds"},
			{"blank tenant", flag.RuleInput{Type: flag.RuleWhenTenant, Config: flag.RuleConfig{TenantIDs: []string{" "}}, ReturnValue: true}, "rules[0].config.tenantIds"},
			{"duplicate tenant", flag.RuleInput{Type: flag.RuleWhenTenant, Config: flag.RuleConfig{TenantIDs: []string{"a", " a"}}, ReturnValue: true}, "rules[0].config.tenantIds"},
			{"empty user list", flag.RuleInput{Type: flag.RuleWhenUser, ReturnValue: true}, "rules[0].config.userIds"},
			{"unknown type", flag.RuleInput{Type: "nope", ReturnValue: true}, "rules[0].type"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := m.SetRules(bg(), "r", []flag.RuleInput{tc.rule})
				wantValidation(t, err, tc.field)
			})
		}

		// The field index follows the rule, not the list head.
		_, err := m.SetRules(bg(), "r", []flag.RuleInput{
			{Type: flag.RuleRollout, Config: flag.RuleConfig{Percentage: 5}, ReturnValue: true},
			{Type: flag.RuleRollout, Config: flag.RuleConfig{Percentage: 500}, ReturnValue: true},
		})
		wantValidation(t, err, "rules[1].config.percentage")

		// Nothing above wrote anything.
		got, err := v.Store().GetFlagRules(bg(), "r", mgrApp)
		if err != nil || len(got) != 0 {
			t.Errorf("rules after refusals = %v, %v, want none", got, err)
		}

		_, err = m.SetRules(bg(), "nope", nil)
		if !errors.Is(err, vault.ErrFlagNotFound) {
			t.Errorf("SetRules on a missing flag err = %v, want ErrFlagNotFound", err)
		}
	})
}

func TestManagerSetRulesRoundTrip(t *testing.T) {
	backends(t, func(t *testing.T, v *vault.Vault) {
		mustCreate(t, v, flag.CreateInput{Key: "rt", Type: flag.TypeBool, DefaultValue: false, Enabled: true})
		m := v.FlagManager()

		zone := time.FixedZone("x", 2*3600)
		start := time.Date(2030, 1, 2, 3, 4, 5, 0, zone)
		end := start.Add(24 * time.Hour)

		got, err := m.SetRules(bg(), "rt", []flag.RuleInput{
			{Type: flag.RuleCustom, Config: flag.RuleConfig{Evaluator: "beta-users", Params: map[string]any{"n": "x"}}, ReturnValue: true},
			{Type: flag.RuleWhenTenant, Config: flag.RuleConfig{TenantIDs: []string{" a ", "b"}}, ReturnValue: true},
			{Type: flag.RuleSchedule, Config: flag.RuleConfig{StartAt: &start, EndAt: &end}, ReturnValue: false},
			{Type: flag.RuleWhenTenantTag, Config: flag.RuleConfig{TagKey: "plan", TagValue: "pro"}, ReturnValue: true},
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 4 {
			t.Fatalf("got %d rules, want 4", len(got))
		}
		for i, r := range got {
			if r.Priority != i {
				t.Errorf("rule %d priority = %d, want %d", i, r.Priority, i)
			}
			if r.FlagKey != "rt" || r.AppID != mgrApp || r.ID.String() == "" {
				t.Errorf("rule %d = %+v, want flag key, app id and an id", i, r)
			}
		}
		if got[0].Type != flag.RuleCustom || got[0].Config.Evaluator != "beta-users" || got[0].Config.Params["n"] != "x" {
			t.Errorf("custom rule did not round-trip: %+v", got[0])
		}
		if ids := got[1].Config.TenantIDs; len(ids) != 2 || ids[0] != "a" || ids[1] != "b" {
			t.Errorf("tenant ids = %v, want trimmed [a b]", ids)
		}
		s := got[2].Config
		if s.StartAt == nil || s.EndAt == nil || !s.StartAt.Equal(start) || !s.EndAt.Equal(end) {
			t.Fatalf("schedule = %+v, want the same instants", s)
		}
		if _, off := s.StartAt.Zone(); off != 0 {
			t.Errorf("StartAt zone offset = %d, want UTC", off)
		}
		if got[3].Config.TagKey != "plan" || got[3].Config.TagValue != "pro" {
			t.Errorf("tag rule = %+v", got[3].Config)
		}

		// Replacing with none clears.
		cleared, err := m.SetRules(bg(), "rt", nil)
		if err != nil || len(cleared) != 0 {
			t.Errorf("SetRules(nil) = %v, %v, want empty", cleared, err)
		}
	})
}

func TestManagerTenantOverrides(t *testing.T) {
	backends(t, func(t *testing.T, v *vault.Vault) {
		m := v.FlagManager()

		if _, err := m.SetTenantOverride(bg(), "nope", "t1", true); !errors.Is(err, vault.ErrFlagNotFound) {
			t.Errorf("override on a missing flag err = %v, want ErrFlagNotFound", err)
		}
		if err := m.DeleteTenantOverride(bg(), "nope", "t1"); !errors.Is(err, vault.ErrFlagNotFound) {
			t.Errorf("delete override on a missing flag err = %v, want ErrFlagNotFound", err)
		}

		mustCreate(t, v, flag.CreateInput{Key: "o", Type: flag.TypeBool, DefaultValue: false, Enabled: true})
		_, err := m.SetTenantOverride(bg(), "o", "  ", true)
		wantValidation(t, err, "tenantId")

		ov, err := m.SetTenantOverride(bg(), "o", " t1 ", true)
		if err != nil {
			t.Fatal(err)
		}
		if ov.TenantID != "t1" || ov.Value != true || ov.FlagKey != "o" || ov.ID.String() == "" {
			t.Errorf("override = %+v", ov)
		}

		if err := m.DeleteTenantOverride(bg(), "o", "t1"); err != nil {
			t.Fatal(err)
		}
		if err := m.DeleteTenantOverride(bg(), "o", "t1"); !errors.Is(err, vault.ErrOverrideNotFound) {
			t.Errorf("second delete err = %v, want ErrOverrideNotFound", err)
		}
	})
}

func TestManagerDelete(t *testing.T) {
	backends(t, func(t *testing.T, v *vault.Vault) {
		m := v.FlagManager()
		mustCreate(t, v, flag.CreateInput{Key: "d", Type: flag.TypeBool, DefaultValue: true, Enabled: true})
		if _, err := v.FlagEngine().Evaluate(bg(), "d", mgrApp); err != nil {
			t.Fatal(err)
		}
		if err := m.Delete(bg(), "d"); err != nil {
			t.Fatal(err)
		}
		if _, err := v.FlagEngine().Evaluate(bg(), "d", mgrApp); !errors.Is(err, vault.ErrFlagNotFound) {
			t.Errorf("Evaluate after delete err = %v, want ErrFlagNotFound (cache must be dropped)", err)
		}
		if err := m.Delete(bg(), "d"); !errors.Is(err, vault.ErrFlagNotFound) {
			t.Errorf("second Delete err = %v, want ErrFlagNotFound", err)
		}
	})
}

func TestManagerAuditRows(t *testing.T) {
	backends(t, func(t *testing.T, v *vault.Vault) {
		m := v.FlagManager()
		step := func(name, wantAction string, fn func() error) {
			t.Helper()
			before := len(flagAudit(t, v))
			if err := fn(); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			after := flagAudit(t, v)
			if len(after)-before != 1 {
				t.Fatalf("%s wrote %d audit rows, want 1", name, len(after)-before)
			}
			found := 0
			for _, e := range after {
				if e.Action == wantAction {
					found++
					if e.Resource != audithook.ResourceFlag || e.Key != "a" || e.AppID != mgrApp {
						t.Errorf("%s row = %+v, want resource flag, key a, app %s", name, e, mgrApp)
					}
				}
			}
			if found == 0 {
				t.Errorf("%s: no row with action %q", name, wantAction)
			}
		}

		step("create", "flag.created", func() error {
			_, err := m.Create(bg(), flag.CreateInput{Key: "a", Type: flag.TypeBool, DefaultValue: false, Enabled: true})
			return err
		})
		desc := "d"
		step("update", "flag.updated", func() error {
			_, err := m.Update(bg(), "a", flag.UpdateInput{Description: &desc})
			return err
		})
		step("toggle", "flag.toggled", func() error {
			_, err := m.SetEnabled(bg(), "a", false)
			return err
		})

		before := len(flagAudit(t, v))
		def, err := m.SetEnabled(bg(), "a", false)
		if err != nil || def == nil || def.Enabled {
			t.Fatalf("no-op SetEnabled = %+v, %v", def, err)
		}
		if n := len(flagAudit(t, v)); n != before {
			t.Errorf("SetEnabled to the current value wrote %d audit rows, want 0", n-before)
		}

		step("rules", "flag.rules_set", func() error {
			_, err := m.SetRules(bg(), "a", []flag.RuleInput{{Type: flag.RuleRollout, Config: flag.RuleConfig{Percentage: 10}, ReturnValue: true}})
			return err
		})
		step("override set", "flag.override_set", func() error {
			_, err := m.SetTenantOverride(bg(), "a", "t1", true)
			return err
		})
		step("override delete", "flag.override_deleted", func() error {
			return m.DeleteTenantOverride(bg(), "a", "t1")
		})
		step("delete", "flag.deleted", func() error { return m.Delete(bg(), "a") })

		// A refused write leaves no row.
		before = len(flagAudit(t, v))
		if _, err := m.Create(bg(), flag.CreateInput{Key: "", Type: flag.TypeBool, DefaultValue: true}); err == nil {
			t.Fatal("expected a validation error")
		}
		if n := len(flagAudit(t, v)); n != before {
			t.Errorf("a refused create wrote %d audit rows", n-before)
		}
	})
}

func TestManagerWithoutEngineOrHookDoesNotPanic(t *testing.T) {
	m := flag.NewManager(memory.New(), nil, flag.WithManagerAppID(mgrApp))
	if _, err := m.Create(bg(), flag.CreateInput{Key: "k", Type: flag.TypeBool, DefaultValue: true, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SetEnabled(bg(), "k", false); err != nil {
		t.Fatal(err)
	}
	if err := m.Delete(bg(), "k"); err != nil {
		t.Fatal(err)
	}
}

// The hook receives the caller's context, so scope on it reaches the audit row.
func TestManagerHookGetsTheCallerContext(t *testing.T) {
	var gotCtx context.Context
	var gotAction, gotKey, gotApp string
	m := flag.NewManager(memory.New(), nil,
		flag.WithManagerAppID(mgrApp),
		flag.WithOnFlagMutate(func(ctx context.Context, action, key, appID string) {
			gotCtx, gotAction, gotKey, gotApp = ctx, action, key, appID
		}),
	)
	type ck struct{}
	ctx := context.WithValue(bg(), ck{}, "marker")
	if _, err := m.Create(ctx, flag.CreateInput{Key: "k", Type: flag.TypeBool, DefaultValue: true}); err != nil {
		t.Fatal(err)
	}
	if gotCtx == nil || gotCtx.Value(ck{}) != "marker" {
		t.Error("hook did not get the caller's context")
	}
	if gotAction != "flag.created" || gotKey != "k" || gotApp != mgrApp {
		t.Errorf("hook = %q %q %q", gotAction, gotKey, gotApp)
	}
}
