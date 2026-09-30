package configmgr_test

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
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
	"github.com/xraph/vault/config"
	"github.com/xraph/vault/configmgr"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/override"
	"github.com/xraph/vault/scope"
	"github.com/xraph/vault/store"
	"github.com/xraph/vault/store/memory"
	sqlitestore "github.com/xraph/vault/store/sqlite"
)

const mgrApp = "cfg-app"

func bg() context.Context { return context.Background() }

// backends runs fn once per store backend the manager must behave the same
// on, each built through vault.New.
func backends(t *testing.T, fn func(t *testing.T, v *vault.Vault)) {
	t.Helper()
	t.Run("memory", func(t *testing.T) {
		fn(t, newVault(t, memory.New()))
	})
	t.Run("sqlite", func(t *testing.T) {
		fn(t, newVault(t, newSQLiteStore(t)))
	})
}

func newVault(t *testing.T, st store.Store) *vault.Vault {
	t.Helper()
	v, err := vault.New(vault.WithStore(st), vault.WithAppID(mgrApp))
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	return v
}

func newSQLiteStore(t *testing.T) *sqlitestore.Store {
	t.Helper()
	sdb := sqlitedriver.New()
	dsn := filepath.Join(t.TempDir(), "config_test.db")
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

func mustCreate(t *testing.T, v *vault.Vault, in configmgr.CreateInput) *config.Entry {
	t.Helper()
	e, err := v.ConfigManager().Create(bg(), in)
	if err != nil {
		t.Fatalf("Create(%q): %v", in.Key, err)
	}
	return e
}

// wantValidation asserts err is a *config.ValidationError naming field.
func wantValidation(t *testing.T, err error, field string) {
	t.Helper()
	var ve *config.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v (%T), want *config.ValidationError for %q", err, err, field)
	}
	if ve.Field != field {
		t.Errorf("ValidationError.Field = %q, want %q (message %q)", ve.Field, field, ve.Message)
	}
}

func auditRows(t *testing.T, v *vault.Vault, resource string) []*audit.Entry {
	t.Helper()
	entries, err := v.Store().ListAudit(bg(), mgrApp, audit.ListOpts{Resource: resource})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	return entries
}

func versions(t *testing.T, v *vault.Vault, key string) []*config.EntryVersion {
	t.Helper()
	vs, err := v.Store().ListConfigVersions(bg(), key, mgrApp)
	if err != nil {
		t.Fatalf("ListConfigVersions: %v", err)
	}
	return vs
}

func strp(s string) *string { return &s }
func anyp(v any) *any       { return &v }

func TestCreateTwiceIsExistsAndChangesNothing(t *testing.T) {
	backends(t, func(t *testing.T, v *vault.Vault) {
		mustCreate(t, v, configmgr.CreateInput{Key: "dup", ValueType: config.TypeInt, Value: 1.0, Description: "first"})

		_, err := v.ConfigManager().Create(bg(), configmgr.CreateInput{Key: "dup", ValueType: config.TypeString, Value: "x", Description: "second"})
		if !errors.Is(err, vault.ErrConfigExists) {
			t.Fatalf("second Create err = %v, want ErrConfigExists", err)
		}

		got, err := v.Store().GetConfig(bg(), "dup", mgrApp)
		if err != nil {
			t.Fatal(err)
		}
		if got.ValueType != config.TypeInt || got.Description != "first" || got.Version != 1 {
			t.Errorf("stored = type %q desc %q v%d after a refused create, want int, first, v1", got.ValueType, got.Description, got.Version)
		}
		if n := len(versions(t, v, "dup")); n != 1 {
			t.Errorf("versions = %d, want 1", n)
		}
	})
}

func TestCreateTwoWithoutIDs(t *testing.T) {
	backends(t, func(t *testing.T, v *vault.Vault) {
		a := mustCreate(t, v, configmgr.CreateInput{Key: "one", ValueType: config.TypeBool, Value: false})
		b := mustCreate(t, v, configmgr.CreateInput{Key: "two", ValueType: config.TypeBool, Value: true})
		if a.ID.String() == "" || b.ID.String() == "" || a.ID.String() == b.ID.String() {
			t.Errorf("ids = %q, %q, want two distinct non-empty ids", a.ID, b.ID)
		}
		if a.Version != 1 || a.AppID != mgrApp {
			t.Errorf("entry = v%d app %q, want v1 %q", a.Version, a.AppID, mgrApp)
		}
	})
}

func TestCreateClearsOrphanOverrides(t *testing.T) {
	backends(t, func(t *testing.T, v *vault.Vault) {
		err := v.Store().SetOverride(bg(), &override.Override{
			Entity: vault.NewEntity(), ID: id.NewOverrideID(), Key: "ghost", Value: "old", AppID: mgrApp, TenantID: "t1",
		})
		if err != nil {
			t.Fatal(err)
		}

		mustCreate(t, v, configmgr.CreateInput{Key: "ghost", ValueType: config.TypeString, Value: "fresh"})

		ovs, err := v.Store().ListOverridesByKey(bg(), "ghost", mgrApp)
		if err != nil {
			t.Fatal(err)
		}
		if len(ovs) != 0 {
			t.Errorf("new entry inherited %d overrides, want 0", len(ovs))
		}
		got, err := v.Overrides().Resolve(scope.WithTenantID(bg(), "t1"), "ghost", mgrApp)
		if err != nil || got != "fresh" {
			t.Errorf("Resolve for t1 = %v, %v, want the app value", got, err)
		}
	})
}

func TestCreateValidation(t *testing.T) {
	backends(t, func(t *testing.T, v *vault.Vault) {
		m := v.ConfigManager()
		long := make([]byte, 257)
		for i := range long {
			long[i] = 'k'
		}
		cases := []struct {
			name  string
			in    configmgr.CreateInput
			field string
		}{
			{"blank key", configmgr.CreateInput{Key: "  ", ValueType: "string", Value: "x"}, "key"},
			{"padded key", configmgr.CreateInput{Key: " k", ValueType: "string", Value: "x"}, "key"},
			{"long key", configmgr.CreateInput{Key: string(long), ValueType: "string", Value: "x"}, "key"},
			{"no type", configmgr.CreateInput{Key: "k", Value: "x"}, "valueType"},
			{"unknown type", configmgr.CreateInput{Key: "k", ValueType: "yaml", Value: "x"}, "valueType"},
			{"abc as int", configmgr.CreateInput{Key: "k", ValueType: "int", Value: "abc"}, "value"},
			{"1.5 as int", configmgr.CreateInput{Key: "k", ValueType: "int", Value: 1.5}, "value"},
			{"soon as duration", configmgr.CreateInput{Key: "k", ValueType: "duration", Value: "soon"}, "value"},
			{"nil as string", configmgr.CreateInput{Key: "k", ValueType: "string", Value: nil}, "value"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := m.Create(bg(), tc.in)
				wantValidation(t, err, tc.field)
			})
		}
		if rows := auditRows(t, v, audithook.ResourceConfig); len(rows) != 0 {
			t.Errorf("refused creates wrote %d audit rows", len(rows))
		}
		if _, err := v.Store().GetConfig(bg(), "k", mgrApp); !errors.Is(err, vault.ErrConfigNotFound) {
			t.Errorf("a refused create stored something: %v", err)
		}

		if _, err := m.Create(bg(), configmgr.CreateInput{Key: "j", ValueType: "json", Value: nil}); err != nil {
			t.Errorf("json accepts nil, got %v", err)
		}
	})
}

func TestUpdateKeepsDescriptionAndMetadata(t *testing.T) {
	backends(t, func(t *testing.T, v *vault.Vault) {
		seed := &config.Entry{
			Entity: vault.NewEntity(), ID: id.NewConfigID(), Key: "keep", Value: 5.0,
			ValueType: config.TypeInt, Description: "desc one", AppID: mgrApp,
			Metadata: map[string]string{"owner": "me"},
		}
		if err := v.Store().SetConfig(bg(), seed); err != nil {
			t.Fatal(err)
		}
		before, err := v.Store().GetConfig(bg(), "keep", mgrApp)
		if err != nil {
			t.Fatal(err)
		}

		got, err := v.ConfigManager().Update(bg(), "keep", configmgr.UpdateInput{Value: anyp(6.0)})
		if err != nil {
			t.Fatal(err)
		}
		if got.Value != 6.0 || got.ValueType != config.TypeInt || got.Description != "desc one" || got.Metadata["owner"] != "me" {
			t.Errorf("after update = %v %q %q %v, want 6 int 'desc one' owner=me", got.Value, got.ValueType, got.Description, got.Metadata)
		}
		if got.ID != before.ID {
			t.Errorf("id changed from %q to %q", before.ID, got.ID)
		}
		if !got.CreatedAt.Equal(before.CreatedAt) {
			t.Errorf("CreatedAt moved from %v to %v", before.CreatedAt, got.CreatedAt)
		}
		if got.Version != before.Version+1 {
			t.Errorf("version = %d, want %d", got.Version, before.Version+1)
		}
	})
}

func TestUpdateDescriptionAndTypeChange(t *testing.T) {
	backends(t, func(t *testing.T, v *vault.Vault) {
		m := v.ConfigManager()
		mustCreate(t, v, configmgr.CreateInput{Key: "t", ValueType: config.TypeInt, Value: 5.0, Description: "d"})

		got, err := m.Update(bg(), "t", configmgr.UpdateInput{Description: strp("new")})
		if err != nil || got.Description != "new" || got.Value != 5.0 {
			t.Fatalf("description update = %+v, %v", got, err)
		}

		// A type change alone is refused.
		_, err = m.Update(bg(), "t", configmgr.UpdateInput{ValueType: strp(config.TypeString)})
		wantValidation(t, err, "valueType")

		// A type change with a value of the old type is refused, naming the value.
		_, err = m.Update(bg(), "t", configmgr.UpdateInput{ValueType: strp(config.TypeString), Value: anyp(7.0)})
		wantValidation(t, err, "value")

		// A type change with a matching value works.
		got, err = m.Update(bg(), "t", configmgr.UpdateInput{ValueType: strp(config.TypeString), Value: anyp("seven")})
		if err != nil || got.ValueType != config.TypeString || got.Value != "seven" || got.Description != "new" {
			t.Fatalf("retype = %+v, %v", got, err)
		}

		// An unknown target type is refused.
		_, err = m.Update(bg(), "t", configmgr.UpdateInput{ValueType: strp("yaml"), Value: anyp("x")})
		wantValidation(t, err, "valueType")

		// A wrongly typed value for the current type is refused.
		_, err = m.Update(bg(), "t", configmgr.UpdateInput{Value: anyp(1.0)})
		wantValidation(t, err, "value")

		if _, err = m.Update(bg(), "missing", configmgr.UpdateInput{Value: anyp("x")}); !errors.Is(err, vault.ErrConfigNotFound) {
			t.Errorf("update of a missing key err = %v, want ErrConfigNotFound", err)
		}
	})
}

func TestUpdateRefusesValueOnUnsupportedType(t *testing.T) {
	backends(t, func(t *testing.T, v *vault.Vault) {
		err := v.Store().SetConfig(bg(), &config.Entry{
			Entity: vault.NewEntity(), ID: id.NewConfigID(), Key: "legacy", Value: "a: 1",
			ValueType: "yaml", AppID: mgrApp,
		})
		if err != nil {
			t.Fatal(err)
		}
		m := v.ConfigManager()
		_, err = m.Update(bg(), "legacy", configmgr.UpdateInput{Value: anyp("b: 2")})
		wantValidation(t, err, "valueType")

		// The description of a read-only entry can still change.
		got, err := m.Update(bg(), "legacy", configmgr.UpdateInput{Description: strp("noted")})
		if err != nil || got.Description != "noted" || got.ValueType != "yaml" {
			t.Errorf("description update on an unsupported type = %+v, %v", got, err)
		}
	})
}

func TestNoOpUpdateWritesNothing(t *testing.T) {
	backends(t, func(t *testing.T, v *vault.Vault) {
		m := v.ConfigManager()
		mustCreate(t, v, configmgr.CreateInput{Key: "n", ValueType: config.TypeJSON, Value: map[string]any{"a": 1.0}, Description: "d"})
		var calls int
		v.Config().Watch("n", func(context.Context, string, any, any) { calls++ })
		rowsBefore := len(auditRows(t, v, audithook.ResourceConfig))

		// Same value (a Go int inside a map is the same JSON), same
		// description, same type.
		got, err := m.Update(bg(), "n", configmgr.UpdateInput{
			Value:       anyp(map[string]any{"a": 1}),
			ValueType:   strp(config.TypeJSON),
			Description: strp("d"),
		})
		if err != nil {
			t.Fatal(err)
		}
		if got.Version != 1 {
			t.Errorf("version = %d, want 1", got.Version)
		}
		if n := len(versions(t, v, "n")); n != 1 {
			t.Errorf("versions = %d, want 1", n)
		}
		if n := len(auditRows(t, v, audithook.ResourceConfig)); n != rowsBefore {
			t.Errorf("no-op update wrote %d audit rows", n-rowsBefore)
		}
		if calls != 0 {
			t.Errorf("no-op update fired watchers %d times", calls)
		}
	})
}

func TestDeleteRemovesOverridesAndResolution(t *testing.T) {
	backends(t, func(t *testing.T, v *vault.Vault) {
		m := v.ConfigManager()
		mustCreate(t, v, configmgr.CreateInput{Key: "d", ValueType: config.TypeString, Value: "app"})
		for _, tenant := range []string{"t1", "t2"} {
			if _, err := m.SetOverride(bg(), "d", tenant, "over-"+tenant); err != nil {
				t.Fatal(err)
			}
		}
		t1 := scope.WithTenantID(bg(), "t1")
		if got, err := v.Overrides().Resolve(t1, "d", mgrApp); err != nil || got != "over-t1" {
			t.Fatalf("pre-delete Resolve = %v, %v", got, err)
		}

		if err := m.Delete(bg(), "d"); err != nil {
			t.Fatal(err)
		}
		ovs, err := v.Store().ListOverridesByKey(bg(), "d", mgrApp)
		if err != nil {
			t.Fatal(err)
		}
		if len(ovs) != 0 {
			t.Errorf("%d overrides left after delete", len(ovs))
		}
		if got, err := v.Overrides().Resolve(t1, "d", mgrApp); err == nil {
			t.Errorf("Resolve for t1 after delete = %v, want an error", got)
		}

		// Recreating does not bring old overrides back.
		mustCreate(t, v, configmgr.CreateInput{Key: "d", ValueType: config.TypeString, Value: "again"})
		if got, err := v.Overrides().Resolve(t1, "d", mgrApp); err != nil || got != "again" {
			t.Errorf("Resolve after recreate = %v, %v, want the app value", got, err)
		}

		if err := m.Delete(bg(), "missing"); !errors.Is(err, vault.ErrConfigNotFound) {
			t.Errorf("delete of a missing key err = %v, want ErrConfigNotFound", err)
		}
	})
}

func TestRollback(t *testing.T) {
	backends(t, func(t *testing.T, v *vault.Vault) {
		m := v.ConfigManager()
		err := v.Store().SetConfig(bg(), &config.Entry{
			Entity: vault.NewEntity(), ID: id.NewConfigID(), Key: "r", Value: 5.0,
			ValueType: config.TypeInt, Description: "keep me", AppID: mgrApp,
			Metadata: map[string]string{"owner": "me"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = m.Update(bg(), "r", configmgr.UpdateInput{Value: anyp(9.0)}); err != nil {
			t.Fatal(err)
		}

		got, err := m.Rollback(bg(), "r", 1)
		if err != nil {
			t.Fatal(err)
		}
		if got.Value != 5.0 || got.ValueType != config.TypeInt || got.Description != "keep me" || got.Metadata["owner"] != "me" {
			t.Errorf("rolled back = %v %q %q %v, want 5 int 'keep me' owner=me", got.Value, got.ValueType, got.Description, got.Metadata)
		}
		if got.Version != 3 {
			t.Errorf("version = %d, want 3 (rollback adds a version)", got.Version)
		}
		if n := len(versions(t, v, "r")); n != 3 {
			t.Errorf("versions = %d, want 3", n)
		}

		// Rolling back to the value already held is a no-op.
		var watcherCalls int
		v.Config().Watch("r", func(context.Context, string, any, any) { watcherCalls++ })
		rowsBefore := len(auditRows(t, v, audithook.ResourceConfig))
		got, err = m.Rollback(bg(), "r", 3)
		if err != nil {
			t.Fatalf("no-op rollback: %v", err)
		}
		if got.Version != 3 {
			t.Errorf("no-op rollback = v%d, want v3", got.Version)
		}
		if n := len(versions(t, v, "r")); n != 3 {
			t.Errorf("no-op rollback left %d versions, want 3", n)
		}
		if n := len(auditRows(t, v, audithook.ResourceConfig)); n != rowsBefore {
			t.Errorf("no-op rollback wrote %d audit rows", n-rowsBefore)
		}
		if watcherCalls != 0 {
			t.Errorf("no-op rollback fired watchers %d times", watcherCalls)
		}

		if _, err = m.Rollback(bg(), "r", 99); !errors.Is(err, vault.ErrConfigVersionNotFound) {
			t.Errorf("rollback to a missing version err = %v, want ErrConfigVersionNotFound", err)
		}
		if _, err = m.Rollback(bg(), "nope", 1); !errors.Is(err, vault.ErrConfigNotFound) {
			t.Errorf("rollback of a missing key err = %v, want ErrConfigNotFound", err)
		}
	})
}

func TestRollbackRefusesValueInvalidForCurrentType(t *testing.T) {
	backends(t, func(t *testing.T, v *vault.Vault) {
		m := v.ConfigManager()
		mustCreate(t, v, configmgr.CreateInput{Key: "x", ValueType: config.TypeInt, Value: 5.0})
		// Retype to string: v2 holds "five", v1 holds 5.
		if _, err := m.Update(bg(), "x", configmgr.UpdateInput{ValueType: strp(config.TypeString), Value: anyp("five")}); err != nil {
			t.Fatal(err)
		}

		_, err := m.Rollback(bg(), "x", 1)
		wantValidation(t, err, "version")
		var ve *config.ValidationError
		if errors.As(err, &ve) && ve.Message != "version 1 holds a number, not a string" {
			t.Errorf("message = %q", ve.Message)
		}
		got, err := v.Store().GetConfig(bg(), "x", mgrApp)
		if err != nil || got.Value != "five" || got.Version != 2 {
			t.Errorf("a refused rollback changed the entry: %+v, %v", got, err)
		}
	})
}

func TestOverrides(t *testing.T) {
	backends(t, func(t *testing.T, v *vault.Vault) {
		m := v.ConfigManager()

		if _, err := m.SetOverride(bg(), "ghost", "t1", "x"); !errors.Is(err, vault.ErrConfigNotFound) {
			t.Errorf("override on a missing key err = %v, want ErrConfigNotFound", err)
		}

		mustCreate(t, v, configmgr.CreateInput{Key: "n", ValueType: config.TypeInt, Value: 1.0})

		_, err := m.SetOverride(bg(), "n", "t1", "abc")
		wantValidation(t, err, "value")
		_, err = m.SetOverride(bg(), "n", "  ", 2.0)
		wantValidation(t, err, "tenantId")
		if ovs, _ := v.Store().ListOverridesByKey(bg(), "n", mgrApp); len(ovs) != 0 {
			t.Errorf("refused overrides stored %d rows", len(ovs))
		}

		ov, err := m.SetOverride(bg(), "n", " t1 ", 2.0)
		if err != nil {
			t.Fatal(err)
		}
		if ov.TenantID != "t1" || ov.Value != 2.0 || ov.ID.String() == "" || ov.AppID != mgrApp {
			t.Errorf("override = %+v", ov)
		}
		if got, rerr := v.Overrides().Resolve(scope.WithTenantID(bg(), "t1"), "n", mgrApp); rerr != nil || got != 2.0 {
			t.Errorf("Resolve for t1 = %v, %v, want 2", got, rerr)
		}

		// A second override for another tenant needs its own id (sqlite
		// primary key).
		if _, err = m.SetOverride(bg(), "n", "t2", 3.0); err != nil {
			t.Fatalf("second override: %v", err)
		}
		// Overwriting keeps the id.
		again, err := m.SetOverride(bg(), "n", "t1", 4.0)
		if err != nil || again.ID != ov.ID || again.Value != 4.0 {
			t.Errorf("overwrite = %+v, %v, want same id and value 4", again, err)
		}

		if err = m.DeleteOverride(bg(), "n", "t1"); err != nil {
			t.Fatal(err)
		}
		if got, rerr := v.Overrides().Resolve(scope.WithTenantID(bg(), "t1"), "n", mgrApp); rerr != nil || got != 1.0 {
			t.Errorf("Resolve for t1 after delete = %v, %v, want the app value", got, rerr)
		}
		if err = m.DeleteOverride(bg(), "n", "t1"); !errors.Is(err, vault.ErrOverrideNotFound) {
			t.Errorf("second delete err = %v, want ErrOverrideNotFound", err)
		}
		// The entry is not read: a missing override is a missing override
		// whether or not its key exists.
		if err = m.DeleteOverride(bg(), "ghost", "t1"); !errors.Is(err, vault.ErrOverrideNotFound) {
			t.Errorf("delete on a missing key err = %v, want ErrOverrideNotFound", err)
		}
		wantValidation(t, m.DeleteOverride(bg(), "n", ""), "tenantId")
	})
}

func TestEveryWriteWritesOneAuditRow(t *testing.T) {
	backends(t, func(t *testing.T, v *vault.Vault) {
		m := v.ConfigManager()
		step := func(name, wantAction, resource, wantTenant string, fn func() error) {
			t.Helper()
			before := len(auditRows(t, v, resource))
			if err := fn(); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			after := auditRows(t, v, resource)
			if len(after)-before != 1 {
				t.Fatalf("%s wrote %d %s audit rows, want 1", name, len(after)-before, resource)
			}
			found := false
			for _, e := range after {
				if e.Action == wantAction && e.Key == "a" && e.AppID == mgrApp && e.TenantID == wantTenant {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: no %s row with action %q key a app %s tenant %q in %+v", name, resource, wantAction, mgrApp, wantTenant, after)
			}
		}

		step("create", "config.set", "config", "", func() error {
			_, err := m.Create(bg(), configmgr.CreateInput{Key: "a", ValueType: config.TypeInt, Value: 1.0})
			return err
		})
		step("update", "config.set", "config", "", func() error {
			_, err := m.Update(bg(), "a", configmgr.UpdateInput{Value: anyp(2.0)})
			return err
		})
		step("rollback", "config.rolled_back", "config", "", func() error {
			_, err := m.Rollback(bg(), "a", 1)
			return err
		})
		step("override set", "override.set", "override", "t9", func() error {
			_, err := m.SetOverride(bg(), "a", "t9", 3.0)
			return err
		})
		step("override delete", "override.deleted", "override", "t9", func() error {
			return m.DeleteOverride(bg(), "a", "t9")
		})
		step("delete", "config.deleted", "config", "", func() error { return m.Delete(bg(), "a") })
	})
}

func TestWatchersFireOnCreateUpdateRollbackAndDelete(t *testing.T) {
	backends(t, func(t *testing.T, v *vault.Vault) {
		type call struct{ old, new any }
		var mu sync.Mutex
		var calls []call
		v.Config().Watch("w", func(_ context.Context, _ string, o, n any) {
			mu.Lock()
			defer mu.Unlock()
			calls = append(calls, call{o, n})
		})
		m := v.ConfigManager()

		mustCreate(t, v, configmgr.CreateInput{Key: "w", ValueType: config.TypeInt, Value: 1.0})
		if _, err := m.Update(bg(), "w", configmgr.UpdateInput{Value: anyp(2.0)}); err != nil {
			t.Fatal(err)
		}
		if _, err := m.Rollback(bg(), "w", 1); err != nil {
			t.Fatal(err)
		}
		if err := m.Delete(bg(), "w"); err != nil {
			t.Fatal(err)
		}

		want := []call{{nil, 1.0}, {1.0, 2.0}, {2.0, 1.0}, {1.0, nil}}
		if len(calls) != len(want) {
			t.Fatalf("watchers fired %d times, want %d: %+v", len(calls), len(want), calls)
		}
		for i, w := range want {
			if calls[i] != w {
				t.Errorf("call %d = %+v, want %+v", i, calls[i], w)
			}
		}
	})
}

// A resolver with a cache must not keep serving what a write replaced.
func TestWritesInvalidateTheResolverCache(t *testing.T) {
	st := memory.New()
	res := override.NewResolver(st, st, override.WithCacheTTL(time.Hour))
	svc := config.NewService(st, config.WithAppID(mgrApp), config.WithResolver(res))
	m := configmgr.NewManager(st, st, res, svc, configmgr.WithManagerAppID(mgrApp))
	t1 := scope.WithTenantID(bg(), "t1")

	if _, err := m.Create(bg(), configmgr.CreateInput{Key: "c", ValueType: config.TypeInt, Value: 1.0}); err != nil {
		t.Fatal(err)
	}
	resolve := func() any {
		t.Helper()
		got, err := res.Resolve(t1, "c", mgrApp)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		return got
	}
	if got := resolve(); got != 1.0 {
		t.Fatalf("Resolve = %v, want 1", got)
	}
	if _, err := m.Update(bg(), "c", configmgr.UpdateInput{Value: anyp(2.0)}); err != nil {
		t.Fatal(err)
	}
	if got := resolve(); got != 2.0 {
		t.Errorf("after update Resolve = %v, want 2", got)
	}
	if _, err := m.SetOverride(bg(), "c", "t1", 7.0); err != nil {
		t.Fatal(err)
	}
	if got := resolve(); got != 7.0 {
		t.Errorf("after override Resolve = %v, want 7", got)
	}
	if err := m.DeleteOverride(bg(), "c", "t1"); err != nil {
		t.Fatal(err)
	}
	if got := resolve(); got != 2.0 {
		t.Errorf("after override delete Resolve = %v, want 2", got)
	}
	if _, err := m.Rollback(bg(), "c", 1); err != nil {
		t.Fatal(err)
	}
	if got := resolve(); got != 1.0 {
		t.Errorf("after rollback Resolve = %v, want 1", got)
	}
	if err := m.Delete(bg(), "c"); err != nil {
		t.Fatal(err)
	}
	if got, err := res.Resolve(t1, "c", mgrApp); err == nil {
		t.Errorf("after delete Resolve = %v, want an error", got)
	}
}

func TestManagerWithoutResolverServiceOrHookDoesNotPanic(t *testing.T) {
	st := memory.New()
	m := configmgr.NewManager(st, st, nil, nil, configmgr.WithManagerAppID(mgrApp))
	if _, err := m.Create(bg(), configmgr.CreateInput{Key: "k", ValueType: config.TypeBool, Value: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Update(bg(), "k", configmgr.UpdateInput{Value: anyp(false)}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SetOverride(bg(), "k", "t", true); err != nil {
		t.Fatal(err)
	}
	if err := m.Delete(bg(), "k"); err != nil {
		t.Fatal(err)
	}
}

func TestHookGetsTheMutationDetails(t *testing.T) {
	st := memory.New()
	type rec struct{ action, resource, key, appID, tenant string }
	var got []rec
	m := configmgr.NewManager(st, st, nil, nil,
		configmgr.WithManagerAppID(mgrApp),
		configmgr.WithOnConfigMutate(func(_ context.Context, action, resource, key, appID, tenantID string) {
			got = append(got, rec{action, resource, key, appID, tenantID})
		}),
	)
	if _, err := m.Create(bg(), configmgr.CreateInput{Key: "k", ValueType: config.TypeBool, Value: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SetOverride(bg(), "k", "t", false); err != nil {
		t.Fatal(err)
	}
	want := []rec{
		{"config.set", "config", "k", mgrApp, ""},
		{"override.set", "override", "k", mgrApp, "t"},
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("hook calls = %+v, want %+v", got, want)
	}
}

// An override whose entry is gone still resolves for its tenant, so it must
// be removable: the manager deletes it without reading the entry.
func TestDeleteOverrideRemovesAnOrphan(t *testing.T) {
	backends(t, func(t *testing.T, v *vault.Vault) {
		m := v.ConfigManager()
		mustCreate(t, v, configmgr.CreateInput{Key: "orph", ValueType: config.TypeString, Value: "app"})
		if _, err := m.SetOverride(bg(), "orph", "acme", "tenant"); err != nil {
			t.Fatal(err)
		}
		// Delete the key through the store, which leaves the override behind.
		if err := v.Store().DeleteConfig(bg(), "orph", mgrApp); err != nil {
			t.Fatal(err)
		}
		acme := scope.WithTenantID(bg(), "acme")
		if got, err := v.Overrides().Resolve(acme, "orph", mgrApp); err != nil || got != "tenant" {
			t.Fatalf("orphan Resolve = %v, %v, want it to still resolve", got, err)
		}

		before := len(auditRows(t, v, "override"))
		if err := m.DeleteOverride(bg(), "orph", " acme "); err != nil {
			t.Fatalf("DeleteOverride of an orphan: %v", err)
		}
		rows := auditRows(t, v, "override")
		if len(rows)-before != 1 {
			t.Fatalf("wrote %d override audit rows, want 1", len(rows)-before)
		}
		found := false
		for _, e := range rows {
			if e.Action == "override.deleted" && e.Key == "orph" && e.TenantID == "acme" {
				found = true
			}
		}
		if !found {
			t.Errorf("no override.deleted row for tenant acme in %+v", rows)
		}
		if got, err := v.Overrides().Resolve(acme, "orph", mgrApp); err == nil {
			t.Errorf("Resolve after removing the orphan = %v, want an error", got)
		}
		if ovs, _ := v.Store().ListOverridesByKey(bg(), "orph", mgrApp); len(ovs) != 0 {
			t.Errorf("%d overrides left", len(ovs))
		}
	})
}

func TestDeleteOverrideOnAMissingKeyIsOverrideNotFound(t *testing.T) {
	backends(t, func(t *testing.T, v *vault.Vault) {
		err := v.ConfigManager().DeleteOverride(bg(), "nothing", "acme")
		if !errors.Is(err, vault.ErrOverrideNotFound) {
			t.Errorf("err = %v, want ErrOverrideNotFound", err)
		}
		if rows := auditRows(t, v, "override"); len(rows) != 0 {
			t.Errorf("a failed delete wrote %d audit rows", len(rows))
		}
	})
}
