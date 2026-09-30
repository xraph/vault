package contract

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	dashauth "github.com/xraph/forge/extensions/dashboard/auth"
	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"

	"github.com/xraph/vault"
	"github.com/xraph/vault/audit"
	"github.com/xraph/vault/scope"
)

const operatorSubject = "user_operator_1"

var operatorPrincipal = dashcontract.Principal{User: &dashauth.UserInfo{Subject: operatorSubject}}

func TestWithOperator(t *testing.T) {
	cases := []struct {
		name string
		p    dashcontract.Principal
		want string
	}{
		{"principal with a subject", operatorPrincipal, operatorSubject},
		{"nil user", dashcontract.Principal{}, ""},
		{"empty subject", dashcontract.Principal{User: &dashauth.UserInfo{}}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, got, _ := scope.FromContext(withOperator(context.Background(), tc.p))
			if got != tc.want {
				t.Errorf("user = %q, want %q", got, tc.want)
			}
		})
	}

	// An existing scope survives and is not replaced.
	base := scope.WithTenantID(scope.WithAppID(context.Background(), "a"), "t")
	app, tenant, user, _ := scope.FromContext(withOperator(base, operatorPrincipal))
	if app != "a" || tenant != "t" || user != operatorSubject {
		t.Errorf("scope = %q %q %q", app, tenant, user)
	}
}

func auditRows(t *testing.T, v *vault.Vault) []*audit.Entry {
	t.Helper()
	rows, err := v.Store().ListAudit(context.Background(), testAppID, audit.ListOpts{Limit: 500})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	return rows
}

// Every command handler records the operator on the rows it writes, and
// rows written with no principal carry no user.
func TestCommandsRecordTheOperator(t *testing.T) {
	v, _ := newTestVault(t)
	deps := Deps{Vault: v}
	ctx := context.Background()
	p := operatorPrincipal

	type step struct {
		name string
		want string // an action this step must write
		run  func() error
	}
	steps := []step{
		{"secrets.create", "secret.set", func() error {
			_, err := secretsCreateHandler(deps)(ctx, secretsCreateRequest{Key: "s1", Value: "v1"}, p)
			return err
		}},
		{"secrets.update", "secret.set", func() error {
			_, err := secretsUpdateHandler(deps)(ctx, secretsUpdateRequest{Key: "s1", Value: "v2"}, p)
			return err
		}},
		{"rotation.rotateNow", "secret.rotated", func() error {
			v.Rotation().RegisterRotator("s1", func(_ context.Context, cur []byte) ([]byte, error) { return cur, nil })
			_, err := rotationRotateNowHandler(deps)(ctx, rotationRotateNowRequest{Key: "s1"}, p)
			return err
		}},
		{"secrets.delete", "secret.delete", func() error {
			_, err := secretsDeleteHandler(deps)(ctx, secretsDeleteRequest{Key: "s1"}, p)
			return err
		}},
		{"flags.create", "flag.created", func() error {
			_, err := flagsCreateHandler(deps)(ctx, flagsCreateRequest{Key: "f1", Type: "bool", DefaultValue: true, Enabled: true}, p)
			return err
		}},
		{"flags.update", "flag.updated", func() error {
			d := "hello"
			_, err := flagsUpdateHandler(deps)(ctx, flagsUpdateRequest{Key: "f1", Description: &d}, p)
			return err
		}},
		{"flags.setEnabled", "flag.toggled", func() error {
			_, err := flagsSetEnabledHandler(deps)(ctx, flagsSetEnabledRequest{Key: "f1", Enabled: false}, p)
			return err
		}},
		{"flags.setRules", "flag.rules_set", func() error {
			rules := []flagRuleRequest{}
			_, err := flagsSetRulesHandler(deps)(ctx, flagsSetRulesRequest{Key: "f1", Rules: &rules}, p)
			return err
		}},
		{"flags.setTenantOverride", "flag.override_set", func() error {
			_, err := flagsSetTenantOverrideHandler(deps)(ctx, flagsSetTenantOverrideRequest{Key: "f1", TenantID: "t1", Value: false}, p)
			return err
		}},
		{"flags.deleteTenantOverride", "flag.override_deleted", func() error {
			_, err := flagsDeleteTenantOverrideHandler(deps)(ctx, flagsDeleteTenantOverrideRequest{Key: "f1", TenantID: "t1"}, p)
			return err
		}},
		{"flags.delete", "flag.deleted", func() error {
			_, err := flagsDeleteHandler(deps)(ctx, flagsDeleteRequest{Key: "f1"}, p)
			return err
		}},
		{"config.create", "config.set", func() error {
			_, err := configCreateHandler(deps)(ctx, decodeCommand[configCreateRequest](t, `{"key":"c1","valueType":"string","value":"a"}`), p)
			return err
		}},
		{"config.update", "config.set", func() error {
			_, err := configUpdateHandler(deps)(ctx, decodeCommand[configUpdateRequest](t, `{"key":"c1","value":"b"}`), p)
			return err
		}},
		{"config.rollback", "config.rolled_back", func() error {
			_, err := configRollbackHandler(deps)(ctx, configRollbackRequest{Key: "c1", Version: 1}, p)
			return err
		}},
		{"overrides.set", "override.set", func() error {
			_, err := overridesSetHandler(deps)(ctx, decodeCommand[overridesSetRequest](t, `{"key":"c1","tenantId":"t1","value":"x"}`), p)
			return err
		}},
		{"overrides.delete", "override.deleted", func() error {
			_, err := overridesDeleteHandler(deps)(ctx, overridesDeleteRequest{Key: "c1", TenantID: "t1"}, p)
			return err
		}},
		{"config.delete", "config.deleted", func() error {
			_, err := configDeleteHandler(deps)(ctx, configDeleteRequest{Key: "c1"}, p)
			return err
		}},
	}

	for _, s := range steps {
		before := len(auditRows(t, v))
		if err := s.run(); err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
		rows := auditRows(t, v)
		fresh := rows[:len(rows)-before] // newest first
		if len(fresh) == 0 {
			t.Fatalf("%s wrote no audit row", s.name)
		}
		found := false
		for _, r := range fresh {
			if r.Action == s.want {
				found = true
			}
			if r.UserID != operatorSubject {
				t.Errorf("%s: row %s has user %q, want %q", s.name, r.Action, r.UserID, operatorSubject)
			}
		}
		if !found {
			t.Errorf("%s: no %s row among %d new rows", s.name, s.want, len(fresh))
		}
	}
}

// A command with no principal, or one with no subject, writes no user.
func TestCommandWithoutAPrincipalWritesNoUser(t *testing.T) {
	v, _ := newTestVault(t)
	deps := Deps{Vault: v}
	ctx := context.Background()

	for i, p := range []dashcontract.Principal{{}, {User: &dashauth.UserInfo{}}} {
		if _, err := flagsCreateHandler(deps)(ctx, flagsCreateRequest{Key: fmt.Sprintf("np%d", i), Type: "bool", DefaultValue: true}, p); err != nil {
			t.Fatal(err)
		}
	}
	rows := auditRows(t, v)
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
	for _, r := range rows {
		if r.UserID != "" {
			t.Errorf("row %s has user %q, want none", r.Action, r.UserID)
		}
	}
}

// A query never puts a user on the log: no query writes a row, and the
// principal it was given must not leak onto the context a later write uses.
func TestQueriesWriteNoUser(t *testing.T) {
	v, _ := newTestVault(t)
	deps := Deps{Vault: v}
	ctx := context.Background()
	p := operatorPrincipal

	if _, err := v.Secrets().Set(ctx, "q", []byte("v"), testAppID); err != nil {
		t.Fatal(err)
	}
	if _, err := flagsCreateHandler(deps)(ctx, flagsCreateRequest{Key: "qf", Type: "bool", DefaultValue: true}, dashcontract.Principal{}); err != nil {
		t.Fatal(err)
	}
	if _, err := configCreateHandler(deps)(ctx, decodeCommand[configCreateRequest](t, `{"key":"qc","valueType":"string","value":"a"}`), dashcontract.Principal{}); err != nil {
		t.Fatal(err)
	}
	before := len(auditRows(t, v))

	queries := map[string]func() error{
		"secrets.list":   func() error { _, err := secretsListHandler(deps)(ctx, secretsListRequest{Limit: 10}, p); return err },
		"secrets.detail": func() error { _, err := secretsDetailHandler(deps)(ctx, secretsDetailRequest{Key: "q"}, p); return err },
		"secrets.versions": func() error {
			_, err := secretsVersionsHandler(deps)(ctx, secretsVersionsRequest{Key: "q"}, p)
			return err
		},
		"flags.list":    func() error { _, err := flagsListHandler(deps)(ctx, flagsListRequest{Limit: 10}, p); return err },
		"flags.detail":  func() error { _, err := flagsDetailHandler(deps)(ctx, flagsDetailRequest{Key: "qf"}, p); return err },
		"config.list":   func() error { _, err := configListHandler(deps)(ctx, configListRequest{Limit: 10}, p); return err },
		"config.detail": func() error { _, err := configDetailHandler(deps)(ctx, configDetailRequest{Key: "qc"}, p); return err },
		"config.versions": func() error {
			_, err := configVersionsHandler(deps)(ctx, configVersionsRequest{Key: "qc"}, p)
			return err
		},
		"overrides.list": func() error {
			_, err := overridesListHandler(deps)(ctx, overridesListRequest{Key: "qc"}, p)
			return err
		},
		"rotation.policies": func() error {
			_, err := rotationPoliciesHandler(deps)(ctx, rotationPoliciesRequest{Limit: 10}, p)
			return err
		},
	}
	for name, run := range queries {
		if err := run(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}

	rows := auditRows(t, v)
	if len(rows) != before {
		t.Errorf("queries wrote %d audit rows, want none", len(rows)-before)
	}
	for _, r := range rows {
		if r.UserID != "" {
			t.Errorf("row %s has user %q after queries", r.Action, r.UserID)
		}
	}
}

// A failed manual rotation records who ran it, and why it failed.
func TestRotateNowFailureRecordsOperatorAndError(t *testing.T) {
	v, _ := newTestVault(t)
	deps := Deps{Vault: v}
	ctx := context.Background()
	if _, err := v.Secrets().Set(ctx, "rk", []byte("v"), testAppID); err != nil {
		t.Fatal(err)
	}
	v.Rotation().RegisterRotator("rk", func(context.Context, []byte) ([]byte, error) {
		return nil, errRotatorBoom
	})

	if _, err := rotationRotateNowHandler(deps)(ctx, rotationRotateNowRequest{Key: "rk"}, operatorPrincipal); err == nil {
		t.Fatal("want an error from a failing rotator")
	}
	rows, err := v.Store().ListAudit(ctx, testAppID, audit.ListOpts{Limit: 50, Action: "secret.rotated", Outcome: "failure"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("failure rows = %d, want 1", len(rows))
	}
	if rows[0].UserID != operatorSubject || rows[0].Key != "rk" {
		t.Errorf("row = %+v", rows[0])
	}
	if msg, _ := rows[0].Metadata["error"].(string); msg == "" || !strings.Contains(msg, errRotatorBoom.Error()) {
		t.Errorf("metadata = %v, want the rotator's error text", rows[0].Metadata)
	}
}

var errRotatorBoom = errors.New("rotator exploded")
