# AGENTS.md

Vault is a Go library for encrypted secrets, rule-based feature flags and runtime config, with per-tenant overrides, secret rotation and an audit trail on top. There's no binary. You import the package, hand `vault.New` a store and an encryption key, and the process lifecycle stays yours.

The module is `github.com/xraph/vault`. There is one `go.mod`, at the root, and that root module is the only thing the release workflow tags.

## Commands

Run everything from the repo root. This repo has no `go.work` and CI builds without one, so prefix with `GOWORK=off` if a workspace further up your tree could leak in.

| What | Command |
|---|---|
| Build | `GOWORK=off go build ./...` |
| Tests | `make test` (runs `go test -v ./...`) |
| Race tests | `make test-race` |
| Coverage | `make coverage`, or `make coverage-html` for the HTML report |
| Vet | `make vet` |
| Lint | `make lint` (golangci-lint v2 with `.golangci.yml`) |
| Lint and fix | `make lint-fix` |
| Format | `make fmt` (`gofmt -s -w`, then `goimports -local github.com/xraph/vault`) |
| Format, vet, lint | `make check` |
| Tidy | `make tidy` (`go mod tidy`, then `go mod verify`) |
| Docs site | `make docs` or `make docs-build` (pnpm, inside `docs/`) |

Skip `make build`, `make run`, `make install` and `make dev`. All four point at `./cmd/vault`, which doesn't exist.

CI lives in `.github/workflows/ci.yml`. Its `ci` job calls the shared `xraph/workflows/.github/workflows/go-ci.yml@v1` on Go 1.26, Ubuntu only, and that workflow runs `make test` (it prefers a Makefile target when one exists), a race-enabled coverage run, golangci-lint, a `gofmt -l` check, `make vet`, a `go mod tidy` diff check, gosec and govulncheck. A separate `format` job fails on any file that `goimports -l -local github.com/xraph/vault .` lists. A `docs` job type-checks, lints and builds the Fumadocs site with pnpm. Run `make fmt` before you push.

### What the tests need

A plain `go test ./...` covers the memory and SQLite stores and everything that sits on top of them. SQLite is pure Go here (modernc), and each test opens a temp-file database under `t.TempDir()`, so you don't need anything installed.

Postgres and Mongo need a real server. Both skip silently without one.

- `store/postgres` tests carry `//go:build integration` and read `VAULT_TEST_PG_URL`. Without the tag they aren't compiled at all; with the tag and no URL they call `t.Skip`. They `DELETE FROM` every `vault_*` table before each test, so point them at a throwaway database.
- `store/mongo` tests have no build tag. They read `VAULT_TEST_MONGO_URL`, skip without it, and create a database per test (`vault_test_<test>_<nanos>`) that they drop on cleanup.

```bash
VAULT_TEST_PG_URL='postgres://user:pass@localhost:5432/vault_test?sslmode=disable' \
  GOWORK=off go test -tags integration ./store/postgres/...
VAULT_TEST_MONGO_URL='mongodb://localhost:27017' GOWORK=off go test ./store/mongo/...
```

CI sets neither variable and starts no database, which means a green CI run tells you nothing about the Postgres or Mongo stores, and if you touch either one you have to run its suite yourself against a local server before you call the change done.

Shared conformance tests live in `internal/storetest` (`RunSecretExpiry`, `RunVersionEncryption`), and every backend calls them. If you add behaviour all four stores must share, put the test there.

## Layout

| Path | What lives there |
|---|---|
| `vault.go`, `options.go`, `config.go` | The `Vault` type, `New(opts ...Option)`, `Config` and its defaults |
| `aliases.go`, `id.go` | Re-exports of `core` and `id` types, so callers can write `vault.ErrSecretNotFound` and `vault.ID` |
| `core/` | Leaf package: `Entity` and every sentinel error. Imports nothing from vault |
| `id/` | TypeID-based `ID` with entity prefixes (`sec`, `flag`, `rule`, `cfg`, `ovr`, `rot`, `ver`, `vaudit`) |
| `secret/`, `flag/`, `config/`, `override/`, `rotation/`, `audit/` | One subsystem each: entity types, a `Store` interface, and the service or manager |
| `configmgr/` | Write service for config entries and their overrides. It needs both stores, so it can't sit in either package |
| `scope/` | Context keys and helpers for app, tenant, user and IP |
| `crypto/` | AES-256-GCM encryptor and the encryption key providers, including the env var one |
| `source/` | Config sources (memory, env, database) and a priority chain |
| `plugin/` | Plugin base interface, the optional capability interfaces, and the registry |
| `metrics/` | Deprecated metric interfaces nothing records through. Real metrics go through `vault.WithMetrics` |
| `confy/` | Adapter that exposes vault as a confy config source and secret provider |
| `audit_hook/` | Forwards audit events to an external `Recorder` |
| `store/` | `store.Store`, the composite interface, plus the `memory`, `postgres`, `sqlite` and `mongo` backends |
| `extension/` | The Forge extension, its options and YAML config |
| `extension/contract/` | Dashboard contract contributor: the embedded `manifest.yaml` and the intent handlers |
| `internal/storetest/` | Shared store conformance tests |
| `internal/telemetry/` | Span helpers, metric names and label vectors over a go-utils sink. Every span and metric vault records goes through it |
| `internal/telemetrytest/` | Span recorder, fake metrics sink and leak assertions for tests |
| `docs/` | Fumadocs site (Next.js, pnpm) |

`MIGRATION.md` records, page by page, how the dashboard moved from templ to the React shell. `api/`, `encryption/`, `middleware/`, `telemetry/` and `_examples/` exist on disk but hold no tracked files.

## Conventions

Subsystem packages import `core`. Never the root. The root imports every subsystem to compose `Vault`, so if `secret/` or `flag/` reached back for `github.com/xraph/vault` you'd have a cycle; store backends and `extension/` sit downstream of the root and import it freely.

Errors are sentinels declared once in `core/errors.go` with a `vault:` prefix. `aliases.go` re-exports the same values (not copies), so `errors.Is` matches either name. Backends map their driver's not-found error to the sentinel, for example `sql.ErrNoRows` to `vault.ErrSecretNotFound`. When you wrap, use `%w` and a package prefix such as `vault/sqlite: create migration executor: %w`, and compare with `errors.Is`, since `errorlint` fails a `==` on errors.

IDs come from `id.New(prefix)` or the typed constructors like `id.NewSecretID()`. They're K-sortable UUIDv7 TypeIDs, and `id.ParseWithPrefix` rejects an ID with the wrong prefix. A new entity type gets its own `Prefix` constant in `id/id.go`.

Every backend implements `store.Store`, which embeds each subsystem's `Store` interface plus `Migrate`, `Ping` and `Close`. A new store method goes into the subsystem interface first, then into all four backends. The Postgres, SQLite and Mongo stores are built on grove with `New(db *grove.DB, opts ...StoreOption)`, and each keeps its migrations in a `migrate.NewGroup("vault")` group in its own `migrations.go`. Append a new migration with the next `Version` and leave shipped ones alone. The SQLite store leaves the migration executor to the caller, so you import `github.com/xraph/grove/drivers/sqlitedriver/sqlitemigrate` for its side effect (the SQLite tests show how).

Options are functional: `type Option func(*Vault)` on the root, `type Option func(*Extension)` on the extension, `StoreOption` on the stores. `vault.WithConfig` overlays only non-zero fields, so it combines with the other options in any order.

Telemetry goes through `internal/telemetry`. Spans use the global tracer provider under the scope `github.com/xraph/vault`, and metrics go to the go-utils sink a package's `WithMetrics` option receives (nil records nothing). A long-lived loop calls `telemetry.Detach` once on the ctx it was handed, so its idle queries don't land in the starter's trace, and starts its spans with `telemetry.StartRoot` only when there's work. Nothing that names a secret, flag or config key, a value, a tenant or a user goes on a span or a label, and error text never goes on a span: mark failures with `telemetry.Fail` or `FailAs`. `docs/content/docs/subsystems/observability.mdx` lists every span and metric, so change it with them.

Logging goes through `github.com/xraph/go-utils/log`. The default is `log.NewNoopLogger()` and you pass a real one with `WithLogger`. Inside the extension you log with `e.Logger()` and `forge.F` fields.

Tenant scoping rides on `context.Context` through `scope` (`scope.WithTenantID`, `scope.WithScope`). Don't add tenant or app parameters to service methods. Contract handlers answer for `deps.Vault.AppID()` and never take an app ID on the request.

The Forge extension embeds `*forge.BaseExtension` and reads YAML under `extensions.vault` or `vault`. It looks for a store in this order: `WithStore`, then the named or default `*grove.DB` when `WithGroveDatabase` or `grove_database` is set, then any `*grove.DB` already in the vessel container, and it picks the backend from the grove driver name (`pg`, `sqlite`, `mongo`). It provides `*vault.Vault` and `store.Store` through `vessel.Provide`. `Start` launches the rotation loop and a version-encryption backfill; `Stop` cancels both before it closes the store. Keep forge's dashboard root package out of the extension's imports, because it would pull templ UI into every build. That's why the `ContractContributorAware` check lives in a test file.

`extension/contract/manifest.yaml` is embedded, and `manifest_test.go` asserts the intent count. Adding an intent means you change the manifest, its handler and that count together.

Lint rules that bite (from `.golangci.yml`):

- `errcheck` runs with `check-blank` and `check-type-assertions`, so `_ = f()` and unchecked type assertions fail outside tests. Where ignoring is right, the code says `//nolint:errcheck // reason`. Keep the reason, and delete the directive when it stops being needed: `nolintlint` is on.
- `govet` runs every analyzer except `fieldalignment`. That includes `shadow`, so a shadowed `err` in an inner scope fails lint.
- `revive` checks error strings, receiver names, context as the first argument and unused parameters.
- `gosec` runs outside tests with G104, G304 and G401 excluded. `noctx`, `bodyclose`, `rowserrcheck`, `sqlclosecheck` and `usetesting` are on too, so in new tests reach for `t.Context()`, `t.TempDir()` and `t.Setenv`.
- Imports follow goimports with `github.com/xraph/vault` as the local prefix: standard library, third party, then vault.

## Dependencies

Vault depends on these xraph modules (versions are in `go.mod`): `grove` with `drivers/mongodriver`, `drivers/pgdriver` and `drivers/sqlitedriver`, then `forge`, `confy`, `go-utils` and `vessel`. Downstream, `trove/extension` and `authsome` import vault.

Bump one xraph module at a time, then tidy:

```bash
GOWORK=off go get github.com/xraph/grove@vX.Y.Z
GOWORK=off go get github.com/xraph/grove/drivers/pgdriver@vX.Y.Z
GOWORK=off go mod tidy
```

Grove tags its drivers in lockstep with its root, so you move grove and all three drivers to the same version. CI's verify job runs `go mod tidy` and fails on any diff to `go.mod` or `go.sum`. Commit the tidied files. Never commit a `replace` that points at a sibling checkout such as `../grove`; it builds on your machine and nowhere else.

## Releasing

You cut a release by dispatching the release workflow. Never push a tag by hand.

1. Wait for CI on `main` to go green.
2. Check that every upstream xraph change vault needs is already released and pinned in `go.mod`.
3. Dispatch:

```bash
gh workflow run release.yml --ref main -f tag=vX.Y.Z
```

The tag keeps its leading `v`. `release.yml` creates the tag on the root module and pushes it, runs `go build ./...` and `go test -race -count=1 ./...`, and then creates a GitHub release whose notes come from `git log` since the previous tag. Mind the order. The tag is pushed before the build and tests run, so if they fail you're left with a published tag and no GitHub release, and the fix ships as the next patch version. `git tag --sort=-v:refname | head` shows where the line is.

After the release exists, `trove/extension` and `authsome` re-pin with `go get github.com/xraph/vault@vX.Y.Z`.

## Branches

`main` has no branch protection and no rulesets, so a push lands directly. CI runs on every push to `main` and on every pull request against it.
