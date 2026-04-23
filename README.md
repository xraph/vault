# Vault

Composable secrets, feature flags, and runtime config for Go.

Vault is a Go library that unifies three capabilities behind a single API surface: **encrypted secrets**, **rule-based feature flags**, and **hot-reloadable runtime configuration**. It is a library, not a service — you import it, bring your own database and encryption key, and control the process lifecycle. Vault provides the plumbing: encryption, versioning, tenant-scoped evaluation, rotation, audit, and a plugin system for extending every subsystem.

Vault is part of the Forge ecosystem and integrates cleanly with [Forge](https://github.com/xraph/forge) extensions, [Grove](https://github.com/xraph/grove) ORM stores, and [Confy](https://github.com/xraph/confy) config sources — but none of them are required to use it standalone.

## Features

**Secrets**
- AES-256-GCM encryption at rest, transparent decryption on read
- Auto-versioning — every `Set` archives the previous value; fetch any historical version by number
- Environment-variable key provider with hex/base64 auto-detection
- Optional metadata (expiration, custom fields)

**Feature flags**
- Five value types: `bool`, `string`, `int`, `float`, `json`
- Six targeting rule types: `WhenTenant`, `WhenTenantTag`, `WhenUser`, `Rollout` (deterministic %), `Schedule` (time window), `Custom` (plugin-evaluated)
- Priority-ordered evaluation with per-tenant overrides
- Type-safe accessors (`Bool`, `String`, `Int`, `Float`, `JSON`) that return a default on error
- LRU evaluation cache with configurable TTL (default 30s)

**Runtime configuration**
- Typed entries (`string`, `bool`, `int`, `float`, `json`) with `Duration` parsing
- Per-tenant overrides resolved ahead of the app-level value
- Version tracking and `Watch` callbacks fired on mutation
- Composable sources: memory, env, database, priority chain

**Cross-cutting**
- **Tenant isolation by design** — `scope.WithTenantID(ctx, ...)` propagates to every service via `context.Context`; cross-tenant reads are structurally impossible
- **Secret rotation** — background manager with per-key `Rotator` callbacks, automatic versioning, and record-keeping
- **Audit logging** — append-only trail of action/resource/outcome with full scope context; optional hook for forwarding to external systems
- **Plugin system** — register plugins that implement any subset of eight capability interfaces (`OnInit`, `OnShutdown`, `SourceProvider`, `EncryptionProvider`, `FlagEvaluator`, `OnSecretAccess`, `OnConfigChange`, `RotationStrategy`)
- **TypeID identifiers** — every entity uses type-prefixed, K-sortable UUIDv7 IDs (`sec_`, `flag_`, `cfg_`, …); passing the wrong prefix fails at parse time

## Install

```bash
go get github.com/xraph/vault
```

## Quick start

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/xraph/vault/config"
    "github.com/xraph/vault/crypto"
    "github.com/xraph/vault/flag"
    "github.com/xraph/vault/scope"
    "github.com/xraph/vault/secret"
    "github.com/xraph/vault/store/memory"
)

func main() {
    ctx := scope.WithScope(context.Background(), "myapp", "tenant-1", "user-42", "10.0.0.1")

    store := memory.New()

    enc, err := crypto.NewEncryptor([]byte("my-32-byte-secret-key-for-vault!"))
    if err != nil {
        log.Fatal(err)
    }

    // Secrets — encrypted, auto-versioned
    secrets := secret.NewService(store, enc, secret.WithAppID("myapp"))
    meta, _ := secrets.Set(ctx, "openai-api-key", []byte("sk-abc123"), "myapp")
    sec, _ := secrets.Get(ctx, "openai-api-key", "myapp")
    fmt.Printf("secret v%d = %s\n", meta.Version, sec.Value)

    // Feature flags — evaluated against context scope
    flags := flag.NewService(flag.NewEngine(store), flag.WithAppID("myapp"))
    if flags.Bool(ctx, "new-dashboard", false) {
        fmt.Println("new dashboard enabled")
    }

    // Runtime config — typed accessors with defaults
    cfg := config.NewService(store, config.WithAppID("myapp"))
    _ = cfg.Set(ctx, "rate-limit", 100, "myapp")
    fmt.Printf("rate limit = %d\n", cfg.Int(ctx, "rate-limit", 50))
}
```

See [docs/content/docs/getting-started.mdx](docs/content/docs/getting-started.mdx) for a step-by-step walkthrough covering rule-based flags, tenant overrides, rotation, and swapping in a production store.

## Storage backends

Every backend satisfies the same composite [`store.Store`](store/store.go) interface — secrets, flags, config, overrides, rotation, and audit — so switching stores is a single type change. All expose `Migrate`, `Ping`, and `Close`.

| Backend | Import | Use case |
| --- | --- | --- |
| Memory | `github.com/xraph/vault/store/memory` | Tests, development, single-process demos |
| PostgreSQL | `github.com/xraph/vault/store/postgres` | Production, direct `pgx` connection pool |
| SQLite | `github.com/xraph/vault/store/sqlite` | Embedded deployments, local-first apps (via Grove) |
| MongoDB | `github.com/xraph/vault/store/mongo` | Document-oriented workloads (`mongo-driver/v2`) |
| Grove | `github.com/xraph/vault/store/grovestore` | Apps already using the Grove ORM |

## Architecture at a glance

Vault is organised as a root package with shared types, six service packages implementing domain logic, supporting packages for encryption/scoping/sources, and a set of store backends implementing one composite interface.

- Services — [secret/](secret/), [flag/](flag/), [config/](config/), [override/](override/), [rotation/](rotation/), [audit/](audit/)
- Supporting — [crypto/](crypto/) (AES-256-GCM), [id/](id/) (TypeID), [scope/](scope/) (context keys), [source/](source/) (memory/env/database/chain), [plugin/](plugin/), [audit_hook/](audit_hook/), [metrics/](metrics/)
- Stores — [store/memory/](store/memory/), [store/postgres/](store/postgres/), [store/sqlite/](store/sqlite/), [store/mongo/](store/mongo/), [store/grovestore/](store/grovestore/)
- Integrations — [extension/](extension/) (Forge), [confy/](confy/) (Confy), [dashboard/](dashboard/) (Templ UI)

Every operation follows the same three-phase flow: **scope** the context → **resolve** the value (tenant override → rule match → default) → **respond** with a coerced type or the caller's default on error. See [docs/content/docs/architecture.mdx](docs/content/docs/architecture.mdx) for the full package diagram and request-flow breakdown.

## Ecosystem integration

**Forge extension.** Mount Vault as a Forge extension to auto-wire the store, encryption, audit hooks, and a management dashboard into your Forge app. See [extension/](extension/) and [docs/content/docs/guides/forge-extension.mdx](docs/content/docs/guides/forge-extension.mdx).

**Confy source.** Adapt Vault as a Confy `ConfigSource` and `SecretProvider` so a single `confy.Load` call pulls typed config and encrypted secrets through Vault alongside your other sources. See [confy/](confy/) and [docs/content/docs/guides/confy-integration.mdx](docs/content/docs/guides/confy-integration.mdx).

## Configuration

The root [`Config`](config.go) struct controls instance-wide behaviour. All fields have sensible defaults via `DefaultConfig()`.

| Field | Purpose | Default |
| --- | --- | --- |
| `AppID` | Application identifier used to scope secrets, flags, and config | — |
| `EncryptionKey` | 32-byte AES-256-GCM master key | — |
| `EncryptionKeyEnv` | Fallback environment variable holding the key (hex or base64) | — |
| `FlagCacheTTL` | TTL for the flag evaluation cache | `30s` |
| `SourcePollInterval` | Interval for polling database-backed config sources | `30s` |

Matching functional options live in [options.go](options.go): `WithAppID`, `WithEncryptionKey`, `WithEncryptionKeyEnv`, `WithLogger`, `WithConfig`.

## Development

The [Makefile](Makefile) exposes short aliases for the common workflows:

```sh
make test         # go test ./...
make test-race    # go test -race ./...
make coverage     # coverage.out + function-level summary
make coverage-html
make lint         # golangci-lint run ./...
make fmt          # gofmt + goimports
make check        # fmt + vet + lint
make docs         # serve the Next.js docs site at http://localhost:3000
make deps         # install goimports, air, golangci-lint
```

Requires Go 1.25+. See [go.mod](go.mod) for the full dependency set.

## Documentation

A full documentation site lives under [docs/](docs/) and can be served locally with `make docs`. Key pages:

- [Getting started](docs/content/docs/getting-started.mdx) — eight-step walkthrough from install to Postgres
- [Architecture](docs/content/docs/architecture.mdx) — package diagram, request flow, plugin system, package index
- Concepts — [entities](docs/content/docs/concepts/entities.mdx), [multi-tenancy](docs/content/docs/concepts/multi-tenancy.mdx), [identity](docs/content/docs/concepts/identity.mdx), [errors](docs/content/docs/concepts/errors.mdx)
- Subsystems — [secrets](docs/content/docs/subsystems/secrets.mdx), [feature flags](docs/content/docs/subsystems/feature-flags.mdx), [runtime config](docs/content/docs/subsystems/runtime-config.mdx), [overrides](docs/content/docs/subsystems/overrides.mdx), [rotation](docs/content/docs/subsystems/rotation.mdx), [audit](docs/content/docs/subsystems/audit.mdx), [encryption](docs/content/docs/subsystems/encryption.mdx), [sources](docs/content/docs/subsystems/sources.mdx), [plugins](docs/content/docs/subsystems/plugins.mdx), [observability](docs/content/docs/subsystems/observability.mdx)
- Stores — [memory](docs/content/docs/stores/memory.mdx), [postgres](docs/content/docs/stores/postgres.mdx), [sqlite](docs/content/docs/stores/sqlite.mdx), [mongo](docs/content/docs/stores/mongo.mdx), [grove](docs/content/docs/stores/grove.mdx)
- Guides — [full example](docs/content/docs/guides/full-example.mdx), [custom store](docs/content/docs/guides/custom-store.mdx), [Forge extension](docs/content/docs/guides/forge-extension.mdx), [Confy integration](docs/content/docs/guides/confy-integration.mdx), [multi-tenant patterns](docs/content/docs/guides/multi-tenant-patterns.mdx)

## Status

Actively developed. Core service APIs (secret, flag, config) are stable; storage backends and the Forge/Confy integrations continue to evolve — see recent commits on `main`.

## License

See the repository root for licensing.
