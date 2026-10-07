# Dashboard migration: templ to React shell

Vault's dashboard used to render server-side with templ and ForgeUI, from
`vault/dashboard/`. It now lives in the Forge dashboard's React shell as
`@forge-go/dashboard-plugin-vault`, reading the `vault` contract contributor in
`extension/contract`. The templ package is gone.

This file is the record of that move. We wrote it by walking every templ page
before deleting it: 32 `.templ` files (17 pages, 12 components, 2 widgets and a
helpers file), plus `contributor.go`, `data.go` and `manifest.go`. Once the
directory is gone there is nothing left to check against, and anything not
written down here is a feature that went missing by accident. Every page,
column, action, filter, badge, empty state and widget is listed, and each one
says whether it moved, changed, was dropped, or is blocked, and why.

## What you need to do

If you ran the templ dashboard through `DashboardAware`, you don't need to do
anything in Vault. The extension no longer implements `DashboardAware`. It
registers the contract contributor through `ContractContributorAware`, and the
shell finds it. If your own code imports `github.com/xraph/vault/dashboard`
(its widgets, say), that import has to go: the package no longer exists.

Add the plugin to your shell:

```tsx
import vaultPlugin from "@forge-go/dashboard-plugin-vault"

const plugins = [corePlugin, vaultPlugin]
```

The plugin's pages use Tailwind classes of their own, so the shell's stylesheet
has to scan the package. If your shell declares its sources with `@source`, add
`@source "<path to>/packages/plugin-vault/src";` next to the others.

Vault now needs forge v1.12.0 and grove v1.7.0. On forge v1.10.0 the dashboard
transport never passed a manifest's `invalidates` to the client, so no write
refreshed any page. Vault declares its cache hints in
`extension/contract/manifest.yaml` and returns none from its handlers, and that
is the case v1.10.0 dropped. v1.12.0 is also the first forge whose dashboard
contract doesn't pull in templ, so with it vault builds without `a-h/templ` or
`forgeui` at all. `go.mod` pins both versions already; if a workspace `replace`
or another module holds them back, lift it.

The extension now starts the rotation loop, on every replica. Each minute the
loop looks for enabled policies whose rotation is due. Before it rotates one,
it claims the policy through `rotation.Store.ClaimDueRotation`, which moves the
due time forward by a five minute lease, so only one replica rotates a given
policy. A replica with no rotator registered for a key never claims that key's
policy. A rotation that fails is retried when the lease runs out, not every
minute. The loop also returns at once when the app id is empty
(`checkDuePolicies` in `rotation/manager.go`), so a vault with an empty
`app_id` never rotates on a schedule. Rotators are still registered in
application code with `RegisterRotator`, and a policy for a key nobody
registered a rotator for does nothing.

The extension also runs a version-encryption backfill on every start, on every
replica, in the background. Start doesn't wait for it, and Stop cancels it and
waits for it to return. It looks at the version rows whose algorithm was never
recorded (every version written before this release) and tries the configured
key on each. A row the key decrypts is marked encrypted. A row it can't decrypt
is left alone, because a failed decrypt can't tell plaintext from a value
sealed with some other key, so those rows are read again on each start. With
no key configured it reads nothing. When it finishes it logs how many rows it
marked.

`enable_audit` is deprecated, and so is `WithEnableAudit`. Audit is always on,
whatever you set. Drop the setting the next time you touch your config.

A named key variable that is missing now refuses to start. If
`encryption_key_env` names an environment variable that is unset or empty,
`vault.New` returns an error and the extension fails to start. Before, it
started and wrote plaintext while you believed it was encrypting. Set the
variable, or delete the name to run without encryption on purpose. A key that is
present but can't be decoded fails the same way.

If you call Vault from Go, you will notice these changes:

- `vault.NewVault`, which returned a stub, is gone. `vault.New(opts...)` returns
  `(*Vault, error)` and composes the real services. `Secrets()`, `Flags()`,
  `FlagEngine()`, `FlagManager()`, `Config()`, `ConfigManager()`, `Overrides()`,
  `Rotation()`, `Audit()` and `Store()` all work.
- `flag.WithOnFlagMutate` is new since v1.6.4, an option for the new
  `flag.Manager`. Its callback is
  `func(ctx, action, key, appID, tenantID string)`. The tenant is the one a
  per-tenant override write targets, and empty for writes to the flag itself.
- `rotation.Store` has a new method, `ClaimDueRotation(ctx, key, appID string,
  now, until time.Time) (bool, error)`. It must claim atomically: two callers
  racing on one policy get one `true` between them.
- The store interfaces gained counts, and a custom store has to implement all of
  them. `secret.Store` gets `CountSecrets` and `CountSecretsUnencrypted`.
  `flag.Store` gets `CountFlagDefinitions` and `CountFlagDefinitionsMatching`.
  `config.Store` gets `CountConfig` and `CountConfigMatching`. `override.Store`
  gets `CountOverrides`. `rotation.Store` gets `CountRotationPolicies` (and
  `ClaimDueRotation`, above). `audit.Store` gets `CountAudit` and
  `CountAuditMatching`. A `...Matching` count and its list must apply the same
  filter, or a page and its total disagree.
- `secret.Store` has four more methods for version encryption and expiry.
  `CountSecretsMatching(ctx, appID, opts)` counts what `ListSecrets` would list
  for the same options. `ListUnrecordedVersions(ctx, appID, after, limit)`
  returns version rows whose algorithm was never recorded, in ascending id
  order, starting strictly after the id `after` (empty means from the start).
  `SetVersionEncryption(ctx, versionID, alg)` records one row's algorithm, and
  an unknown id returns nil. `CountVersionEncryption(ctx, appID)` tallies the
  earlier version rows recorded as plaintext and the ones never recorded,
  leaving out each secret's current version, which `CountSecretsUnencrypted`
  already covers. If your `ListUnrecordedVersions` ignores `after`, the
  backfill stops with an error the first time a full page doesn't move past
  the cursor.
- A custom store's `SetSecret` has to record the version row's algorithm too:
  a non-nil `Version.EncryptionAlg`, set to the secret's `EncryptionAlg` (empty
  for plaintext). Its `GetSecretVersion` has to return the version's own
  algorithm when one is recorded, and the current row's only when it isn't.
  Without that, a version written before a key change is read with the current
  row's algorithm, and decrypts wrongly or not at all.
- `secret.Service.GetVersion` now refuses an encrypted version with
  `core.ErrDecryptionFailed` when no key is configured. It used to hand back
  the ciphertext as the value.
- The audit log writes `secret.get` when a secret is read. The declared constant
  `audit_hook.ActionSecretAccessed` (`secret.accessed`) is never written, so
  filter on `secret.get`.
- The list options grew filters that every backend must honour in the query
  itself, never after paging: `audit.ListOpts` takes `Resource`, `Key`,
  `Action`, `Outcome`, `Since` and `ExcludeActions`; `flag.ListOpts` takes
  `Type`; `config.ListOpts` takes `KeyPrefix`, matched case-sensitively;
  `secret.ListOpts` takes `ExpiresAfter` (exclusive, `expires_at > t`) and
  `ExpiresBefore` (inclusive, `expires_at <= t`). When either is set, a secret
  with no expiry is left out and the list is ordered by expiry, then key.
  `CountSecretsMatching` must apply exactly the same bounds. Expired is
  `ExpiresBefore = now`, so a secret that expires exactly now is expired and
  never also "expiring".
- `secret.Meta` has an `EncryptionAlg` field. Empty means the row is stored
  unencrypted. A custom store's `ListSecrets` has to fill it in.
- `confy.NewVaultSecretProvider` and `confy.NewVaultConfigSource` take a secret
  service (`SecretService` and `SecretReader`) instead of a `secret.Store`.
  Reading through the store returned an empty string for every secret on a real
  backend, because no backend keeps the decrypted value.
- The tenant and user context keys are one type across `scope`, `flag` and
  `override`. A tenant you set with `scope.WithTenantID` now reaches flag
  evaluation and override resolution, so a request context that already carries
  a tenant will now drive `when_tenant` rules, rollouts and overrides.
- The memory store no longer keeps a decrypted `Value`, so it behaves like
  postgres, sqlite and mongo.
- `Entity` and the sentinel errors moved to `vault/core`. `vault.Entity` and
  `vault.Err...` are aliases of the same values, so `errors.Is` keeps matching.

This release changes the schema, and `Migrate` (or the `Migrations` group
your host runs) has new steps:

- Postgres and sqlite `20240101120011` adds a nullable `encryption_alg` column
  to `vault_secret_versions`. `NULL` means never recorded, `''` plaintext.
- Postgres and sqlite `20240101120012` adds the indexes
  `idx_secrets_app_expires` on `(app_id, expires_at)` and
  `idx_secret_versions_app_alg` on `(app_id, encryption_alg)`. Postgres's
  `Store.Migrate()` runs the same statements as its group.
- Mongo `20240101000012` adds the same two indexes.
- Mongo `20240101000013` fixes the validators the group put on every vault
  collection. They typed a flag's default, a rule's return value and every
  config or override value as a string, and refused a null map or list, so on
  a host that ran the group a secret saved without metadata, a boolean flag
  and most audit rows were rejected. The migration regenerates each validator
  with those value fields untyped and maps and lists allowed to be null, at
  the moderate level. The store now writes `{}` and `[]` for empty maps and
  lists as well. `Store.Migrate()` never created validators, so hosts on it
  saw none of this.

One limit remains, and nothing on the dashboard fixes it. A version written as plaintext before this release has no recorded
algorithm, and the backfill can't classify it (a failed decrypt looks the same
for plaintext and for another key). It shows as "Unknown" in the secret's
history and counts in the overview's "Vault can't tell how N older versions
were stored". While the secret's current value is plaintext, that old version
still reads back correctly. Once you replace the current value with a key
configured, reading the old version fails with a decrypt error. It never
returns the wrong bytes. If you know those rows were stored in the clear, set
the algorithm to empty in the store and they read and count as plaintext from
then on:

```sql
UPDATE vault_secret_versions SET encryption_alg = ''
 WHERE app_id = '<app>' AND secret_key = '<key>' AND version = <n>;
```

On mongo, `$set: {encryption_alg: ""}` on the same rows in
`vault_secret_versions`.

## Bugs found on the way

Reading the domain closely enough to build the React pages turned up bugs the
templ pages had been hiding. All of them are fixed.

- Secret create wrote an empty encrypted value and a zero ID. It called
  `store.SetSecret` with only `Value` set, and every backend discards `Value`.
  The contract goes through `secret.Service.Set`, which encrypts and assigns an
  ID.
- The secret create form had an "Expires At" field that the handler never read.
  Whatever you typed there was thrown away.
- The audit log was never written. Nothing constructed `audit.Logger`, so the
  Audit page, the Recent Audit widget and the audit card on secret detail all
  read a table nobody wrote to. The logger is now wired into
  `secret.Service`'s `WithOnAccess` and `WithOnMutate` hooks, the flag manager,
  the config manager and the rotation manager.
- Scheduled rotation never ran. Nothing started `rotation.Manager`'s loop, so
  the "next rotation" the templ page showed never happened.
- The "Rotate Now" button on the rotation page did nothing. It sent
  `action=rotate_now` and no code read that parameter, so the page just
  reloaded.
- Every update and every rotation erased the secret's expiry and metadata,
  because `Set` builds a fresh row and the backends upsert both columns from it.
- A policy saved from the dashboard never fell due: `NextRotationAt` was only
  ever set after a rotation.
- The rotation loop claimed a policy before checking it had a rotator, so a
  policy on a key nothing could rotate was claimed, failed and pushed out by a
  lease every five minutes, forever. A second `Start` also leaked the first
  loop.
- A rotation looked like a secret read plus a write, and a failed one left only
  the read. The scheduled loop's retry lease made a failing policy look
  healthy. Rotation now writes `secret.rotated` rows, failures included, and
  keeps the row when the client disconnects mid-rotation.
- Flag create stored every default as a string. A bool flag got `"true"`, an int
  got `"42"`, so every non-string flag made there evaluated to the caller's own
  fallback. Those rows still exist: the new pages mark each one "Wrong type" and
  leave the fix to you, since only you know the value you meant.
- Flag create set no ID, so the second flag made there failed on a unique
  violation on sqlite, postgres and mongo. It also overwrote an existing key,
  type included, because `DefineFlag` is an upsert.
- Flag create took the app id from a form field, and the detail page took it
  from the query string, so either could read or write another app's flags. The
  config and override pages did the same.
- Enable and disable ran over GET, with no cache invalidation and no audit row,
  so a disabled flag kept answering from cache for up to 30 seconds.
- The flag list and detail pages swallowed store errors into their empty
  states, and the list counted at most 100 flags. The other lists did the same.
- The flag store accepted rules and overrides for a key that did not exist, and
  they attached themselves to whatever flag got that key later. Mongo also
  removed the flag before its rules, so a failed cleanup left orphans that a
  retry could never reach.
- Config create stored every value as the raw string from the form, whatever its
  type, set no ID (so the second create failed on sqlite and postgres), and
  overwrote an existing key. Edit turned invalid JSON into a string and silently
  retyped any label outside six known ones to "string".
- Deleting a config key left its overrides behind. They kept answering for their
  tenants and came back when the key was recreated. Delete now removes them
  first, create clears any left over, and an orphan that survives anyway (from
  `config.Service.Delete`, which the dashboard doesn't use) can be removed from
  the overrides page. Mongo deleted a config before its versions, which left
  the same kind of orphan.
- A rollback through `config.Service.Set` relabelled the type and wiped the
  description and metadata, and `GetConfigVersion` reported the old value under
  the current type. Versions only ever stored the value.
- A config type change checked the new value but not the tenant overrides, so a
  string override stayed a string after the entry became an int and that tenant
  silently read the caller's fallback. It is now refused, naming the first
  tenant.
- A config save that changed nothing minted a version. The check compared
  marshalled bytes, which differ for the same object on mongo. It now compares
  values.
- The overrides page showed only the overrides of the first 100 keys, took the
  app id from the request, and could not change anything. Nothing audited config
  or override writes.
- Sqlite matched a config key prefix case-insensitively, so `Billing/` also
  listed `billing/plans` where the other backends did not.
- The audit page filtered in memory over the newest 100 rows, had no paging,
  showed the page's length as its count, and printed times with no year or zone.
  Every row said "success", because nothing ever wrote a failure, and no row
  carried a user. A flag override row did not say which tenant it was about.
- The overview's Overrides card was always 0, because nothing set it. Every
  count was capped at 10000 by a list limit, and any error showed as 0.
- The settings page showed "Audit Logging: Disabled" forever, from a config
  field nothing read, and only one of its nine fields, App ID, was ever passed in.
- The tenant and user context keys were three different types that shared
  string values, so a tenant set with `scope.WithTenantID` never reached flag
  evaluation or override resolution.
- confy returned an empty string for every secret on a real backend.
- The flag evaluation cache never evicted anything, nothing invalidated it, and
  an evaluation already in flight could put a stale value back after an
  invalidation.
- A named encryption key variable that was missing fell back to plaintext
  without a word.
- Dashboard writes refreshed nothing against a real server on forge v1.10.0. The
  fixture hid it, because it builds its meta itself.
- A non-UTC secret expiry round-tripped through sqlite as a string the store
  could not parse back, and one such row made the whole app's secret list fail.

## Deliberately dropped

- The settings page and the settings panel `vault-config`. Of its nine fields
  only App ID was ever passed in, and the Encryption card (algorithm, key size,
  nonce) was hardcoded constants. `encryptionEnabled` moved to
  `overview.stats`.
- The Overrides stat on the overview, as it was. It was never populated and
  always read zero. It is replaced by a real count.
- `secrets.setExpiry`. Nothing in the store or the service changes an expiry
  without rewriting the value, and the server can't read the value back under
  the write-only decision. You set an expiry on create and change it when you
  replace the value.
- The key filter on the secrets list. The templ page filtered the first 100 rows
  after reading them and reported that as a complete search. A real filter needs
  a store filter across four backends.
- The `yaml` type on the flag create page, and on the config create page. It was
  never a flag type: the engine and every typed reader ignore it. Config has six
  types and yaml is not one of them.
- The flag list's free-text type box. It is a type select now, backed by a real
  store filter, so the page and the total agree.

Everything else that was dropped is explained where it appears below.

## Blocked

- `rotation.rotateNow` for any secret without a registered rotator. The
  registration is application Go code and no dashboard can supply it. The UI
  reports which policies are executable rather than offering a button that
  fails.
- `when_tenant_tag` and `custom` rules. The engine returns false for both. They
  are displayed where data contains them, marked "Never matches", and cannot be
  created.
- A tag filter on the flag list. Tags are a JSON array in three different column
  types across the backends, so a filter that keeps paging exact needs three
  dialects of array query.
- Keys or tenant ids the templ pages stored with leading or trailing spaces. The
  new pages list them, but every write path trims its input, so such a row can't
  be opened, changed or reverted from the dashboard. Fix those rows in the store
  first.
- Editing a config value whose type is not one of the six the vault checks (the
  templ page's `yaml`). It is shown read-only with the reason. The way out is a
  retype that comes with a valid value: `config.update` accepts `valueType`, but
  no React page sends it, so today you make that call from your own client.
- An overrides list with no tenant or key chosen. The templ page listed
  overrides with no filter, but it only ever reached the first 100 keys. The
  store can list overrides by tenant or by key and no other way, so the React
  page asks you to pick one first. A list of everything needs a store method on
  all four backends.
- The Vault Stats and Recent Audit widgets on the Forge dashboard's home. The
  React shell has no widget surface for plugins yet. The same numbers are on
  Vault's overview.

## Page by page

Status is one of **migrated** (same thing, same place), **changed** (the
behaviour is different on purpose, with the reason), **dropped** (gone, with
the reason) or **blocked** (wanted, and waiting on work outside Vault).

Every paged list in the React pages shows the server's total in its caption,
never the length of the page. The templ badges counted the rows on screen, so
they were wrong past 100. A timestamp is a date and time in your browser's
zone, and an absent one says "none". The templ pages printed a date with no
zone, and a dash when empty. Identifiers are in mono, and an empty value in a
description list is a "none" cell.

### Route map

| templ route | React route | status |
|---|---|---|
| `/` | `/` | migrated |
| `/secrets` | `/secrets` | migrated |
| `/secrets/detail?key=&app_id=` | `/secrets/:key` | migrated |
| `/secrets/create` | `/new-secret` | changed: a create page never sits at `/secrets/new`, because a key can be called "new" |
| `/flags` | `/flags` | migrated |
| `/flags/detail?key=&app_id=` | `/flags/:key` | migrated |
| `/flags/create` | `/new-flag` | changed: same reason |
| `/config` | `/config` | migrated |
| `/config/detail?key=&app_id=` | `/config/:key`, loaded lazily | migrated |
| `/config/create` | `/new-config` | changed: same reason |
| `/config/edit?key=&app_id=` | none: editing happens on `/config/:key` | changed: see Config edit |
| `/overrides` | `/overrides` | changed: see Overrides |
| `/overrides/detail?key=&app_id=&tenant_id=` | none | dropped: see Override detail |
| `/rotation` | `/rotation` | migrated |
| `/rotation/detail?key=&app_id=` | `/rotation/:key` | migrated |
| `/audit` | `/audit` | migrated |
| `/settings` | none | dropped: see Settings |

The templ links built their URLs by joining a key and an app id with no
escaping, so a key holding `&`, `#`, `+`, `%` or a space broke navigation. The
React links encode the key into the path (`encodeURIComponent`), and no link
carries an app id.

### Overview

`pages/overview.templ`, `components/stat_card.templ`.

| templ | React | status |
|---|---|---|
| Title "Overview", subtitle "Secrets, feature flags, and runtime configuration at a glance." | "Overview", "What needs attention in this vault, then what it holds." | changed: the page leads with problems |
| Stat card Secrets, "Encrypted secrets" | Secrets, `overview.stats` `secrets` | changed: the subtitle said encrypted whatever the vault held. Encryption has its own line now |
| Stat card Feature Flags, "Flag definitions" | Flags, `flags` | migrated |
| Stat card Config Entries, "Runtime configuration" | Config entries, `configEntries` | migrated |
| Stat card Overrides, "Tenant overrides", always 0 | Config overrides, `configOverrides`, a real count | changed: it was never populated |
| Stat card Rotation Policies, "Active policies", which counted disabled ones | Rotation policies with the hint "N enabled" | changed |
| Stat card Audit Entries, "Logged operations" | none | dropped: a log that grows on every read has no useful total on a home page, and the audit page's caption gives the total for any filter |
| Stat card icons (lock, flag, settings-2, layers, refresh-cw, file-text) | none | dropped: the kit's stat grid carries a label, a value and a hint |
| Counts capped at 10000, and a store error shown as 0 | counts from `Count*`, and any failed count fails the whole query. The rotation figures come from one read of the policy list, so the total and its subsets agree | changed |
| Card "Quick Actions", "Create new secrets, flags, or configuration entries." | none | changed: the card is gone and its three buttons live on the lists they belong to |
| Quick action button New Secret | "New secret" on the Secrets page | changed: it lives with the list it belongs to |
| Quick action button New Flag | "New flag" on the Flags page | changed |
| Quick action button New Config Entry | "New config" on the Config page | changed |
| Card "Recent Activity", "The last 10 audit log entries.", an audit table | "Recent activity", the newest 10 writes as a list with key, outcome, user, tenant, time and the error of a failed one, and a "See the audit log" link | changed: reads are left out so they don't bury the writes |
| Empty state "No audit entries yet" | "No recorded activity yet." | changed |
| A failed audit read shown as that empty state | the query fails and says so | changed |

The overview also gained what the templ page never had: a "Needs attention"
list (secrets stored without encryption, expired secrets, secrets expiring
within 30 days, earlier versions stored without encryption, overdue rotation
policies, enabled policies with no rotator, rotation attempts that failed in
the last 24 hours, each linking to where you fix it), and a line saying whether
new secrets are encrypted and with which algorithm. With a key configured, that
line also says how many earlier versions are stored without encryption and how
many older versions vault can't vouch for. The expired and expiring lines open
the Secrets list already filtered. The plaintext-versions line opens the plain
list, because no page lists versions across secrets.

### Secrets

`pages/secrets.templ`, `components/secret_table.templ`.

| templ | React | status |
|---|---|---|
| Title "Secrets", subtitle "Encrypted key-value secrets with versioning." | "Secrets", "Values are write-only: you can set and replace them here, never read them back." | changed: the old subtitle claimed encryption for every row |
| Count badge "N secrets", the rows on the page, at most 100 | caption with the server's total | changed |
| Button "Create Secret" | "New secret", linking to `/new-secret` | migrated |
| Search box "Filter by key..." | none | dropped: see Deliberately dropped |
| Column Key, mono and medium, whole row clickable | Key, a link | migrated |
| Column Version, "v3" | Version | migrated |
| Column App ID | none | dropped: a vault answers for one app, so every row said the same thing |
| Column Expires, a date or a dash | Expires | migrated |
| Column Updated | Updated | migrated |
| No column for encryption | Encryption badge: the algorithm, or "Not encrypted" | changed: new, and the reason the page can no longer imply everything is safe |
| No paging, 100 rows at most | 25 a page with the total | changed |
| No filter on expiry | An Expiry select: All, Expired, Expires within 7 days, Expires within 30 days. It filters on the server, so the page and the total agree, and it orders by expiry, then key. The choice is kept in the URL as `?expiry=` | changed: new |
| Empty state "No secrets found", "Secrets will appear here once they are created." | "No secrets yet." with a New secret button, or "No secrets match this expiry filter." when a filter is on | changed |
| A failed read shown as that empty state | the query fails and says so | changed |

When a row on the page is "Not encrypted", a line under the header says why and
that adding a key later does not encrypt it.

### Secret create

`pages/secret_create.templ`, at `/new-secret`.

| templ | React | status |
|---|---|---|
| Back button "Back to Secrets" | see Shared components | dropped |
| Title "Create Secret", subtitle "Store a new encrypted secret." | "New secret", "The value is write-only. Once you save it, it cannot be shown again." | changed |
| Field Key, required, "e.g. database_password" | Key | migrated |
| Field App ID, prefilled and editable | none | dropped: a request-supplied app id lets any operator write into any app. The server uses the vault's own |
| Field Value, a textarea | Value, a password field. Uncontrolled, so the plaintext never enters React state or the DOM's `value` attribute | changed |
| Field "Expires At (optional)", RFC3339 text, which the handler never read | "Expires (optional)", a date and time picker. A time in the past disables the button and says why | changed |
| Button Cancel | Cancel, a link | migrated |
| Button "Create Secret" | "Create secret", disabled until there is a key and a value | migrated |
| Error banner with the raw store error | An alert with a mapped message. A key that exists says so and links to it | changed |
| Success re-rendered the list | Goes to the new secret's page and empties the value field first | changed |

### Secret detail

`pages/secret_detail.templ`, `components/version_table.templ`
(`SecretVersionTable`), `components/audit_table.templ`.

| templ | React | status |
|---|---|---|
| Back button "Back to Secrets" | see Shared components | dropped |
| Header card: lock tile, key in mono, "Secret version N", badge "vN" | Page title is the key. The version is a field | changed |
| Field Secret ID | ID | migrated |
| Field Key | the page title | migrated |
| Field Version | Version | migrated |
| Field App ID | none | dropped: same reason as the list |
| Field Expires At, shown only when set | Expires, "none" when unset | changed |
| Field Created | Created | migrated |
| Field Updated | Updated | migrated |
| No field for encryption | Encryption: the badge, and for an unencrypted row a sentence saying replacing the value while a key is configured stores it encrypted | changed: new |
| Metadata card, only when non-empty, in random map order | Metadata field as sorted `key=value` tags, "none" when empty | changed |
| Version History card, count badge, "All versions of this secret." | "Versions (N)", a list newest first | changed: a timeline instead of a table, because there is nothing to diff |
| Version table column Version "vN" | Version, with a "Current" mark on the newest | changed |
| Version table column Created By, a dash when empty | Author, "none" when empty | migrated |
| No encryption per version | A badge on each version: Encrypted, Not encrypted, or Unknown for a row stored before vault recorded it (its title says why) | changed: new. A version keeps the algorithm it was written with, so replacing a value doesn't change the badges below it |
| Version table column Created At | the time beside the author | migrated |
| Empty text "No version history available." | "No versions recorded." | changed |
| Rotation Policy card, only when a policy exists | "Rotation" pane; with no policy it says so and links "Set up rotation" | changed |
| Policy field Interval, a Go duration such as `24h0m0s` | Interval, "Every 1 day" | changed |
| Policy field Status, "Enabled" or "Disabled" | Status badge, outline or secondary | migrated |
| Policy field Next Rotation | Next rotation, shown only when the policy is enabled and has a rotator | changed |
| Policy field Last Rotated | none on this page | changed: it is on the rotation page |
| Audit Trail card, count badge, "Recent access and mutation logs for this secret." | "Recent activity", the newest 10 rows for this key, where the old card showed 20 | changed |
| Audit table columns Action, Resource, Key, Outcome, App ID, Tenant, User, Time | action, outcome, "by" user, tenant and time on one line, with the error of a failure underneath | changed: the resource and key are the page's own, and App ID is dropped |
| Empty text "No audit entries for this secret." | "No recorded activity yet." | changed |
| A failed version, policy or audit read shown as "No version history available.", as no policy, or as "No audit entries for this secret." | each query fails and says so | changed |
| The row found by listing up to 10000 secrets, so a key past that answered not found | the server reads the one secret by key | changed |

Secret detail also gained what the templ page never had: "Replace value"
(`secrets.update`, with a keep, set or remove choice for the expiry) and
"Delete" (`secrets.delete`, confirmed, which also removes the rotation policy).

### Rotation

`pages/rotation.templ`, `components/rotation_table.templ`.

| templ | React | status |
|---|---|---|
| Title "Rotation Policies", subtitle "Automatic secret rotation schedules and history." | "Rotation", a subtitle saying due policies are checked once a minute in each vault process and that a rotator is required | changed |
| Count badge "N policies" | caption with the server's total | changed |
| Column Secret Key, whole row clickable | Secret, a link | migrated |
| Column Interval, a Go duration | Interval, "every 1 day" | changed |
| Column Status, green or red dot badge | Status, outline or secondary badge | changed: the dots are gone, and neither state is an error |
| Column Last Rotated | Last rotated | migrated |
| Column Next Rotation | Next rotation, blank for a disabled policy or one with no rotator | changed: a time that will not happen is not shown |
| Column App ID | none | dropped: same reason as the secrets list |
| No column for rotators | Rotator badge: "Rotator registered" or "No rotator" | changed: new |
| Empty state "No rotation policies", "Rotation policies will appear here once configured for secrets." | "No rotation policies. Set one up from a secret's page." | changed |
| A failed read shown as that empty state | the query fails and says so | changed |
| No paging, every policy in one table | 25 a page with the total | changed |

### Rotation detail

`pages/rotation_detail.templ`, `components/rotation_record_table.templ`.

| templ | React | status |
|---|---|---|
| Back button "Back to Rotation" | see Shared components | dropped |
| Header card: refresh tile, key in mono, "Rotation policy for secret", Enabled badge | Title is the key, "Rotation policy and history for this secret.", and a "View secret" link. Status is in the policy summary | changed |
| Button "Rotate Now", with a browser confirm. It did nothing | "Rotate now", with a dialog saying applications must pick up the new value. It is disabled, with the reason beside it, when no rotator is registered. The result is a line "Rotated from v3 to v4." | changed |
| Field Policy ID | none | dropped: nothing acts on it, a policy is addressed by its secret key |
| Field Secret Key | the page title | migrated |
| Field App ID | none | dropped: same reason as the lists |
| Field Interval | Interval | migrated |
| Field Status | Status | migrated |
| Field Last Rotated | Last rotated | migrated |
| Field Next Rotation | Next rotation, only for a policy that will really rotate | changed |
| Field Created | none | dropped: the history's times are the ones that answer a question |
| Field Updated | none | dropped: same reason |
| Rotation History card, count badge, "Historical record of all rotations performed on this secret." | "Rotation history", with a caption count, up to 50 records as before | migrated |
| Record column Old Version and column New Version | Versions, "v3 to v4" | changed: one column |
| Record column Rotated By, "system" when empty | Rotated by, "none" when empty | changed: the word "system" was invented |
| Record column Rotated At | Rotated at | migrated |
| Empty text "No rotation records yet." | "No rotations recorded yet." | changed |
| A failed record read shown as "No rotation records yet." | the query fails and says so | changed |

A failed rotation is not a record here. It is a `secret.rotated` row with
outcome `failure` on the audit page, and the overview counts the last 24 hours
of them.

The page also gained a policy form (`rotation.savePolicy`: an interval in hours
or days, at least 60 seconds, and an enable checkbox, with a preview of the
next run) and "Delete policy" (`rotation.deletePolicy`, confirmed). The templ pages
couldn't create or change a policy at all.

### Flags

`pages/flags.templ`, `components/flag_table.templ`.

| templ | React | status |
|---|---|---|
| Title "Feature Flags", subtitle "Toggle features with targeting rules and rollout strategies." | "Flags", "Feature flags, each with a default and the rules that override it." | changed |
| Count badge "N flags", the rows on the page, at most 100 | caption with the server's total | changed |
| Button "Create Flag" | "New flag", linking to `/new-flag` | migrated |
| Search box "Filter by type (bool, string, int, float, json)...", case-insensitive, in memory over the first 100 rows | "Type" select: All types and the five types, a store filter | changed: see Deliberately dropped |
| Column Key, mono and medium, whole row clickable | Key, a link | migrated |
| Column Type, outline badge | Type, outline badge in mono | migrated |
| Column Default, `%v` cut to 20 characters, so the string "true" and the bool true looked alike | Default, shown by its type, with a "Wrong type" badge when it isn't a value of the flag's type | changed: that is how the create bug hid |
| Column Status, green or red dot badge | Status, "On" outline or "Off" secondary | changed: an off flag is deliberate, not a fault |
| Column Tags, comma joined or a dash | Tags, tag list, "none" when empty | migrated |
| Column App ID | none | dropped: same reason as the secrets list |
| Column Updated | Updated | migrated |
| Empty state "No feature flags found", "Feature flags will appear here once they are defined." | "No flags yet." with a New flag button, or "No int flags." under a type filter | changed |
| A failed read shown as that empty state | the query fails and says so | changed |

### Flag detail

`pages/flag_detail.templ`, `components/rule_table.templ` (`RuleTable` and
`FlagOverrideTable`). The page is now one ladder read top to bottom in the
engine's own order: enabled, tenant overrides, rules, default. The templ page
laid the same facts out as sibling cards, which hid that an override beats every
rule and that a disabled flag makes the rule table dead weight.

| templ | React | status |
|---|---|---|
| Back button "Back to Flags" | see Shared components | dropped |
| Header: flag tile, key in mono, description when set | Title is the key, the description under it, or "No description" | changed |
| Header badges Enabled or Disabled, and Type | Type badge in the header. Enabled is rung 1, a switch with an "On" or "Off" badge | changed |
| Button Disable or Enable, a GET with a browser confirm | The switch, a command with cache invalidation and an audit row, no confirm | changed |
| Field Flag ID | none | dropped: nothing on the page uses it |
| Field Key | the page title | migrated |
| Field Type | Type badge | migrated |
| Field Default Value | Definition, Default, typed, with "Wrong type" and an "Edit default" button | changed |
| Field App ID | none | dropped: same reason as the lists |
| Field Enabled | rung 1 | migrated |
| Field Created | none | dropped: nothing on the page uses it. Updated is on the list |
| Field Updated | none | dropped: same reason |
| Tags card, count badge, code chips | Tags under the title and in Definition, with "Edit tags" | changed |
| Variants card, "Named flag value variants.", value and description | Variants in Definition, value and description, "none" when absent | changed |
| Metadata card, random map order | Metadata in Definition as sorted `key=value` tags | changed |
| Targeting Rules card, count badge, "Rules are evaluated in priority order (lower number = higher priority)." | Rung 3 "Rules", "First match wins." Numbers are positions, not priorities, because the engine walks the list in order | changed |
| Rule column Priority | the row's number | changed |
| Rule column Type, outline badge | the words of the rule: "Tenant is one of", "User is one of", "Rollout to 25% of tenants", "Between X and Y UTC", and so on | changed |
| Rule column Config, "Tenants: a, b", "Users: ...", "N% rollout", "Schedule: Jan 02 15:04 - ..." | the same facts in words, ids as chips. A rollout adds "Tenants are bucketed by id, never by user." | changed |
| Rule config "Tag: k=v" and "Evaluator: name", shown like any other rule | "Tenant tag k = v" and "Custom evaluator name", each with a "Never matches" badge | changed: the engine returns false for both |
| Rule column Return Value, `%v` cut to 20 characters | the value on each row, with "Wrong type" when it does not fit | changed |
| Empty text "No targeting rules defined. The default value will always be returned." | "No rules. Whatever reaches this rung falls through to the default." | changed |
| Tenant Overrides card, count badge, "Direct per-tenant value overrides that bypass rules." | Rung 2 "Tenant overrides", "Beat every rule below." | changed |
| Override column Tenant ID | the tenant, in mono | migrated |
| Override column Value | the value, with "Wrong type" when it does not fit | migrated |
| Empty text "No tenant overrides defined." | "No tenant overrides." | changed |
| A store error shown as "No targeting rules" or "No tenant overrides" | the query fails and says so | changed |
| A rule of a type the table did not know, shown as a dash | "Unknown rule type X" with a "Never matches" badge | changed |
| A missing flag answered with a raw wrapped store error | "No flag named X." with a link back to the flags | changed |
| No rung for the default | Rung 4 "Default", "Returned when nothing above decides." | changed |

The page also gained what the templ page never had: an evaluation bar (a tenant
and a user, then "Evaluate", which marks the rung that decided, greys the rungs
never reached and annotates each rule checked and turned down, including the
rollout bucket), a whole-list rule editor with drag to reorder and a menu of the
four rule types that can match (`flags.setRules`), editing of the default, the
description and the tags (`flags.update`), adding and removing tenant overrides,
"Delete" (confirmed), and the ten newest audit rows for the flag.

### Flag create

`pages/flag_create.templ`, at `/new-flag`.

| templ | React | status |
|---|---|---|
| Back button "Back to Flags" | see Shared components | dropped |
| Title "Create Feature Flag", subtitle "Define a new feature flag with type and default value." | "New flag", "Give it a key, a type and a default. Rules and tenant overrides come after it exists." | changed |
| Field Key, required | Key | migrated |
| Field App ID | none | dropped: same reason as secret create |
| Type options bool, string, int, float, json | the same five | migrated |
| Type option yaml | none | dropped: see Deliberately dropped |
| Field Default Value, text, required, "e.g. true, hello, 42" | A typed input for the chosen type. A bool sends a real boolean and an int a real number. Changing the type clears it | changed: the old form sent every default as a string |
| Code textarea for json with live validation ("Valid JSON", "JSON syntax error: ...") | A mono textarea that says "Not valid JSON" with the reason | changed |
| YAML validation with js-yaml loaded from a CDN | none | dropped: yaml was never a type, and the page no longer loads a script from a third party |
| Field Description, a textarea | Description, one line | migrated |
| Field Tags, comma separated | Tags, "Comma separated." | migrated |
| Checkbox Enabled, checked by default | Enabled, checked by default | migrated |
| Buttons Cancel and "Create Flag" | Cancel, and "Create flag", disabled until there is a key and a default | migrated |
| Error banner with the raw store error | An alert with a mapped message. A key that exists says so and links to it, where the old form overwrote it | changed |
| Success re-rendered the list | Goes to the new flag's page | changed |

### Config

`pages/config.templ`, `components/config_table.templ`.

| templ | React | status |
|---|---|---|
| Title "Config Entries", subtitle "Runtime configuration with versioning and per-tenant overrides." | "Config", "Typed application settings, each with a version and a value per tenant when you override it." | changed |
| Count badge "N entries", the rows on the page, at most 100 | caption with the server's total | changed |
| Button "Create Entry" | "New config", linking to `/new-config` | migrated |
| Search box "Filter by key...", a case-insensitive substring over the first 100 rows | "Key starts with", a case-sensitive prefix filter in the store, asked 300 ms after you stop typing | changed: a prefix can be answered exactly and paged, a substring over a page cannot |
| Column Key, mono and medium, whole row clickable | Key, a link | migrated |
| Column Value, `%v` cut to 20 characters, so an object printed as Go map syntax | Value, shown by its type, with "Wrong type" when it does not fit | changed |
| Column Type, outline badge, blank when empty | Type, outline badge in mono, plus "Unsupported type" beside a type outside the six | changed |
| Column Version, "vN" | Version | migrated |
| Column App ID | none | dropped: same reason as the secrets list |
| Column Updated | Updated | migrated |
| Empty state "No config entries found", "Config entries will appear here once they are created." | "No config yet." with a New config button, or "No keys start with X." | changed |
| A failed read shown as that empty state | the query fails and says so | changed |

### Config detail

`pages/config_detail.templ`, `components/override_table.templ`,
`components/version_table.templ` (`ConfigVersionTable`). This is the only lazy
route: it carries CodeMirror, so the shell's entry chunk does not.

| templ | React | status |
|---|---|---|
| Back button "Back to Config" | see Shared components | dropped |
| Header: settings tile, key in mono, description when set | Title is the key. The description is in Definition, with an "Edit description" dialog | changed |
| Header badge "vN" | Version in Definition | migrated |
| Header badge for the type | Type badge, plus "Unsupported type" or "Wrong type" when they apply | changed |
| Header button Edit, to the edit page | none: the value is edited where it is shown, and the description in a dialog | changed: see Config edit |
| Field Config ID | none | dropped: nothing on the page uses it |
| Field Key | the page title | migrated |
| Field Value, `%v` | the "Value" section: a typed input, or a JSON editor for json | changed |
| Field Value Type | Type badge | migrated |
| Field Version | Version | migrated |
| Field App ID | none | dropped: same reason as the lists |
| Field Created | Created | migrated |
| Field Updated | Updated | migrated |
| Metadata card, random map order | Metadata in Definition, sorted, "none" when empty | changed |
| Version History card, count badge, "All versions of this config entry." | "Versions" | migrated |
| Version column Version "vN" | Version, with a "Current" mark | migrated |
| Version column Value, cut to 20 characters | Value, capped, with the whole of it in the tooltip and in Compare, and "Wrong type" when it no longer fits the type | changed |
| Version column Created By, always empty because versions store no actor | none | dropped: nothing ever filled it |
| Version column Created At | Saved | migrated |
| Empty text "No version history available." | "No versions." | changed |
| Tenant Overrides card, count badge, "Per-tenant value overrides for this config key." | "Overrides", with a caption count | migrated |
| Override column Key | none | dropped: every row is this entry's |
| Override column Value | Value, with "Wrong type" when it does not fit | migrated |
| Override column Tenant ID | Tenant | migrated |
| Override column App ID | none | dropped: same reason as the lists |
| Override column Updated | Updated | migrated |
| Override row clickable, to the override page | none | dropped: see Override detail |
| Empty text "No tenant overrides for this key." | "No tenant overrides." | changed |
| A failed version or override read shown as "No version history available." or "No tenant overrides for this key." | the query fails and says so | changed |
| A missing entry answered with a raw wrapped store error | "No config entry named X." | changed |

The page also gained what the templ page never had: "Compare" for any version
(a diff for json, side by side values otherwise), "Roll back" (`config.rollback`,
confirmed, and not offered when the old value no longer fits the type or
matches the current one), "Delete" (`config.delete`, confirmed, which removes the
overrides), "Add override", "Change" and "Revert to app default" per row
(`overrides.set` and `overrides.delete`), a "Resolve" panel that says what a
given tenant gets for this key and where the answer came from
(`config.resolve`), and the ten newest audit rows for the key and its
overrides. Values are checked against the entry's type in the browser and again
by the server.

### Config create

`pages/config_create.templ`, at `/new-config`.

| templ | React | status |
|---|---|---|
| Back button "Back to Config" | see Shared components | dropped |
| Title "Create Config Entry", subtitle "Add a new runtime configuration entry." | "New config entry", "Give it a key, a type and a value. Tenant overrides come after it exists." | changed |
| Field Key, required, "e.g. rate_limit" | Key | migrated |
| Field App ID | none | dropped: same reason as secret create |
| Type options string, bool, int, float, json | string, int, float, bool, json, and duration, which is new | changed |
| Type option yaml | none | dropped: see Deliberately dropped |
| Field Value, text, required, "e.g. 100, true, hello" | A typed input for the chosen type. Changing the type clears it | changed: the old form stored the raw string whatever the type |
| The form trimmed the value | the value is sent as typed | changed: the trim lost leading and trailing spaces in a string |
| Code textarea for json and yaml with live validation | A mono textarea for json that says "Not valid JSON" with the reason. No editor is loaded on this route | changed |
| YAML validation with js-yaml from a CDN | none | dropped: same reason as flag create |
| Field Description, a textarea with "Describe what this config controls..." | Description, one line | migrated |
| Buttons Cancel and "Create Entry" | Cancel, and "Create entry", disabled until there is a key and a value | migrated |
| Error banner with the raw store error, which discarded what you had typed | An alert with a mapped message. The form keeps what you typed. A key that exists says so and links to it, where the old form overwrote it | changed |
| Success re-rendered the list | Goes to the new entry's page | changed |

### Config edit

`pages/config_edit.templ`. The route is gone. You edit a value on the entry's
page.

| templ | React | status |
|---|---|---|
| Back button "Back to Detail" | none | dropped: the page it led back from no longer exists |
| Title "Edit Config Entry", subtitle "Update key" | none | dropped: with the page |
| Disabled fields Key and App ID, "Key cannot be changed after creation." | none | dropped: the entry's page shows the key as its title |
| Field Value Type, a select of six labels | none | blocked: `config.update` accepts `valueType` and refuses a change that strands an override, but no React page offers it. The templ select silently retyped any label outside its six to "string" |
| Field Value, text or a JSON and YAML textarea, prefilled | The "Value" section on the entry's page, with "Save value". Save is off until the draft is a value of the type and differs from what is stored | changed |
| Field Description, a textarea | "Edit description" dialog | changed |
| JSON and YAML validation in the browser | JSON: the editor validates as you type and the server checks the type. YAML: none | changed |
| The yaml textarea prefilled through a JSON formatter, which quoted a plain string | none | dropped: yaml is not a config type here |
| Buttons Cancel and "Save Changes" | "Save value" and "Save description". There is no Cancel: an unsaved edit warns you before you leave | changed |
| Error banner with the raw store error | An alert with a mapped message | changed |
| Success re-rendered the detail page | Stays on the page with "Saved as version N." | changed |
| Invalid JSON stored as a string | not possible: json is parsed in the browser and by the server | changed |

### Overrides

`pages/overrides.templ`, `components/override_table.templ`.

| templ | React | status |
|---|---|---|
| Title "Overrides", subtitle "Per-tenant configuration overrides." | "Overrides", "The values tenants get in place of an entry's app default." | changed |
| Count badge "N overrides", at most 100 | caption with the server's total, once you have picked something | changed |
| Search box "Filter by tenant ID...", an exact match, asked as you type | "Tenant id" with a "Show overrides for a tenant" button | changed: you ask on purpose |
| No filter by key | "Config key" with a "Show overrides for a key" button | changed: new |
| The unfiltered list, built from the first 100 config keys | a prompt: "Pick a tenant or a key to see its overrides." | blocked: see Blocked |
| Column Key | Key, a link to the entry, or "Key deleted" when the entry is gone | changed |
| Column Value, cut to 20 characters | Value, with "Wrong type" when it does not fit | migrated |
| Column Tenant ID | Tenant | migrated |
| Column App ID | none | dropped: same reason as the other lists |
| Column Updated | Updated | migrated |
| Row clickable, to the override page | none | dropped: see Override detail |
| Empty state "No overrides found", "Overrides will appear here once per-tenant values are set." | "No overrides for tenant X." or "No overrides for key X." | changed |
| A failed tenant read shown as that empty state, and a failed per-key read skipped without a word | the query fails and says so | changed |
| Read-only | Per row, "Revert to app default", or "Remove leftover override" for an orphan whose entry is gone. Both are confirmed | changed |

### Override detail

`pages/overrides_detail.templ`. The route is gone.

| templ | React | status |
|---|---|---|
| Back button "Back to Overrides" | see Shared components | dropped |
| Header card: layers tile, key in mono, "Tenant override for X" | none | dropped: the page showed one row of a list, and the rows now carry everything it did |
| Field Override ID | none | dropped: an override is addressed by key and tenant |
| Field Key | Key on the overrides list, and the entry's page | migrated |
| Field Value | Value on the overrides list, and on the entry's Overrides table | migrated |
| Field Tenant ID | Tenant on both | migrated |
| Field App ID | none | dropped: same reason as the lists |
| Field Created | none | dropped: Updated is on both tables |
| Field Updated | Updated on both | migrated |
| Metadata card | none | dropped: nothing in the dashboard or the config manager sets an override's metadata, so the card had nothing to show |

### Audit

`pages/audit.templ`, `components/audit_table.templ`,
`components/status_badge.templ` (`OutcomeBadge`, `ResourceBadge`).

| templ | React | status |
|---|---|---|
| Title "Audit Log", subtitle "Comprehensive access and mutation log for all vault operations." | "Audit", "Every change made to secrets, flags, config, overrides and rotation policies, and every failed attempt." | changed: reads are hidden until you ask |
| Count badge "N entries", the rows on the page | caption with the total for the filters you set | changed |
| Search box "Filter by resource type (secret, flag, config, override)...", case-insensitive, in memory over the newest 100 rows | "Resource" select: All, secret, flag, config, override, rotation. A store filter | changed |
| No other filters | Action (every action the vault writes), Outcome, Key (exact), a "Show reads" checkbox, and a "Since" chip when the overview linked you here | changed: new |
| No paging, 100 rows at most | 25 a page with the total | changed |
| Column Action | Action, in mono | migrated |
| Column Resource, secondary badge | Resource, secondary badge in mono | migrated |
| Column Key, mono | Key, linked to the secret, flag or config page unless the row is a delete | changed |
| Column Outcome, green "Success" or red "Failure" for anything else | Outcome, outline for success and destructive for failure, with the error under a failure. An outcome it doesn't know is shown as it came | changed |
| Column App ID | none | dropped: same reason as the other lists |
| Column Tenant, a dash when empty | Tenant, "none" when empty. On an override row it is the tenant the change was about | migrated |
| Column User, a dash when empty | User, "none" when empty. Every dashboard write records its operator | migrated |
| Column Time, "Jan 02, 15:04" with no year and no zone | Time, first, with date, time and your zone | changed |
| No column for the IP or the metadata | none | dropped: the templ table never had them either, and the vault records no metadata on audit rows |
| Empty state "No audit entries", "Audit entries will appear here as vault operations are performed." | "No audit entries match these filters.", and with reads hidden a hint to turn on "Show reads" | changed |
| A failed read shown as that empty state | the query fails and says so | changed |

Reads (`secret.get`) are hidden unless you turn on "Show reads" or pick that
action. An app that reads secrets through confy writes a row for each read, so
they would otherwise bury the writes.

### Settings

`pages/settings.templ`, settings panel `vault-config`. The page and the panel
are dropped. The templ page took a nine-field struct and `renderSettings`
passed only `AppID`. Four rows showed a dash, `0s` or "Disabled" (Encryption
Key Env, both durations, Audit Logging), and four showed plausible defaults that
came from the template, not from your config (Base Path `/vault`, Routes and
Auto-Migrate "Enabled", Grove Database "default (auto-discovered)").

| templ | React | status |
|---|---|---|
| Title "Settings", subtitle "Vault extension configuration (read-only)." | none | dropped: see Deliberately dropped |
| Field App ID | none | dropped: no page takes or shows an app id, and every intent answers for the configured one |
| Field Encryption Key Env | none | dropped: never populated, and a variable's name does not say whether a key loaded. The overview says whether encryption is on |
| Field Flag Cache TTL | A line under the ladder on the flag page: applications may serve a cached answer for up to that many seconds after a change | changed: it matters where you change a flag, so it sits there |
| Field Source Poll Interval | none | dropped: never populated, and no page needs it |
| Field Audit Logging, "Disabled" forever | none | dropped: the setting is deprecated and audit is always on |
| Field Base Path | none | dropped: never populated, and a routing detail |
| Field Routes | none | dropped: never populated |
| Field Auto-Migrate | none | dropped: never populated |
| Card Store Backend, field Grove Database, "default (auto-discovered)" | none | dropped: never populated |
| Card Encryption, field Algorithm "AES-256-GCM" | The overview's "New secrets are encrypted with AES-256-GCM", read from the server | changed: the templ text was a constant and said it with no key configured |
| Card Encryption, fields Key Size and Nonce | none | dropped: constants of the algorithm |
| Settings panel `vault-config`, "Vault Configuration", "Secrets engine settings", in the Forge dashboard's settings | none | dropped: the shell has no per-plugin settings panel, and the page it showed is dropped |

### Widgets

`widgets/stats.templ`, `widgets/recent_audit.templ`.

| templ | React | status |
|---|---|---|
| Widget `vault-stats`, "Vault Stats", "Secrets, flags, and config metrics", size md, refreshed every 30 seconds, group Vault: a two by two grid of Secrets ("Encrypted secrets"), Flags ("Feature flags"), Config ("Config entries") and Audit ("Log entries") | none | blocked: the React shell has no widget surface for plugins. Secrets, flags and config are on Vault's overview. The audit count is dropped with the overview's |
| Widget `vault-recent-audit`, "Recent Audit", "Latest vault audit log entries", size lg, refreshed every 15 seconds, group Vault: the last 5 audit rows in the audit table | none | blocked: same blocker. The overview's Recent activity shows the last 10 writes |
| Widget empty state "No recent audit", "Audit entries will appear here." | none | blocked: with the widget |

### Navigation and manifest

`manifest.go`.

| templ | React | status |
|---|---|---|
| Nav item Overview, group Overview, icon layout-dashboard | Overview at `/`, group Secrets, first | changed |
| Nav item Secrets, group Secrets | Secrets, group Secrets | migrated |
| Nav item Feature Flags, group Feature Flags | Flags, group Flags | migrated |
| Nav item Config Entries, group Configuration | Config, group Config | migrated |
| Nav item Overrides, group Configuration | Overrides, group Config | migrated |
| Nav item Rotation, group Operations | Rotation, group Secrets | changed: a policy belongs to a secret |
| Nav item Audit Log, group Operations | Audit, group Audit | migrated |
| Nav item Settings, group System | none | dropped: with the page |
| Nav groups Overview, Secrets, Feature Flags, Configuration, Operations, System | Secrets, Flags, Config, Audit | changed |
| Nav icons | a distinct icon per item | migrated |
| Detail, create and edit routes with no nav entry | the same: create and detail pages are reached from rows and buttons | migrated |
| Display name "Vault", icon shield, version "1.0.0", layout "extension", sidebar shown | plugin label "Vault" | changed: the shell decides layout and sidebar |
| Topbar title, logo icon and accent colour `#8b5cf6` | none | dropped: the shell themes every plugin the same way |
| Topbar search box | none | dropped: covered by the shell's own page search |
| Topbar action "API Docs", linking to `/docs` | none | dropped: the shell has no per-plugin topbar actions |
| Capability `searchable` | none | dropped: covered by the shell's own page search |

### Shared components and helpers

`components/empty_state.templ`, `components/stat_card.templ`,
`components/status_badge.templ`, `pages/helpers.templ`, and the shared table
components. Each table is covered on the page that rendered it: `AuditTable` on
Audit, Secret detail and Overview; `SecretTable` on Secrets; `SecretVersionTable`
on Secret detail; `RotationTable` on Rotation; `RotationRecordTable` on Rotation
detail; `FlagTable` on Flags; `RuleTable` and `FlagOverrideTable` on Flag
detail; `ConfigTable` on Config; `ConfigVersionTable` and `OverrideTable` on
Config detail, and `OverrideTable` on Overrides.

| templ | React | status |
|---|---|---|
| `EmptyState`: a 48 pixel muted icon, a title, an optional description | the kit's `EmptyState`: a title, an optional description, an optional action | changed: the large icon is gone, and the action is new |
| `StatCard`: icon, label, value, subtitle | the kit's `StatGrid` item: label, value, hint | changed: no icon |
| `resolveIcon`, which mapped 20 icon names and fell back to an info icon | none | dropped: the nav takes its icons directly |
| `EnabledBadge`: green dot "Enabled" (default), red dot "Disabled" (secondary) | `PolicyStatusBadge` (Enabled outline, Disabled secondary) and `FlagEnabledBadge` ("On" outline, "Off" secondary) | changed: colour is the scan signal, and neither state is an error |
| `OutcomeBadge`: green "Success", red "Failure" for anything else | `OutcomeBadge`: outline or destructive, and unknown outcomes as they came | changed |
| `TypeBadge`: outline | `FlagTypeBadge` and `ConfigTypeBadge`: outline, in mono | migrated |
| `ResourceBadge`: secondary | `ResourceBadge`: secondary, in mono | migrated |
| A whole table row clickable through `hx-get` | the key cell is a link | changed |
| "Back to ..." buttons on every detail and create page | none. The sidebar entry is one click away, and create pages keep a Cancel link | dropped |
| Browser `hx-confirm` on Enable, Disable and Rotate Now | `ConfirmDialog` where confirmation is needed (delete, rotate, revert, roll back). Errors show inside the dialog and it cannot close while a command is pending | changed |
| `fieldRow` | the kit's `DescriptionList` | migrated |
| `formatAny`: `%v` cut to 20 characters, a dash for nil | `FlagValue` and `ConfigValue`: typed display, objects as JSON | changed |
| `formatValue`: plain `%v`, a dash for nil | `FlagValue` and `ConfigValue`: typed display, objects as JSON | changed |
| `formatJSON` | the JSON viewer and editor | changed |
| `enabledStr` and `nonEmpty` | "On" and "Off" badges, and "none" cells | changed |
| Dates formatted "Jan 02, 2006" and "Jan 02, 2006 15:04" | the kit's `Timestamp` | changed |
| `codeBlock`, `credentialField`, `truncateString`, `formatTimeAgo`: defined and never used | none | dropped: dead code |
| htmx swaps of `#content` and `hx-push-url` | the shell's router | changed |

## Still open

These are known gaps, and none has a fix on the way. Most were never in the
templ pages. Two are regressions from them, and we'd rather say so plainly: the
templ edit page could change a config entry's type, and the React pages can't;
and the templ detail pages opened a key or tenant id saved with leading or
trailing spaces (they never trimmed), and the React pages can't.

- A version stored as plaintext before this release stays "Unknown" for good,
  and fails to decrypt once its secret's current value is encrypted. Nothing on
  the dashboard can fix it. See "What you need to do" for the one-line store
  update.
- Nothing purges the audit log. Every secret read through confy writes a row, so
  the table grows without bound, and a total over millions of rows is slow.
- `audit_hook` is never attached. `audit.WithHook` exists and nothing calls it
  outside tests, so Chronicle sees no vault events. Deleting a config key also
  removes its overrides without an `override.deleted` row each.
- "Enabled with no rotator" is judged by the replica that answers, so it can be
  wrong where another replica holds the rotator. A dashboard save of a rotation
  policy is a read and then a full-row write, so saving within milliseconds of a
  replica claiming that policy can put the old due time back and cause one
  repeat rotation.
- The flag list has no tag filter. Tags are a JSON array in three column types.
- Two people editing one flag or one config entry at once means the last save
  wins, because no store has a version column. Two creates of the same key can
  both pass the existence check: memory and sqlite quietly add a version 2, and
  postgres answers `INTERNAL` on its unique constraint.
- Mongo's `SetFlagRules` deletes and reinserts without a transaction, so a
  failure halfway leaves a partial rule list live.
- Keys and tenant ids the templ pages saved with leading or trailing spaces can
  be listed but not opened, changed or reverted, because every write trims its
  input. Fix those rows in the store.
- Flag cache invalidation reaches only the replica that served the write. Other
  replicas catch up within the cache TTL, 30 seconds by default, and the
  evaluation panel says so. `WithCacheMaxEntries` is not reachable from
  `vault.Config`, so the default cap of 10000 applies everywhere.
- An existing config entry's type can't be changed from a page, so an entry of a
  type the vault doesn't check (a legacy `yaml`) stays read-only there until you
  call `config.update` with a `valueType` and a valid value yourself.
- `overrides.list` reads every override for a tenant or a key before paging,
  because the store can't page or count them.
- The CodeMirror editor exists twice, in relay and in vault. One shared editor
  in the kit is the follow-up. The postgres and mongo suites skip unless you
  point `VAULT_TEST_PG_URL` (with `-tags integration`) or
  `VAULT_TEST_MONGO_URL` at a server, so CI runs neither unless you set one up.
