# Installation Profiles

An **installation profile** tailors the product to a deployment type. It is
chosen during the install wizard and decides which modules are visible, the
RBAC model, the tenant model and the recommended database. One binary serves a
private homelab, a small team, an advanced self-hosted fleet, or a multi-tenant
hosting provider - without separate builds.

## Profiles

| Profile | For | Recommended DB | Tenant | RBAC |
|---|---|---|---|---|
| `homelab` | single owner / tiny private install | SQLite* | single | owner |
| `smallteam` | small team or family, per-user access | SQLite* or MySQL | single | team |
| `advanced` | DevOps / larger homelab, multi-node | MySQL/MariaDB | single | ops |
| `provider` | hosting provider / reseller, multi-client | MySQL/MariaDB (required) | multi | tenant |

Profiles are **cumulative**: each enables everything the one below it does, plus
its own modules.

- **homelab**: hosts, tunnels, certificates, map, local backup, NPM import, settings.
- **smallteam**: + users, basic audit.
- **advanced**: + multi-node, L4 streams, statistics, alerts, bandwidth, API
  tokens, WAF, external allowlist, restore drill, DNS providers.
- **provider**: + clients, plans, services, per-client admin scopes, customer portal.

## Database

> **MySQL/MariaDB never goes away.** It is the primary, fully supported driver
> and is **required** for `provider` mode.

`*` SQLite is **available** (`deployment.SQLiteAvailable = true`) and is the
recommended driver for `homelab`/`smallteam` single-node installs. The wizard
offers it as a selectable option (see the DB step in `docs/INSTALL.md`); the
`provider` profile still hard-requires MySQL/MariaDB. Driver choice is persisted
in install state and gated per-profile by `Profile.AllowsDriver`.

- `provider` hard-requires MySQL/MariaDB; the wizard and the profile switch both
  block any other driver.
- All other profiles also default to MySQL/MariaDB today.

## How it works

- The chosen profile is persisted in **install state** (`install_state.json`,
  field `Profile`), stamped with `SetupVersion` on completion so future schema
  changes can detect and upgrade older installs. No database row is involved, so
  resolving it costs no per-request query.
- At request time, each page's base data is populated with
  `deployment.Parse(state.Profile).Features()` - a `deployment.Features` struct
  whose bool fields gate nav items
  (`{{ if .Data.Features.Nodes }}...{{ end }}`).
- **Legacy / unset installs default to `provider`** (every module on), so an
  upgrade from a pre-profile build never hides anything that was visible.

## Changing the profile (Deployment mode)

The active profile is visible after install at **Deployment mode**
(`/admin/deployment`), in the System section of the admin menu.

- Switching the profile is **Owner (super_admin) only** - enforced on the POST
  handler, with the switch controls hidden for everyone else (defense in depth).
- **Upgrades** (e.g. `homelab -> advanced`) apply immediately.
- **Downgrades** are allowed but require an explicit confirmation: they hide
  active modules. **Data is kept, never deleted** - only menu visibility and
  defaults change.
- Switching to `provider` is rejected unless the database is MySQL/MariaDB.
- Every change is written to the audit log (`deployment.profile_changed`).

## Colocated panel + edge

Every profile supports running the panel and its Caddy edge on one host,
with that Caddy carrying real customer traffic - it's the default shape of
`deploy/docker-compose.yml`, not a separate mode to opt into. See
[`MULTI_NODE.md` § 11 "Colocated Panel + Edge (Single Host)"](MULTI_NODE.md)
for the port layout and how it interacts with adding remote nodes later.

## For developers

- Package: `internal/deployment` (`profile.go`) is the single source of truth:
  profiles, cumulative `Features`, `Label`/`Description`, `UIMode`/`TenantMode`/
  `RBACMode`, `DB()`/`AllowsDriver`, `IsDowngrade`, `SetupVersion`,
  `SQLiteAvailable`.
- Add a new gated module by adding a bool to `Features`, setting it in the right
  cumulative tier in `Profile.Features()`, and guarding the nav item / page with
  that field. Provider is the fallback for unknown profiles, so new modules are
  visible by default there.
- Tests: `internal/deployment/profile_test.go` (logic),
  `internal/httpserver/handlers/{admin_deployment,nav_gating,wizard_profile}_test.go`.
