# Hostyt Proxy Gateway

Self-hosted control panel for a fleet of [Caddy](https://caddyserver.com)
reverse-proxy nodes. Customers get a VPS with a fixed backend IP and a
fixed range of public ports; they map their own domains to those ports
through the panel. The control plane configures every Caddy node over
WireGuard, drives Let's Encrypt issuance, and surfaces traffic stats.

**Status:** working MVP. Stack: Go 1.26, chi, MariaDB, Redis, Caddy 2.8.
Single binary ~21 MB image, ~28 MB idle RAM.

---

## Highlights

- **NPM-style operator surface**: `/admin/hosts` is a flat list of
  every domain across every client. **Add host** in one form (domain +
  backend IP:port + node) - the implied client/plan/service rows are
  provisioned automatically under your admin account.
- **Self-bootstrap panel route**: the install wizard pushes a virtual
  Caddy route for the public APP URL → app container on the first
  node, so you can sign in via `https://proxy.example.com` without
  adding a host first.
- **Two plan kinds**:
  - `restricted` (default) - admin pins backend IP + port range,
    client picks domain + port from the range. The hosting-provider
    model.
  - `npm` - full self-service: the client may edit backend IP + port
    range from `/app/services`. Use for resellers / your own accounts.
- **Auditable client impersonation**: super-admin opens `/admin/users`,
  clicks Impersonate, sees the client portal as them. Every action is
  audit-attributed to the admin with `impersonated_user_id` in meta;
  the impersonation banner is visible on every page. Back to admin
  via `/auth/end-impersonation`.
- **Bulk actions on hosts**: enable / disable / delete many rows from
  the flat list, with a single Caddy resync per affected node.
- **Inline DNS pre-check** on the Add-host form before submit.
- **Per-host retry** triggers a DNS re-check + Caddy re-push, which
  is the clean unblock when Let's Encrypt has been failing for a host
  whose DNS is already correct.
- **One-command node join** (Docker-Swarm style): operator generates a
  token in the panel; new VPS runs one `curl | sudo bash` line and is
  fully provisioned, including WireGuard mesh and Caddy.
- **WireGuard sidecar** on the manager auto-applies peer add/remove via
  `wg syncconf` - no manual interface restart on each join.
- **Caddy Admin API** driven in JSON mode, source of truth is the DB.
- **On-Demand TLS** with an `/internal/ask` allowlist gate; ACME
  certificates issued automatically when a domain points at the right
  node.
- **2FA TOTP** with recovery codes, **OIDC** (Authentik / Microsoft /
  generic), **CSRF**, **Argon2id** passwords, **Redis-backed brute-
  force lockout**, **Cloudflare Turnstile** CAPTCHA, **AES-256-GCM**
  encryption for secrets at rest.
- **REST API v1** with bearer-token auth for FOSSBilling / Hostyt-style
  provisioning integrations.
- **Live admin stats**: KPI cards, doughnut/line/bar charts, per-node
  traffic (Prometheus-scraped from Caddy).
- **Dark / light mode** UI with Inter font and a consistent design
  system.

---

## Quick start (single host)

```bash
git clone <repo> hostyt-proxy-gateway && cd hostyt-proxy-gateway
cp .env.example .env
$EDITOR .env       # at minimum: APP_URL, APP_SECRET (openssl rand -hex 32), DB_PASSWORD

docker compose -f deploy/docker-compose.yml --env-file .env up -d
open http://localhost:8080            # walks through the install wizard
```

After the wizard completes, sign in with the admin user you just
created.

For multi-node deployments enable the WireGuard sidecar profile:

```bash
docker compose -f deploy/docker-compose.yml --env-file .env --profile mesh up -d
```

Then in **Settings → WireGuard**, fill `Public endpoint`
(`manager.example.com:51820`), Save → keypair generated.

To add a remote Caddy node:

1. **Admin → Caddy nodes → Auto-join → Generate join command** -
   shows a one-time `curl … | sudo bash …` line (TTL 30 min).
2. Paste it on the new VPS as root. It installs WireGuard, Docker,
   Caddy, joins the mesh, and registers itself.

Full guide: [docs/MULTI_NODE.md](docs/MULTI_NODE.md).

---

## Repository map

```
cmd/server/         entrypoint (thin)
internal/
  audit/            audit-log writer
  auth/             Argon2id, sessions, TOTP, recovery codes, API keys, password reset
  caddyapi/         Caddy Admin API client + JSON config builder
  captcha/          Cloudflare Turnstile verifier (DB-backed live config)
  cloudflare/       Cloudflare API token + CF-Connecting-IP trust toggle
  config/           env loader + validation
  dns/              pre-flight DNS resolver
  domain/           business logic per aggregate (routes, plans, services, …)
  httpserver/       chi router, handlers, middleware (CSRF, security headers, etc.)
  installstate/     wizard state file + AES-256-GCM crypto helpers
  mail/             SMTP send + email templates
  metrics/          Caddy /metrics scraper + delta aggregator
  nodejoin/         one-time join-token mint + redeem
  oidc/             coreos/go-oidc wrapper, DB-backed config
  store/            DB pool + goose migration runner
  view/             html/template sets per audience (install, auth, admin, app)
  wireguard/        Curve25519 keypair gen, config writer, IP allocator
deploy/
  docker-compose.yml    manager stack (app + mariadb + redis + caddy + optional wg)
  caddy/                Caddy node image (Caddyfile bootstrap)
  remote-node/          drop-in compose for an external Caddy node
  wireguard/            WG sidecar image (alpine + wg-tools + watch loop)
migrations/             goose .sql files
scripts/                node-join.sh - bash bootstrap for remote nodes
docs/                   all the docs you'll find linked below
```

---

## Documentation

| Doc | What's in it |
| --- | ------------ |
| [`docs/INSTALL.md`](docs/INSTALL.md) | Step-by-step first-deploy |
| [`docs/DEPLOY.md`](docs/DEPLOY.md) | Production deploy + Portainer + reverse-proxy tips |
| [`docs/MULTI_NODE.md`](docs/MULTI_NODE.md) | WireGuard mesh + one-command node join |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | How the pieces talk |
| [`docs/API.md`](docs/API.md) | REST API v1 contract |
| [`docs/SPEC.md`](docs/SPEC.md) | Functional specification |
| [`docs/SECURITY.md`](docs/SECURITY.md) | Threat model and security model |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Shipped features and planned work |
| [`docs/FEATURE_MATRIX.md`](docs/FEATURE_MATRIX.md) | HPG vs alternatives comparison |
| [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) | Common issues + fixes |
| [`CHANGELOG.md`](CHANGELOG.md) | Notable changes |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | How to develop / submit changes |
| [`SECURITY.md`](SECURITY.md) | Reporting vulnerabilities |

---

## License

See [LICENSE](LICENSE). For open-sourcing guidance see
[`docs/OPENSOURCING.md`](docs/OPENSOURCING.md).
