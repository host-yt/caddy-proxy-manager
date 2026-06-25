# Changelog

All notable changes to this project. Format inspired by
[Keep a Changelog](https://keepachangelog.com); the project does not
yet ship versioned releases.

## Unreleased

### Added
- **Scoped admin access model** with `admin_client_scope` assignments
  for non-super-admin staff accounts. The admin Users screen now shows
  role, status, 2FA state, and assigned customer scope in one access
  control view.
- **Client-scope enforcement for sensitive admin surfaces**. Tunnel
  management and host access logs now check the acting admin's assigned
  clients before rendering, exporting, streaming, or mutating data.
- **AI provider abstraction** for Anthropic, OpenAI, Gemini, and
  OpenRouter using direct `net/http` integrations and encrypted
  settings keys.
- **WireGuard key-rotation scheduler** with bounded per-tick execution
  and consistent timestamp handling.
- **System events storage** and database migrations for operational
  event history.
- **Route egress settings** migration and host editor fields for
  route-level egress control.
- **Admin access UI refresh** with a dedicated Users / Access screen,
  scope assignment modal, clearer role hierarchy, and safer action
  grouping.
- **Client portal refresh** across dashboard, services, domain routes,
  and private tunnels. The customer-facing UI now uses the shared
  Hostyt card, pill, and metric components for a more consistent
  operational workflow.
- **Admin statistics page** at `/admin/stats` with KPI cards, doughnut
  for route status, line chart for 24 h requests, bar chart for
  audit-event activity, per-node table, top clients, recent routes.
  Chart.js 4.4 loaded from jsdelivr (CSP widened).
- **Caddy `/metrics` poller** (60 s interval) that scrapes the
  Prometheus text format over each enabled node's WG admin URL.
  Stores deltas in `node_traffic_samples`. 14-day retention.
- **One-command node auto-join** (Docker-Swarm style). Admin generates
  a one-time token; a remote VPS runs a single
  `curl … | sudo bash` command that installs WireGuard, Docker,
  Caddy, joins the mesh, and registers itself.
- **WireGuard sidecar** for the manager. Renders `wg0.conf` from the
  DB on each peer change; sidecar applies via `wg syncconf` within
  ~10 s.
- **OIDC sign-in** (Authentik / Microsoft / generic). Server-side
  state + nonce in Redis, ID-token signature + nonce verified, local
  user upsert or auto-provisioning with a configurable default role.
- **Cloudflare integration**: API token saved + verified, optional
  `CF-Connecting-IP` trust toggle, Turnstile CAPTCHA on login (live
  reload of site_key + secret from DB).
- **API keys + REST API v1** with bearer-token middleware. Endpoints
  for services / routes / nodes / health.
- **Password reset** flow (email + 30-min token), **brute-force
  lockout** (10 fails / 15 min, Redis), **2FA TOTP** with QR
  enrollment + recovery codes for both admin and client roles.
- **Customer portal** at `/app` (services view, domain mapping CRUD,
  DNS recheck, 2FA self-enrollment).
- **Audit log** writer with entries for every mutation surface +
  filterable admin page.
- **Settings page**: SMTP (encrypted password), ACME contact +
  staging toggle, OIDC config, Turnstile, Cloudflare token,
  WireGuard endpoint + keypair generation.
- **Dark / light mode** with localStorage + prefers-color-scheme,
  Inter font, consistent design across install / auth / admin / app
  layouts.
- **Security headers** middleware (CSP, HSTS, X-Frame-Options,
  Referrer-Policy, Permissions-Policy, X-Content-Type-Options).
- **CSRF middleware** with hidden tokens on every authenticated form.
- **Plan limits** enforcement at route create (`max_domains`).
- **Trusted proxies** wired into chi's `RealIP`.

### Fixed
- Tunnel hard-delete now revokes a peer before removing the database row
  so node agents can observe the removal intent.
- Host log export now has a per-session rate limit and scope checks
  before CSV/JSON export.
- AI provider responses are decoded with a bounded reader to prevent
  unbounded response bodies from consuming memory.
- Six admin / app form templates were missing `csrf_token` hidden
  inputs; the CSRF middleware was rejecting them with 403. Added
  tokens to clients, plans, services, users, route-new, routes-list
  templates.
- API key plaintext leaked through URL query string on create. Now
  rendered inline on the same response, never via redirect.
- `/static/` directory listing was enabled by default
  (`http.FileServer` behaviour). Wrapped with `noDirListing` -
  trailing-slash URLs return 404.

### Security
- Added IDOR protections for admin tunnel actions, bandwidth data, host
  log pages, host log JSON, host log export, and live log streams.
- Admin scope wiring is now initialized at server startup instead of
  relying on optional handler state.
- Latest internal audit: [`docs/SECURITY_REVIEW_2.md`](docs/SECURITY_REVIEW_2.md).
- Pentest report: [`docs/PENTEST_REPORT.md`](docs/PENTEST_REPORT.md).
- Carry-forward P0: encrypt `users.totp_secret` at rest (recipe in
  the security review).

### Infrastructure
- Migrations now auto-apply on boot (goose, idempotent).
- Build is a pure static Go binary, distroless `nonroot` runtime.
- Compose stack: app + mariadb (or external) + redis + caddy + WG
  sidecar (profile `mesh`).
