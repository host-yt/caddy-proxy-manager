# Changelog

All notable changes to this project. Format inspired by
[Keep a Changelog](https://keepachangelog.com); the project does not
yet ship versioned releases.

## Unreleased

### Added
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
- Latest internal audit: [`docs/SECURITY_REVIEW_2.md`](docs/SECURITY_REVIEW_2.md).
- Pentest report: [`docs/PENTEST_REPORT.md`](docs/PENTEST_REPORT.md).
- Carry-forward P0: encrypt `users.totp_secret` at rest (recipe in
  the security review).

### Infrastructure
- Migrations now auto-apply on boot (goose, idempotent).
- Build is a pure static Go binary, distroless `nonroot` runtime.
- Compose stack: app + mariadb (or external) + redis + caddy + WG
  sidecar (profile `mesh`).
