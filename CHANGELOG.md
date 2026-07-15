# Changelog

All notable changes to this project. Format: [Keep a Changelog](https://keepachangelog.com).

## [1.4.0] - 2026-07-15

### Added

- **SQLite database engine**: the panel now runs its full MySQL-dialect query set on SQLite, so a homelab/single-node install needs no MariaDB - pick `db_driver=sqlite3` in the install wizard. Migrations, the missing SQL functions (`NOW`, `DATE_FORMAT`, `GREATEST`, `SHA2`, …), engine-native backup dump and restore-drill are all covered. MySQL/MariaDB stays the default for multi-writer/scale deployments; SQLite runs single-writer (`MaxOpenConns(1)`).
- **Serve operator-imported TLS certs on the edge**: a manual certificate linked to a route is now pushed to that route's node(s) and served for its domain over TLS with no ACME (`apps.tls.certificates.load_pem`). Previously manual certs were only stored/monitored. A pooled cert matches its SNI before on-demand issuance, so private-CA / internal domains just work; unlinked certs stay import-only.
- **Group-first add-host form**: `/admin/hosts/new` leads with the node group / mode, gates on the DNS-ownership check, and lands on the edit page - a clearer path than the old flat form.
- **Health-driven DNS steering** and **RTT tracking from health probes**: nodes record round-trip latency and DNS can steer away from unhealthy nodes.
- **Inbound PROXY protocol for HTTP**: read the real client IP from an upstream L4 balancer/tunnel (per-node, allow-listed).
- **Doctor preflight checks** for the panel and node-agent.

### Fixed

- **Multi-node cluster drops routes on non-anchor nodes (#3)**: a route on a node group compiled `routes: 1` only for the node matching `caddy_node_id`; every other node in the group got `routes: 0` and answered `NOP`. The config builder now emits the route for every node serving it (direct assignment or `route_node_assignments` fan-out), so all peers in an `active_active`/`failover` group get the identical payload.
- **Enabling WAF could brick a node**: Coraza's audit log opens `/var/log/caddy/waf-audit.log` at config-load; a missing dir made Caddy reject the whole `/load` (400) and freeze the node. The edge image now bakes the directory.
- **Enabling GeoIP could brick a node**: the panel emitted a maxmind matcher even when the country DB was absent, so Caddy rejected the whole node config. Geo is now gated on the DB being present.
- **Blank Manual Certificates page**: `/admin/manual-certs` rendered only chrome (no import form or table) because the page was missing from the admin layout's content dispatch. Added, plus a test that fails if any admin page is left undispatched.
- **Already-expired auth tokens on non-UTC servers**: password-reset / node-join / registration tokens computed expiry in Go-UTC but checked it against DB-local `NOW()`, so a fresh token could be born expired on a non-UTC server. Expiry is now computed DB-side.
- **Module capability flags not passed to the app**: the compose forwarded only `LAYER4`/`CACHE`; WAF/GeoIP/rate-limit/weighted-LB flags an operator set in `.env` are now honored.
- **Compose network race**: `geoip-init` is pinned to the internal network so its implicit default network can't collide with the pinned `172.18.0.0/16` subnet.

## [1.3.4] - 2026-07-12

### Fixed

- **First-run On-Demand TLS 403 (#1)**: on a clean install the panel's own domain lived only in `caddy_nodes`, so `/internal/ask` denied Caddy's cert request and the panel could never provision its own certificate. The panel's `APP_URL` host is now always approved for issuance.
- **First-run login loop over HTTP IP (#1)**: the session/auth cookie `Secure` flag was static from config, so accessing the panel via `http://<IP>:8080` before TLS was set up made browsers silently drop the cookie (endless redirect to login). `Secure` is now derived per-request - kept on real HTTPS (direct TLS or `X-Forwarded-Proto: https`), dropped on plain HTTP. Never upgrades a request that config marked insecure.
- **WireGuard node-to-master 0 bit/s stall (#2)**: Docker forces the kernel `FORWARD` policy to `DROP`, so node-to-master traffic that DNATs into a published container port was silently dropped (infinite TCP retransmits). The master `wg0.conf` now installs `FORWARD` accept rules for `wg0` on interface up and removes them on down; harmless on non-Docker hosts.

## [1.3.2] - 2026-07-03

### Fixed

- **Admin resellers page 500**: `/admin/resellers` returned HTTP 500 for super-admins because a page-local `Features` field shadowed the shared nav-gating one. Renamed to `PkgFeatures`.
- **Blank client route pages**: `/app/routes/{id}/edit` and `/app/routes/{id}/logs` rendered empty for clients - the layout content dispatch had no branch for those pages (handlers and templates already existed). Both now render.
- **WAF ingest throughput**: a full 500-event batch could not finish within the 30s budget (it did ~2000 sequential DB round trips) and looped 503s in production. Route resolution now runs as one indexed query per batch and inserts commit in one transaction per batch.

### Added

- **Backend-server registry**: manage named backend servers (name + IP + external reference) under `/admin/servers`, reseller-scoped, and pick one from a dropdown in the service form instead of retyping raw IPs.
- **Plan-driven port range**: selecting a plan auto-fills a service's end port from the plan's port count; only the start port is entered.
- **First-free-port pre-fill**: the client new-route form pre-fills the first unused port from the client's pool.

### Changed

- **Port-collision guards**: reject a service port range that overlaps another service on the same backend IP, and a route port already used within its service.
- **Client portal**: removed the duplicate sidebar dark/light toggle (top-bar one stays); `Cmd/Ctrl+K` command palette now works in the client portal.

## [1.3.1] - 2026-07-02

### Fixed

- **DNS domain-ownership proof**: the panel now reads the `_hpg-verify` TXT record straight from the domain's authoritative nameservers instead of the container's default resolver. Fixes verification failing when the record is published and visible to external tools but the container's Docker DNS returns a stale/split-horizon answer, without weakening the proof (it stays anchored to the zone's delegation). The A/CNAME serving check uses public resolvers for the same reason.
- **WAF event ingest loop**: a backlog could get stuck re-shipping forever. Per-route pruning moved off the per-event hot path (once per route per batch), the ingest handler no longer aborts on client disconnect mid-batch, unattributed (route-less) events are now globally capped, and an incomplete batch returns a retryable error so no events are silently dropped. A concurrency cap sheds load under retry storms.
- **Node control-plane rate limiting**: authenticated node endpoints (`/api/node/*`, `/internal/*`) are exempt from the unauthenticated-POST limit, so a busy node's WAF/access-log batches can no longer 429 themselves into a stall.

### Removed

- **Client support/contact form**: removed the in-app contact page and its mail path.

## [1.3.0] - 2026-07-02

### Reseller multi-tenancy

- **Resellers**: a reseller owns a set of clients (and optionally its own plans + branding) and is managed by a reseller-admin who sees ONLY that reseller's clients - never platform-global infra or other resellers.
- **Explicit admin tiers**: super_admin > unrestricted platform admin > reseller-admin (`users.reseller_id`) / client-scoped admin (`users.is_restricted` + `admin_client_scope`). Restriction is now an explicit opt-in flag, no longer inferred from assignment-row count.
- **Reseller-scoped plans**: plans may be global (available to every tenant) or owned by one reseller; reseller-admins create and manage only their own.
- **Self-service provisioning**: reseller-admins provision their own clients, hosts, services, routes, tunnels and L4 streams, all bound to the reseller's ownership.
- **Per-reseller branding**: client portal + public status page overlay the owning reseller's brand name, logo, colours and support email.
- **Suspend/resume**: suspending a reseller fails closed - reseller-admin scope resolves to nothing (never falls through to platform-wide access), and their sessions are revoked immediately.
- **Super-admin management UI** for reseller CRUD, client assignment and reseller-admin provisioning.

### API & Terraform

- **Multi-tenant API v1 key scope**: a reseller-admin API key is transparently scoped to its own clients/plans and cannot touch global infrastructure (nodes, node pools, global plans, client provisioning are platform-admin only).
- **Terraform provider** (`terraform-provider-hpg`, in-repo nested module): resources `hpg_node_pool`, `hpg_node`, `hpg_plan`, `hpg_client`, `hpg_service`, `hpg_route` - a thin client over API v1 with import support and async-SSL awareness. Ships GoReleaser + release workflow for turnkey Terraform Registry publishing.

### Deployment

- **Lite stack**: `deploy/docker-compose.lite.yml` runs stock Caddy with every edge module disabled (`*_AVAILABLE=0`), for installs that do not need WAF/GeoIP/L4/cache/rate-limit. Full-vs-lite guidance added to the install docs.

### Security

- Closed multiple reseller-boundary and IDOR gaps found by adversarial review: scope-checked single-service, client status-slug and bulk admin handlers; restricted plan mutation to unrestricted platform admins; scoped L4 streams to the owning client.
- Fixed a scope-escalation footgun by making admin restriction explicit (`users.is_restricted`) instead of inferring it from `admin_client_scope` row count.
- Terraform `hpg_service` delete now calls the registered `DELETE /services/{id}` (previously an unregistered `POST /delete` whose 404 was swallowed as success, leaving services live while dropping them from state).
- Scoped `ClientDelete` so a reseller-admin can destroy its own client via the API/Terraform.
- Earlier hardening batch: rotate all `_enc` columns per purpose, force remote-backup encryption, configurable Caddy Admin API bind, AI-chat retention + rate-limit + error redaction, Docker hardening.

## [1.0.0] - 2026-06-28

### Authentication & Access Control

- **Argon2id** password hashing (3 iterations, 64 MiB, 2 threads, ~150 ms verification).
- **2FA**: TOTP (30-second window, QR enrollment, recovery codes), Email OTP, SMS OTP, WebAuthn/passkeys (discoverable login, sign-count tracking, backup eligibility).
- **RequireAdmin2FA** enforcement middleware with 60-day first-login grace period.
- **OIDC sign-in** (Authentik, Microsoft, generic): PKCE S256, nonce verification, auto-provisioning, configurable scopes, SSRF-guarded discovery.
- **OAuth2 social login**: GitHub and Google as forward-auth portal providers.
- **Multi-provider CAPTCHA**: Cloudflare Turnstile, hCaptcha, reCAPTCHA v3 - live site-key reload from DB every 30 seconds.
- **API keys**: `hpg_PREFIX_SECRET` format, HMAC-SHA256 fast-path verification, per-key RPM cap, last-used IP and timestamp tracking, revocation and expiry.
- **Brute-force lockout**: 10 failed logins per 15 minutes, Redis-backed, per-IP.
- **Password reset**: email + 30-minute single-use token (FOR UPDATE locking on redeem).
- **Auditable impersonation**: super-admin sees client portal; every action attributed to admin + impersonated user in audit log; banner on all pages.
- **Scoped admin access**: `admin_client_scope` assignments for non-super-admin staff; scope enforced on tunnels, host logs, exports, and all write surfaces.
- **Session security**: per-session CSRF token, Redis-backed sessions, configurable TTL, destroy-all on password reset.

### Proxy Configuration

- **HTTP routes** with full per-route control: upstream scheme (http/https), SNI pinning, skip-TLS-verify, custom Host header, response compression (gzip + zstd).
- **Load balancing**: `round_robin`, `least_conn`, `ip_hash`, `weighted_round_robin`, `uri_hash`, `header`, `cookie` (with HMAC secret).
- **Active health checks**: URI, interval, timeout, expected status, fail threshold.
- **Passive health checks**: consecutive failures, fail duration.
- **Per-route timeouts**: dial, read, write, idle configurable.
- **Multi-upstream support**: dial list per route with independent health state.
- **HTTP cache** per route (Souin/caddy-cache-handler module): TTL, Vary header, GET/HEAD only, skips auth routes.
- **Rate limiting** per route (caddy-ratelimit module): zone, key (`{http.request.remote.host}` default), window, max events.
- **WAF (Coraza/corazawaf)**: OWASP CRS, detection-only or blocking mode, custom SecLang directives, per-route toggle, rule suppression, event acknowledgement. Requires non-stock Caddy build.
- **GeoIP country/continent blocking** (caddy-maxmind-geolocation module): allow/deny mode, ISO 3166-1 country codes, continent codes (AF/AN/AS/EU/NA/OC/SA), configurable response code, fail-closed option, CIDR bypass list, CIDR always-block list. Weekly MaxMind DB download. Requires non-stock Caddy build.
- **mTLS** (stock Caddy tls_connection_policies): per-tenant CA generation, client cert issue/revoke, require_and_verify or request mode, path-based RBAC via panel internal forward-auth endpoint.
- **L4 TCP/UDP streams** (caddy-l4 module): SNI routing, configurable log retention. Requires non-stock Caddy build.
- **SSO forward-auth**: any Authentik/Authelia-compatible provider, per-route, strict zero-trust mode, copy-headers, trusted-proxies.
- **Built-in forward-auth portal**: panel-hosted login gate with OAuth2 social login, TLS, custom dial.
- **HTTP basic auth**: single-user or multi-user (JSON array, bcrypt hashes).
- **IP access lists**: CIDR allow/deny, block-all mode, maintenance allow-list.
- **Maintenance mode**: 503 static response, custom message, IP allow-list bypass.
- **Location rules**: path-specific proxy, redirect, rewrite, or block within a single host.
- **Custom JSON handlers**: admin-supplied Caddy handler array injected into route config.
- **On-demand TLS** with `/internal/ask` allowlist gate and DB lookup.
- **DNS-01 wildcard ACME** (caddy-dns module): per-provider credentials, per-zone policies.
- **Manual TLS certificate import** with expiry monitoring and alerts.
- **Configurable ACME CA**: Let's Encrypt, ZeroSSL, or custom URL.
- **IPv6 dual-stack**: verified dual-stack listen config and upstream dial.
- **DNS resolver controls**: per-route resolver IP, WireGuard-routed resolver, address family preference.

### WireGuard

- **L3 mesh**: automatic peer add/remove via `wg syncconf` (~10 s apply time).
- **One-command node auto-join**: admin generates a one-time token (30-minute TTL); remote VPS runs `curl | sudo bash` to install WireGuard, Docker, Caddy, and register itself.
- **WireGuard-over-WSS** (wstunnel): firewall-traversal for nodes behind CGNAT; node-agent supervises wstunnel process and publishes availability.
- **Key rotation scheduler**: bounded per-tick execution, consistent timestamp handling.
- **nftables enforcement**: node-agent verifies ip_forward, firewall backend, MTU; blocks cross-peer traffic.
- **Per-tunnel bandwidth stats**: ingress/egress bytes tracked and surfaced in admin UI.

### Multi-tenancy & Client Portal

- **Client tenants** with plan-based quotas: `max_domains`, port ranges, RPM caps per tier.
- **Two plan types**: `restricted` (admin pins backend IP + port range) and `npm` (full client self-service).
- **Customer portal** (`/app`): service listing, domain route CRUD, DNS pre-check, SSL retry, 2FA self-enrollment, API key management.
- **Client self-registration**: opt-in toggle in settings; configurable default role.
- **Client tags**: operator-defined labels for tenant filtering and segmentation.
- **Custom fields**: operator-defined metadata fields for clients and hosts (JSON-backed per-entity storage).
- **Host groups**: named groups with filter and badge in admin host list.

### AI Assistant

- **Multi-provider streaming**: Anthropic, OpenAI, Gemini, OpenRouter via direct HTTP (`net/http`), encrypted API keys in DB.
- **Scoped read-only tool-calling**: admin tools (fleet-wide), client tools (own services only, cross-tenant isolation enforced via `client_id IN` filter).
- **Available tools**: traffic stats, top hosts, top countries, route logs, route detail, client detail, node detail, plan violations, active alerts, list clients/routes/nodes/plans/services.
- **Floating bubble**: type-to-start UX, in-panel conversation list, auto-title at 5 turns.
- **Markdown rendering**: mdlite.js with table support, code blocks, inline formatting.
- **Per-user rate limiting** and anti-hallucination system prompt hardening.

### Monitoring & Analytics

- **Prometheus poller**: scrapes Caddy `/metrics` every 60 seconds; stores `node_traffic_samples` deltas; 14-day retention; ~20 k rows/node at 60 s interval.
- **Hourly log rollups**: aggregate bytes sent/received, request count, country breakdown; survives raw-log prune; 14-day retention.
- **Admin stats page** (`/admin/stats`): KPI cards, doughnut (route status), 24 h request line chart, audit-event bar chart, per-node traffic table, top clients, recent routes. Chart.js 4.4.
- **World traffic map**: country-level heatmap of visitor traffic; visible to both admin and client roles (client sees own routes only).
- **Alert rules**: high-error-rate detection (5xx ratio), custom threshold alerts, manual certificate expiry alerts.
- **Access log analytics**: bytes sent/received, protocol, country, ASN per request; analytics charts on host logs page.
- **Node egress IPs**: display and per-tunnel bandwidth in node detail view.

### REST API

- **`/api/v1`** endpoints: services (CRUD + port assignment), routes (create/delete/verify-DNS/retry-SSL), nodes (list/register/resync), health.
- **Idempotency keys**: per-request deduplication, 24-hour TTL.
- **Per-key rate limiting**: RPM cap enforced at middleware, 429 on exceed.
- **FOSSBilling provisioning integration**: external billing system can provision services via API.
- **NPM importer**: migrate hosts from Nginx Proxy Manager config format.

### UI & Design System

- **Dark-ops console** (P0-P6 redesign): teal accent token system, gold secondary accent, semantic color layer, Tailwind bridge.
- **Command palette** (`Cmd+K`): fuzzy search across admin and client nav items, keyboard-first navigation.
- **Right-sheet drawer**: slides in from right for modals, inline edits, route details.
- **Collapsible navigation groups** with greeting header and CTA button.
- **Dark / light mode**: localStorage preference + `prefers-color-scheme` fallback.
- **Inter font** with consistent type scale across install, auth, admin, and app layouts.
- **40+ admin templates**: dashboard, hosts, clients, plans, services, nodes, streams, tunnels, certs, WAF events, audit, stats, alerts, access groups, users, mTLS, backups, DNS providers, webhooks, branding, world map, AI chat, host logs, and more.
- **13 client portal templates**: dashboard, services, routes, route logs, tunnels, API keys, account, 2FA, world map, contact.
- **htmx** for HTMX partial updates on host-delete and DNS-check flows.
- **Row-action kebab menu** unified across all list tables.

### Audit & Security

- **Audit log**: every write operation logged with actor ID, IP, impersonator ID, and timestamp; filterable admin page.
- **CSRF middleware**: per-session token, constant-time compare, applied to all authenticated non-GET routes.
- **CSP**: per-request nonce, `default-src 'self'`, script-src nonce-only + captcha vendor exceptions.
- **HSTS**: 63 million seconds with `includeSubDomains`.
- **IDOR protections**: scope-checked before every read or write on tunnels, bandwidth data, host logs, log export, live streams.
- **Stored-XSS fix** in custom-field definition list; atomic host metadata persistence.
- **Static file directory listing** disabled (`noDirListing` wrapper).
- **API key plaintext** never returned via redirect; inline on create response only.
- **Atomic audit clear** and WAF global purge restricted to `super_admin` role.

### Infrastructure & Deployment

- **Docker Compose stack**: `app` + `mariadb` (MariaDB 11) + `redis` (Redis 7) + `caddy` (xcaddy with cache-handler, L4) + `geoip-init` (volume prep) + `hpg-node-agent` (log forwarder, WG sync) + `wireguard` sidecar (profile: `mesh`).
- **4 installation profiles**: `homelab` (single owner), `smallteam` (shared ops), `advanced` (DevOps/fleet), `provider` (hosting provider with multi-tenant).
- **Dual database backends**: MariaDB/MySQL (default, recommended for production and multi-node) and SQLite (`DB_DRIVER=sqlite3`, embedded pure-Go driver, no separate service, intended for homelab/single-node). Backend is chosen during the install wizard or via `DB_DRIVER` env var.
- **goose migrations**: 117 migrations, out-of-order apply via Provider API with `WithAllowOutofOrder(true)`, MySQL GET_LOCK serialization for concurrent boots; runtime SQL transformer rewrites MySQL DDL to SQLite-compatible syntax.
- **Pure static Go binary**: distroless `nonroot` runtime, ~21 MB image, ~28 MB idle RAM.
- **Node agent** (Go): WireGuard peer sync, nftables verification, wstunnel supervision, access log forwarding, WAF audit log forwarding, GeoIP DB distribution, health reporting.
- **Backup targets**: S3 (MinIO-compatible), SFTP, FTP; restore drill CLI endpoint.
- **Instance sync**: master/slave HPG config replication for multi-panel deployments.

### Fixed

- Tunnel hard-delete revokes WireGuard peer before removing DB row so node agents observe removal intent.
- Host log CSV/JSON export enforces per-session rate limit and scope checks.
- AI provider responses decoded with bounded reader (prevents unbounded memory consumption on large completions).
- Six admin/app form templates missing `csrf_token` hidden inputs (clients, plans, services, users, route-new, routes-list) - CSRF middleware now accepts them.
- API key plaintext no longer leaks through URL query string.
- `/static/` directory listing disabled.
- Stored-XSS in custom-field definition list with atomic host metadata persistence.
- mTLS RBAC scope checks, cert subject ambiguity, body buffering, portal OAuth cross-host state.
- Instance sync context race, slave resync notification, and geo SQL argument mismatch.
- WAF event pipeline: wire coraza-caddy audit directives and agent env correctly (events log was always empty before fix).
- Settings `#banner` and `#instances` tabs showed empty pane due to DOM mid-parse IIFE timing; fixed with `DOMContentLoaded` deferral and lazy pane query.
- Captcha provider-switch login lockout: prevented by preserving provider on partial config.
- Custom `onmouseover`/`onmouseout` inline handlers replaced with delegated `data-action` listeners (CSP violation).
- Node capability probe: removed fake `/modules` probe; gate WAF/GeoIP/rate-limit via env-flag fallback.
- Prefill node edit form with effective capabilities so save cannot accidentally disable env-backed modules.
- WAF `action` value corrected from `'block'`/`'detect'` to `'blocked'`/`'detected'` in SQL queries.
- `DATE_FORMAT` used for timestamp columns in AI tool queries (`parseTime=true` breaks `*string` scan).
- Access log `request.host` field parsing (every ingested line was dropped without this fix).
- Caddy access log file stayed empty: removed invalid `logger_names` wildcard.
- GeoIP self-provisioning volume permissions; surface refresh errors in settings UI.
- Forward-DROP alarm suppressed when Docker iptables covers the rule.
- Live-tail SSE killed by absolute `WriteTimeout`: use `ResponseController` for flush.
- mTLS CSP blocks inline `onclick` handlers: use delegated `data-action`.
- OAuth account state: fail-closed on undecryptable secret; clamp mTLS leaf to CA NotAfter.
- Saved filter load: escape LIKE wildcards, wire filter restore on page load.
- `saved_filters` FK type mismatch crashing boot.
- AI chat FK name collision crashing boot (`ai_chat` tables).
- OIDC `users.oidc_subject`/`oidc_issuer` legacy columns dropped cleanly (migration 94).
- `plans.websocket_enabled` column name inconsistency in ownership and violation queries.
- `clients.plan_id` join corrected to go via `services.plan_id`.
- Fix cross-attribute `{{if}}` context mismatch in admin dashboard template.
- IP access list syntax parsing.

### Security

- IDOR protections added for admin tunnel actions, bandwidth data, host log pages, host log JSON, host log export, and live log streams.
- Admin scope wiring initialized at server startup (not deferred to first request).
- SSRF-guarded HTTP client enforced on OIDC discovery, JWKS fetch, and token endpoint calls (rejects RFC 1918, loopback, link-local).
- `RequireRole` middleware applied consistently before any DB write in all admin handlers.
- `scopeCheckRoute` called before every write in multi-tenant handler chains.
- Encrypted field pattern (`_enc`, AES-256-GCM via `APP_SECRET`) applied to OIDC client secret, SMTP password, Cloudflare token, captcha secret, GeoIP license key, mTLS private keys, AI provider keys.
- Pentest findings addressed: see `docs/PENTEST_REPORT.md`.
- Internal security review: see `docs/SECURITY_REVIEW_2.md`.

---

## [0.1.0] - 2026-06-24

Initial working MVP. Go 1.26, chi router, MariaDB, Redis, Caddy 2.8, WireGuard mesh, multi-tenant client portal, plans/quotas, TOTP 2FA, OIDC, API keys, REST API v1 (partial), audit log, install wizard.
