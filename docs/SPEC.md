# Hostyt Proxy Gateway - Functional Specification

## Overview

Hostyt Proxy Gateway (HPG) is a self-hosted multi-tenant control plane for a fleet of Caddy reverse-proxy nodes. A single Go binary manages plans, services, domains, and tunnels; translates them into Caddy JSON configs; and pushes configs over WireGuard to every node in the fleet.

Target use case: hosting providers, homelabs, and small teams that want an NPM-style UI with multi-tenancy, API access, and WireGuard tunnel management.

---

## Roles

| Role | Description | Key Permissions |
|------|-------------|-----------------|
| `super_admin` | Platform owner | All operations, global settings, plan management, impersonation |
| `admin` | Staff operator | Client and node management, impersonation, no global settings |
| `client` | End user | Own services and routes only; no backend IPs visible |
| `support` | Read-only staff | View clients and routes; no write access |

Role is stored in the `users.role` column and re-checked on every request - no caching in session or API key.

---

## Core Entities

### Nodes

Caddy proxy nodes registered with the manager. Each node has:
- WireGuard peer entry (key + allocated IP in the mesh)
- `max_routes` capacity and `current_routes` counter for placement heuristics
- Group membership for multi-node deployments
- Health polling via Caddy Admin API (`:2019`)

### Hosts (Services)

NPM-style flat host records owned by admin. Each host maps a domain to an upstream. Backed by a `services` row linking a client, a plan, and a node group.

### Routes

Per-service routing rules created by clients or admins. A route maps a hostname (+optional path prefix) to an upstream. Features per route:
- TLS (auto ACME or custom cert)
- HTTP redirect
- Static response
- WebSocket gating
- Basic auth
- SSO forward-auth
- ACL (IP allowlist/blocklist)
- Cache (Souin, if module loaded)
- gzip/zstd encoding
- Custom response headers
- Rate limiting
- Force HTTPS redirect

### Tunnels

Customer-facing WireGuard tunnels. Each tunnel is a WireGuard peer with:
- Auto-allocated IP in the customer subnet
- Key negotiation (panel generates keypair; client downloads config)
- Handshake health reporting
- Optional WireGuard-over-WebSocket (wstunnel) for firewalled networks

### Clients

User accounts with role `client`. Linked to a `services` record (plan + node group). Admins can impersonate clients.

### Plans

Named quota sets defining:
- `max_domains` - maximum active routes
- `max_ports` - maximum L4 stream endpoints
- `rate_limit_rpm` - default RPM cap applied to client API keys
- Route type permissions (`restricted` vs `npm`)

### Resellers

A white-label tenant that owns a set of clients (and optionally its own plans + branding). A reseller has:
- Identity/branding: `name`, `slug` (unique), `brand_name`, `logo_url`, `support_email`, `primary_color`
- `status` - `active` or `suspended`; suspending a reseller revokes every session belonging to its users and fails closed (its admins immediately lose access, never fall through to unrestricted)
- An owner account (`owner_user_id`) - a user with `role = 'reseller'` created atomically with the reseller
- A subscribed package (`reseller_plan_id`, see ResellerPlan below); new resellers default to the "Unlimited" package
- Policy flags: `overselling_allowed` (real-usage vs allocation-based domain enforcement) and `can_create_plans` (whether the reseller may author its own service `Plans`, bounded by its package's grants)

Ownership is expressed by `clients.reseller_id` / `plans.reseller_id` / `users.reseller_id` (all `NULL` = platform-direct). A reseller-admin user (`role = 'reseller'`, or a legacy `role = 'admin'` with `reseller_id` set) sees only clients owned by its own reseller - never platform-global infrastructure or another reseller's tenants.

### ResellerPlan

A reseller package: the aggregate quota + resource grant tier a reseller subscribes to (analogous to a Plesk "reseller plan" or WHM "account limits"). Distinct from a `Plan`, which caps a single client `Service`. A ResellerPlan defines:
- `max_clients`, `max_domains_total`, `max_services_total` - aggregate caps across every client/service/route owned by the subscribed reseller (`0` = unlimited)
- `rate_limit_rpm_cap` - ceiling a reseller's own authored plans may not exceed
- Node pool grants (`reseller_plan_node_groups`) - which node groups the reseller's services may be placed on
- Feature grants (`reseller_plan_features`) - which route features (`ssl`, `wildcard`, `websocket`, `path`, `external`, `waf`, `geo`, `l4`, `cache`, `rate_limit`, `dns01`, `weighted_lb`) the reseller's own plans may enable

Package management is platform-admin only; a super_admin must grant a package before a reseller can author its own plans.

### Aggregate quota enforcement (`internal/quota`)

A business limit, not a security boundary - tenant isolation is a separate concern (see Roles/scoping). Enforced at three create surfaces for any client/service/route owned by a reseller with a subscribed package:
- **Client creation** - rejected once the reseller's client count reaches `max_clients`
- **Service creation** - rejected once the reseller's service count reaches `max_services_total`; when `overselling_allowed` is off, the new service's plan `max_domains` must also fit the package's remaining `max_domains_total` allocation (routes are then bounded by the per-plan cap, so the aggregate holds without a per-route check)
- **Route creation** - when `overselling_allowed` is on (or for the internal `npm`-kind plans used by the flat hosts flow, whose capacity is never pre-allocated), the real route count is checked against `max_domains_total` directly

A reseller with no package subscribed, or a platform-direct client (`reseller_id IS NULL`), is never limited.

---

## Auth Flows

### Password Login

1. POST credentials → Argon2id verify
2. If 2FA enrolled: TOTP / email OTP / SMS OTP challenge
3. Session ID (24-byte random, Redis-backed, 12 h TTL) set as `HttpOnly` cookie
4. CSRF synchronizer token issued on first GET

### WebAuthn / Passkey

Registration and assertion handled by `internal/auth/webauthn.go`. Requires HTTPS.

### OAuth2 / OIDC

Optional OIDC provider (Google, etc.) configured via env. Redirects to `/auth/oidc/callback`. Account linked by email; role defaults to `client`.

### API Key Auth

Bearer token: `Authorization: Bearer hpg_live_<random>`. Key stored as Argon2id hash with HMAC pre-screen. Per-key RPM cap enforced via Redis sliding window.

### SSO Jump Token

JWT-signed URL (`/auth/sso-jump`) for admin-generated single-use login links. 5-minute expiry.

### Admin 2FA Enforcement

When `REQUIRE_ADMIN_2FA` is set, admins without any enrolled 2FA factor are blocked from `/admin/*` with a grace-period countdown.

---

## Caddy Integration

The panel drives Caddy exclusively through the Admin API (`:2019`). It never modifies Caddyfile on disk.

Config delivery modes:
- **Full load** (`POST /load`) - replaces the entire running config; used on node join and forced resync
- **Incremental** (`PATCH /id/<tag>`) - single-route update; used on route create/edit/delete to avoid full reload

Config builder (`internal/caddyapi/config.go`) assembles:
- `apps.http.servers.srv0` with all routes for the node
- `apps.tls.automation` with ACME issuers and DNS-01 wildcard policies
- `apps.cache` block (requires Souin module)
- `apps.layer4` block (requires caddy-l4 module)

On-demand TLS: Caddy calls `/internal/ask` before issuing a cert. The panel verifies the hostname is a known active route.

Module availability is gated by env flags (`CACHE_HANDLER_AVAILABLE`, `LAYER4_AVAILABLE`, `WAF_MODULE_AVAILABLE`, `MTLS_AVAILABLE`) so a stock Caddy build runs without those config blocks.

---

## WireGuard Tunnels

The manager maintains its own WireGuard identity (mesh key) for node-to-manager communication. Customer tunnels are a separate WireGuard interface.

Key operations:
- Key generation: pure Go `golang.org/x/crypto/curve25519`, no shell calls
- Private keys AES-256-GCM encrypted at rest in `settings` table
- Peer config files written to disk; WG sidecar container picks them up via `wg syncconf`
- Node-agent binary on remote nodes pulls peer lists from the manager

WireGuard-over-WebSocket: wstunnel sidecar forwards WG UDP over WSS for networks that block UDP. Panel generates client installer scripts.

---

## L4 Streams

Requires `caddy-l4` module. Admin defines TCP/UDP stream endpoints:
- Port number + protocol
- Upstream address
- Optional TLS termination / passthrough

Emitted as `apps.layer4` routes in the Caddy config. Guarded by `LAYER4_AVAILABLE` flag.

---

## AI Assistant

Floating chat bubble available to both admin and client roles. Backed by an LLM provider configured via env.

Scope isolation via `Scope` type: admin tools operate on all records; client tools filter by `client_id` using `IN` clauses - no cross-tenant data leakage.

Rate limiting: per-user RPM cap, Redis-backed. Available tools are dynamically filtered by role and `FEATURE_AI_ASSISTANT` flag.

---

## Analytics

Prometheus scrape from each Caddy node, stored or proxied. Surfaces:
- Request rate, error rate, latency percentiles per route
- Top countries (GeoIP, Country-level only - no city)
- World map view (country-level choropleth, available to both admin and client)
- KPI dashboard with big-number cards and time-series charts

GeoIP database loaded from `GeoLite2-Country.mmdb`. City-level data is not loaded or stored.
