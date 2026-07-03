# Security Model

## Threat Model

Primary threats considered:

| Threat | Mitigation |
|--------|-----------|
| Credential theft / brute force | Argon2id hashing, Redis brute-force counter, TOTP/passkey 2FA |
| Session hijacking | HttpOnly cookie, 24-byte random session ID, 12 h TTL, rotated on login |
| CSRF | Synchronizer token (`crypto/subtle.ConstantTimeCompare`), checked on all non-safe non-API routes |
| Cross-tenant data access | Privilege changes revoke live sessions immediately; client handlers filter by `client_id`; backend IPs never exposed to clients |
| API key compromise | Argon2id hash + HMAC pre-screen; per-key RPM cap; key disable takes effect immediately |
| Config injection to Caddy | Panel is the only writer to Caddy Admin API; nodes are firewalled behind WireGuard |
| Supply chain / binary tampering | Single static Go binary; no runtime plugins; module flags disable non-stock blocks |
| Secrets at rest | AES-256-GCM for WG private keys and DB credentials in install state; `APP_SECRET` ≥ 32 chars enforced |

Out of scope: physical access to the host, kernel exploits, cloud provider compromise.

---

## Authentication

### Password

- Argon2id (PHC format): 64 MiB memory, 3 iterations, 2 threads
- No plaintext ever logged or stored

### TOTP

- RFC 6238 HOTP/TOTP, 6-digit, 30-second window
- Secret encrypted at rest, never returned to client after setup

### Email OTP / SMS OTP

- One-time codes sent via configured SMTP / SMS provider
- Redis-backed with TTL; single-use

### WebAuthn / Passkey

- Standard Web Authentication API, requires HTTPS
- Credential stored in DB; no private key touches the server

### OAuth2 / OIDC

- Provider-issued tokens validated on callback; account linked by email
- No OAuth tokens stored long-term

### API Keys

- Format: `hpg_live_<random>`
- Stored as Argon2id hash; HMAC pre-screen avoids full Argon2 on invalid keys
- Per-key RPM cap in Redis; disabling a key takes effect on the next request

---

## Authorization (RBAC)

Base roles (`users.role`): `super_admin`, `admin`, `client`, `support`, plus `api` for machine keys.

The `admin` role has an explicit sub-hierarchy (`internal/adminscope/service.go` `resolveMode`):

- **Unrestricted platform admin** - full access.
- **Reseller-admin** (`users.reseller_id` set) - scoped to its reseller's owned clients/plans only; a default-deny allow-list middleware (`reseller_boundary.go`) gates its panel routes, and its API key cannot touch global infra (`requireGlobalAPIAdmin`).
- **Client-scoped admin** (`users.is_restricted = 1`) - limited to its `admin_client_scope` assignments. Restriction is an **explicit opt-in flag**, not inferred from assignment-row count: this closes the old footgun where deleting a scoped admin's last client silently escalated it to full access. `is_restricted=1` with zero scope rows now means "sees nothing".

- Role stored in `users.role`. The API-key path re-reads `role`/`is_active`
  from the DB on every request. Cookie sessions cache the role in the Redis
  session record for speed; any privilege change - role edit, deactivate,
  delete, password rotation, reseller reassignment, GDPR erase - immediately
  calls `DestroyAllForUser`, so a stale-privilege session cannot outlive the
  change (it does not merely expire at session TTL)
- Route groups enforce role at the chi middleware level (`RequireRole` middleware)
- Client handlers use `client_id` from session context and apply `IN (...)` DB filters; never trust user-supplied IDs for scoping
- Admin impersonation sets `ImpersonatorUserID` in session; audit log records both IDs
- `REQUIRE_ADMIN_2FA` flag blocks admin routes until a 2FA factor is enrolled
- **Reseller suspension is fail-closed**: setting `resellers.status='suspended'` makes `resolveMode` return a hard-empty (`denied`) scope - the reseller-admin sees and manages nothing (never falls through to platform-wide access), and its live sessions are revoked on suspend.

---

## Secrets Storage

| Secret | Storage | Encryption |
|--------|---------|-----------|
| WireGuard private key | `settings` table | AES-256-GCM, key from `APP_SECRET` |
| Install-state DB credentials | `data/install_state.json` | AES-256-GCM, key derived via HKDF-SHA256 from `APP_SECRET` |
| TOTP secrets | `users` table | AES-256-GCM |
| API key hashes | `api_keys` table | Argon2id hash |
| User passwords | `users` table | Argon2id hash |

`APP_SECRET` must be ≥ 32 characters. The `cmd/rotate-secret` tool re-encrypts all blobs under a new key without downtime.

---

## HTTPS Enforcement

- The panel itself is served behind Caddy with auto-ACME or a custom cert
- `HSTS: max-age=63072000; includeSubDomains` header on all responses
- Force-HTTPS subroute wrapper can be enabled per route (emits Caddy redirect handler)
- WebAuthn requires HTTPS; passkey registration fails on plain HTTP

---

## Content Security Policy

Nonce-based CSP generated per request. Inline scripts require the per-request nonce. Static CSP header includes:
- `default-src 'self'`
- `script-src 'self' 'nonce-<random>'`
- `style-src 'self' 'unsafe-inline'` (inline template styles; nonce
  migration pending - see SECURITY.md "Known limitations")
- `frame-ancestors 'none'`

Additional headers set by `security_headers.go` middleware:
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin`

---

## mTLS

Implemented via Caddy `tls_connection_policies`; works on stock Caddy, no
extra module needed. When enabled on a route:
- Caddy requests a client certificate during TLS handshake
- Panel emits the `client_authentication` block in the route's TLS config with the configured CA
- `MTLS_AVAILABLE` is a UI feature flag only (whether the option is offered),
  not a functional gate - see `docs/MTLS.md`

---

## WAF

Requires `WAF_MODULE_AVAILABLE` Caddy module. When enabled:
- Emitted as a WAF handler at the front of the route handler chain
- WAF log events stored in `waf_events` table with route, IP, rule ID, and timestamp
- Admin can view WAF events per route

---

## Rate Limiting

Redis sliding-window implementation (`internal/httpserver/middleware/ratelimit.go`):

| Scope | Limit |
|-------|-------|
| Login attempts | Per IP, configurable, default strict |
| `/internal/ask` (on-demand TLS) | Per IP |
| Unauthenticated POST (global) | Per IP |
| API key requests | Per key, set on key record (RPM) |
| AI assistant | Per user, RPM cap |

Exceeding limits returns HTTP 429 with `Retry-After` header.

---

## Audit Log

All write operations by admins and clients are logged to the `audit_log` table:
- Actor user ID (and impersonator ID if active)
- Action type and target entity
- Source IP
- Timestamp

The application never updates or deletes individual audit rows. A single
bulk-purge exists (`POST /admin/audit/clear`, super_admin + CSRF only): it
wipes the table and, in the same transaction, writes an `audit.cleared`
tombstone recording the actor, IP, user agent and purged row count - so a
clear cannot itself go untraced. For tamper-evident retention beyond this,
ship audit rows to an external append-only sink.

---

## Known Limitations

- No row-level encryption on route records (hostnames, upstreams stored plaintext in MariaDB)
- OIDC provider tokens are not revocation-checked after initial login
- WireGuard mesh relies on host firewall to restrict Caddy Admin API access; no mutual auth on `:2019`
- City-level GeoIP is not loaded but Country-level data is processed
- SMS OTP security depends on the third-party SMS provider's delivery integrity
