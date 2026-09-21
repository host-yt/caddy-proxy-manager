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
| Config injection to Caddy | Panel is the only writer to Caddy Admin API; nodes are firewalled behind WireGuard; raw custom handler JSON is allow-listed and a failing chain is quarantined behind a 503 |
| Reaching the node control plane through tenant config | Custom-handler allow-list (no `reverse_proxy`/`templates`, no env/file placeholders); L4 stream destinations screened against an infrastructure deny set incl. port 2019 - see "Caddy Admin API - known limitation" |
| Hostname takeover (claiming someone else's domain) | Per-route and **per-alias** DNS-TXT proof at `_hpg-verify.<host>`; unproven hosts are neither emitted into the host matcher nor certificate-eligible - see [ROUTES.md](ROUTES.md) |
| Compromised node agent poisoning other tenants' data | Node ingest (access log, WAF) attributes only to routes that node serves; mTLS RBAC checks need a panel-issued per-(node, route) token - see "Node ingest endpoints" |
| Harvest-now-decrypt-later (recorded traffic decrypted by a future quantum computer) | Hybrid X25519MLKEM768 key exchange on every TLS hop by default; WireGuard preshared keys on the panel-node mesh and on customer tunnels; optional PQ-only enforcement per host - see [POST_QUANTUM.md](POST_QUANTUM.md) |
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
  session record for speed, but that cache cannot go stale: every session
  carries an authorization epoch that is re-read from the database on every
  request (see "Authorization epoch" below)
- Route groups enforce role at the chi middleware level (`RequireRole` middleware)
- Client handlers use `client_id` from session context and apply `IN (...)` DB filters; never trust user-supplied IDs for scoping
- Admin impersonation sets `ImpersonatorUserID` in session; audit log records both IDs
- `REQUIRE_ADMIN_2FA` flag blocks admin routes until a 2FA factor is enrolled
- **Reseller suspension is fail-closed**: setting `resellers.status='suspended'` makes `resolveMode` return a hard-empty (`denied`) scope - the reseller-admin sees and manages nothing (never falls through to platform-wide access), and its live sessions are revoked on suspend.

---

## Authorization epoch

The guarantee an operator can rely on: **a privilege change takes effect on the
victim's very next request.** Revocation does not wait for a cache to expire,
for the 12-hour session TTL, or for a best-effort Redis purge to succeed.

Mechanism (`users.auth_epoch`, migration `00132`,
`internal/auth/epoch.go`):

- Every session record stores the epoch it was minted with (`Session.Epoch`).
- `LoadSession` runs on every request for every role - admin, reseller, client -
  and reads `SELECT auth_epoch FROM users WHERE id = ?` from the database. There
  is no cache in front of it; one was tried and removed.
- On mismatch the session record is deleted from Redis and the request proceeds
  with no session, i.e. the user lands on the login page. On a *deleted* user the
  same happens. If the epoch cannot be read at all (DB error, no epoch source
  wired) the request is still refused, but the session record is left alone -
  fail closed, non-destructive.
- Impersonation carries a second epoch for the impersonator, checked the same
  way.
- Sessions are also versioned (`hpg:sess2:`); any record older than the current
  session schema is deleted on load, so pre-epoch sessions cannot survive an
  upgrade.

Every one of these operations bumps the epoch **inside the same transaction as
the change itself**:

| Operation | Where |
|---|---|
| Role change, deactivate, or admin-set password | user update handler |
| Admin scope save (`admin_client_scope` / `is_restricted`) | scope editor |
| Activate / deactivate toggle | user list |
| Client bulk suspend | client bulk actions |
| Password reset completion | also revokes all of that user's API keys in the same transaction |
| GDPR mask / erase | GDPR handler |
| Reseller-admin assign / release | reseller handlers |
| Reseller suspend or delete via the API | `PATCH`/`DELETE /api/v1/resellers/{id}` |
| Promotion that clears confinement (`is_restricted`, `reseller_id`, scope rows) | user update handler |

Redis session purging still runs, but it is an optimisation. The epoch is the
durable half: if the purge fails or a replica has the session cached, the next
request still fails the epoch check.

API keys are epoch-checked too (since 1.4.6, migration `00139`): a key carries
the owner's epoch from issue time, the lookup joins `users`, and any epoch bump,
`is_active = 0` or a deleted owner denies on the next request. Revoking an
operator's access therefore takes their API keys with it - though issuing them a
fresh key after a legitimate role change is then a deliberate step.

---

## L4 stream target screening

An L4 stream forwards raw TCP/UDP from a public port to a destination. The
RFC1918 policy for stream destinations is deliberately permissive - tenants
legitimately proxy to private backends - so private addresses alone are not a
usable signal. `internal/streamguard` adds a second, independent screen for
**infrastructure** addresses on top of the generic SSRF policy.

### Deny set

Built fresh from the database on every screen (no cache):

| Source | Denied |
|---|---|
| `caddy_nodes.public_ip`, `wg_ip`, `public_hostname` | exact address / hostname |
| `caddy_nodes.api_url` | the host part of the URL |
| `caddy_nodes.tunnel_subnet` | the subnet's network base and the `.1` bridge - the node's own address inside a customer tunnel. Tenant peer addresses in that subnet stay allowed. |
| `settings.wireguard.control_ip` | exact address |
| `settings.wireguard.subnet` | the **whole** control-plane prefix, because node admin APIs bind their `wg_ip` inside it |
| any host | port **2019** - this repo publishes Caddy's unauthenticated admin API there |

Ordinary private-network backends and customer tunnel peers are unaffected.

### Fail-closed

- On write (stream create, stream update, extra upstreams): if the deny set
  cannot be loaded the write is refused with `backend screening unavailable, try
  again` / `upstream screening unavailable, try again`.
- At emission: if it cannot be loaded, `buildStreamsForNode` returns an error and
  the **whole config push aborts**. A node is never pushed a config built without
  the screen.

### Resolve once, pin the literal

A hostname destination is resolved exactly once. Every address in that single
answer is checked against both the generic SSRF policy and the infrastructure
deny set; any hit rejects the whole target. The address that is stored and
emitted is a literal from that same validated answer, so Caddy never re-resolves
and a hostile DNS server cannot answer differently at dial time.

### Quarantine

Screening runs at emission as well as on write, so a row written before the
upgrade - or one whose destination only later became a node address - cannot be
re-emitted by boot push, manual resync or drift recovery. Such a row is
quarantined instead of silently dropped:

- `stream_routes.quarantined_at` / `quarantine_reason` (migration `00137`, which
  also backfills obvious cases: `upstream_port = 2019`, an upstream address
  ending in `:2019`, and a `services.backend_ip` matching a node's `public_ip`
  or `wg_ip`).
- The emission query skips any row with `quarantined_at IS NOT NULL`.
- The panel shows the stream's status as `quarantined` plus the stored
  `quarantine_reason` on the stream list and edit pages.
- Audit action `stream.quarantined` (entity `stream_route`, meta `reason` and
  `listen_port`), plus a `stream quarantined: unsafe destination` log line.

### Release

A quarantine is only ever lifted by a destination that passes the same screen:

- **Edit and save.** The stream edit page exposes the destination (`backend_ip`,
  stored per stream in `stream_routes.backend_ip_override` from migration
  `00140`, and `upstream_port`). `saveStreamUpdate` screens the whole
  destination - primary backend plus every extra upstream - and writes the edit
  and the cleared quarantine columns in one transaction. A destination that
  fails is rejected outright, so the row keeps both the flag and a reason.
- **Re-check destination** (`POST /admin/streams/{id}/recheck`) for a stream
  whose destination became safe without the row changing (a decommissioned
  node). It re-runs the real screen over the stored destination; it never just
  clears the flag, and a still-rejected row gets a refreshed reason. Audit
  action `admin.stream.recheck`.

Both paths go through `scopeCheckStream`, so a scoped admin can only act on its
own streams and cannot clear a quarantine without fixing the destination.

---

## Secrets Storage

| Secret | Storage | Encryption |
|--------|---------|-----------|
| WireGuard private key | `settings` table | AES-256-GCM, key from `APP_SECRET` |
| Install-state DB credentials | `data/install_state.json` | AES-256-GCM, key derived via HKDF-SHA256 from `APP_SECRET` |
| TOTP secrets | `users` table | AES-256-GCM |
| WireGuard preshared keys (mesh) | `caddy_nodes.wg_psk_enc`, `wg_psk_pending_enc` | AES-256-GCM, envelope purpose `wg` |
| WireGuard preshared keys (customer tunnel) | `customer_wg_peer.psk_enc` | AES-256-GCM, envelope purpose `wg` |
| API key hashes | `api_keys` table | Argon2id hash |
| User passwords | `users` table | Argon2id hash |

`APP_SECRET` must be ≥ 32 characters.

### Rotating `APP_SECRET`

`cmd/rotate-secret` re-encrypts every at-rest blob under a new key. It is
**not** a zero-downtime operation, and it invalidates API keys:

1. **Stop the panel.** The tool rewrites rows the panel reads on boot; running
   it against a live instance is unsupported.
2. **Back up** the database and `data/install_state.json`. A half-applied
   rotation is unrecoverable without them.
3. Run `hpg-rotate-secret --state ./data/install_state.json --old-secret
   <current> --new-secret <new>` (add `--apply`; without it the run prints a
   dry-run summary and changes nothing).
4. Set the new `APP_SECRET` in `.env` (or the orchestrator's secret store) and
   start the panel.
5. **Re-issue every API key.** `api_keys.key_hmac` is keyed off `APP_SECRET`
   and cannot be re-derived from a hash, so rotation nulls it out. Existing
   integration tokens stop working: create replacements in
   **Admin → API keys** and distribute them before the next automated run.

Node admin-proxy keys, WireGuard keys and TOTP secrets are re-encrypted in
place and need no operator action. A restored backup paired with a *different*
`APP_SECRET` is the failure mode to avoid - `server doctor` reports the node
keys it can no longer decrypt.

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

### Path RBAC checks (`/internal/mtls-rbac/{route_id}`)

Routes with mTLS path rules run a Caddy `forward_auth` subrequest against the
panel. The subrequest carries the client-certificate subject in a header the
node sets, so the endpoint must be sure the caller is a node the route is
actually placed on - reaching it from somewhere inside the mesh CIDR or from a
configured trusted proxy is not proof of that.

Each check therefore carries a panel-issued token:

- the token is `HMAC-SHA256(HKDF(APP_SECRET, "mtls-rbac"), node_id || route_id)`,
  written into **one** node's Caddy config next to the route it belongs to;
- the panel verifies it in constant time and then re-reads placement from the
  database, so a route that moved to another node stops being checkable from the
  old one without waiting for a config push;
- a check with no token, a token minted for another route, or a token from a
  node that no longer serves the route is refused with 403.

`MTLS_RBAC_ALLOW_UNSIGNED=1` accepts token-less checks. It exists only for the
upgrade window on a fleet whose pushed config predates signed checks (the next
push adds the token) and logs a warning on every accepted request; leaving it on
keeps the old "anyone on the mesh may query the RBAC oracle" trust model.

---

## Post-quantum

The threat is harvest-now-decrypt-later: traffic recorded today, decrypted once
a quantum computer exists. Key exchange is therefore hardened and signatures are
not (a signature only has to be unforgeable when it is verified).

- TLS, panel and edge: hybrid X25519MLKEM768 offered by default. CI fails the
  build on a `GODEBUG` that disables ML-KEM or a `CurvePreferences` in non-test
  Go code, and the release pipeline probes the freshly built edge image by
  digest before the `edge`, `latest` and semver tags are created: one that
  cannot negotiate it is never published.
- WireGuard has no hybrid mode, so both planes use a 32-byte `PresharedKey`
  mixed into every handshake: the panel-node mesh (automatic on join, one-time
  rekey script for older nodes) and customer tunnels (automatic once the node's
  agent declares support on its peer pull; an agent that does not, on a node
  with PSK-bearing peers, is refused rather than handed a peer set it would
  apply without the keys).
- Per-host PQ-only enforcement is opt-in and rejects clients without ML-KEM.
- Certificates, ACME account keys, OIDC tokens and image signatures stay
  classical - blocked upstream, and outside the harvest-now threat model.

Full detail, verification commands and rollout order: [POST_QUANTUM.md](POST_QUANTUM.md).

---

## Node ingest endpoints

Node agents authenticate with their per-node token (`caddy_nodes.agent_token_hash`,
SHA-256, header only - never a query string). Authentication alone is not
attribution: what a node may *write about* is scoped to the routes that node
serves, which is the anchor placement plus any active-active fan-out peer in
`route_node_assignments`.

- **Access log** (`POST /internal/access-log`): each batch resolves against an
  index of the authenticated node's own routes. Hosts match the primary domain
  and proven aliases only, and the longest matching `path_prefix` wins, so
  several path-routed routes on one domain are told apart. A line for a host
  the node does not serve is dropped, never attributed elsewhere.
- **WAF events** (`POST /api/node/waf/events`): same index, same rules; a
  client-supplied `route_id` is ignored and resolved server-side.

The property both uphold: a stolen node token can lie about that node's own
traffic, and cannot touch another node's or another tenant's history.

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

## Caddy Admin API - known limitation

**Caddy's admin API has no authentication of any kind.** Anything that can open a
TCP connection to it can `POST /load` and replace the entire configuration of
that node - every route, every tenant, every certificate on it. There is no
token, no password and no client certificate in front of it.

The security model is therefore **network reachability only**:

- On the manager stack, `:2019` is reachable inside the compose network
  (`CADDY_ADMIN_URL: http://caddy:2019`) and the compose file deliberately never
  publishes the port to the host.
- On a remote node it is published on **host loopback only**
  (`deploy/remote-node/docker-compose.yml` binds `"127.0.0.1:2019:2019"`), and
  the node-agent fronts it with an authenticated proxy on the node's WireGuard
  address (`:2021`). Nodes deployed before 1.5.2 published `"<wg_ip>:2019:2019"`
  and are reachable from anything on the control-plane mesh until migrated -
  `server doctor` flags each one.

Two of the critical findings closed in 1.4.4/1.4.5 were paths into that API from
tenant-controlled configuration, not from the network:

- a `reverse_proxy` in a route's custom Caddy JSON pointed at `127.0.0.1:2019`;
- an L4 stream whose destination was a node's WireGuard address on port 2019.

The mitigations are the custom-handler allow-list
([ROUTES.md](ROUTES.md#4-custom-caddy-json-allow-list-and-quarantine)) and the
stream infrastructure deny set (above). Both are compensating controls. They
narrow the paths that reach the admin API; they do not authenticate it.

### Removing the port entirely

Both controls above screen *addresses*. The endpoint itself can be taken off
TCP instead: Caddy accepts a filesystem socket as its admin endpoint
(`admin unix//sockets/caddy-admin.sock|0666`, verified against the pinned
2.11.4), and the panel or the node-agent reaches it over a shared volume. There
is then no address for anything to name - inside the Caddy process included,
which is the one place no network boundary can help.

This is opt-in per node (`HPG_CADDY_ADMIN_LISTEN` plus
`HPG_CADDY_ADMIN_LISTEN_NODES`), verifiable with `server doctor` and the
agent's own doctor before the published port is removed, and reversible. The
rollout order is in
[MULTI_NODE.md](MULTI_NODE.md#moving-a-node-off-the-tcp-admin-port).

Caddy can dial a socket upstream as well as listen on one, so a socket path
remains something the config format can express. The panel emits every
tenant-controlled target through `net.JoinHostPort`, which cannot produce that
shape, and `caddyapi.ScreenDialTarget` rejects any upstream that is not a plain
host:port.

### Closing it per node: the agent's admin proxy

A node can now put its node-agent in front of the admin API, so reaching a port
is no longer authorization:

```
panel ──(bearer key, over the WG mesh)──▶ node-agent ──(127.0.0.1)──▶ Caddy admin API
```

- The key is per node, generated by **Enable tunnel** / **Rotate**
  (`/admin/nodes/{id}/tunnel/enable`), stored encrypted in
  `caddy_nodes.admin_proxy_key_enc`, and shown once with the other agent
  credentials. The panel sends it as a bearer token on every admin call; the
  agent compares it in constant time.
- The agent also enforces a method+path allow-list covering exactly what the
  control plane does - `POST /load`, `GET /config/...`, `POST /config/.../routes`,
  `PATCH`/`DELETE` on `/config/...` and `/id/route_<n>`, `POST /souin-api/...`.
  A leaked key therefore still cannot `POST /stop`, `/adapt`, or rewrite the
  node's own admin configuration.
- It refuses to start bound to `0.0.0.0`, and refuses a key shorter than 32
  characters, rather than serving something that only looks authenticated.

It is required for remote nodes: the panel refuses to register a node whose
API URL is a raw remote `:2019`, in `/admin/nodes` and in `POST /api/v1/nodes`.
Set it up with `HPG_ADMIN_PROXY_LISTEN` + `HPG_ADMIN_PROXY_KEY` on the agent,
then point the node's API URL at the agent and publish Caddy's admin port on
host loopback - see
[MULTI_NODE.md](MULTI_NODE.md#12-authenticating-the-nodes-admin-api) for the
order, which matters.

Existing fleets are not cut off: nothing changes for nodes already registered,
the auto-join script still onboards a node on the direct path (its agent, and
therefore its key, only exists after tunnel-enable), and
`HPG_ALLOW_UNAUTHENTICATED_NODE_ADMIN=1` on the panel re-opens registration for
a fleet mid-migration. `server doctor` prints an `admin API auth` row per node
so the remaining ones are visible.

**Still outstanding.** Until a node is migrated, treat reachability of
`<wg_ip>:2019` as equivalent to root on that node and keep the control-plane
mesh restricted accordingly. Caddy's own `admin.identity` + `admin.remote`
(mTLS between panel and node, no proxy in between) remains the stronger end
state; the agent proxy is what gets authentication in front of the API today
without changing how nodes are deployed.

---

## Known Limitations

- No row-level encryption on route records (hostnames, upstreams stored plaintext in MariaDB)
- OIDC provider tokens are not revocation-checked after initial login
- **Caddy Admin API has no authentication of its own.** A node whose agent
  fronts it (see above) is authenticated by the panel-issued key; a node that
  has not been migrated still depends entirely on who can reach `:2019`
- API keys are bound to the owner's authorization epoch and `is_active`, so a
  privilege change or disable invalidates them on the next request (1.4.6)
- A quarantined L4 stream cannot be released from the panel; it must be
  recreated or cleared in the database
- City-level GeoIP is not loaded but Country-level data is processed
- SMS OTP security depends on the third-party SMS provider's delivery integrity
