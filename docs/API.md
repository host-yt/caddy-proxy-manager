# Hostyt Proxy Gateway - REST API v1 Reference

> Infrastructure-as-code: see [TERRAFORM.md](TERRAFORM.md) for the Terraform
> provider resource mapping. The machine-readable spec is served at
> `GET /api-docs/openapi.json`.

## Base URL

```
https://your-panel.example.com/api/v1
```

---

## Authentication

Most `/api/v1` endpoints require a **Bearer API key**.

```
Authorization: Bearer hpg_live_xxxxxxxxxxxx
```

**Admin keys** - issued at `Admin → API Keys`.  
**Client keys** - issued at `App → API Keys`.

Role enforcement is per-endpoint. Keys that belong to a disabled or demoted user are rejected on every request (roles are re-checked live, not cached in the token).

A key in the older (pre-HMAC) format may occasionally get `429` instead of a
credential verdict, if that verification path is temporarily over capacity:

```
HTTP 429 Too Many Requests
Retry-After: 60
{"error":"api key verification throttled; retry"}
```

This is not a rejection of the key - wait the given number of seconds and
retry the same request.

### Key scope (multi-tenant)

An admin key's reach is derived from the owning user, not the token:

| Owner | Data reach | Global infra (nodes / pools / plans) | Client provisioning |
|-------|-----------|--------------------------------------|---------------------|
| `super_admin` / unrestricted `admin` / `api` | all clients | allowed | allowed |
| Reseller-admin (`users.reseller_id` set, reseller active) | only that reseller's clients | denied (`403 global admin scope required`) | allowed (client owned by its reseller) |
| Suspended-reseller admin (`resellers.status != 'active'`) | none - hard fail-closed | denied | denied |
| Client-scoped admin (`users.is_restricted=1` + `admin_client_scope` rows) | only assigned clients | denied | denied |
| `client` | only its own client | n/a | n/a |

List endpoints return only in-scope rows; single-resource reads and mutations
return `403` for out-of-scope ids. A reseller-admin key may create and delete
clients owned by its reseller, but never touches shared node infrastructure.
Plan management via API key is platform-admin only (a reseller-admin manages its
own plans through the panel UI, not the API); global plans stay platform-only.

---

## Common Response Format

All responses use `Content-Type: application/json`.

**Success** - status varies by operation (200, 201, 204).

**Error**

```json
{ "error": "human-readable message" }
```

---

## Rate Limiting

Authenticated `/api/v1` endpoints share a per-key requests-per-minute cap stored on the key record. Exceeding the cap returns:

```
HTTP 429 Too Many Requests
Retry-After: 60
{"error":"rate_limit_exceeded","cap_rpm":120}
```

Unauthenticated endpoints (WireGuard bootstrap, node join) are rate-limited per source IP. Those limits are documented per-endpoint below.

---

## Pagination

`GET /api/v1/services` and `GET /api/v1/routes` accept opt-in keyset pagination:

- `?limit=` - page size, `1`-`500`. Omit it and the endpoint returns the
  complete result set (unchanged legacy behavior).
- `?cursor=` - a row id from the previous page's `next_cursor`. Results are
  ordered by `id` descending; the cursor is exclusive (rows with `id <`
  cursor).
- The response carries `next_cursor` only when more rows exist.
- `?limit=` outside `1-500`, or a `?cursor=` that isn't a positive row id,
  returns `400`.
- Without `?limit=`, a result set over 5000 rows returns `413 Request Entity
  Too Large`: `{"error":"result set exceeds 5000 rows; page it with ?limit= and ?cursor="}`.

No other list endpoint paginates. Every list/detail endpoint now returns
`500` instead of a shortened list if a row fails to read - a read failure is
never silently truncated into a smaller-but-successful response.

---

## Idempotency

Any mutating call (`POST`, `PUT`, `PATCH`, `DELETE`) under `/api/v1` may carry
an `Idempotency-Key` header (max 128 chars) to make retries safe:

- The response always carries `X-Operation-Id` - a durable handle for that
  attempt, worth logging even when no key was sent.
- First use of a key: the call executes normally.
- A second request with the same key while the first is still running gets
  `409`: `{"error":"request with this idempotency_key is already in progress"}`.
- A second request with the same key, method, path and body, sent after the
  first completed: the original response is replayed verbatim, with
  `X-Idempotency-Replayed: true` added.
- The same key reused for a different method, path or body gets `409`:
  `{"error":"idempotency_key reused for a different request"}`.
- If the server cannot confirm whether the call actually ran, a retry gets
  `409`:
  ```json
  {
    "error": "operation with this idempotency_key was executed but its result was not recorded; reconcile before retrying",
    "code": "idempotent_operation_unresolved",
    "operation_id": "…"
  }
  ```
  Do not retry blindly here - check whether the operation's effect already
  happened (e.g. did the route get created?) before repeating the call, using
  `operation_id` to correlate with support/logs if needed.

Keys are scoped to the caller (one user cannot replay another user's key) and
expire after 24 hours.

---

## Roles

| Role | Access |
|------|--------|
| `admin` / `super_admin` | All write operations |
| `client` | Read own services and routes; create/delete own routes |

---

## Endpoints

### Health

---

#### `GET /api/v1/health`

Returns API version and liveness status. No authentication required.

**Response `200`**

```json
{
  "status": "ok",
  "version": "0.1.174"
}
```

---

### Services

A service links a client to a backend IP address and an allowed port range (e.g. `30000-30019`). Routes are then mapped from domains to ports within that range.

---

#### `GET /api/v1/services`

List services.

**Auth:** Bearer token - admin only. A reseller/scoped admin key sees only in-scope services.

**Query parameters:** `limit`, `cursor` - see [Pagination](#pagination).

**Response `200`**

```json
{
  "services": [
    {
      "id": 42,
      "client_id": 7,
      "name": "Acme VPS #1",
      "backend_ip": "10.0.1.55",
      "allowed_port_start": 30000,
      "allowed_port_end": 30019,
      "plan_id": 3,
      "status": "active",
      "external_reference": "fossbilling-service-99",
      "created_at": "2026-01-15T08:30:00Z"
    }
  ],
  "next_cursor": "17"
}
```

`next_cursor` is present only when more rows exist.

**Errors**

| Code | Meaning |
|------|---------|
| 400 | Invalid `limit` or `cursor` |
| 401 | Auth required |
| 403 | Admin role required, or scope unresolved |
| 413 | Unpaginated result exceeds 5000 rows - retry with `?limit=` |
| 429 | Rate limit exceeded |
| 500 | Database error |

---

#### `POST /api/v1/services`

Create a service.

**Auth:** Bearer token - admin only.

**Request body**

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `client_id` | integer | yes | ID of the client to assign the service to |
| `name` | string | yes | Human-readable label |
| `backend_ip` | string (IPv4) | yes | Backend IP of the customer VPS |
| `allowed_port_start` | integer | yes | First port in allowed range (1-65534) |
| `allowed_port_end` | integer | yes | Last port in allowed range (2-65535) |
| `plan_id` | integer | yes | Plan ID; determines node group and domain limits |
| `external_reference` | string | no | Billing system reference (e.g. `fossbilling-service-99`) |

```json
{
  "client_id": 7,
  "name": "Acme VPS #1",
  "backend_ip": "10.0.1.55",
  "allowed_port_start": 30000,
  "allowed_port_end": 30019,
  "plan_id": 3,
  "external_reference": "fossbilling-service-99"
}
```

**Response `201`**

```json
{ "id": 42 }
```

**Errors**

| Code | Meaning |
|------|---------|
| 400 | Missing required fields, invalid IP, or invalid port range |
| 401 | Missing or invalid bearer token |
| 403 | Admin role required |
| 429 | Rate limit exceeded |
| 500 | Database error |

---

#### `GET /api/v1/services/{id}`

Get a single service.

**Auth:** Bearer token. Admins can fetch any service; clients may only fetch their own.

**Response `200`**

```json
{
  "id": 42,
  "client_id": 7,
  "name": "Acme VPS #1",
  "backend_ip": "10.0.1.55",
  "allowed_port_start": 30000,
  "allowed_port_end": 30019,
  "plan_id": 3,
  "status": "active",
  "external_reference": "fossbilling-service-99",
  "created_at": "2026-01-15T08:30:00Z"
}
```

`status` values: `active`, `suspended`, `terminated`.

**Errors**

| Code | Meaning |
|------|---------|
| 401 | Auth required |
| 403 | Not your service (client accessing another client's service) |
| 404 | Service not found |
| 429 | Rate limit exceeded |

---

#### `PATCH /api/v1/services/{id}`

Update a service.

**Auth:** Bearer token - admin only.

All fields are optional; omit to leave unchanged.

**Request body**

| Field | Type | Notes |
|-------|------|-------|
| `status` | string | `active`, `suspended`, or `terminated` |
| `external_reference` | string | Billing system reference |
| `notes` | string | Internal admin notes |

```json
{
  "status": "suspended",
  "external_reference": "new-ref-123"
}
```

Setting `status` drives the service lifecycle, not a bare column write:

- `suspended` stops every route of the service from being served. Route
  definitions are not deleted - they flip to route `status: "disabled"`
  without touching their config, and every node holding one of them is
  rebuilt to drop it.
- `active` resumes a suspended service: only the routes that `suspended`
  disabled are re-enabled. A route an operator individually disabled by hand
  stays disabled. Resuming a service that is already active is a no-op, not
  an error.
- `terminated` is final: routes stop serving the same way `suspended` does,
  but no further status change is accepted and the service can never be
  resumed.

`PUT /api/v1/provisioning/service/{id}/suspend` (the FOSSBilling integration)
suspends through this same lifecycle, so both entry points behave
identically.

**Response `200`**

```json
{ "id": 42, "updated": true }
```

**Errors**

| Code | Meaning |
|------|---------|
| 400 | Invalid `status` value |
| 401 | Auth required |
| 403 | Admin role required |
| 404 | Service not found |
| 409 | Service is terminated |
| 429 | Rate limit exceeded |
| 500 | Database error |

---

#### `POST /api/v1/services/{id}/ports`

Replace the allowed port range for a service.

**Auth:** Bearer token - admin only.

Existing routes that fall outside the new range must be deleted before calling this endpoint.

**Request body**

```json
{
  "allowed_port_start": 31000,
  "allowed_port_end": 31019
}
```

**Response `200`**

```json
{ "id": 42 }
```

**Errors**

| Code | Meaning |
|------|---------|
| 400 | Invalid port range |
| 401 | Auth required |
| 403 | Admin role required |
| 429 | Rate limit exceeded |
| 500 | Database error |

---

#### `GET /api/v1/services/{id}/routes`

List routes attached to a service.

**Auth:** Bearer token. Clients may only query their own services.

Use the `status` field to track SSL provisioning progress.

**Response `200`**

```json
{
  "routes": [
    {
      "id": 201,
      "domain": "app.example.com",
      "path_prefix": "/api",
      "upstream_port": 30005,
      "status": "active"
    }
  ]
}
```

`status` values: `active`, `pending_ssl`, `error`, `inactive`, `disabled`. A
service-level suspend or terminate flips a route to `disabled` instead of
deleting it - this endpoint keeps listing it.

**Errors**

| Code | Meaning |
|------|---------|
| 401 | Auth required |
| 403 | Not your service |
| 404 | Service not found |
| 429 | Rate limit exceeded |
| 500 | Database error |

---

### Routes

A route maps a domain (and optional path prefix) to a port on a service's backend. Caddy configuration is pushed asynchronously. SSL provisioning may take up to a few minutes after DNS propagates.

---

#### `GET /api/v1/routes`

List routes.

**Auth:** Bearer token. Admins see all in-scope routes; clients see only routes on services they own.

**Query parameters:** `service_id` (optional filter), `limit`, `cursor` - see [Pagination](#pagination).

**Response `200`**

```json
{
  "routes": [
    {
      "id": 201,
      "service_id": 42,
      "domain": "app.example.com",
      "path_prefix": "/api",
      "upstream_port": 30005,
      "ssl": true,
      "websocket": false,
      "force_https": true,
      "status": "active",
      "caddy_node_id": 1,
      "created_at": "2026-01-15T08:30:00Z"
    }
  ],
  "next_cursor": "150"
}
```

`next_cursor` is present only when more rows exist.

**Errors**

| Code | Meaning |
|------|---------|
| 400 | Invalid `limit` or `cursor` |
| 401 | Auth required |
| 403 | Client or admin scope unresolved |
| 413 | Unpaginated result exceeds 5000 rows - retry with `?limit=` |
| 429 | Rate limit exceeded |
| 500 | Database error |

---

#### `POST /api/v1/routes`

Create a route.

**Auth:** Bearer token. Admins can create routes for any service. Clients can only create routes for services they own.

**Request body**

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `service_id` | integer | yes | Service to attach the route to |
| `upstream_port` | integer | yes | Must be within the service's allowed port range |
| `domain` | string | yes | Fully-qualified domain name |
| `path_prefix` | string | no | Optional sub-path routing (e.g. `/api`) |
| `ssl` | boolean | no | Default `true` - enables automatic HTTPS |
| `websocket` | boolean | no | Default `false` |
| `force_https` | boolean | no | Default `true` - redirect HTTP to HTTPS |
| `upstream_url` | string | no | Admin keys only. External origin `https://host[:port][/path]` (no credentials, query or fragment). Replaces `upstream_port`; see [External and ephemeral routes](#external-and-ephemeral-routes) |
| `strip_path_prefix` | boolean | no | Default `false`. Strip `path_prefix` before proxying; the route then matches only `path_prefix` and `path_prefix/...`. Requires `path_prefix` |
| `ttl_seconds` | integer | no | `0` (default) = permanent. `1`-`86400`: the route is deleted automatically once it expires |

```json
{
  "service_id": 42,
  "upstream_port": 30005,
  "domain": "app.example.com",
  "path_prefix": "/api",
  "ssl": true,
  "websocket": false,
  "force_https": true
}
```

**Response `201`**

```json
{ "id": 201 }
```

Caddy config is pushed in the background. Poll `GET /api/v1/services/{id}/routes` and watch `status` for SSL provisioning progress.

##### External and ephemeral routes

A short-lived proxy to a third-party HTTPS origin (e.g. a provider's
web console), served under your own domain:

```json
{
  "service_id": 7,
  "domain": "console.example.com",
  "path_prefix": "/console/3f9c...e1",
  "upstream_url": "https://kvm.provider.example/base",
  "strip_path_prefix": true,
  "websocket": true,
  "ssl": true,
  "force_https": true,
  "ttl_seconds": 900
}
```

- A request for `/console/3f9c...e1/vnc.html?x=1` reaches
  `https://kvm.provider.example/base/vnc.html?x=1`. The query string is kept.
- TLS to the origin is always verified; SNI and the `Host` header are the
  origin's host name. The inbound `Authorization` header is not forwarded.
- `websocket: true` passes upgrades through (noVNC / HTML5 KVM consoles). On
  external routes a live stream survives config reloads for up to 15 minutes
  (`stream_close_delay`), so pushing another route does not cut a session.
- The origin host must be on the external upstream allowlist
  (`Admin -> System -> External allowlist` or `EXTERNAL_UPSTREAM_ALLOWLIST`).
  An entry `*.zone` allows every subdomain of `zone`; a host matched only by
  a wildcard must resolve to public addresses (no loopback, RFC1918, CGNAT,
  link-local), and an IP literal must be listed exactly.
- The service's plan needs `external_proxy_enabled`, path routing and
  websocket; set `max_domains` to `0`, since each route counts.
- With `ttl_seconds`, the route stops being emitted the moment it expires and
  the leader deletes it within about 30 seconds. `DELETE /api/v1/routes/{id}`
  removes it earlier.

**Errors**

| Code | Meaning |
|------|---------|
| 400 | Invalid domain or port outside allowed range; invalid `upstream_url`; host not allowlisted, resolving to a non-public address, or naming control-plane infrastructure / a reserved port; invalid `strip_path_prefix` / `ttl_seconds`; path routing or websocket not in plan |
| 401 | Auth required |
| 403 | Service not yours; `upstream_url` sent with a client key; plan has no external upstreams |
| 409 | Domain already mapped, no node available, or plan domain limit reached |
| 429 | Rate limit exceeded |
| 500 | Internal error |

---

#### `PATCH /api/v1/routes/{id}`

Update a route.

**Auth:** Bearer token. Clients may only update routes on services they own.

All fields are optional; omit to leave unchanged.

**Request body**

| Field | Type | Notes |
|-------|------|-------|
| `upstream_port` | integer | Must be within the service's allowed port range and not already used by another route on the service |
| `path_prefix` | string | Max 100 chars; requires the plan's path-routing feature |
| `ssl_enabled` | boolean | Requires the plan's SSL feature; cannot be turned off while mTLS (`require_client_cert`) is set on the route |
| `websocket` | boolean | Requires the plan's websocket feature |
| `force_https` | boolean | |

```json
{ "upstream_port": 30006 }
```

The full resulting route state is validated against the service's plan and
port allocation - the same checks `POST /api/v1/routes` applies, so an update
can no longer move a route somewhere create would have refused. A request
that changes nothing on an existing, authorized route succeeds without
pushing a resync.

**Response `200`**

```json
{ "id": 201, "updated": true, "resync_required": true }
```

`resync_required: false` (with `updated: false`) means the patch was a no-op.

**Errors**

| Code | Meaning |
|------|---------|
| 400 | Invalid JSON; `upstream_port` out of range or already in use; `path_prefix` too long; the new state isn't permitted by the plan (path routing, SSL, websocket); or `ssl_enabled` turned off while mTLS requires it |
| 401 | Auth required |
| 403 | Not your route |
| 404 | Route not found |
| 429 | Rate limit exceeded |
| 500 | Internal error |

---

#### `DELETE /api/v1/routes/{id}`

Delete a route.

**Auth:** Bearer token. Clients may only delete routes on services they own.

Caddy config is updated asynchronously.

**Response `200`**

```json
{ "id": 201, "deleted": true }
```

**Errors**

| Code | Meaning |
|------|---------|
| 401 | Auth required |
| 403 | Not your route |
| 429 | Rate limit exceeded |
| 500 | Internal error |

---

#### `POST /api/v1/routes/{id}/verify-dns`

Queue a DNS verification check.

**Auth:** Bearer token. Clients may only verify routes on services they own.

Caddy issues a TLS certificate once DNS resolves to the node's IP. This call enqueues a background job.

**Response `200`**

```json
{ "id": 201, "queued": true }
```

**Errors**

| Code | Meaning |
|------|---------|
| 401 | Auth required |
| 403 | Not your route |
| 429 | Rate limit exceeded |
| 500 | Internal error |

---

#### `POST /api/v1/routes/{id}/retry-ssl`

Retry SSL certificate provisioning.

**Auth:** Bearer token. Clients may only retry routes on services they own.

Alias of `verify-dns`. Triggers a fresh DNS check and certificate retry on Caddy.

**Response `200`**

```json
{ "id": 201, "queued": true }
```

**Errors** - same as `verify-dns`.

---

### Nodes

Caddy nodes are the reverse-proxy servers that serve customer routes.

---

#### `GET /api/v1/nodes`

List all Caddy nodes, ordered by priority descending.

**Auth:** Bearer token - admin only.

**Response `200`**

```json
{
  "nodes": [
    {
      "id": 1,
      "name": "ams-node-01",
      "api_url": "http://10.8.0.2:2019",
      "public_hostname": "ams01.proxy.example.com",
      "public_ip": "185.10.20.30",
      "node_group_id": 1,
      "max_routes": 500,
      "current_routes": 127,
      "enabled": true,
      "health": "healthy"
    }
  ]
}
```

`health` values: `healthy`, `degraded`, `unknown`.

**Errors**

| Code | Meaning |
|------|---------|
| 401 | Auth required |
| 403 | Admin role required |
| 429 | Rate limit exceeded |
| 500 | Database error |

---

#### `POST /api/v1/nodes`

Register a Caddy node manually.

**Auth:** Bearer token - admin only.

Alternative to the automatic node-join flow. The node starts enabled with `health: unknown`.

**Request body**

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `name` | string | yes | Unique node label |
| `api_url` | string | yes | Internal Caddy Admin API URL (e.g. `http://10.8.0.2:2019`) |
| `public_hostname` | string | no | Public DNS hostname |
| `public_ip` | string (IPv4) | no | Public IP address |
| `node_group_id` | integer | yes | Node group this node belongs to |
| `max_routes` | integer | yes | Maximum number of routes this node can serve |
| `priority` | integer | no | Higher value = preferred for new route placement (default `0`) |

```json
{
  "name": "ams-node-01",
  "api_url": "http://10.8.0.2:2019",
  "public_hostname": "ams01.proxy.example.com",
  "public_ip": "185.10.20.30",
  "node_group_id": 1,
  "max_routes": 500,
  "priority": 10
}
```

**Response `201`**

```json
{ "id": 1 }
```

**Errors**

| Code | Meaning |
|------|---------|
| 400 | Missing required fields |
| 401 | Auth required |
| 403 | Admin role required |
| 429 | Rate limit exceeded |
| 500 | Database error |

---

#### `POST /api/v1/nodes/{id}/resync`

Rebuild and push the full Caddy route config from the database to a node.

**Auth:** Bearer token - admin only.

Use after manual DB edits or to recover from config drift. The operation is synchronous with a 15-second timeout.

**Response `200`**

```json
{ "id": 1, "resynced": true }
```

**Errors**

| Code | Meaning |
|------|---------|
| 401 | Auth required |
| 403 | Admin role required |
| 429 | Rate limit exceeded |
| 500 | Resync failed (message includes reason) |

---

#### `POST /api/v1/nodes/join`

Register a Caddy node via one-shot join token.

**Auth:** The `hpg_join_` token in the request body is the credential. No Bearer API key is needed. Rate-limited per IP.

This endpoint is called by the node bootstrap script (`/install/node.sh`). Do not call it manually unless you are building a custom provisioning tool.

**Request body**

```json
{
  "token": "hpg_join_xxxxxxxxxxxxxxxxxxxxxxxx",
  "public_hostname": "ams01.proxy.example.com",
  "public_ip": "185.10.20.30"
}
```

**Response `200`**

```json
{
  "node_id": 1,
  "node_name": "ams-node-01",
  "fingerprint": "sha256:...",
  "wireguard": { }
}
```

**Errors**

| Code | Meaning |
|------|---------|
| 400 | Empty body or invalid JSON |
| 401 | Token invalid, already used, or malformed |
| 429 | Rate limit exceeded |

---

### Resellers

A reseller is a white-label tenant that owns a set of clients (and optionally its own plans + branding). Reseller management is **platform-admin only** - a reseller-admin API key passes the role check but is denied by the global-scope gate (`403 global admin scope required`); it manages its own tenants through the scoped `/clients`, `/services`, and `/routes` endpoints instead.

---

#### `GET /api/v1/resellers`

List all resellers.

**Auth:** Bearer token - platform-admin only.

**Response `200`**

```json
{
  "resellers": [
    {
      "id": 3,
      "name": "Acme Hosting",
      "slug": "acme-hosting",
      "status": "active",
      "brand_name": "Acme Cloud",
      "support_email": "support@acme.example",
      "reseller_plan_id": 2,
      "overselling_allowed": false,
      "can_create_plans": true,
      "owner_user_id": 41
    }
  ]
}
```

**Errors**

| Code | Meaning |
|------|---------|
| 401 | Auth required |
| 403 | Admin role required, or caller is not a global-scope admin (reseller-admin key) |
| 429 | Rate limit exceeded |
| 500 | Database error |

---

#### `GET /api/v1/resellers/{id}`

Get a single reseller, including current package usage.

**Auth:** Bearer token - platform-admin only.

**Response `200`**

```json
{
  "id": 3,
  "name": "Acme Hosting",
  "slug": "acme-hosting",
  "status": "active",
  "brand_name": "Acme Cloud",
  "support_email": "support@acme.example",
  "reseller_plan_id": 2,
  "overselling_allowed": false,
  "can_create_plans": true,
  "owner_user_id": 41,
  "usage": {
    "Clients": 4,
    "MaxClients": 10,
    "Services": 6,
    "MaxServices": 25,
    "Domains": 18,
    "MaxDomains": 50,
    "Overselling": false,
    "Limited": true
  }
}
```

`usage.Limited` is `false` when the reseller has no package subscribed (unlimited); the `Max*` fields are then `0` and not enforced.

**Errors**

| Code | Meaning |
|------|---------|
| 401 | Auth required |
| 403 | Admin role required, or caller is not a global-scope admin |
| 404 | Reseller not found |
| 429 | Rate limit exceeded |
| 500 | Database error |

---

#### `POST /api/v1/resellers`

Create a reseller and its owner login in one atomic operation.

**Auth:** Bearer token - platform-admin only.

**Request body**

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `name` | string | yes | Display name |
| `slug` | string | yes | Lowercase alphanumeric/dashes; unique |
| `owner_email` | string | yes | Login for the reseller-admin owner account |
| `owner_password` | string | yes | >= 12 characters |
| `brand_name` | string | no | White-label brand name |
| `support_email` | string | no | Support contact shown to the reseller's own clients |

```json
{
  "name": "Acme Hosting",
  "slug": "acme-hosting",
  "owner_email": "owner@acme.example",
  "owner_password": "correct-horse-battery-staple",
  "brand_name": "Acme Cloud",
  "support_email": "support@acme.example"
}
```

The owner account is created with `role=reseller` and `users.reseller_id` set to the new reseller, and is subscribed to the default "Unlimited" package.

**Response `201`**

```json
{ "id": 3, "owner_user_id": 41 }
```

**Errors**

| Code | Meaning |
|------|---------|
| 400 | Missing/invalid `name`, `slug`, `owner_email`, or `owner_password` too short |
| 401 | Auth required |
| 403 | Admin role required, or caller is not a global-scope admin |
| 409 | `slug` or `owner_email` already exists |
| 429 | Rate limit exceeded |
| 500 | Hash or database error |

---

#### `PATCH /api/v1/resellers/{id}`

Update a reseller's identity, branding, status, and package policy.

**Auth:** Bearer token - platform-admin only.

All fields are optional; omit to leave unchanged.

**Request body**

| Field | Type | Notes |
|-------|------|-------|
| `name` | string | |
| `status` | string | `active` or `suspended` |
| `brand_name` | string | |
| `support_email` | string | |
| `reseller_plan_id` | integer | Subscribed package (see Reseller plans below) |
| `overselling_allowed` | boolean | Policy flag |
| `can_create_plans` | boolean | Policy flag |

```json
{ "status": "suspended" }
```

Setting `status: "suspended"` revokes every active session for that reseller's users (fail-closed - a reseller-admin cannot keep working through an already-open session).

**Response `200`** - same shape as `GET /api/v1/resellers/{id}` (without `usage`).

**Errors**

| Code | Meaning |
|------|---------|
| 400 | Invalid JSON, or `status` not `active`/`suspended` |
| 401 | Auth required |
| 403 | Admin role required, or caller is not a global-scope admin |
| 404 | Reseller not found |
| 429 | Rate limit exceeded |
| 500 | Database error |

---

#### `DELETE /api/v1/resellers/{id}`

Delete a reseller.

**Auth:** Bearer token - platform-admin only.

Owned clients, plans, and users have `reseller_id` reset to `NULL` (they become platform-direct) - deleting a reseller never cascades a delete of customer data. Sessions of the freed users are revoked.

**Response `200`**

```json
{ "id": 3, "deleted": true }
```

**Errors**

| Code | Meaning |
|------|---------|
| 401 | Auth required |
| 403 | Admin role required, or caller is not a global-scope admin |
| 404 | Reseller not found |
| 429 | Rate limit exceeded |
| 500 | Database error |

---

### Reseller plans

A reseller plan (package) is the aggregate quota + resource grant tier a reseller subscribes to - analogous to a Plesk "reseller plan" or WHM "account limits". It is distinct from a `Plan` (`plans` table), which is the quota a client's *service* uses; a reseller plan caps the reseller's totals across all of its clients/services/domains and grants which node pools and route features the reseller may use when authoring its own plans.

---

#### `GET /api/v1/reseller-plans`

List all reseller packages.

**Auth:** Bearer token - platform-admin only.

**Response `200`**

```json
{
  "reseller_plans": [
    {
      "id": 2,
      "name": "Growth",
      "max_clients": 10,
      "max_services_total": 25,
      "max_domains_total": 50,
      "rate_limit_rpm_cap": 600,
      "node_group_ids": [1, 2],
      "features": ["ssl", "wildcard", "websocket"]
    }
  ]
}
```

`0` on any `max_*`/`rate_limit_rpm_cap` field means unlimited/uncapped.

**Errors**

| Code | Meaning |
|------|---------|
| 401 | Auth required |
| 403 | Admin role required, or caller is not a global-scope admin |
| 429 | Rate limit exceeded |
| 500 | Database error |

---

#### `POST /api/v1/reseller-plans`

Create a reseller package.

**Auth:** Bearer token - platform-admin only.

**Request body**

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `name` | string | yes | Unique package name |
| `max_clients` | integer | no | `0` = unlimited |
| `max_services_total` | integer | no | `0` = unlimited |
| `max_domains_total` | integer | no | `0` = unlimited |
| `rate_limit_rpm_cap` | integer | no | `0` = uncapped |
| `node_group_ids` | array of integer | no | Node pools this package may place services on |
| `features` | array of string | no | Grantable set: `ssl`, `wildcard`, `websocket`, `path`, `external`, `waf`, `geo`, `l4`, `cache`, `rate_limit`, `dns01`, `weighted_lb` |

```json
{
  "name": "Growth",
  "max_clients": 10,
  "max_services_total": 25,
  "max_domains_total": 50,
  "rate_limit_rpm_cap": 600,
  "node_group_ids": [1, 2],
  "features": ["ssl", "wildcard", "websocket"]
}
```

**Response `201`**

```json
{ "id": 2 }
```

**Errors**

| Code | Meaning |
|------|---------|
| 400 | `name` missing |
| 401 | Auth required |
| 403 | Admin role required, or caller is not a global-scope admin |
| 409 | Package name already exists |
| 429 | Rate limit exceeded |
| 500 | Database error |

---

#### `PATCH /api/v1/reseller-plans/{id}`

Replace a reseller package's limits and grant sets.

**Auth:** Bearer token - platform-admin only.

This is a full replace, not a partial patch: `node_group_ids` and `features` are wholesale-replaced with the arrays supplied, so omitting them clears the grant. Request body is the same shape as create.

**Response `200`**

```json
{ "id": 2, "updated": true }
```

**Errors**

| Code | Meaning |
|------|---------|
| 400 | `name` missing |
| 401 | Auth required |
| 403 | Admin role required, or caller is not a global-scope admin |
| 409 | Package name already exists |
| 429 | Rate limit exceeded |
| 500 | Database error |

---

#### `DELETE /api/v1/reseller-plans/{id}`

Delete a reseller package.

**Auth:** Bearer token - platform-admin only.

**Response `200`**

```json
{ "id": 2, "deleted": true }
```

**Errors**

| Code | Meaning |
|------|---------|
| 401 | Auth required |
| 403 | Admin role required, or caller is not a global-scope admin |
| 404 | Package not found |
| 409 | Package still in use - reassign resellers to a different package first |
| 429 | Rate limit exceeded |
| 500 | Database error |

---

### Reseller quota errors

`POST /api/v1/clients` and `POST /api/v1/services` enforce the caller's reseller package limits (`internal/quota`) when the target client/service belongs to a reseller. Exceeding a limit returns `403` with the standard error envelope:

```json
{ "error": "reseller quota: client limit reached" }
```

```json
{ "error": "reseller quota: service limit reached" }
```

```json
{ "error": "reseller quota: domain limit reached" }
```

These are business limits, not authorization failures - they only trigger for resellers that are actually subscribed to a package (a reseller with no package, or a platform-direct client, is never limited). Domain (route) capacity is enforced either as an allocation check at service-create time (sum of attached plans' `max_domains` against the package total) or, when `overselling_allowed` is on, as a real route count at route-create time.

---

## WireGuard Tunnel Endpoints

These endpoints serve customer-side WireGuard tunnel setup. They are **not** under `/api/v1` and use a different authentication scheme.

Authentication is via a single-shot **192-hex-char bootstrap token** passed as `?token=`. Tokens have a 24-hour TTL and are invalidated on first use. All endpoints are rate-limited to 10 requests per minute per source IP.

---

#### `GET /api/wg/bootstrap?token=<token>`

Download the WireGuard `.conf` file for a customer tunnel.

The token is consumed on first call. Subsequent calls with the same token return `403`. Use the installer script endpoint instead of calling this directly.

**Response `200`** - `text/plain` WireGuard configuration file

```
[Interface]
PrivateKey = ...
Address = 100.96.5.42/32

[Peer]
PublicKey = ...
Endpoint = ams01.proxy.example.com:51820
```

Response header: `Content-Disposition: attachment; filename="hostyt-tunnel-<id>.conf"`

**Errors**

| Code | Meaning |
|------|---------|
| 403 | Token invalid, expired, or already consumed |
| 429 | Rate limit exceeded |
| 500 | Internal error |

---

#### `GET /api/wg/install.sh?token=<token>`

Download the bash installer script.

The script installs `wireguard-tools`, fetches `/api/wg/bootstrap`, and creates a systemd unit.

```bash
# Install
curl 'https://your-panel.example.com/api/wg/install.sh?token=<token>' | sudo bash

# Remove
curl 'https://your-panel.example.com/api/wg/install.sh?token=<token>' | sudo bash -s -- remove
```

The bootstrap token is embedded in the script and consumed when the script calls `/api/wg/bootstrap`. Running the script a second time with the same URL is safe - it detects the existing config and validates/repairs the tunnel instead of re-downloading.

**Response `200`** - `text/x-shellscript`

**Errors**

| Code | Meaning |
|------|---------|
| 400 | Missing or malformed token (must be exactly 192 chars) |
| 429 | Rate limit exceeded |
| 503 | Panel URL not configured or tunnel transport not ready |

---

#### `GET /api/wg/status?token=<token>`

Poll whether the customer WireGuard peer has established a handshake.

**Response `200`**

```json
{
  "status": "active",
  "last_handshake": "2026-06-24T10:00:00Z"
}
```

`status` values: `pending`, `active`.  
`last_handshake` is `null` when no handshake has occurred.

**Errors**

| Code | Meaning |
|------|---------|
| 400 | Missing or malformed token |
| 404 | Unknown token |
| 429 | Rate limit exceeded |

---

## Node Agent Endpoints

These endpoints are called by `hpg-node-agent` on each Caddy node. They are **not** under `/api/v1`.

**Authentication:** `Authorization: Bearer <agent_token>` or `?node_token=<agent_token>`.

The agent token is the per-node token stored as a SHA-256 hash in `caddy_nodes.agent_token_hash`. It is issued during node join or rotated via `Admin → Nodes → Rotate`.

---

#### `GET /api/node/wg/peers?node_token=<token>`

Pull the list of WireGuard peers this node should configure.

Called by the agent every ~30 seconds.

**Response `200`**

```json
{
  "psk_managed": true,
  "peers": [
    {
      "pubkey": "abc123...==",
      "allowed_ip": "100.96.5.42/32",
      "status": "active"
    }
  ]
}
```

`status` values: `active`, `pending`, `revoked`.

Agents send `X-HPG-Agent-PSK: 1` to declare that they apply `preshared_key`;
the panel records that capability before building the answer (`500` if it
cannot) and echoes `psk_managed: true`, which tells the agent this is the
complete key set and a peer listed without one has really lost it. Omitted
for agents that do not declare the header - see
[POST_QUANTUM.md](POST_QUANTUM.md#the-pull-negotiates-capability-409-conflict).

**Errors**

| Code | Meaning |
|------|---------|
| 401 | Missing token |
| 403 | Invalid token |
| 503 | Database not ready |

---

#### `POST /api/node/wg/stats`

Report WireGuard peer stats parsed from `wg show <iface> dump`.

Supersedes `/api/node/wg/handshakes`. The panel stores reset-safe byte deltas and updates `wstunnel_healthy`, triggering a Caddy route resync on any health transition.

**Request body**

```json
{
  "stats": [
    {
      "pubkey": "abc123...==",
      "last_handshake": 1719216000,
      "rx_bytes": 1048576,
      "tx_bytes": 524288,
      "endpoint": "203.0.113.5:51820"
    }
  ],
  "node": {
    "ip_forward_enabled": true,
    "forward_policy_drop_detected": false,
    "docker_rules_installed": true,
    "firewall_backend": "nftables",
    "mtu": 1420,
    "listen_port": "51821",
    "last_setup_error": "",
    "wstunnel_healthy": true
  }
}
```

The `node` object is optional - older agents that omit it leave diagnostic fields as `NULL` in the database rather than overwriting with false negatives.

**Response `204 No Content`**

**Errors**

| Code | Meaning |
|------|---------|
| 400 | Malformed body |
| 401 | Missing token |
| 403 | Invalid token |
| 503 | Database not ready |

---

#### `POST /api/node/wg/handshakes` (legacy)

Report WireGuard handshake timestamps.

Superseded by `/api/node/wg/stats`. Kept live for rolling agent upgrades.

**Request body** (JSON or form-encoded)

```json
{
  "reports": [
    {
      "pubkey": "abc123...==",
      "last_handshake": "2026-06-24T10:00:00Z"
    }
  ]
}
```

**Response `204 No Content`**

**Errors**

| Code | Meaning |
|------|---------|
| 401 | Missing token |
| 403 | Invalid token |

---

## Async Operations

Caddy configuration changes (route create, route delete, node resync) are pushed to each node in a background goroutine. The API call returns as soon as the database row is committed.

SSL certificate provisioning is also asynchronous. After creating a route:

1. Point the domain's DNS A/AAAA record to the node's public IP.
2. Call `POST /api/v1/routes/{id}/verify-dns` to trigger a DNS check.
3. Poll `GET /api/v1/services/{id}/routes` and watch `status` - it moves from `pending_ssl` to `active` once Caddy obtains the certificate.

---

## Interactive API Docs

The panel ships a built-in Swagger UI at `/api-docs` (no login required when enabled by the operator). The OpenAPI 3.1 spec is available at `/api-docs/openapi.json`.
