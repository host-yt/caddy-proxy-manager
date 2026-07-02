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

`status` values: `active`, `pending_ssl`, `error`, `inactive`.

**Errors**

| Code | Meaning |
|------|---------|
| 401 | Auth required |
| 403 | Not your service |
| 404 | Service not found |
| 429 | Rate limit exceeded |

---

### Routes

A route maps a domain (and optional path prefix) to a port on a service's backend. Caddy configuration is pushed asynchronously. SSL provisioning may take up to a few minutes after DNS propagates.

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

**Errors**

| Code | Meaning |
|------|---------|
| 400 | Invalid domain or port outside allowed range |
| 401 | Auth required |
| 403 | Service not yours |
| 409 | Domain already mapped, no node available, or plan domain limit reached |
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
