# Terraform Provider - Resource Reference

The Terraform provider lives in-repo at [`../terraform-provider-hpg/`](../terraform-provider-hpg/)
as a nested Go module (its own `go.mod`, built independently). It is a thin
client over the [REST API v1](API.md). To publish on the Terraform Registry,
split that directory into a standalone `terraform-provider-hpg` repo and tag
releases - the code is unchanged, only the repo layout.

This document is the contract the provider implements: resource/attribute
mapping, auth, and import semantics. The machine-readable source of truth is the
OpenAPI spec served at:

```
GET /api-docs/openapi.json
```

Implemented resources: `hpg_node_pool`, `hpg_plan`, `hpg_client`, `hpg_service`,
`hpg_route`. (`hpg_node` follows the same shape against `/nodes`.)

## Provider configuration

```hcl
provider "hpg" {
  endpoint = "https://panel.example.com" # base URL, no trailing /api/v1
  api_key  = var.hpg_api_key             # HPG_API_KEY env var also honoured
}
```

The key's reach follows [API key scope](API.md#key-scope-multi-tenant): a
platform-admin key manages global infrastructure; a reseller-admin key is
transparently scoped to its own clients/plans and cannot manage nodes.

## Resource mapping

Every resource maps 1:1 to an API v1 collection. `id` is the numeric primary key
returned by the API and is used verbatim for `terraform import`.

| Resource | Create | Read | Update | Delete | Notes |
|----------|--------|------|--------|--------|-------|
| `hpg_node_pool` | `POST /node-pools` | `GET /node-pools/{id}` | `PATCH /node-pools/{id}` | `DELETE /node-pools/{id}` | platform-admin key only |
| `hpg_node` | `POST /nodes` | `GET /nodes/{id}` | `PATCH /nodes/{id}` | `DELETE /nodes/{id}` | platform-admin key only; `node_group_id` -> `hpg_node_pool.id` |
| `hpg_plan` | `POST /plans` | `GET /plans/{id}` | `PATCH /plans/{id}` | `DELETE /plans/{id}` | reseller keys create own-reseller plans |
| `hpg_client` | `POST /clients` | `GET /clients/{id}` | `PATCH /clients/{id}` | `DELETE /clients/{id}` | reseller keys stamp `reseller_id` automatically |
| `hpg_service` | `POST /services` | `GET /services/{id}` | `PATCH /services/{id}` | `POST /services/{id}/delete` | `client_id` + `plan_id` must be in key scope |
| `hpg_route` | `POST /routes` | `GET /routes/{id}` | `PATCH /routes/{id}` | `DELETE /routes/{id}` | `service_id` -> `hpg_service.id`; SSL is async |

### Attribute reference (abridged)

See the OpenAPI schema for the exhaustive list; these are the required/notable
attributes a provider must expose.

- **hpg_node_pool**: `name` (required), `mode` (`single`|`active_active`|`failover`).
- **hpg_node**: `name`, `api_url`, `node_group_id`, `max_routes` (required); `public_hostname`, `public_ip`, `priority`. Backend/URL is SSRF-screened server-side.
- **hpg_plan**: `name`, `max_domains`, `max_ports`, `node_group_id` (required); feature flags `ssl_enabled`, `path_routing_enabled`, `wildcard_enabled`, `websocket_enabled`, `external_proxy_enabled`, `allow_egress_ip`; `rate_limit_rpm`, `wg_key_rotation_days` (0 = unset).
- **hpg_client**: `email`, `name`, `password` (>= 12 chars, required on create); `external_ref` for idempotent external mapping. `password` is write-only.
- **hpg_service**: `client_id`, `name`, `backend_ip`, `allowed_port_start`, `allowed_port_end`, `plan_id` (required); `external_reference`. `status` is computed.
- **hpg_route**: `service_id`, `upstream_port`, `domain` (required); `path_prefix`, `ssl`, `websocket`, `force_https`. `status` and `caddy_node_id` are computed; SSL provisioning is asynchronous (poll `status`).

## Import

```
terraform import hpg_service.web 42
```

All resources import by numeric id. `hpg_client` imports by the **client id**
(not the user id); the create call returns `user_id`, so capture the client id
from a follow-up `GET /clients` if you provision outside Terraform.

## Async & drift notes

- Route SSL/DNS is provisioned in the background. After `POST /routes` the
  `status` moves `pending_dns -> dns_ok -> pending_ssl -> active`. A provider
  should treat non-`active` as "still converging", not an error, and may expose
  `verify-dns` / `retry-ssl` as no-op-on-success operations.
- Deleting a `hpg_node` with active routes returns `409`; reassign first.
- Deleting a `hpg_plan`/`hpg_node_pool` in use returns `409`.

See [docs/terraform/main.tf](terraform/main.tf) for a full worked example.
