# terraform-provider-hpg

Terraform provider for **Hostyt Proxy Gateway**. A thin client over the panel's
[REST API v1](../docs/API.md); the resource contract is in
[../docs/TERRAFORM.md](../docs/TERRAFORM.md).

This lives as a nested Go module (its own `go.mod`) inside the panel repo so it
builds independently. To publish on the Terraform Registry, split this directory
into a standalone repo named `terraform-provider-hpg` and tag semver releases -
the code does not change, only the repo layout.

## Build

```bash
cd terraform-provider-hpg
go build -o terraform-provider-hpg .
```

## Resources

| Resource | Notes |
|----------|-------|
| `hpg_node_pool` | platform-admin key only |
| `hpg_plan` | reseller keys create own-reseller plans |
| `hpg_client` | create returns `user_id`; the provider resolves the client `id`. `password` is create-only (rotate in-panel) |
| `hpg_service` | `name`/`backend_ip`/`plan_id`/`client_id` are immutable (force replace); ports patched via the dedicated endpoint |
| `hpg_route` | `service_id`/`domain` force replace; SSL is asynchronous (`status` converges to `active`) |

`hpg_node` follows the same shape as `hpg_node_pool` against `/nodes` and can be
added when node bootstrap via API is needed.

## Configuration

```hcl
provider "hpg" {
  endpoint = "https://panel.example.com" # or HPG_ENDPOINT
  api_key  = var.hpg_api_key             # or HPG_API_KEY
}
```

Key reach (platform vs reseller-scoped) is enforced server-side; see
[API key scope](../docs/API.md#key-scope-multi-tenant).

## Local install (dev override)

```hcl
# ~/.terraformrc
provider_installation {
  dev_overrides { "host-yt/hpg" = "/absolute/path/to/terraform-provider-hpg" }
  direct {}
}
```

Then `terraform plan` in [examples/](examples/) picks up the local binary.

See [examples/main.tf](examples/main.tf) for a full resource graph.
