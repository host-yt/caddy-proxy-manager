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
| `hpg_node` | platform-admin key only; only `name`/`is_enabled` mutable in place, other fields force replace; delete refuses a node with active routes (409) |

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

## Publish to the Terraform Registry

Everything needed is in this directory - it just has to become its own repo:

1. Split this directory into a standalone repo (keeps history):
   ```bash
   git subtree split -P terraform-provider-hpg -b provider-split
   # push provider-split to a new github.com/host-yt/terraform-provider-hpg repo
   ```
2. Generate a GPG key, add its public key to your Registry account, and add the
   private key + passphrase as the `GPG_PRIVATE_KEY` / `PASSPHRASE` repo secrets.
3. Tag a release: `git tag v0.1.0 && git push --tags`. The bundled
   [`.github/workflows/release.yml`](.github/workflows/release.yml) runs
   [`.goreleaser.yaml`](.goreleaser.yaml), which builds signed multi-arch
   archives + `terraform-registry-manifest.json` (protocol 6.0) that the
   Registry ingests.

No code changes are required for the split - the module path
(`github.com/host-yt/terraform-provider-hpg`) already matches the target repo.
