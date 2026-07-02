# Web Application Firewall (WAF)

## Overview

HPG supports per-route WAF inspection powered by [Coraza](https://coraza.io) via the
`corazawaf/coraza-caddy` Caddy module. When enabled on a route the WAF handler runs
first in the handler chain, before any upstream proxying.

## Requirements

Coraza is not part of stock Caddy. You need a custom Caddy build that includes
`corazawaf/coraza-caddy` on every node in the fleet, and the env flag
`WAF_MODULE_AVAILABLE=1` set on the HPG process. Without the flag, WAF settings are
saved but no WAF block is pushed to Caddy (routes still work normally).

Use the provided `deploy/caddy/Dockerfile` as the base; it already includes the module.

The lite stack (`deploy/docker-compose.lite.yml`) runs stock Caddy with no custom
modules and ships `WAF_MODULE_AVAILABLE=0`, so WAF is unavailable there - switch to
the full/custom-build stack to enable it.

## Enablement runbook

WAF is code-complete; turning it on is a deploy operation. Order matters - do NOT
flip the flag before every node runs the edge image.

1. **Build + roll the edge image to ALL nodes** (central panel node + every remote
   join node):
   ```bash
   make edge-push EDGE_IMAGE=ghcr.io/host-yt/caddy-proxy-manager-edge:latest
   ```
   Then redeploy each node onto that image. **Trap:** stock Caddy rejects the WAF
   (and cache/L4) config on `/load` and the node drops offline - identical to the
   `CACHE_HANDLER_AVAILABLE` gotcha. A node that has been capability-probed
   (`modules_probed_at` set, `has_waf=1/0`) is protected: the panel emits WAF
   config only to nodes whose probe reports coraza (`probedOr` in
   `internal/domain/routes/service.go`). The risk window is an **un-probed** node
   while the global flag is on - so probe/roll first.
2. **Flip the flag** on the HPG app process and redeploy the app:
   ```
   WAF_MODULE_AVAILABLE=1
   ```
3. **Start in detection-only** per route (default). Watch `Admin → WAF` events for
   false positives before switching any route to blocking mode.

## Configuration

### Per-route toggle

On the host edit page (Admin → Hosts → Edit) you will find the WAF section:

| Field | Meaning |
|-------|---------|
| **Enable WAF** | Injects the Coraza handler for this route |
| **Blocking mode** | On = block matching requests (default: detection only) |
| **Extra directives** | SecLang appended after the default ruleset include |

The base configuration HPG emits:

```
Include @coraza.conf-recommended
Include @crs-setup.conf.example
<your extra directives>
Include @owasp_crs/*.conf
```

Detection-only mode (`SecRuleEngine DetectionOnly`) logs events but returns 200 to
the client. Blocking mode uses the Coraza default action (typically 403).

### Extra directives

Free-form SecLang text appended after the CRS includes. Use this to tune rules,
add exclusions, or set custom variables. Example:

```
SecRule REQUEST_URI "@contains /healthz" "id:9001,phase:1,pass,nolog"
```

## Events

Every rule match is stored in the `waf_events` table:

| Column | Description |
|--------|-------------|
| `route_id` | Soft reference to the matched route |
| `ts` | Event timestamp |
| `severity` | low / medium / high / critical (from Coraza) |
| `rule_id` | CRS rule ID (e.g. `949110`) |
| `action` | `detected` or `blocked` |
| `remote_ip` | Client IP |
| `host` | Virtual host matched |
| `uri` | Request URI at time of match |
| `message` | Coraza rule message |
| `acknowledged_at` / `acknowledged_by` | Set when an admin marks the event reviewed |

View events at Admin → Security → WAF Events, filterable by route and severity.
Individual events can be acknowledged. Frequent false-positive rules can be suppressed
globally or per-route in `waf_rule_suppressions` (Admin → Security → WAF Suppressions).

Export: the WAF Events page has an "Export CSV" button.

### Event forwarding (how events reach the panel)

Coraza writes a JSON audit log on each node (`/var/log/caddy/waf-audit.log`). The
`hpg-node-agent` sidecar tails it and POSTs new lines to `/api/node/waf/events`.
The agent records its read position in a `.hpgpos` sidecar so a restart resumes
instead of re-shipping the whole log.

Relevant node-agent environment variables:

| Variable | Purpose |
|----------|---------|
| `HPG_CADDY_WAF_AUDIT_LOG` | Path to the Coraza audit log to tail (e.g. `/var/log/caddy/waf-audit.log`). Empty disables WAF forwarding. |
| `HPG_CADDY_ACCESS_LOG` | Same, for the access log forwarded to `/internal/access-log`. |
| `HPG_AGENT_STATE_DIR` | Writable dir for the read-offset sidecars. **Required** when the log volume is mounted read-only (the default) - otherwise the offset cannot persist and every restart replays the log. |
| `HPG_FORWARD_TAIL_ONLY` | `1` = on first run skip the existing backlog and forward only new lines. Default forwards the backlog once. |

The panel ingest is idempotent: a `waf_seen_events` ledger fingerprints every
event it has stored, so a replayed line is dropped rather than duplicated.
**"Clear events" never touches that ledger**, so cleared events stay cleared even
if a node re-ships its log; genuinely new attacks (a new fingerprint) still
appear. The ledger is capped to its newest 100k entries and pruned automatically.

> If cleared events keep reappearing, the node-agent cannot persist its read
> offset (read-only log volume + no `HPG_AGENT_STATE_DIR`). Set the env to a
> writable volume and redeploy the agent. See `docs/MULTI_NODE.md` troubleshooting.

## Limitations

- Requires a non-stock Caddy build on every fleet node; deploying it to a mixed fleet
  (some nodes without the module) will cause Caddy to reject the config on those nodes.
- Country-level GeoIP blocking and WAF are independent features; WAF does not use the
  MaxMind DB.
- CRS ruleset is bundled with the Coraza module version in the image; updating rules
  requires a Caddy image rebuild.
- No streaming inspection for HTTP/2 or HTTP/3 request bodies beyond what Coraza
  buffers.
