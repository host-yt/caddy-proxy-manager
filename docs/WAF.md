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

## Limitations

- Requires a non-stock Caddy build on every fleet node; deploying it to a mixed fleet
  (some nodes without the module) will cause Caddy to reject the config on those nodes.
- Country-level GeoIP blocking and WAF are independent features; WAF does not use the
  MaxMind DB.
- CRS ruleset is bundled with the Coraza module version in the image; updating rules
  requires a Caddy image rebuild.
- No streaming inspection for HTTP/2 or HTTP/3 request bodies beyond what Coraza
  buffers.
