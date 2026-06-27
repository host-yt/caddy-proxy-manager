# Access Log Analytics

## Overview

HPG captures per-request access log entries from Caddy, stores them in MariaDB, and
exposes analytics queries in the admin UI. The data is visible per route or
aggregated across all routes.

## Data collected

Each entry in `host_access_log` contains:

| Field | Type | Description |
|-------|------|-------------|
| `method` | VARCHAR(16) | HTTP method (GET, POST, …) |
| `uri` | VARCHAR(2048) | Full request URI including query string |
| `status` | SMALLINT | HTTP response status code |
| `latency_ms` | INT | Round-trip latency in milliseconds |
| `remote_ip` | VARCHAR(45) | Client IP (IPv4 or IPv6) |
| `user_agent` | VARCHAR(512) | User-Agent header |
| `bytes_resp` | BIGINT UNSIGNED | Response body size in bytes |
| `proto` | VARCHAR(8) | Protocol version: `HTTP/1.1`, `HTTP/2.0`, or `HTTP/3.0` |
| `country` | CHAR(2) | ISO 3166-1 alpha-2 country code (empty if GeoIP not available) |

Entries are written on each proxied request via the Caddy access-log handler
delivered to HPG's `/internal/log` endpoint.

## Retention

The table is pruned to the most recent **500 entries per route** on each insert.
This is a fixed limit (`maxPerHost = 500`); there is no time-based expiry for raw
log rows.

Hourly rollup aggregates (request count, 4xx/5xx error counts, latency sum/max) are
stored in `log_rollups` for trend charts and are kept for a longer window.

## 24-hour window

The default analytics window is 24 hours, capped at 30 days. Most charts and tables
in the UI default to the last 24 hours. The filter can be adjusted via the date-range
picker on the analytics page.

## Protocol breakdown

The `proto` column enables HTTP version breakdown:

- `h1` - HTTP/1.1
- `h2` - HTTP/2
- `h3` - HTTP/3 (QUIC)

The analytics page shows a protocol distribution breakdown (count or percentage) for
the selected time range and route.

## Country detection

The `country` field is populated when:

1. `GEOIP_AVAILABLE=1` is set on the HPG process, and
2. The MaxMind GeoLite2-Country DB is downloaded and current.

Without GeoIP, `country` is an empty string. Country data is used in the Top Countries
widget and the world map on the Stats page.

See [GEOIP.md](GEOIP.md) for setup instructions.

## Top metrics

The analytics package exposes the following aggregated views (used by the admin UI):

- **Top URIs** - most-requested exact URIs
- **Top paths** - most-requested paths (query string stripped)
- **Top remote IPs** - most-active client IPs
- **Top countries** - most-active countries (requires GeoIP)
- **Status bucket breakdown** - 2xx / 3xx / 4xx / 5xx counts
- **Traffic timeseries** - request count bucketed by configurable step (min 1 min,
  max 720 buckets)

## Export

On Admin → Hosts → (host) → Logs, click **Export CSV** to download all raw log rows
for that route as a CSV file. The export includes all columns from `host_access_log`.

## Limitations

- Raw log retention is capped at 500 rows per route; historical analysis beyond that
  window requires the rollup tables.
- Log ingestion is best-effort: if the HPG process is unreachable when Caddy flushes
  logs, those entries are lost.
- `bytes_resp` reflects the compressed response size when Caddy compresses output;
  it is not the uncompressed body size.
- City-level or ASN data is not collected; only the two-letter country code.
