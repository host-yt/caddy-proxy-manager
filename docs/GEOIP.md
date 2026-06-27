# GeoIP / Country Filtering

## Overview

HPG can restrict or allow HTTP traffic per route based on the client's country, using
the MaxMind GeoLite2-Country database and the
[caddy-maxmind-geolocation](https://github.com/porech/caddy-maxmind-geolocation) Caddy
module.

## Requirements

Two things must be true before geo filtering is active:

1. Every Caddy node in the fleet must run a custom build that includes
   `maxmind/caddy-maxmind-geolocation`.
2. The env flag `GEOIP_AVAILABLE=1` must be set on the HPG process.

Without the flag, geo settings are stored in the DB but no geo matcher is pushed to
Caddy. Routes continue to work without any country filtering.

## Setup

### MaxMind account

1. Sign up for a free MaxMind account at <https://www.maxmind.com/en/geolite2/signup>.
2. Generate a license key (Account → Manage License Keys).
3. Note the numeric Account ID shown on the same page.

### HPG configuration

In Admin → Settings → GeoIP enter the Account ID and License Key. HPG stores these
encrypted (`AES-256-GCM` via `APP_SECRET`) in the `settings` table under the keys
`geoip.account_id` and `geoip.license_key`.

Once credentials are saved a background job (`geoip_update`) downloads the
`GeoLite2-Country.mmdb` file (approx. 6 MB) from:

```
https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz
```

The DB is placed at `/data/geoip/GeoLite2-Country.mmdb` inside the app container and
refreshed weekly. Download status and last error are visible in Settings → GeoIP.

## How `geo_mode` works

Each route has two DB columns:

| Column | Values | Default |
|--------|--------|---------|
| `geo_mode` | `off` / `allow` / `deny` | `off` |
| `geo_countries` | Comma-separated ISO 3166-1 alpha-2 codes | `''` |

| `geo_mode` | Behaviour |
|------------|-----------|
| `off` | No geo matcher emitted; all traffic passes |
| `allow` | Only listed countries are allowed; all others get 403 |
| `deny` | Listed countries are blocked; all others pass |

The matcher is emitted as a `maxmind_geolocation` named matcher at the front of the
route handler chain with `db_path: /data/geoip/GeoLite2-Country.mmdb`.

## Country codes

Use ISO 3166-1 alpha-2 codes (two uppercase letters), e.g. `US`, `DE`, `PL`.
The admin UI accepts a comma-separated list. Blank value with `allow` or `deny` mode
is treated as "no countries" which effectively blocks or allows everything - validate
the list before saving.

## Per-node capability

Admin → Caddy Nodes shows a `GeoIP` badge on nodes where the module was detected.
`GEOIP_AVAILABLE=1` is a fleet-wide flag; if any node lacks the module it will reject
the Caddy config containing the geo matcher.

## DB status

Admin → Settings → GeoIP shows:

- Whether credentials are configured
- Last successful download timestamp
- Last error and last attempt timestamp (columns `last_error`, `last_attempt_at` in
  `geoip_db_meta`)

## Limitations

- Country-level resolution only. City or region filtering is not supported.
- GeoIP accuracy depends on MaxMind's data; VPN/proxy users may appear in the wrong
  country.
- The DB must be present on the container filesystem at `/data/geoip/`; bind-mount or
  volume required in production deployments.
- MaxMind GeoLite2 is free but requires a license key; GeoIP2 (paid) is not tested.
