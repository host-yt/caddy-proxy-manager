# Install Guide

Step-by-step first-deploy for **Hostyt Proxy Gateway** on a single Linux VPS.
For multi-node and production hardening see [`DEPLOY.md`](DEPLOY.md) and [`MULTI_NODE.md`](MULTI_NODE.md).

---

## 1. Prerequisites

| Requirement | Minimum version | Notes |
|---|---|---|
| Docker Engine | 24.0 | `docker --version` |
| Docker Compose | v2.20 (plugin) | `docker compose version` |
| Linux VPS | Ubuntu 22.04 / Debian 12 | ARM64 and x86-64 supported |

**Open firewall ports before starting:**

| Port | Protocol | Purpose |
|---|---|---|
| 80 | TCP | HTTP + ACME HTTP-01 challenge |
| 443 | TCP + UDP | HTTPS + HTTP/3 |
| 8080 | TCP | Panel web UI (can be changed via `APP_PORT`) |
| 51820 | UDP | WireGuard mesh (only needed for multi-node) |

Port 2019 (Caddy Admin API) must **not** be exposed - it is internal-only.

---

## 2. Quick start (single VPS)

### 2.1 Clone and configure

```bash
git clone https://github.com/host-yt/caddy-proxy-manager.git hostyt-proxy-gateway
cd hostyt-proxy-gateway
cp .env.example .env
```

Open `.env` and set the four required variables:

```bash
# Publicly reachable URL of the panel (must match your DNS A record)
APP_URL=https://panel.example.com

# Random 64-character hex secret - generate with:
APP_SECRET=$(openssl rand -hex 32)

# MariaDB passwords - use strong, unique values
DB_PASSWORD=change_me_strong
MARIADB_ROOT_PASSWORD=change_me_root_strong

# Let's Encrypt contact address
CADDY_ACME_EMAIL=ops@example.com
```

### 2.2 Start the stack

```bash
docker compose -f deploy/docker-compose.yml --env-file .env up -d
```

Services started: `app`, `mariadb`, `redis`, `caddy`.
The `wireguard` service is in the `mesh` profile and is **not** started here.

Watch startup logs:

```bash
docker compose -f deploy/docker-compose.yml logs -f --tail=100
```

### 2.3 Open the install wizard

Navigate to `http://<your-server-ip>:8080/install` (or the URL set in `APP_URL`).

The wizard is only reachable while `INSTALLED=0`. It flips itself to `1` on completion.

### 2.4 Full vs Lite stack

Two compose files ship. Pick by whether you can run the custom Caddy build.

| | `docker-compose.yml` (full) | `docker-compose.lite.yml` (lite) |
|---|---|---|
| Caddy image | `caddy-proxy-manager-edge` (xcaddy build) | stock `caddy:2.11.3` |
| Core reverse proxy + ACME | yes | yes |
| Panel, clients, tunnels, access logs, analytics rollups | yes | yes |
| WAF (coraza) | yes (flag) | **no** |
| Origin cache, L4 streams, GeoIP matcher, per-route rate-limit, weighted LB, DNS-01 wildcard | yes (flags) | **no** |

Lite runs everything except the advanced Caddy modules; those surfaces stay
hidden while their `*_AVAILABLE` flags are `0`. Start it with:

```bash
docker compose -f deploy/docker-compose.lite.yml --env-file .env up -d
```

To move from lite to full later: switch to `docker-compose.yml` (edge image),
roll it to every node, then flip the module flags - see [WAF.md](WAF.md) for the
enablement runbook and the offline trap.

---

## 3. Environment variables reference

All variables live in `.env` (copied from `.env.example`). Values in the **Default** column are the compose fallback when the variable is absent; **-** means no default (the field is blank or must be set explicitly).

### App

| Variable | Default | Required | Description |
|---|---|---|---|
| `APP_ENV` | `production` | no | `production` or `development` |
| `APP_URL` | - | **yes** | Public URL of the panel, e.g. `https://panel.example.com` |
| `APP_BIND` | `0.0.0.0:8080` | no | Interface and port the Go server listens on |
| `APP_SECRET` | - | **yes** | 64-char hex key for sessions and encryption - generate with `openssl rand -hex 32` |
| `APP_TRUSTED_PROXIES` | - | no | Comma-separated CIDR list of trusted reverse proxies (for real-IP extraction) |
| `LOG_LEVEL` | `info` | no | `debug`, `info`, `warn`, or `error` |

### Install wizard

| Variable | Default | Required | Description |
|---|---|---|---|
| `INSTALLED` | `0` | no | `0` = wizard accessible; wizard sets this to `1` on completion. Do not flip manually before running the wizard. |

### Database

| Variable | Default | Required | Description |
|---|---|---|---|
| `DB_DRIVER` | `mysql` | no | Database backend: `mysql` (MariaDB/MySQL) or `sqlite3` (single-node, no separate service) |

#### MariaDB / MySQL (default)

| Variable | Default | Required | Description |
|---|---|---|---|
| `DB_HOST` | `mariadb` | no | Hostname or IP of the database server |
| `DB_PORT` | `3306` | no | Database port |
| `DB_NAME` | `hostyt_proxy` | no | Database name |
| `DB_USER` | `hostyt` | no | Database user |
| `DB_PASSWORD` | `change_me_strong` | **yes** | Database password - change before first start |
| `DB_TLS` | `false` | no | Set `true` for managed cloud databases that require TLS |
| `DB_DSN` | - | no | Full DSN override - takes precedence over the individual fields above |
| `MARIADB_ROOT_PASSWORD` | `change_me_root_strong` | **yes** | Root password for the bundled MariaDB container - ignored when using an external DB |

#### SQLite (single-node homelab)

Set `DB_DRIVER=sqlite3` in `.env` **before** running the install wizard, or choose SQLite in the wizard itself. No separate database container is needed.

| Variable | Default | Required | Description |
|---|---|---|---|
| `DB_SQLITE_PATH` | `./data/hpg.db` | no | Path to the SQLite database file. The directory must be writable by the `app` container. |

SQLite is intended for homelab and single-node installs. It requires no credentials or separate service. For production multi-node deployments use MariaDB/MySQL.

### Redis

| Variable | Default | Required | Description |
|---|---|---|---|
| `REDIS_ADDR` | `redis:6379` | no | Redis address |
| `REDIS_PASSWORD` | - | no | Redis password (leave blank if not set on the Redis container) |
| `REDIS_DB` | `0` | no | Redis database index |

### Caddy

| Variable | Default | Required | Description |
|---|---|---|---|
| `CADDY_ADMIN_URL` | `http://caddy:2019` | no | Internal URL for the Caddy Admin API |
| `CADDY_PUBLIC_HOSTNAME` | `proxy.example.com` | no | Public hostname of this Caddy node (shown in node list) |
| `CADDY_PUBLIC_IP` | - | no | Override public IP of this node (auto-detected when blank) |
| `CADDY_ACME_EMAIL` | `ops@example.com` | **yes** | Contact address sent to Let's Encrypt |
| `CADDY_ACME_STAGING` | `false` | no | Set `true` to use Let's Encrypt staging CA while testing |

### SMTP

All SMTP variables are optional. They provide bootstrap defaults; the admin UI can override them at runtime.

| Variable | Default | Description |
|---|---|---|
| `SMTP_HOST` | - | SMTP server hostname |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_ENCRYPTION` | `tls` | `tls`, `ssl`, or `none` |
| `SMTP_USERNAME` | - | SMTP auth username |
| `SMTP_PASSWORD` | - | SMTP auth password |
| `SMTP_FROM_EMAIL` | `no-reply@example.com` | Sender address |
| `SMTP_FROM_NAME` | `Hostyt Proxy` | Sender display name |

### Security

| Variable | Default | Description |
|---|---|---|
| `SESSION_COOKIE_NAME` | `hpg_session` | Session cookie name |
| `SESSION_COOKIE_SECURE` | `true` | Set `false` only for plain-HTTP local testing |
| `SESSION_COOKIE_SAMESITE` | `lax` | SameSite policy: `lax`, `strict`, or `none` |
| `CSRF_COOKIE_NAME` | `hpg_csrf` | CSRF cookie name |
| `RATE_LIMIT_LOGIN_PER_MIN` | `10` | Max login attempts per IP per minute |
| `RATE_LIMIT_ASK_PER_MIN` | `120` | Max On-Demand TLS ask requests per minute |

### CAPTCHA (optional)

| Variable | Default | Description |
|---|---|---|
| `CAPTCHA_PROVIDER` | - | `turnstile`, `recaptcha`, or blank to disable |
| `CAPTCHA_SITE_KEY` | - | Provider site key |
| `CAPTCHA_SECRET` | - | Provider secret key |

### OIDC / SSO (optional)

These are bootstrap defaults; the admin UI is the canonical place to configure OIDC.

| Variable | Default | Description |
|---|---|---|
| `OIDC_ENABLED` | `false` | Enable OIDC login |
| `OIDC_ISSUER` | - | OIDC issuer URL (e.g. `https://auth.example.com`) |
| `OIDC_CLIENT_ID` | - | Client ID |
| `OIDC_CLIENT_SECRET` | - | Client secret |
| `OIDC_REDIRECT_URL` | - | Callback URL registered with the provider |

### SSO jump login

| Variable | Default | Description |
|---|---|---|
| `SSO_JUMP_SHARED_SECRET` | - | Shared secret for FOSSBilling / Hostyt jump-login |

### External HTTPS upstream

| Variable | Default | Description |
|---|---|---|
| `EXTERNAL_UPSTREAM_ALLOWLIST` | - | Comma-separated FQDNs that the "External HTTPS upstream" host type may proxy to. Empty = feature disabled. |

### Caddy module gates

These flags must remain `0` until **every** Caddy node in the fleet (central and remote) runs the custom xcaddy image. Flipping one to `1` while any node runs stock Caddy will cause that node to reject the next `/load` call and go offline.

| Variable | Default | Description |
|---|---|---|
| `WEIGHTED_LB_AVAILABLE` | `0` | Enable `weighted_round_robin` load-balancing policy |
| `RATE_LIMIT_AVAILABLE` | `0` | Enable per-route rate-limit handler (`caddy-ratelimit`) |
| `WAF_MODULE_AVAILABLE` | `0` | Enable per-route Coraza WAF (`coraza-caddy`) |
| `DNS01_AVAILABLE` | `0` | Enable wildcard DNS-01 certificate automation |

### Admin 2FA enforcement

| Variable | Default | Description |
|---|---|---|
| `REQUIRE_ADMIN_2FA` | `0` | Block `admin`/`super_admin` users without 2FA enrolled from accessing `/admin/*` |
| `REQUIRE_ADMIN_2FA_GRACE_HOURS` | `0` | Hours of grace after enforcement is first applied, so existing admins are not instantly locked out. `0` = immediate effect. |

### Audit SIEM webhook (optional)

| Variable | Default | Description |
|---|---|---|
| `AUDIT_SIEM_WEBHOOK` | - | URL to POST each audit event as JSON. RFC1918 and loopback targets are blocked (SSRF guard). Fire-and-forget. |

---

## 4. Install wizard walkthrough

Open `http://<server-ip>:8080/install` (or `APP_URL/install`).

The wizard runs four steps:

1. **Welcome** - confirms database and Redis connectivity before proceeding.

2. **Database backend** - choose MariaDB/MySQL (default, requires bundled `mariadb` service) or SQLite (embedded, no extra service). If you set `DB_DRIVER=sqlite3` in `.env` before opening the wizard, this step is pre-selected.

3. **Admin account** - create the first `super_admin` user (email + password). This account owns the panel. Store the credentials; password reset requires SMTP to be configured.

4. **First Caddy node registration** - the wizard registers the bundled `caddy` container (from `CADDY_ADMIN_URL`) as the first node. It pushes the initial Caddy config via the Admin API.

5. **Self-route setup** - the wizard pushes a virtual host route for `APP_URL` → the `app` container on the first node, so the panel becomes accessible at `https://panel.example.com` (with a valid TLS certificate) without requiring a manual "Add host" step.

On completion the wizard sets `INSTALLED=1` in the persistent state file. The `/install` path becomes inaccessible.

After the wizard, sign in at `APP_URL` with the admin credentials you created.

---

## 5. Verify install

**Health endpoint:**

```bash
curl -sf http://localhost:8080/healthz && echo "OK"
```

Expected response: `{"status":"ok"}` with HTTP 200.

**Check all containers are running:**

```bash
docker compose -f deploy/docker-compose.yml ps
```

All four services (`app`, `mariadb`, `redis`, `caddy`) should show `running` / `healthy`.

**Confirm Caddy is serving TLS:**

```bash
curl -I https://panel.example.com
```

Expected: `HTTP/2 200` (or `301` redirect to HTTPS). A `526` or certificate error means DNS for `APP_URL` has not propagated yet or `CADDY_ACME_EMAIL` was left as the placeholder.

---

## 6. Upgrade

Pull the latest images and restart:

```bash
docker compose -f deploy/docker-compose.yml --env-file .env pull
docker compose -f deploy/docker-compose.yml --env-file .env up -d
```

Database migrations run automatically on startup (`goose up` embedded in the binary).

To pin to a specific release, set `IMAGE_APP` and `IMAGE_CADDY` in `.env`:

```bash
IMAGE_APP=ghcr.io/host-yt/caddy-proxy-manager:v1.2.3
IMAGE_CADDY=ghcr.io/host-yt/caddy-proxy-manager-edge:v1.2.3
```

---

## 7. Troubleshooting

See [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) for common issues:

- Container fails to start / MariaDB not healthy
- `APP_SECRET` missing or too short
- TLS certificate not issued (On-Demand TLS `ask` endpoint unreachable)
- Caddy Admin API connection refused
- Wizard inaccessible after `INSTALLED` was set manually
- WireGuard mesh issues (multi-node)
