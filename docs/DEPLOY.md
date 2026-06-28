# Deploy Guide

Production-hardened deployment for **Hostyt Proxy Gateway**. Covers Docker Compose, Portainer, reverse-proxy front-end, module gates, backups, sizing, and upgrades.

For the initial first-install walkthrough see [`INSTALL.md`](INSTALL.md). For multi-node WireGuard mesh see [`MULTI_NODE.md`](MULTI_NODE.md).

---

## 1. Production checklist

Before starting the stack on a public VPS, verify every item:

**Secrets**

- [ ] `APP_SECRET` is set to a fresh 64-char hex value:
  ```bash
  openssl rand -hex 32
  ```
  Never reuse a value from another project. Rotating this key after install invalidates all encrypted settings rows - take a DB backup before rotating.

- [ ] `DB_PASSWORD` and `MARIADB_ROOT_PASSWORD` are both changed from the `change_me_*` placeholders to strong unique passwords.

- [ ] `.env` is excluded from git (`grep '\.env' .gitignore` should match). Never commit it.

**TLS and cookies**

- [ ] `SESSION_COOKIE_SECURE=true` (default; only set `false` for plain-HTTP local testing).
- [ ] `CADDY_ACME_STAGING=false` (default). Use `true` only while testing to avoid burning Let's Encrypt rate limits; flip back before going live.
- [ ] `CADDY_ACME_EMAIL` is set to a real address. Let's Encrypt contacts it for expiry warnings and policy changes.

**Firewall**

| Port | Proto | Required on | Purpose |
|------|-------|-------------|---------|
| 80 | TCP | manager + every node | HTTP, ACME HTTP-01 challenge |
| 443 | TCP + UDP | manager + every node | HTTPS + HTTP/3 |
| 51820 | UDP | manager only | WireGuard mesh (multi-node) |
| 2019 | - | - | Caddy Admin API - **must not be exposed publicly** |
| 8080 | TCP | manager | Panel web UI - expose only if not behind a reverse proxy |
| custom | TCP/UDP | every node | **L4 streams**: each stream rule listens on a port you configure; map those ports in `docker-compose.yml` under the `caddy` service `ports:` section. Example: `"5432:5432"` for a PostgreSQL passthrough stream. |

The Caddy Admin API (`:2019`) stays on the internal Docker network (`internal` bridge). Never map it to `0.0.0.0`.

### L4 stream port mapping

Each L4 stream (TCP/UDP passthrough) created in the panel binds a port on the node's Caddy process. Caddy can only serve a port that is mapped through the Docker port bindings. For each L4 stream you create, add the corresponding port mapping to the `caddy` service in your compose file:

```yaml
# deploy/docker-compose.yml - caddy service
services:
  caddy:
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"
      # --- L4 streams ---
      - "5432:5432"     # PostgreSQL passthrough
      - "6379:6379"     # Redis passthrough
      - "25565:25565"   # Minecraft server
```

After adding ports, restart the Caddy container (`docker compose up -d caddy`) and resync the node from the panel so Caddy picks up the new stream configuration.

---

## 2. Docker Compose production deploy

```bash
# Clone (or pull latest)
git clone https://github.com/host-yt/caddy-proxy-manager.git hostyt-proxy-gateway
cd hostyt-proxy-gateway

# Configure
cp .env.example .env
$EDITOR .env   # set APP_URL, APP_SECRET, DB_PASSWORD, CADDY_ACME_EMAIL at minimum

# Start core services (app + mariadb + redis + caddy)
docker compose -f deploy/docker-compose.yml --env-file .env up -d

# Enable WireGuard sidecar for multi-node mesh
docker compose -f deploy/docker-compose.yml --env-file .env --profile mesh up -d

# Tail startup logs
docker compose -f deploy/docker-compose.yml logs -f --tail=100
```

Open the install wizard at `http://<server-ip>:8080/install` to create the admin account and register the first Caddy node.

**Environment file tips:**

- Keep `.env` on the same host as the compose file.
- Pass `--env-file .env` explicitly so Docker Compose picks it up regardless of working directory.
- To pin to a specific release, add to `.env`:
  ```
  IMAGE_APP=ghcr.io/host-yt/caddy-proxy-manager:v1.2.3
  IMAGE_CADDY=ghcr.io/host-yt/caddy-proxy-manager-edge:v1.2.3
  IMAGE_PULL_POLICY=missing
  ```

---

## 3. Portainer deploy

### Option A - Stack from git repository

1. In Portainer, go to **Stacks -> Add stack -> Repository**.
2. Set **Repository URL** to the repo and **Compose path** to `deploy/docker-compose.yml`.
3. Under **Environment variables**, add each variable from `.env.example` (Portainer lets you paste them as a block under **Advanced mode**).
4. Click **Deploy the stack**.

Portainer pulls and starts the services. The stack name becomes the Docker Compose project name; note it for later CLI commands.

If you use an external managed MariaDB, use `deploy/portainer-external-db.yml`
as the compose path instead. It includes the bundled Redis, bundled Caddy, the
host-network node-agent, and the shared Caddy access-log volume used by the
logs/analytics screens.

### Option B - Paste compose YAML

1. Go to **Stacks -> Add stack -> Web editor**.
2. Paste the contents of `deploy/docker-compose.yml`.
3. Scroll to **Environment variables** and add each required variable.
4. Deploy.

**Important:** All secrets (`APP_SECRET`, `DB_PASSWORD`, `MARIADB_ROOT_PASSWORD`, `CADDY_ACME_EMAIL`) must be set in the Portainer env-var UI, not hardcoded into the YAML you paste.

Before deploying on a Linux host with bundled Redis, set the host overcommit
flag so Redis background persistence does not fail under memory pressure:

```bash
sudo sysctl -w vm.overcommit_memory=1
echo 'vm.overcommit_memory = 1' | sudo tee /etc/sysctl.d/99-hostyt-redis.conf
sudo sysctl --system
```

Portainer Stacks support auto-update from git with a webhook - enable it under **Stack details -> Git polling** or **Webhooks** after the initial deploy.

---

## 4. Reverse proxy in front of the panel

If you want the panel itself reachable at a clean hostname (e.g. `panel.example.com`) behind a separate Caddy or Nginx instance on the same host, bind the app to `127.0.0.1` and proxy it.

**Change in `.env`:**
```
APP_PORT=127.0.0.1:8080
SESSION_COOKIE_SECURE=true
APP_TRUSTED_PROXIES=127.0.0.1/8,::1/128
```

**Caddyfile snippet (outer Caddy):**
```
panel.example.com {
    reverse_proxy 127.0.0.1:8080 {
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
    }
}
```

**Nginx snippet:**
```nginx
server {
    listen 443 ssl;
    server_name panel.example.com;

    # TLS config omitted - manage certs as usual

    location / {
        proxy_pass         http://127.0.0.1:8080;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
```

Set `APP_TRUSTED_PROXIES` to the CIDR of the upstream proxy so the panel reads the real client IP from `X-Forwarded-For` instead of the loopback address. Without this, brute-force lockout and audit logs will record the proxy's IP, not the client's.

---

## 5. Caddy module gates

Four feature flags control capabilities that require the custom Caddy image (`deploy/caddy/Dockerfile`, built via xcaddy). **Never flip a gate to `1` while any node in the fleet still runs stock `caddy:2.x`.** The panel pushes a `/load` config to every node on each change; a node that does not have the module compiled in will reject the entire config and go offline.

| Variable | Module | What it enables |
|----------|--------|-----------------|
| `WEIGHTED_LB_AVAILABLE` | built-in xcaddy policy | `weighted_round_robin` load-balancing on multi-backend hosts |
| `RATE_LIMIT_AVAILABLE` | `caddy-ratelimit` | Per-route rate-limit handler in the admin UI |
| `WAF_MODULE_AVAILABLE` | `coraza-caddy/v2` | Per-route Coraza OWASP WAF toggle |
| `DNS01_AVAILABLE` | `caddy-dns/*` | Wildcard TLS via DNS-01 challenge (needs provider API key) |

All four default to `0`.

**Safe rollout procedure:**

1. Update every remote node's Caddy image to `ghcr.io/host-yt/caddy-proxy-manager-edge:latest` (or the same pinned tag as the manager).
2. Verify all nodes show **Online** in **Admin -> Caddy nodes**.
3. Set the desired gate(s) to `1` in `.env` and restart only the `app` container:
   ```bash
   docker compose -f deploy/docker-compose.yml --env-file .env up -d app
   ```
4. The new flag takes effect immediately for new host configurations. Existing hosts keep their current settings until edited.

`LAYER4_AVAILABLE` (TCP/UDP stream proxy) defaults to `1` in the compose file because the bundled Caddy image already includes `caddy-l4`. Do not set it to `1` on a remote node that still runs stock Caddy.

---

## 6. Backup

**What to back up:**

| What | How |
|------|-----|
| MariaDB database | `mysqldump` (see below) |
| `app_data` Docker volume | contains the install state file and any uploaded assets |
| `.env` file | offline, encrypted storage |

**Daily MariaDB dump (example cron):**

```bash
# /etc/cron.d/hostyt-backup
0 3 * * * root docker exec $(docker ps -qf name=mariadb) \
  mysqldump -u root -p"${MARIADB_ROOT_PASSWORD}" --single-transaction hostyt_proxy \
  | gzip > /var/backups/hostyt_proxy_$(date +\%F).sql.gz
# Prune backups older than 14 days
5 3 * * * root find /var/backups -name 'hostyt_proxy_*.sql.gz' -mtime +14 -delete
```

Replace `${MARIADB_ROOT_PASSWORD}` with the literal value (or source the env file in the cron wrapper script).

**Back up the `app_data` volume:**

```bash
docker run --rm \
  -v hostyt-proxy-gateway_app_data:/data:ro \
  -v /var/backups:/out \
  alpine tar czf /out/app_data_$(date +%F).tar.gz -C /data .
```

The volume name prefix matches the Docker Compose project name (`hostyt-proxy-gateway` by default; adjust if you named the stack differently in Portainer).

**Restore MariaDB:**

```bash
gunzip < /var/backups/hostyt_proxy_2026-01-01.sql.gz \
  | docker exec -i $(docker ps -qf name=mariadb) \
      mysql -u root -p"${MARIADB_ROOT_PASSWORD}" hostyt_proxy
```

---

## 7. Resource sizing

The Go binary idles at ~28 MB RAM. Most memory is consumed by MariaDB and the number of concurrent connections.

| Fleet size | Hosts | Recommended RAM | vCPU |
|------------|-------|-----------------|------|
| Small | up to 50 | 1 GB | 1 |
| Medium | 50-500 | 2 GB | 2 |
| Large | 500+ | 4 GB+ | 4+ |

These figures cover the full stack (app + MariaDB + Redis + Caddy) on a single manager host. MariaDB benefits most from additional RAM (InnoDB buffer pool). Set `innodb_buffer_pool_size` in a MariaDB config override if you have a dedicated DB host.

Redis memory usage is negligible for brute-force counters and sessions at these scales.

Remote Caddy nodes are stateless and scale horizontally. Each node is a single Caddy container; 512 MB RAM and 1 vCPU handles thousands of concurrent connections.

---

## 8. Upgrading

Always take a database backup before upgrading (see section 6). Migrations run automatically on startup via the embedded goose runner and are idempotent.

```bash
# Pull latest images
docker compose -f deploy/docker-compose.yml --env-file .env pull

# Recreate containers with new images
docker compose -f deploy/docker-compose.yml --env-file .env up -d
```

Watch logs during startup to confirm migrations complete:

```bash
docker compose -f deploy/docker-compose.yml logs -f app --tail=50
```

Expected output includes lines like:
```
goose: migrating db, current version: 44, target: 45
goose: OK   0045_some_change.sql
```

To roll back to a specific version, pin `IMAGE_APP` and `IMAGE_CADDY` in `.env` to the previous tag before running `pull` + `up -d`.
