# Troubleshooting

Common issues and fixes for **Hostyt Proxy Gateway**. For first-install steps see [`INSTALL.md`](INSTALL.md). For production-hardening see [`DEPLOY.md`](DEPLOY.md).

---

## 1. Panel won't start

### APP_SECRET missing or too short

**Symptom:** App container exits immediately; logs contain:
```
FATAL config: APP_SECRET is required (generate with: openssl rand -hex 32)
```
or
```
FATAL config: APP_SECRET must be at least 32 bytes
```

**Fix:** Set `APP_SECRET` in `.env` to the output of `openssl rand -hex 32` and restart:
```bash
docker compose -f deploy/docker-compose.yml --env-file .env up -d app
```

### Database connection failed

**Symptom:** App container keeps restarting; logs contain:
```
dial tcp mariadb:3306: connect: connection refused
```
or
```
Error 1045 (28000): Access denied for user 'hostyt'@'...'
```

**Check MariaDB status:**
```bash
docker compose -f deploy/docker-compose.yml ps mariadb
docker compose -f deploy/docker-compose.yml logs mariadb --tail=30
```

The `app` container depends on `mariadb` reaching healthy state (up to 10 × 10 s retries). If MariaDB itself is unhealthy, fix that first - usually a wrong `MARIADB_ROOT_PASSWORD` or a corrupt volume.

**Access denied:** `DB_USER` / `DB_PASSWORD` in `.env` do not match what MariaDB was initialized with. If you changed the password after the volume was created, you must drop and recreate the volume or update the password inside MariaDB manually:
```bash
docker exec -it $(docker ps -qf name=mariadb) mysql -u root -p
# inside mysql:
ALTER USER 'hostyt'@'%' IDENTIFIED BY 'new_password';
FLUSH PRIVILEGES;
```

### Port already in use

**Symptom:** Caddy container fails to bind port 80 or 443:
```
listen tcp 0.0.0.0:80: bind: address already in use
```

**Fix:** Find and stop whatever is using the port:
```bash
sudo ss -tlnp | grep ':80\|:443'
sudo systemctl stop nginx   # example
```

If another web server must keep running on the host, configure Caddy to bind to a different external port and front it with that web server (see [`DEPLOY.md` § Reverse proxy in front of the panel](DEPLOY.md#4-reverse-proxy-in-front-of-the-panel)).

---

## 2. Can't reach panel via HTTPS

### Caddy container not running

```bash
docker compose -f deploy/docker-compose.yml ps caddy
docker compose -f deploy/docker-compose.yml logs caddy --tail=50
```

Common cause: Caddyfile syntax error or `ASK_ENDPOINT_URL` pointing at an unreachable host. Check that the `app` container is healthy before Caddy starts.

### ACME email missing or invalid

**Symptom:** Caddy logs contain:
```
no email address provided; ACME account will be anonymous
```
or ACME registration fails with a 400.

**Fix:** Set `CADDY_ACME_EMAIL` in `.env` to a real address and restart the Caddy container:
```bash
docker compose -f deploy/docker-compose.yml --env-file .env up -d caddy
```

### Staging certificate in browser

**Symptom:** Browser shows "Your connection is not private" with issuer `(STAGING) Let's Encrypt`.

`CADDY_ACME_STAGING=true` was left in `.env`. Change it to `false`, then clear Caddy's certificate cache so it re-issues:
```bash
# Stop Caddy
docker compose -f deploy/docker-compose.yml stop caddy

# Remove cached staging certs from the caddy_data volume
docker run --rm -v hostyt-proxy-gateway_caddy_data:/data alpine \
  find /data/caddy/certificates -type f -name '*.crt' -delete

# Start Caddy again
docker compose -f deploy/docker-compose.yml --env-file .env up -d caddy
```

---

## 3. Host shows "SSL pending" forever

### DNS not yet propagated

The On-Demand TLS flow: browser hits Caddy -> Caddy calls `/internal/ask` -> app checks domain is registered -> Caddy requests cert from Let's Encrypt -> Let's Encrypt makes HTTP-01 challenge back to the domain.

If the domain's A record does not yet point at the node's public IP, the HTTP-01 challenge fails silently and the host stays in `ssl_pending`.

**Check from the server (not your local machine):**
```bash
dig +short yourdomain.example.com
# should return the node's public IP
```

Also verify the `/internal/ask` endpoint reaches the app:
```bash
curl -sf "http://localhost:8080/internal/ask?domain=yourdomain.example.com"
# expected: HTTP 200 (allowed) or 403 (domain not registered / not pointing here)
```

### Let's Encrypt rate limit hit

**Symptom:** Caddy logs contain:
```
too many certificates already issued for exact set of domains
```

Let's Encrypt limits 5 duplicate certificates per 7 days and 50 new certs per registered domain per week. Use `CADDY_ACME_STAGING=true` during bulk testing. In production, wait for the rate limit window to expire or use `DNS01_AVAILABLE=1` with a DNS provider API key for wildcard certs.

### Wrong IP on the host record

In **Admin -> Hosts**, the node field must match the Caddy node whose IP the domain points at. If the host is assigned to Node A but the DNS A record points at Node B, Let's Encrypt will never reach the right node for the challenge.

---

## 4. Caddy node shows offline

### WireGuard not connected (remote nodes)

The panel reaches remote nodes via their WireGuard IP (e.g. `10.66.0.2:2019`). If WireGuard is down, all Admin API calls time out and the node shows offline.

**On the manager host:**
```bash
sudo wg show wg0
# should list the remote peer with a recent "latest handshake"
```

**On the remote node:**
```bash
sudo wg show wg0
sudo wg show wg0 transfer   # confirm traffic is flowing
```

If no handshake: check that UDP 51820 is open on the manager's firewall, the node's public endpoint is correct in **Settings -> WireGuard**, and the join token was redeemed (not expired).

### Caddy Admin API unreachable

**On the manager, for the local bundled Caddy:**
```bash
curl -sf http://localhost:2019/config/ | head -c 200
# 2019 is internal-only; run from inside the container or the host
docker exec $(docker ps -qf name=caddy) curl -sf http://localhost:2019/config/
```

**For a remote node (from the manager, over WireGuard):**
```bash
curl -sf http://10.66.0.2:2019/config/ | head -c 200
```

`connection refused` means the Caddy container on that node is not running. SSH to the node and check:
```bash
docker compose -f /opt/hostyt-node/docker-compose.yml ps
docker compose -f /opt/hostyt-node/docker-compose.yml logs caddy --tail=30
```

---

## 5. Node join fails

### Token expired

Join tokens have a 30-minute TTL. If the `curl | bash` command was run more than 30 minutes after the token was generated, the join script exits with:
```
Error: join token expired or invalid
```

**Fix:** Go to **Admin -> Caddy nodes -> Auto-join -> Generate join command** and generate a new token. Run the new command immediately.

### Firewall blocking WireGuard

After the join script runs, the new node sends a WireGuard handshake to the manager on UDP 51820. If the manager's firewall drops inbound UDP 51820 from the node's public IP, the peer never connects.

**Check on the manager:**
```bash
sudo ufw status | grep 51820
# or
sudo iptables -L INPUT -n | grep 51820
```

**Allow if missing (ufw example):**
```bash
sudo ufw allow 51820/udp
```

Also confirm the node's own firewall allows outbound UDP 51820.

---

## 6. 2FA locked out

### Recovery codes

During 2FA enrollment the panel displays 8 one-time recovery codes. Each code is single-use and bypasses the TOTP requirement. Use one on the login screen by entering it in place of the 6-digit code.

Recovery codes are stored in the database (table `totp_recovery_codes`). If you did not save them:

**Super-admin break-glass procedure (requires DB access):**

```bash
# Open a MariaDB shell
docker exec -it $(docker ps -qf name=mariadb) mysql -u root -p hostyt_proxy

-- Find the locked-out user
SELECT id, email FROM users WHERE email = 'admin@example.com';

-- Disable 2FA for that user (lets them log in, then re-enroll)
UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE email = 'admin@example.com';
DELETE FROM totp_recovery_codes WHERE user_id = <id from above>;
```

After logging in, re-enroll 2FA immediately and save the new recovery codes.

### REQUIRE_ADMIN_2FA enforcement locked everyone out

If `REQUIRE_ADMIN_2FA=1` was set without `REQUIRE_ADMIN_2FA_GRACE_HOURS` and no admin has 2FA enrolled:

**Fix:** Set `REQUIRE_ADMIN_2FA=0` in `.env` and restart the app container, log in, enroll 2FA on all admin accounts, then re-enable:
```bash
docker compose -f deploy/docker-compose.yml --env-file .env up -d app
```

---

## 7. Database migration failed

### Goose error on startup

Migrations run automatically via the embedded goose runner. Errors appear in app logs:
```
goose: failed to migrate db: ERROR 1091 (42000): Can't DROP 'idx_foo'; check that it exists
```
or
```
goose: migration 0031_some_table.sql: pq: column "foo" of relation "bar" already exists
```

**Check current migration state:**
```bash
docker exec $(docker ps -qf name=mariadb) \
  mysql -u root -p hostyt_proxy -e "SELECT version_id, is_applied, tstamp FROM goose_db_version ORDER BY id DESC LIMIT 10;"
```

**Common causes and fixes:**

- **Migration applied twice:** Goose tracks applied migrations in `goose_db_version`. If a migration file was renamed or its checksum changed, goose may try to re-apply it. Do not rename migration files after they have been applied.
- **Manual schema change conflicts:** If you modified the schema manually (e.g., added an index that a migration also adds), drop the conflicting object and restart.
- **Dirty migration state:** A partially applied migration leaves the DB in an inconsistent state. Restore from backup (see [`DEPLOY.md` § Backup](DEPLOY.md#6-backup)), or fix the schema manually and mark the migration as applied:
  ```bash
  docker exec -it $(docker ps -qf name=mariadb) mysql -u root -p hostyt_proxy
  -- After manually applying the migration:
  INSERT INTO goose_db_version (version_id, is_applied) VALUES (31, 1);
  ```

---

## 8. Redis overcommit warning

Redis may log this warning during container startup:

```
WARNING Memory overcommit must be enabled!
```

Redis still starts, but background saves or replication can fail under memory pressure. This is a Linux host kernel setting, not an application setting. Fix it on the Docker host:

```bash
sudo sysctl -w vm.overcommit_memory=1
echo 'vm.overcommit_memory = 1' | sudo tee /etc/sysctl.d/99-hostyt-redis.conf
sudo sysctl --system
```

Then restart the Redis container:

```bash
docker compose -f deploy/docker-compose.yml restart redis
```

---

## 9. Useful diagnostic commands

### View logs

```bash
# All services
docker compose -f deploy/docker-compose.yml logs -f --tail=100

# Single service
docker compose -f deploy/docker-compose.yml logs -f app --tail=100
docker compose -f deploy/docker-compose.yml logs -f caddy --tail=100
docker compose -f deploy/docker-compose.yml logs -f mariadb --tail=50
```

### App container shell (distroless - no shell available)

The app image is distroless; `docker exec ... sh` will fail. Use `curl` or `wget` from within the container via an ephemeral debug container on the same network:

```bash
docker run --rm --network hostyt-proxy-gateway_internal \
  curlimages/curl curl -sf http://app:8080/healthz
```

Or run diagnostic commands against the exposed port:
```bash
curl -sf http://localhost:8080/healthz && echo OK
curl -sf http://localhost:8080/internal/ask?domain=test.example.com
```

### MariaDB shell

```bash
docker exec -it $(docker ps -qf name=mariadb) mysql -u hostyt -p hostyt_proxy
```

### Check WireGuard mesh status

```bash
# On the manager host (host network, outside Docker)
sudo wg show wg0

# Full peer table including last handshake and transfer bytes
sudo wg show wg0 dump
```

A peer with `latest handshake: X seconds ago` less than 3 minutes is connected. A peer with no handshake or a very old one is disconnected - check the node.

### Caddy config currently loaded

```bash
# From the manager host (Caddy admin is internal; use the container)
docker exec $(docker ps -qf name=caddy) \
  wget -qO- http://localhost:2019/config/ | python3 -m json.tool | head -80
```

### Caddy health on a remote node (over WireGuard)

```bash
curl -sf http://10.66.0.2:2019/config/ | python3 -m json.tool | head -20
# replace 10.66.0.2 with the node's WireGuard IP
```

### Force a Caddy config resync

From the panel UI: **Admin -> Caddy nodes -> (node) -> Sync**. This re-pushes the full config from the DB to that node's Admin API.

To trigger it from the command line (with an API key from **Admin -> API keys**):
```bash
curl -X POST https://panel.example.com/api/v1/nodes/<node-id>/resync \
  -H "Authorization: Bearer <api-key>"
```
