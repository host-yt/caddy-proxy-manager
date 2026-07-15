# Multi-Node Deployment and WireGuard Mesh

This guide covers adding remote Caddy nodes to a Hostyt Proxy Gateway manager
and explains how the control plane communicates with them.

---

## 1. Overview

Every Caddy node exposes its Admin API on port 2019. That port must never be
reachable from the public internet - it accepts JSON config pushes with no
per-request auth. The control plane therefore communicates exclusively through a
WireGuard mesh:

- Manager gets a private WG IP (`10.66.0.1` by default).
- Each remote node gets a unique private WG IP (`10.66.0.2`, `.3`, etc.).
- Caddy Admin API on every node binds to its WG IP only, never to
  `0.0.0.0`.
- All `/load`, `/config`, `/reverse_proxy` and metrics calls from the manager
  travel over the encrypted WG tunnel, not over the public internet.
- Public traffic (HTTP/HTTPS) arrives at the node directly; WG carries
  control-plane traffic only.

The manager runs a WireGuard sidecar container (`deploy/wireguard/`) in the
host network namespace. When a node joins, the sidecar re-reads `wg0.conf` and
calls `wg syncconf` - no interface restart, no dropped sessions.

Node pools/nodes are platform-global infrastructure managed only by platform
admins (gated by `requireGlobalAPIAdmin`), not reseller-scoped - reseller-admins
cannot manage nodes or the WireGuard mesh.

---

## 2. Network Topology

```
Internet
   |  (80/443 TCP+UDP - public traffic)
   |
+--+-----------------------------------------------------------+
|  Remote VPS A (fra.proxy.example.com)                        |
|  ┌────────────────────┐   ┌──────────────────────────────┐   |
|  │  Caddy 2.x         │   │  hpg-node-agent sidecar      │   |
|  │  :80, :443, :443u  │   │  wg-tun0  (customer tunnels) │   |
|  │  Admin: 10.66.0.2: │   └──────────────────────────────┘   |
|  │         2019  ───────────────────────────────────────┐     |
|  └────────────────────┘                                 │     |
|       wg0  10.66.0.2/24  <── WG UDP 51820 ──>           │     |
+------------------------------------------------------ ──┼────+
                                                          │
                        WireGuard mesh (encrypted)        │
                        AllowedIPs 10.66.0.0/24           │
                                                          │
+----------------------------------------------------------┼────+
|  Manager VPS (manager.example.com)                       │    |
|  ┌───────────────┐  ┌──────────────────┐                 │    |
|  │  HPG app      │  │  WG sidecar      │                 │    |
|  │  :8080        │  │  host-network    │                 │    |
|  │  DB + Redis   │  │  wg0 10.66.0.1  ◄────────────────-┘    |
|  └───────────────┘  └──────────────────┘                      |
|  UDP :51820 open inbound (WireGuard listen port)              |
+---------------------------------------------------------------+

Control-plane flows (all inside WG tunnel):
  Manager → 10.66.0.2:2019  Caddy Admin API  (config push, /load)
  Manager → 10.66.0.2:2019  Prometheus /metrics scrape
  10.66.0.2 → 10.66.0.1:8080  /internal/ask  (On-Demand TLS gate)
  10.66.0.2 → 10.66.0.1:8080  node-agent stats POST
```

---

## 3. Prerequisites for a Remote Node

**Operating system:** Ubuntu 22.04 LTS or later (or any distro with apt-get and
WireGuard kernel support). The join script auto-installs all dependencies.

**Firewall rules required on the remote node:**

| Port | Proto | Direction | Purpose |
|------|-------|-----------|---------|
| 80   | TCP   | inbound   | HTTP (Let's Encrypt challenge + plain traffic) |
| 443  | TCP   | inbound   | HTTPS |
| 443  | UDP   | inbound   | HTTP/3 (QUIC) |

**Firewall rules required on the manager:**

| Port | Proto | Direction | Purpose |
|------|-------|-----------|---------|
| 51820 | UDP | inbound | WireGuard - nodes connect to the manager |

The node does NOT need UDP 51820 open for inbound; it initiates the WG
handshake outward and uses PersistentKeepalive to keep the tunnel alive through
NAT.

**The node does NOT need a public IP assigned by the manager** - it can be
behind NAT as long as it can reach `manager-endpoint:51820` outbound.

---

## 4. Enable WireGuard on the Manager

This step is required once, before any node can join.

1. Log in to the admin panel.
2. Go to **Settings -> WireGuard**.
3. Toggle **Enable WireGuard mesh** on.
4. Set **Public endpoint** to the manager's publicly reachable address and WG
   port, e.g. `manager.example.com:51820`.
5. Optionally adjust **Subnet** (default `10.66.0.0/24`) and **Listen port**
   (default `51820`). Leave these at defaults unless you have a conflict.
6. Click **Save**.

On first save the panel generates a Curve25519 keypair in pure Go (no shell
call to `wg`). The private key is AES-256-GCM encrypted before being stored in
the `settings` table. The public key is stored in plaintext and shown in the
UI for out-of-band verification.

7. Start the WireGuard sidecar profile on the manager if it is not already
   running:

```bash
docker compose -f deploy/docker-compose.yml --env-file .env --profile mesh up -d
```

The sidecar container (`deploy/wireguard/`) runs in the host network namespace,
requires `NET_ADMIN`, and loops every 10 seconds watching `wg0.conf` for
changes. When the file changes (e.g. after a node joins) it calls:

```bash
wg syncconf wg0 <(wg-quick strip /config/wg0.conf)
```

This adds or removes peers without tearing down the interface.

---

## 5. Add a Remote Caddy Node (Auto-Join)

### 5.1 Generate a join token

1. Go to **Admin -> Caddy nodes**.
2. Click **Auto-join -> Generate join command**.
3. Select (or create) a **node group** and optionally set a **name hint**,
   **max routes**, and **priority**.
4. Click **Generate**.

The panel mints a one-time token with the prefix `hpg_join_` (24 random bytes,
base64url-encoded; stored as a SHA-256 hash). The token expires in **30 minutes**
and can only be used once.

The UI displays a complete `curl | sudo bash` command, e.g.:

```bash
curl -fsSL https://panel.example.com/install/node.sh | sudo bash -s -- \
  --manager https://panel.example.com \
  --token   hpg_join_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

Optional flags you can append:

```
--public-hostname fra.proxy.example.com  # sets caddy_nodes.public_hostname
--public-ip       203.0.113.10           # sets caddy_nodes.public_ip
--install-dir     /opt/hostyt-node       # default: /opt/hostyt-node
```

### 5.2 Run the command on the VPS

Paste the command on the new VPS as root (or with sudo). After it completes:

1. Go back to **Admin -> Caddy nodes**.
2. Find the new node (status: **pending**, health: **unknown**).
3. Verify the **fingerprint** (first 16 chars of the node's WG public key)
   matches what the script printed.
4. Click **Approve**.

Until approved, the node receives no route placements and is excluded from the
load-balancer scheduler. This prevents a stolen join token from immediately
carrying customer traffic.

5. After approval, click **Resync** to push the first Caddy config.

---

## 6. What the Join Script Does (Step by Step)

Source: `scripts/node-join.sh`

### Step 1 - Check and install dependencies

Checks for `wg`, `wg-quick`, `docker`, `curl`, `jq`. If any are missing and
`apt-get` is available, installs them:

```bash
apt-get install -y wireguard wireguard-tools curl jq ca-certificates docker.io
```

Docker comes from the distro repo (`docker.io`), not `get.docker.com | sh`.

Fails fast with an error on non-apt distros.

### Step 2 - Register with the manager

POSTs to `$MANAGER/api/v1/nodes/join`:

```json
{
  "token": "hpg_join_...",
  "public_hostname": "fra.proxy.example.com",
  "public_ip": "203.0.113.10"
}
```

The manager:
- Validates and burns the token (atomic SQL transaction, `FOR UPDATE` lock).
- Generates a fresh Curve25519 keypair for this node.
- Allocates the next unused IP from the WG subnet (linear scan of
  `caddy_nodes.wg_ip`, starts at `.2`).
- Inserts a `caddy_nodes` row with `is_enabled=0` and `health_status='unknown'`.
- Re-renders and atomically writes `/config/wg0.conf` with the new `[Peer]`
  block (via temp-file + rename). The sidecar picks it up within ~10 seconds.
- Returns a JSON bootstrap payload.

The response includes:

```json
{
  "node_id": 3,
  "node_name": "fra-proxy",
  "fingerprint": "AbCdEfGh01234567",
  "wireguard": {
    "interface_address": "10.66.0.3/24",
    "private_key": "<node private key - shown once>",
    "peer": {
      "public_key": "<manager public key>",
      "endpoint": "manager.example.com:51820",
      "allowed_ips": "10.66.0.1/32",
      "persistent_keepalive": 25
    }
  },
  "caddy": {
    "admin_listen": "10.66.0.3:2019",
    "ask_endpoint_url": "http://10.66.0.1:8080/internal/ask",
    "acme_email": "ops@example.com"
  }
}
```

### Step 3 - Write WireGuard config

Writes `/etc/wireguard/wg0.conf`:

```ini
[Interface]
Address    = 10.66.0.3/24
PrivateKey = <node private key>

[Peer]
PublicKey  = <manager public key>
Endpoint   = manager.example.com:51820
AllowedIPs = 10.66.0.1/32
PersistentKeepalive = 25
```

`AllowedIPs = 10.66.0.1/32` routes only the manager's WG IP through the
tunnel; all other traffic (public) goes via the default route.

Brings up the interface:

```bash
systemctl enable --now wg-quick@wg0
# or, if systemctl is unavailable:
wg-quick up wg0
```

### Step 4 - Write Caddy compose and Caddyfile

Creates `/opt/hostyt-node/docker-compose.yml` binding Caddy's Admin API to the
WG IP only:

```
- "10.66.0.3:2019:2019"   # WG IP only - never public
- "80:80"
- "443:443"
- "443:443/udp"
```

Creates `/opt/hostyt-node/Caddyfile.bootstrap`:

```caddyfile
{
    admin 10.66.0.3:2019
    email ops@example.com
    on_demand_tls {
        ask http://10.66.0.1:8080/internal/ask
    }
}

:80 {
    respond "Hostyt Proxy node fra-proxy - awaiting routes from control plane" 503
}
```

This bootstrap config is superseded as soon as the manager pushes the first
JSON config via `/load` to `http://10.66.0.3:2019`.

### Step 5 - Start Caddy

```bash
docker compose -f /opt/hostyt-node/docker-compose.yml up -d
```

### Step 6 - Print summary

Prints node ID, name, WG address, and the Admin API URL. If the manager-side
WG sidecar was not running, the script prints the `[Peer]` block you need to
add manually (see Section 7).

---

## 7. Manual Node Setup (Alternative)

Use this if `curl | bash` is not permitted on your VPS, or if you want to
verify every step.

### 7.1 Install WireGuard and Docker

```bash
apt-get update
apt-get install -y wireguard wireguard-tools curl jq docker.io
```

### 7.2 Register the node

```bash
curl -fsSL -X POST https://panel.example.com/api/v1/nodes/join \
  -H 'Content-Type: application/json' \
  -d '{"token":"hpg_join_...","public_hostname":"fra.proxy.example.com"}'
```

Save the entire JSON response; you will need fields from it in subsequent steps.

### 7.3 Write WireGuard config

```bash
mkdir -p /etc/wireguard && chmod 700 /etc/wireguard
cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address    = <wireguard.interface_address>
PrivateKey = <wireguard.private_key>

[Peer]
PublicKey  = <wireguard.peer.public_key>
Endpoint   = <wireguard.peer.endpoint>
AllowedIPs = <wireguard.peer.allowed_ips>
PersistentKeepalive = 25
EOF
chmod 600 /etc/wireguard/wg0.conf
systemctl enable --now wg-quick@wg0
```

Verify the tunnel is up:

```bash
wg show wg0
ping -c3 10.66.0.1   # should reach the manager
```

### 7.4 Write Caddy compose

Create `/opt/hostyt-node/docker-compose.yml` using the template from
`deploy/remote-node/docker-compose.yml`. Change the Admin API bind address to
this node's WG IP:

```yaml
ports:
  - "10.66.0.X:2019:2019"   # replace X with this node's last octet
  - "80:80"
  - "443:443"
  - "443:443/udp"
```

Also set the `internal` network subnet if you need WSS transport (see Section 8):

```yaml
networks:
  internal:
    driver: bridge
    ipam:
      config:
        - subnet: 172.18.0.0/16
          gateway: 172.18.0.1
```

And add the `extra_hosts` entry so Caddy can reach wstunnel on the host:

```yaml
extra_hosts:
  - "host.docker.internal:172.18.0.1"
```

### 7.5 Write bootstrap Caddyfile

```bash
cat > /opt/hostyt-node/Caddyfile.bootstrap <<EOF
{
    admin 10.66.0.X:2019
    email <caddy.acme_email>
    on_demand_tls {
        ask <caddy.ask_endpoint_url>
    }
}

:80 {
    respond "Hostyt Proxy node - awaiting routes from control plane" 503
}
EOF
```

### 7.6 Start Caddy

```bash
cd /opt/hostyt-node && docker compose up -d
```

### 7.7 Update manager WG config (if sidecar was not running)

If the join response included a `manager_note` with a `[Peer]` block, append it
to the manager's WG config and reload without dropping sessions:

```bash
# On the manager VPS:
cat >> /path/to/wg/wg0.conf <<EOF

# Node #3 (fra-proxy)
[Peer]
PublicKey  = <node public key>
AllowedIPs = 10.66.0.3/32
EOF

wg syncconf wg0 <(wg-quick strip /path/to/wg/wg0.conf)
```

---

## 8. WSS Tunnel Transport

By default the control-plane WG mesh uses plain UDP 51820. Migration `00051`
added a `tunnel_transport` column on `caddy_nodes` with values `udp`, `wss`,
and `auto`.

When `tunnel_transport = 'wss'` (or `'auto'` when UDP is detected as blocked),
the `hpg-node-agent` sidecar starts a `wstunnel` server on the node and
the manager connects to it over WebSocket-over-TLS (port configurable via
`tunnel_wstunnel_port`). This lets WG traffic traverse environments that block
UDP entirely (strict corporate firewalls, some cloud providers).

The node-agent image (`deploy/node-agent/Dockerfile`) bundles `wstunnel`
(version 10.5.5, pinned sha256 per arch). It is enabled via environment
variable:

```yaml
HPG_TUNNEL_TRANSPORT: "wss"     # or "auto"
HPG_WSTUNNEL_PORT: "51823"      # loopback port for the wstunnel server
```

The panel gates the WSS option on `tunnel_wstunnel_healthy = 1` being reported
by the node-agent; it will not offer WSS for a node whose agent has not
confirmed wstunnel is healthy.

DB invariant (enforced by `chk_wstunnel_port` CHECK constraint):
`tunnel_transport = 'wss'` requires `tunnel_wstunnel_port IS NOT NULL`.

**Note:** WSS transport is for the customer-VPN tunnel (`wg-tun0`). The
control-plane mesh (`wg0`) still uses UDP 51820 between manager and nodes.
These are two separate WG interfaces with separate purposes.

---

## 9. HA / Failover (Node Groups)

Migration `00003_node_join.sql` introduced `node_join_tokens.node_group_id`.
Every node belongs to a **node group** (table `node_groups`). Hosts can be
assigned to a group; when a group has multiple nodes the scheduler distributes
new host placements across them using `caddy_nodes.priority` and route counts.

Migration `00022_wg_ha_group.sql` added `customer_wg_peer.peer_group_id`
(CHAR(36)), allowing a set of WG peers to be treated as a logical unit for
failover. When one peer in the group becomes unreachable, traffic can be routed
to another peer in the same group without requiring manual intervention.

**Current behavior:**
- Route fan-out: a route on an `active_active` (or `failover`) node group is
  compiled and pushed to **every** node in the group, not just the one matching
  `routes.caddy_node_id`. Each peer receives the identical `reverse_proxy`
  payload (`routes: 1`). (Before 1.4.0 only the anchor node got the route and
  peers answered an empty `NOP` - fixed in #3.)
- Route placement: manager picks the node in the group with the fewest active
  routes, weighted by `caddy_nodes.priority`.
- Node health is tracked in `caddy_nodes.health_status`. The metrics scraper
  updates it from Caddy's Prometheus endpoint.
- `fwd_ip_forward_enabled` and related columns (migration `00050`) surface
  whether IP forwarding and iptables/nftables rules are correctly set on each
  node.

**Automatic failover** is implemented. When `failover.auto_enabled` is set
(`Admin → Settings → Failover`), the alert evaluator moves active routes from
a dead node to a healthy sibling in the same `mode=failover` node group and
triggers a Caddy resync on the sibling. Each moved route is recorded in the
audit log as `node.failover.route_moved`. A dry-run preview of what would be
moved is available at `GET /admin/nodes/{id}/failover-preview` (shown on the
node detail page).

---

## 10. Troubleshooting

### WireGuard handshake not established

**Symptom:** `wg show wg0` on the node shows `latest handshake: (none)`.

1. Check that the manager's UDP 51820 is reachable from the node:
   ```bash
   nc -zu manager.example.com 51820 && echo "open" || echo "blocked"
   ```

2. Check the manager's WG interface is up:
   ```bash
   # On manager:
   wg show wg0
   ```
   If the interface is missing, the sidecar container may not be running:
   ```bash
   docker compose -f deploy/docker-compose.yml ps
   docker compose -f deploy/docker-compose.yml --profile mesh up -d
   ```

3. Check whether the node's public key appears in the manager's peer list:
   ```bash
   # On manager:
   wg show wg0 peers
   ```
   If it is missing, the manager-side WG config was not rewritten after join.
   Go to **Admin -> Caddy nodes -> {node} -> Apply WG config** or manually
   append the `[Peer]` block and call `wg syncconf` (see Section 7.7).

4. On Oracle Cloud: the default iptables policy is `INPUT DROP`. Add:
   ```bash
   iptables -I INPUT -p udp --dport 51820 -j ACCEPT
   # Make persistent:
   apt-get install -y iptables-persistent
   netfilter-persistent save
   ```

### Node shows offline in the panel

1. Verify WG handshake is up (step above).
2. Check the Caddy Admin API is reachable from the manager over WG:
   ```bash
   # On manager:
   curl http://10.66.0.X:2019/config/
   ```
   `connection refused` - Caddy is not running on the node, or it is bound to
   the wrong IP.
3. Check Caddy is running on the node:
   ```bash
   # On node:
   cd /opt/hostyt-node && docker compose ps
   docker compose logs caddy
   ```
4. Confirm the Admin API bind in `Caddyfile.bootstrap` matches the node's WG
   IP. It must be `admin 10.66.0.X:2019`, not `admin localhost:2019` or
   `admin :2019`.

### Node is approved but receives no routes / domains return 503

1. The bootstrap Caddyfile is still active - the manager has not pushed a JSON
   config yet. Click **Resync** on the node in the admin UI.
2. If resync fails, check the manager application logs for the error. Common
   causes: WG tunnel down, Caddy Admin API returning 4xx/5xx, or a malformed
   JSON config (check the `caddyapi` logs).

### DNS not resolving on the node (On-Demand TLS fails)

The Caddy `on_demand_tls` gate calls `/internal/ask` on the manager via the WG
tunnel. If the manager is unreachable at `10.66.0.1:8080` from inside the
Caddy container, On-Demand TLS will refuse all new certificates.

1. Test from inside the Caddy container:
   ```bash
   docker exec <caddy-container> wget -qO- http://10.66.0.1:8080/internal/ask?domain=test.example.com
   ```
   Expected: `{"allow":true}` or `{"allow":false}` (either is fine - `{"error":...}` or a timeout is not).

2. If unreachable: the Docker bridge gateway may not route to the WG interface.
   The `remote-node/docker-compose.yml` pins the bridge to `172.18.0.0/16` with
   gateway `172.18.0.1` and uses `extra_hosts: host.docker.internal:172.18.0.1`
   so Caddy can reach the host's `wg0`. Verify the subnet is not in use by
   another Docker network:
   ```bash
   docker network ls
   docker network inspect bridge
   ```

3. If the bridge gateway is correct but traffic still does not reach `wg0`,
   check `ip_forward`:
   ```bash
   sysctl net.ipv4.ip_forward
   # Must be 1. Enable permanently:
   echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf && sysctl -p
   ```

### wg syncconf fails silently after a new node joins

The manager-side sidecar logs to Docker. Check:

```bash
docker logs <wg-sidecar-container-name>
```

If it reports `syncconf failed, will retry next tick`, check that the config
file is not empty (the app writes atomically via temp-file + rename; a partial
write cannot cause a corrupt file but a missing keypair can cause the render to
fail). Confirm WireGuard settings are saved: **Settings -> WireGuard** should
show a public key.

### Peer stats not updating

The `customer_wg_peer` table tracks `rx_bytes`, `tx_bytes`,
`last_handshake_epoch`, and `endpoint` (migration `00036`). These are updated
by the `hpg-node-agent` stats POST. If they stay at 0:

1. Confirm `hpg-node-agent` is running on the node:
   ```bash
   docker ps | grep hpg-node-agent
   ```
2. Check agent logs:
   ```bash
   docker logs <hpg-node-agent-container>
   ```
3. Verify `HPG_NODE_TOKEN` and `HPG_PANEL_URL` are set correctly in the
   node-agent environment (from `deploy/node-agent/docker-compose.example.yml`).

### Cleared WAF / access events keep reappearing

After clearing events in the panel, old events flood back on the next
node-agent restart.

Cause: the agent persists its log read offset to a `.hpgpos` sidecar, but the
Caddy log volume is mounted read-only, so the write fails silently and every
restart re-reads the whole log from the start and re-ships it.

Fix (per node):

1. Give the agent a writable state dir and point it there:
   ```yaml
   hpg-node-agent:
     environment:
       HPG_AGENT_STATE_DIR: /var/lib/hpg-node-agent
     volumes:
       - caddy_logs:/var/log/caddy:ro          # keep logs read-only
       - node_agent_state:/var/lib/hpg-node-agent   # writable offset store
   # ...
   volumes:
     node_agent_state:
   ```
2. Redeploy the node-agent, then clear events once - they stay cleared.

The bundled composes (`deploy/docker-compose.yml`, `deploy/portainer-external-db.yml`,
`deploy/node-agent/docker-compose.example.yml`) already include this; only custom
stacks need the manual edit. The panel side is also idempotent (a `waf_seen_events`
ledger drops replays), so this only affects efficiency once the offset persists.

---

## 11. Colocated Panel + Edge (Single Host)

Running the panel and its Caddy edge on the **same** box, with that Caddy
carrying real customer traffic, is a supported, default topology - not a
workaround. Everything below already happens when you deploy
`deploy/docker-compose.yml` (or `docker-compose.lite.yml`) and complete the
install wizard; there is no separate "colocated" compose file or wizard step.

### 11.1 Why this needed calling out

Sections 1-10 of this guide describe adding **remote** nodes over a
WireGuard mesh, which can read as "a Caddy node always lives on its own
host, reachable only via WireGuard." That's true for remote nodes, but the
panel's own bundled `caddy` service never goes through that path:

- `deploy/docker-compose.yml` binds `caddy` to `80`, `443`, `443/udp` and
  binds `app` to `127.0.0.1:8080` only (loopback).
- The install wizard's Caddy step defaults `api_url` to `http://caddy:2019`
  - the compose service name, reached over the plain `internal` Docker
  bridge network, no WireGuard involved - and inserts it as the first row
  in `caddy_nodes`.
- On success the wizard pushes a self-bootstrap route for the panel's own
  hostname to that node (`internal/domain/routes.Service.panelRoute`,
  `internal/httpserver/handlers/wizard.go` `CaddySubmit` -> `ResyncNode`),
  so `https://<panel-domain>` works immediately.
- That route is synthesized at config-build time, not stored as a `hosts`
  row, so it never shows up in (and can't be deleted from) the normal Hosts
  UI - it is effectively a protected system route already.

From here, node-1 is a normal node: create Hosts and pick it as the target
like any other. If an operator instead reaches for
`deploy/remote-node/docker-compose.yml` (built for a **separate**,
WireGuard-tunneled VPS) and runs it on this same box, it binds the same
80/443/443-udp ports the panel's own `caddy` already holds and fails to
start - the likely reason anyone concluded "the panel host can't also be a
traffic node" and re-deployed split.

### 11.2 Port layout (single host)

| Port | Bind | Service | Purpose |
|------|------|---------|---------|
| 80 | `0.0.0.0` | `caddy` | HTTP, ACME HTTP-01 challenge, customer + panel traffic |
| 443/tcp | `0.0.0.0` | `caddy` | HTTPS, customer + panel traffic |
| 443/udp | `0.0.0.0` | `caddy` | HTTP/3 (QUIC) |
| 2019 | `internal` bridge only (never published) | `caddy` | Admin API; panel reaches it at `http://caddy:2019` |
| 8080 | `127.0.0.1` (loopback) | `app` | Panel UI; reached only through caddy's self-bootstrap route |
| 3306 | `internal` bridge only | `mariadb` | Database |
| 6379 | `internal` bridge only | `redis` | Sessions, rate limits, cache |
| 51820/udp | manager host, public | `wireguard` sidecar (`--profile mesh`) | Control-plane WG mesh - only if you also add remote nodes later |
| 51821/udp (default) | host network | `hpg-node-agent` (`--profile node`) | Customer VPN tunnel (`wg-tun0`), unrelated to the mesh above |

`docker compose -f deploy/docker-compose.yml --env-file .env up -d` starts
`app`, `mariadb`, `redis`, `caddy`; the `node` and `mesh` profiles stay off
until you opt in (see `docs/DEPLOY.md`).

### 11.3 Growing into multi-node later

Adding remote nodes afterwards (Sections 3-7) doesn't touch this host's
setup - node-1 keeps serving both the panel and whatever customer Hosts are
assigned to it. One caveat: the panel's self-bootstrap route uses a single
global upstream (`APP_INTERNAL_HOST`/`APP_INTERNAL_PORT`, default
`app:8080`) that is pushed to **every** node in the fleet, including remote
ones. Remote nodes can't resolve `app` (it's a Docker service name on the
manager's own bridge network), so they receive a harmless, unreachable copy
of that route. This only matters if the panel's own hostname's DNS is ever
pointed at a remote node instead of the local one, which isn't the
supported pattern.

### 11.4 Re-adding the local node manually

If a pre-existing install predates the wizard's self-registration, or
node-1 was deleted, register it the same way as any manual node - no
WireGuard needed since it shares the `internal` Docker network with the
panel:

1. **Admin -> Caddy nodes -> Add node.**
2. Name: anything (e.g. `node-1`). API URL: `http://caddy:2019`. Public
   hostname: the panel's own domain (or leave for a customer domain).
3. Save, then click **Resync**.

### 11.5 Limitations

- **Upgrade note:** existing split deployments (panel and edge on separate
  hosts) are unaffected - this section describes the default single-host
  compose, nothing about remote-node deployments changed.
- **One Caddy per host owns 80/443.** You cannot run a second, independent
  Caddy container on the same host bound to the same ports - that's the
  `deploy/remote-node` conflict in 11.1, not a limit on how much traffic
  one Caddy can carry.
- **Panel restart is a config-push gap, not a traffic gap.** Caddy keeps
  serving its last-loaded config independently once the `app` container
  restarts or is briefly down; already-configured Hosts keep working. Only
  *new* route pushes and any on-demand-TLS `/internal/ask` calls that miss
  the Redis verdict cache queue until the panel is back.
