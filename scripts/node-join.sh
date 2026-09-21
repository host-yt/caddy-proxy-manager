#!/usr/bin/env bash
# Hostyt Proxy Gateway - remote Caddy node bootstrap.
#
#   curl -fsSL https://panel.example.com/install/node.sh | sudo bash -s -- \
#     --manager https://panel.example.com \
#     --token   hpg_join_xxxxxxxxxxxxxxxxxxxxxxxx
#
# Optional:
#     --public-hostname fra.proxy.example.com
#     --public-ip       203.0.113.10
#     --install-dir     /opt/hostyt-node
#     --wg-listen-port  51820   (only if something already owns that UDP port)
#
# Requires: bash, curl, jq, sudo (root), apt-get (or compatible distro).

set -euo pipefail

INSTALL_DIR="/opt/hostyt-node"
MANAGER=""
TOKEN=""
PUBLIC_HOSTNAME=""
PUBLIC_IP=""
# Mesh wg0 must have a FIXED source port: without ListenPort the kernel picks a
# fresh random one on every `wg syncconf`, the panel's learned peer endpoint
# goes stale, and panel->node packets are blackholed until the node's next
# PersistentKeepalive (<=25 s). 51820 is the mesh port on both ends; the
# customer tunnel is a different interface on 51821, wstunnel uses 51822/51823.
WG_LISTEN_PORT="51820"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manager)         MANAGER="$2"; shift 2 ;;
    --token)           TOKEN="$2"; shift 2 ;;
    --public-hostname) PUBLIC_HOSTNAME="$2"; shift 2 ;;
    --public-ip)       PUBLIC_IP="$2"; shift 2 ;;
    --install-dir)     INSTALL_DIR="$2"; shift 2 ;;
    --wg-listen-port)  WG_LISTEN_PORT="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,16p' "$0"
      exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -z "$MANAGER" || -z "$TOKEN" ]] && {
  echo "missing --manager or --token" >&2
  echo "usage: $0 --manager https://panel --token hpg_join_..." >&2
  exit 2
}
[[ "$WG_LISTEN_PORT" =~ ^[0-9]{1,5}$ ]] && [[ "$WG_LISTEN_PORT" -ge 1 ]] && [[ "$WG_LISTEN_PORT" -le 65535 ]] || {
  echo "invalid --wg-listen-port: $WG_LISTEN_PORT" >&2
  exit 2
}
[[ "$(id -u)" -ne 0 ]] && {
  echo "must run as root (re-run with sudo)" >&2
  exit 1
}

log()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mERR\033[0m %s\n' "$*" >&2; exit 1; }

# 1. Dependencies --------------------------------------------------------
log "Checking prerequisites"
need_apt=0
command -v wg          >/dev/null 2>&1 || need_apt=1
command -v docker      >/dev/null 2>&1 || need_apt=1
command -v jq          >/dev/null 2>&1 || need_apt=1
command -v curl        >/dev/null 2>&1 || need_apt=1
command -v wg-quick    >/dev/null 2>&1 || need_apt=1

if [[ "$need_apt" -eq 1 ]]; then
  if command -v apt-get >/dev/null 2>&1; then
    log "Installing wireguard, docker, curl, jq via apt-get"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    # docker.io from the distro repo instead of piping a remote installer to root (supply-chain).
    apt-get install -y -qq wireguard wireguard-tools curl jq ca-certificates docker.io
    if ! command -v docker >/dev/null 2>&1; then
      die "docker install failed. Install Docker from your distro repo and re-run."
    fi
  else
    die "auto-install only supports apt-based distros. Install wg, docker, jq manually then re-run."
  fi
fi

# 2. Request bootstrap payload from the manager --------------------------
log "Asking $MANAGER to register this node"
payload=$(jq -n \
  --arg t "$TOKEN" --arg h "$PUBLIC_HOSTNAME" --arg i "$PUBLIC_IP" \
  '{token:$t, public_hostname:$h, public_ip:$i, supports_psk:true}')
resp=$(curl -fsS --max-time 30 \
  -H 'Content-Type: application/json' \
  -X POST "$MANAGER/api/v1/nodes/join" \
  -d "$payload") || die "manager rejected the join request - check token + URL"
# Strip CR defensively: a \r smuggled inside any JSON value (e.g. an endpoint
# pasted into the panel on Windows) corrupts wg0.conf, docker-compose.yml and
# the Caddyfile below ("Invalid handshake initiation" and friends).
resp=${resp//$'\r'/}

node_id=$(echo "$resp" | jq -r '.node_id')
node_name=$(echo "$resp" | jq -r '.node_name')
wg_addr=$(echo "$resp" | jq -r '.wireguard.interface_address')
wg_priv=$(echo "$resp" | jq -r '.wireguard.private_key')
peer_pub=$(echo "$resp" | jq -r '.wireguard.peer.public_key')
peer_ep=$(echo "$resp" | jq -r '.wireguard.peer.endpoint')
peer_allowed=$(echo "$resp" | jq -r '.wireguard.peer.allowed_ips')
peer_keepalive=$(echo "$resp" | jq -r '.wireguard.peer.persistent_keepalive')
# Mesh preshared key (post-quantum hardening). Absent on an older panel, in
# which case the peer block stays exactly as it was.
peer_psk=$(echo "$resp" | jq -r '.wireguard.peer.preshared_key // ""')
admin_listen=$(echo "$resp" | jq -r '.caddy.admin_listen')
ask_url=$(echo "$resp" | jq -r '.caddy.ask_endpoint_url')
acme_email=$(echo "$resp" | jq -r '.caddy.acme_email')
manager_note=$(echo "$resp" | jq -r '.manager_note // ""')

log "Registered as ${node_name} (id=${node_id}) on WG ${wg_addr}"

# 3. Write WireGuard config ----------------------------------------------
log "Writing /etc/wireguard/wg0.conf"
mkdir -p /etc/wireguard
chmod 700 /etc/wireguard
umask 077
cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address    = ${wg_addr}
ListenPort = ${WG_LISTEN_PORT}
PrivateKey = ${wg_priv}
# This node listens for its own keepalive only; no inbound clients on WG.

[Peer]
PublicKey  = ${peer_pub}
Endpoint   = ${peer_ep}
AllowedIPs = ${peer_allowed}
PersistentKeepalive = ${peer_keepalive}
EOF
# One malformed line makes `wg syncconf` reject the whole config. Joining
# without the key is not an option either: the panel already stored it and
# would render it on its own side, so the mesh would never handshake.
if [[ -n "$peer_psk" ]]; then
  [[ "$peer_psk" =~ ^[A-Za-z0-9+/]{43}=$ ]] \
    || die "manager returned a malformed preshared key - refusing to join with a half-applied key"
  echo "PresharedKey = ${peer_psk}" >> /etc/wireguard/wg0.conf
fi
chmod 600 /etc/wireguard/wg0.conf

log "Bringing up WireGuard"
systemctl enable --now wg-quick@wg0 || {
  warn "systemctl failed - trying wg-quick directly"
  wg-quick up wg0
}

# 4. Write Caddy compose + Caddyfile -------------------------------------
mkdir -p "$INSTALL_DIR/admin"

log "Writing $INSTALL_DIR/docker-compose.yml"
cat > "$INSTALL_DIR/docker-compose.yml" <<EOF
services:
  caddy:
    image: caddy:2.11.4
    restart: unless-stopped
    ports:
      # SEC-002: Caddy's admin API authenticates nothing, so whoever can route
      # to this address owns the node. Published on the WG address for the
      # legacy direct path; see the migration steps this script prints.
      - "${admin_listen}:2019"
      - "80:80"
      - "443:443"
      - "443:443/udp"
    volumes:
      - ./Caddyfile.bootstrap:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
      - caddy_config:/config
      # Shared with the node-agent: where Caddy puts its admin socket once
      # HPG_CADDY_ADMIN_LISTEN below is switched to the socket form.
      - ${INSTALL_DIR}/admin:${INSTALL_DIR}/admin
    environment:
      ASK_ENDPOINT_URL: "${ask_url}"
      ACME_EMAIL:       "${acme_email}"
      # Bootstrap bind. Socket form (no TCP port at all):
      #   unix/${INSTALL_DIR}/admin/caddy-admin.sock|0660
      HPG_CADDY_ADMIN_LISTEN: "0.0.0.0:2019"
volumes:
  caddy_data:
  caddy_config:
EOF

log "Writing $INSTALL_DIR/Caddyfile.bootstrap"
# admin binds 0.0.0.0 in the CONTAINER's namespace - the WG address lives on
# the host and cannot be bound from inside a bridge container. Reachability is
# decided by the port mapping above, not by this line.
cat > "$INSTALL_DIR/Caddyfile.bootstrap" <<EOF
{
	admin {\$HPG_CADDY_ADMIN_LISTEN:0.0.0.0:2019}
	email ${acme_email}
	on_demand_tls {
		ask ${ask_url}
	}
}

:80 {
	respond "Hostyt Proxy node ${node_name} - awaiting routes from control plane" 503
}
EOF

# 5. Start Caddy ---------------------------------------------------------
log "Starting Caddy container"
docker compose -f "$INSTALL_DIR/docker-compose.yml" up -d

# 6. Final instructions --------------------------------------------------
echo
log "Node bootstrap complete."
echo
echo "  Node ID:       ${node_id}"
echo "  Node name:     ${node_name}"
echo "  WG address:    ${wg_addr}"
echo "  Caddy Admin:   http://${admin_listen}/  (internal, WG-only)"
echo
if [[ -n "$manager_note" ]]; then
  warn "Manager-side step required:"
  echo "  $manager_note"
  echo
  warn "Until you complete that step the manager will not be able to reach this node's Admin API."
fi
echo
log "Open the admin UI → Caddy nodes → click 'resync' once handshake is up."
echo
warn "This node's Caddy Admin API is unauthenticated and reachable from the whole"
warn "control-plane mesh. Close it (docs/MULTI_NODE.md section 12):"
echo "  1. panel → node → Enable tunnel, copy HPG_ADMIN_PROXY_KEY"
echo "  2. run hpg-node-agent here with HPG_ADMIN_PROXY_LISTEN=${wg_addr%%/*}:2021"
echo "  3. panel → node → API URL = http://${wg_addr%%/*}:2021"
echo "  4. change the mapping above to \"127.0.0.1:2019:2019\" and restart Caddy"
echo "  5. optional, strongest: move the admin endpoint onto a socket so it has"
echo "     no TCP port at all - docs/MULTI_NODE.md#moving-a-node-off-the-tcp-admin-port"
