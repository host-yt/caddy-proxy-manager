#!/usr/bin/env bash
# Hostyt Proxy Gateway - install the mesh WireGuard preshared key on a node
# that joined before preshared keys existed.
#
#   curl -fsSL https://panel.example.com/install/node-psk.sh | sudo bash -s -- \
#     --panel https://panel.example.com \
#     --token <64-hex rekey token from the node detail page>
#
# Optional:
#     --interface wg0
#
# Idempotent: re-running with a fresh token replaces the key. wg0.conf is
# backed up first and restored if anything past the rewrite fails.
#
# Requires: bash, curl, jq, wg, wg-quick, root.

set -euo pipefail

PANEL=""
TOKEN=""
IFACE="wg0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --panel)     PANEL="$2"; shift 2 ;;
    --token)     TOKEN="$2"; shift 2 ;;
    --interface) IFACE="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,16p' "$0"
      exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

log()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mERR\033[0m %s\n' "$*" >&2; exit 1; }

[[ -n "$PANEL" && -n "$TOKEN" ]] || die "missing --panel or --token (usage: $0 --panel https://panel --token <hex>)"
[[ "$(id -u)" -eq 0 ]] || die "must run as root (re-run with sudo)"
[[ "$IFACE" =~ ^[a-zA-Z0-9_-]{1,15}$ ]] || die "invalid --interface"
PANEL="${PANEL%/}"

for bin in curl jq wg wg-quick; do
  command -v "$bin" >/dev/null 2>&1 || die "$bin not found - install wireguard-tools, curl and jq first"
done

CONF="/etc/wireguard/${IFACE}.conf"
[[ -f "$CONF" ]] || die "$CONF not found - is this a joined node?"

# 1. Fetch the staged key. This does not consume the token, so a transient
#    failure below can be retried with the same command.
log "Fetching the staged preshared key from $PANEL"
resp=$(curl -fsS --max-time 30 "${PANEL}/api/node/psk?t=${TOKEN}") \
  || die "panel refused the token (bad, expired, or already confirmed)"
psk=$(printf '%s' "$resp" | jq -r '.psk // ""')
# One malformed line makes `wg syncconf` reject the whole config, so validate
# the exact wire format (32 bytes, base64) before it reaches wg0.conf.
[[ "$psk" =~ ^[A-Za-z0-9+/]{43}=$ ]] || die "panel returned a malformed preshared key"

# 2. Back up, then rewrite every [Peer] to carry exactly this PSK.
backup="${CONF}.bak.$(date +%s)"
umask 077
cp -p "$CONF" "$backup"
chmod 600 "$backup"
log "Backed up $CONF to $backup"

tmp=$(mktemp "${CONF}.new.XXXXXX")
chmod 600 "$tmp"
# Drop any existing PresharedKey (idempotent re-run) and emit a fresh one
# right after each PublicKey.
awk -v psk="$psk" '
  /^[[:space:]]*PresharedKey[[:space:]]*=/ { next }
  { print }
  /^[[:space:]]*PublicKey[[:space:]]*=/    { print "PresharedKey = " psk }
' "$backup" > "$tmp"
grep -q '^PresharedKey = ' "$tmp" || { rm -f "$tmp"; die "no [Peer] PublicKey found in $CONF"; }
mv "$tmp" "$CONF"

rollback() {
  warn "Rolling back $CONF"
  cp -p "$backup" "$CONF"
  wg syncconf "$IFACE" <(wg-quick strip "$IFACE") || warn "rollback syncconf failed - run: wg-quick down $IFACE && wg-quick up $IFACE"
}

log "Applying the new config to interface $IFACE"
if ! wg syncconf "$IFACE" <(wg-quick strip "$IFACE"); then
  rollback
  die "wg syncconf failed"
fi

# 3. Tell the panel to switch its own side. Until this returns the panel is
#    still on the old key, so the mesh is only consistent again afterwards.
log "Confirming with the panel"
if ! curl -fsS --max-time 30 -X POST \
      -H "Authorization: Bearer ${TOKEN}" \
      "${PANEL}/api/node/psk/confirm" >/dev/null; then
  rollback
  die "panel confirm failed - the old key is back in place, re-run with a fresh token"
fi

# 4. WireGuard keeps the current session until the next handshake (120 s), so
#    a mismatch only shows up with a delay. Wait for proof, but never fail on
#    it: the config is already committed on both sides at this point.
log "Waiting for a fresh handshake (up to 130 s)"
start=$(date +%s)
ok=0
for _ in $(seq 1 26); do
  sleep 5
  latest=$(wg show "$IFACE" latest-handshakes | awk '{ if ($2 > m) m = $2 } END { print m+0 }')
  if [[ "$latest" -gt "$start" ]]; then
    ok=1
    break
  fi
done
if [[ "$ok" -eq 1 ]]; then
  log "Handshake confirmed - the mesh is up with the preshared key."
else
  warn "No fresh handshake within 130 s. Check 'wg show $IFACE' and the panel's node detail page."
  warn "To back out on this node: cp $backup $CONF && wg syncconf $IFACE <(wg-quick strip $IFACE)"
fi

log "Done. 'wg show $IFACE' should now report 'preshared key: (hidden)'."
