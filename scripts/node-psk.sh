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
# Idempotent: re-running with the same (or a fresh) token is safe. wg0.conf
# is backed up first and restored if anything past the rewrite definitely
# fails; an unknown confirm outcome keeps the new key and asks for a re-run.
#
# Requires: bash, curl, jq, wg, wg-quick, root.

set -euo pipefail

PANEL=""
TOKEN=""
IFACE="wg0"
# See scripts/node-join.sh: the mesh interface needs a fixed source port.
WG_LISTEN_PORT="51820"

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
#    failure below can be retried with the same command. The token goes in
#    the Authorization header, not the URL: a query string ends up in every
#    upstream access log and in this process's argv under /proc.
log "Fetching the staged preshared key from $PANEL"
resp=$(curl -fsS --max-time 30 -H "Authorization: Bearer ${TOKEN}" "${PANEL}/api/node/psk") \
  || die "panel refused the token (bad, expired, or already confirmed)"
psk=$(printf '%s' "$resp" | jq -r '.psk // ""')
peer_pub=$(printf '%s' "$resp" | jq -r '.peer_public_key // ""')
# One malformed line makes `wg syncconf` reject the whole config, so validate
# the exact wire format (32 bytes, base64) before either value reaches wg0.conf.
[[ "$psk" =~ ^[A-Za-z0-9+/]{43}=$ ]] || die "panel returned a malformed preshared key"
[[ "$peer_pub" =~ ^[A-Za-z0-9+/]{43}=$ ]] || die "panel returned a malformed manager public key"

# 2. Back up, then rewrite ONLY the panel's [Peer] block. Any other peer on
#    this interface was added by hand and keeps whatever key it has.
backup="${CONF}.bak.$(date +%s)"
umask 077
cp -p "$CONF" "$backup"
chmod 600 "$backup"
log "Backed up $CONF to $backup"

# conf_has_psk: does the manager's [Peer] block in $1 carry a PresharedKey?
conf_has_psk() {
  awk -v pub="$peer_pub" '
    function emit() { if (p == pub && has) found = 1; p = ""; has = 0 }
    /^[[:space:]]*\[/                        { emit() }
    /^[[:space:]]*PublicKey[[:space:]]*=/    { v = $0; sub(/^[^=]*=[[:space:]]*/, "", v); gsub(/[[:space:]]+$/, "", v); p = v }
    /^[[:space:]]*PresharedKey[[:space:]]*=/ { has = 1 }
    END { emit(); exit !found }
  ' "$1"
}

# psk_live: does the LIVE interface still hold a preshared key for the
# manager peer? The file is not evidence - only the kernel state is.
psk_live() {
  wg show "$IFACE" preshared-keys 2>/dev/null \
    | awk -v p="$peer_pub" '$1 == p && $2 != "(none)" { found = 1 } END { exit !found }'
}

manual_fix() {
  warn "This node is NOT back on its previous key. Run, as root:"
  warn "    wg set $IFACE peer $peer_pub preshared-key /dev/null"
  warn "or, if that fails: wg-quick down $IFACE && wg-quick up $IFACE"
  warn "then check: wg show $IFACE preshared-keys"
}

# Restore the backup AND the live interface. `wg syncconf` can set or change
# a PresharedKey but cannot REMOVE one: a config without the line means
# "leave the current key alone". On a first-time enable the backup has no
# key, so syncconf alone leaves the staged key live, the node keeps
# handshaking for REJECT_AFTER_TIME and then drops off the mesh with nothing
# to explain it. Clear it explicitly in that case.
rollback() {
  trap - ERR INT TERM
  warn "Rolling back $CONF"
  local ok=1
  cp -p "$backup" "$CONF" || ok=0
  wg syncconf "$IFACE" <(wg-quick strip "$IFACE") || { warn "rollback syncconf failed"; ok=0; }
  if [[ "$ok" -eq 1 ]] && ! conf_has_psk "$CONF" && psk_live; then
    warn "Clearing the staged preshared key from the live interface"
    wg set "$IFACE" peer "$peer_pub" preshared-key /dev/null || true
    if psk_live; then
      # Older wg builds refuse an empty key file; a full restart re-reads
      # the restored config from scratch, which has the same effect.
      warn "this wg build could not clear the key directly - restarting $IFACE"
      { wg-quick down "$IFACE" && wg-quick up "$IFACE"; } || ok=0
      if psk_live; then ok=0; fi
    fi
  fi
  [[ "$ok" -eq 1 ]] || { manual_fix; return 1; }
  return 0
}

tmp=$(mktemp "${CONF}.new.XXXXXX")
chmod 600 "$tmp"
# Sections are buffered so a block can be identified by its PublicKey before
# anything is emitted. Inside the manager's block: drop any existing
# PresharedKey (idempotent re-run) and emit a fresh one after PublicKey.
# The key is compared as a literal string - base64 '+' would be a regex quantifier.
if ! awk -v psk="$psk" -v pub="$peer_pub" '
  function flush(   i) {
    for (i = 1; i <= n; i++) {
      if (mine && buf[i] ~ /^[[:space:]]*PresharedKey[[:space:]]*=/) continue
      print buf[i]
      if (mine && buf[i] ~ /^[[:space:]]*PublicKey[[:space:]]*=/) { print "PresharedKey = " psk; done = 1 }
    }
    n = 0; mine = 0
  }
  /^[[:space:]]*\[/ { flush() }
  {
    buf[++n] = $0
    if ($0 ~ /^[[:space:]]*PublicKey[[:space:]]*=/) {
      v = $0
      sub(/^[^=]*=[[:space:]]*/, "", v)
      gsub(/[[:space:]]+$/, "", v)
      if (v == pub) mine = 1
    }
  }
  END { flush(); if (!done) exit 1 }
' "$backup" > "$tmp"; then
  rm -f "$tmp"
  die "no [Peer] block with the manager public key $peer_pub in $CONF"
fi
mv "$tmp" "$CONF"
# From here on wg0.conf holds a key the panel has not committed. A Ctrl-C in
# this window would otherwise leave it there and break the next `wg-quick up`.
trap 'rollback; exit 1' ERR INT TERM

# Heal a config written by a node-join.sh from before ListenPort was pinned.
# Without it the kernel picks a new random source port on every `wg syncconf`,
# the panel keeps sending to the old one, and panel->node is blackholed until
# the next PersistentKeepalive. The same syncconf below applies both changes.
if ! grep -qiE '^[[:space:]]*ListenPort[[:space:]]*=' "$CONF"; then
  log "No ListenPort in $CONF - pinning it to $WG_LISTEN_PORT (it was re-randomised on every syncconf)"
  sed -i "0,/^\\[Interface\\]/s//[Interface]\\nListenPort = ${WG_LISTEN_PORT}/" "$CONF"
  chmod 600 "$CONF"
fi

log "Applying the new config to interface $IFACE"
if ! wg syncconf "$IFACE" <(wg-quick strip "$IFACE"); then
  rollback || true
  die "wg syncconf failed"
fi

# 3. Tell the panel to switch its own side. Until this returns the panel is
#    still on the old key, so the mesh is only consistent again afterwards.
#    Confirm is idempotent on the panel for the lifetime of the token, so a
#    lost response is retried rather than rolled back: rolling back after the
#    panel committed would split the mesh with no way to recover.
log "Confirming with the panel"
ok=0
denied=0
code=000
for attempt in 1 2 3 4 5; do
  code=$(curl -sS --max-time 30 -o /dev/null -w '%{http_code}' -X POST \
           -H "Authorization: Bearer ${TOKEN}" \
           "${PANEL}/api/node/psk/confirm" 2>/dev/null) || code=000
  case "$code" in
    2??)          ok=1; break ;;
    408|429|5??)  warn "confirm attempt ${attempt}: HTTP ${code} - retrying" ;;
    4??)          denied=1; break ;;
    *)            warn "confirm attempt ${attempt}: no usable response (${code}) - retrying" ;;
  esac
  sleep $((attempt * 3))
done

if [[ "$denied" -eq 1 ]]; then
  if rollback; then
    die "panel rejected the confirm (HTTP ${code}) - this node is back on its previous key, re-run with a fresh token"
  fi
  die "panel rejected the confirm (HTTP ${code}) AND the rollback could not finish - run the recovery command printed above before anything else"
fi
trap - ERR INT TERM
if [[ "$ok" -ne 1 ]]; then
  # Unknown outcome: the panel may or may not have committed. Rolling back
  # would brick the mesh in the "committed" case, so leave the node on the
  # new key - re-running this exact command is safe and finishes the job.
  warn "No definite answer from the panel (last HTTP ${code}). The node keeps the new key."
  die "confirm outcome unknown - re-run this same command (confirm is idempotent) while the token is still valid"
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
  warn "and, if $backup has no PresharedKey line, also: wg set $IFACE peer $peer_pub preshared-key /dev/null"
  warn "(syncconf can set a preshared key but never removes one)"
fi

log "Done. 'wg show $IFACE' should now report 'preshared key: (hidden)'."
