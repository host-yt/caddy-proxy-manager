#!/usr/bin/env bash
# Hostyt Proxy Gateway - WG sidecar.
#   - Brings wg0 up from /config/wg0.conf on first run.
#   - Watches the file mtime and applies peer changes via `wg syncconf`
#     when the app re-renders the config (e.g. after a new node joins).
#
# Requires NET_ADMIN + (on most kernels) host network namespace.

set -euo pipefail

CONF=/config/wg0.conf
IFACE=wg0

log() { printf '[wg-sidecar] %s\n' "$*"; }
die() { printf '[wg-sidecar] ERR %s\n' "$*" >&2; exit 1; }

# Wait for the app to drop the first config in.
log "waiting for $CONF"
until [ -s "$CONF" ]; do sleep 2; done
log "config present, bringing up $IFACE"

# Always-clean start: if a stale interface exists from a previous run,
# tear it down so wg-quick up can claim the name.
ip link show "$IFACE" >/dev/null 2>&1 && wg-quick down "$CONF" || true
wg-quick up "$CONF"
log "$IFACE up; entering watch loop"

last=$(stat -c %Y "$CONF" 2>/dev/null || echo 0)

trap 'log "SIGTERM, taking $IFACE down"; wg-quick down "$CONF" || true; exit 0' TERM INT

while true; do
  cur=$(stat -c %Y "$CONF" 2>/dev/null || echo 0)
  if [ "$cur" != "$last" ]; then
    log "config changed (mtime $last -> $cur), wg syncconf"
    # syncconf adds/removes peers without resetting the interface;
    # AllowedIPs and PresharedKey updates are also applied atomically.
    if wg syncconf "$IFACE" <(wg-quick strip "$CONF"); then
      last="$cur"
    else
      log "syncconf failed, will retry next tick"
    fi
  fi
  sleep 10
done
