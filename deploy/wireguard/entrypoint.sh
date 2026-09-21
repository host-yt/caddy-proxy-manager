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

# `wg syncconf` cannot REMOVE a preshared key: a peer block without a
# PresharedKey line means "leave the current key alone", not "clear it". So
# after every sync, clear the key of any peer the config no longer gives one
# - without this an admin "Clear PSK" only rewrites the file and the key
# stays live until the next restart, when the two ends silently split.
clear_removed_psks() {
  local stripped="$1" live rc=0 want pub psk
  want=$(awk '
    function emit() { if (pub != "" && has) print pub; pub = ""; has = 0 }
    /^[[:space:]]*\[/                        { emit() }
    /^[[:space:]]*PublicKey[[:space:]]*=/    { v = $0; sub(/^[^=]*=[[:space:]]*/, "", v); gsub(/[[:space:]]+$/, "", v); pub = v }
    /^[[:space:]]*PresharedKey[[:space:]]*=/ { has = 1 }
    END { emit() }
  ' "$stripped")
  # Via a file, not `< <(wg show ...)`: a process substitution hides the
  # producer's exit status, so a failing `wg show` used to read as "no peer
  # needs clearing" and the reload was reported as fully applied.
  live=$(mktemp)
  if ! wg show "$IFACE" preshared-keys > "$live"; then
    log "ERR SECURITY cannot read the live preshared keys of $IFACE - key removals were NOT applied"
    rm -f "$live"
    return 1
  fi
  while read -r pub psk; do
    case "$psk" in ''|'(none)') continue ;; esac
    # `&& continue` would abort the sidecar on a non-match under `set -e`.
    if printf '%s\n' "$want" | grep -qxF "$pub"; then continue; fi
    log "peer $pub has no preshared key in the config any more, clearing it on $IFACE"
    if ! wg set "$IFACE" peer "$pub" preshared-key /dev/null; then
      log "ERR SECURITY the preshared key of peer $pub is STILL LIVE on $IFACE and could not be removed - run: wg set $IFACE peer $pub preshared-key /dev/null"
      rc=1
    fi
  done < "$live"
  rm -f "$live"
  return "$rc"
}

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
    # syncconf adds/removes peers and updates AllowedIPs without resetting
    # the interface. Setting or changing a PresharedKey is applied too;
    # removing one is not, hence clear_removed_psks below.
    strip=$(mktemp)
    # `last` only moves once syncconf AND every key removal succeeded. An
    # unchanged render keeps the same mtime forever, so advancing it on a
    # partial failure would mean the retry never happens and a key that was
    # supposed to be gone stays live for good.
    if wg-quick strip "$CONF" > "$strip" && wg syncconf "$IFACE" "$strip" && clear_removed_psks "$strip"; then
      last="$cur"
    else
      log "ERR reload of mtime $cur failed, keeping the applied marker at $last - retrying next tick"
    fi
    rm -f "$strip"
  fi
  sleep 10
done
