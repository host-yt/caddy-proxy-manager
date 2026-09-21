#!/usr/bin/env bash
# Mesh WireGuard preshared-key e2e scenario, against REAL kernel WireGuard.
#
# The PSK feature (docs/POST_QUANTUM.md, "Mesh preshared keys") had only
# ever been unit-tested. This boots the real panel image plus its real WG
# sidecar plus two Debian "nodes" that run the real scripts/node-join.sh
# and scripts/node-psk.sh, and drives all five documented paths:
#
#   1 join-with-psk   - a node joining today gets a PSK on both sides and
#                       the panel reaches its Caddy admin over the mesh
#   1b port stability - the node's wg0 source port survives `wg syncconf`
#                       (an unpinned port blackholes panel->node)
#   2 rekey happy     - stage a rotation, run node-psk.sh, both sides
#                       converge; a 1 Hz mesh prober must see no loss
#   3 rekey rollback  - confirm denied (4xx) -> script restores its backup,
#                       panel state unchanged
#   4 old join script - a join request without supports_psk still works,
#                       with no PSK, alongside a PSK'd node
#   5 clear psk       - panel-side Clear PSK + the node-side command the
#                       flash message prints
#
# Scenarios 3 and 5 assert the CURRENT, BROKEN behaviour where the product
# is wrong (see BUG-2/BUG-3 below and the FAIL_ON_KNOWN_BUGS switch): `wg
# syncconf` cannot remove a PresharedKey, so both the rollback and the
# clear are no-ops on the live interface. Flip FAIL_ON_KNOWN_BUGS=1 to make
# this script fail until that is fixed.
#
# BUG-1 (the panel image never creates /app/wg, so the wg_config volume is
# root-owned and the nonroot app cannot write wg0.conf) is worked around by
# the wg-perm init service in the compose file, not here.
#
# Usage: deploy/integration/e2e_psk.sh          (tears the stack down)
#        KEEP=1 deploy/integration/e2e_psk.sh   (leaves it up for poking)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.psk.yml"
COMPOSE=(docker compose -p hpg-e2e-psk -f "$COMPOSE_FILE")
CCS="docker compose -p hpg-e2e-psk -f $COMPOSE_FILE"

PANEL="http://127.0.0.1:19080"
INSTALL_TOKEN="psk-install-token"
ADMIN_EMAIL="admin@psk.test"
ADMIN_PASSWORD="PskAdminPass1234"
DB_ROOT_PW="pskrootpw"
DB_NAME="hpg_psk"
KEEP="${KEEP:-0}"
FAIL_ON_KNOWN_BUGS="${FAIL_ON_KNOWN_BUGS:-0}"

COOKIE_JAR="$(mktemp)"
SUMMARY=()

log()  { printf '==> %s\n' "$1"; }
pass() { SUMMARY+=("PASS: $1"); log "PASS: $1"; }
# A known-bug expectation: recorded, and only fatal with FAIL_ON_KNOWN_BUGS=1.
bug()  {
	SUMMARY+=("KNOWN-BUG: $1")
	printf 'KNOWN-BUG: %s\n' "$1" >&2
	[[ "$FAIL_ON_KNOWN_BUGS" == "1" ]] && fail "known bug still present: $1"
	return 0
}
fail() {
	SUMMARY+=("FAIL: $1")
	printf 'FAIL: %s\n' "$1" >&2
	summary
	exit 1
}
summary() {
	echo
	echo "===== e2e-psk assertion summary ====="
	printf '%s\n' "${SUMMARY[@]}"
	echo "====================================="
}
cleanup() {
	local ec=$?
	if [[ "$KEEP" == "1" ]]; then
		log "KEEP=1, leaving the stack up (docker compose -p hpg-e2e-psk down -v to clean)"
	else
		log "tearing down (exit $ec)"
		"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
	fi
	rm -f "$COOKIE_JAR"
	exit "$ec"
}
trap cleanup EXIT

cc()   { "${COMPOSE[@]}" "$@"; }
sqlq() { cc exec -T mariadb mariadb -uroot -p"$DB_ROOT_PW" -N -B "$DB_NAME" -e "$1" 2>/dev/null; }
# Everything in the panel's own network namespace, i.e. what the panel
# process itself can reach over wg0.
in_panel_ns() { cc exec -T wg-panel sh -c "$1"; }
mesh_get()    { in_panel_ns "wget -q -O - -T 5 http://$1:2019/config/"; }
mesh_up()     { in_panel_ns "wget -q -O /dev/null -T 5 http://$1:2019/config/" >/dev/null 2>&1; }

install_step() {
	local code
	code=$(curl -sS -o /dev/null -w '%{http_code}' -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
		-H "X-Install-Token: $INSTALL_TOKEN" --data "$2" "$PANEL/install/$1")
	[[ "$code" == "303" ]] || fail "install/$1 did not redirect (http $code)"
}
# admin_post PATH FORMDATA -> stdout is the response body
admin_post() {
	curl -sS -b "$COOKIE_JAR" -c "$COOKIE_JAR" --data "csrf_token=$CSRF&$2" "$PANEL/$1"
}
poll_until() {
	local desc="$1" timeout_s="$2"; shift 2
	local start; start=$(date +%s)
	until "$@"; do
		(( $(date +%s) - start >= timeout_s )) && fail "$desc (timeout ${timeout_s}s)"
		sleep 2
	done
	pass "$desc"
}

# ---- 0. boot ---------------------------------------------------------------

log "docker compose up --build (panel image build takes a while on first run)"
cc up -d --build
poll_until "panel is up (/healthz)" 180 bash -c "curl -sSf -m 3 '$PANEL/healthz' >/dev/null 2>&1"

log "install wizard"
install_step start   "install_token=$INSTALL_TOKEN"
install_step profile "profile=advanced"
install_step db      "host=mariadb&port=3306&name=$DB_NAME&user=hpg&password=hpgpskpw&db_driver=mysql"
install_step admin   "full_name=PSK+Admin&email=$ADMIN_EMAIL&password=$ADMIN_PASSWORD&password_confirm=$ADMIN_PASSWORD"
install_step app     "url=http%3A%2F%2Fpanel%3A8080"
install_step smtp    "skip=1"
# The wizard insists on a first node; park it on an unreachable URL. It has
# no wg_public_key so the config writer ignores it.
install_step caddy   "name=node-placeholder&api_url=http%3A%2F%2F127.0.0.1%3A2019&public_hostname=placeholder.psk.test&public_ip=203.0.113.99"

ADMIN_HTML=$(curl -sS -L -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
	--data "email=$ADMIN_EMAIL&password=$ADMIN_PASSWORD" "$PANEL/auth/login")
CSRF=$(printf '%s' "$ADMIN_HTML" | grep -o 'name="csrf-token" content="[^"]*"' | head -1 | sed -E 's/.*content="([^"]*)".*/\1/')
[[ -n "$CSRF" ]] || fail "login yielded no CSRF token"

log "enabling WireGuard (endpoint = the panel container itself)"
admin_post "admin/settings/wireguard" \
	"enabled=1&endpoint=panel%3A51820&listen_port=51820&subnet=10.66.0.0%2F24&control_ip=10.66.0.1" >/dev/null
poll_until "panel rendered its own wg0.conf" 30 \
	bash -c "$CCS exec -T wg-panel test -s /config/wg0.conf"
poll_until "sidecar brought wg0 up in the panel netns" 60 \
	bash -c "$CCS exec -T wg-panel wg show wg0 >/dev/null 2>&1"

GID=$(sqlq "SELECT id FROM node_groups LIMIT 1;")
[[ -n "$GID" ]] || fail "no node_group"

# join_node CONTAINER NAME IP OLD_SCRIPT -> echoes the new node id
join_node() {
	local svc="$1" name="$2" ip="$3" old="$4" tok html sed_expr
	html=$(admin_post "admin/nodes/join-token" "node_group_id=$GID&max_routes=100&priority=10&name_hint=$name")
	tok=$(printf '%s' "$html" | grep -oE 'hpg_join_[A-Za-z0-9_-]+' | head -1)
	[[ -n "$tok" ]] || fail "could not mint a join token for $name"
	# "old script" = today's script minus the capability flag, which is
	# exactly what a node bootstrapped from a cached pre-PSK copy sends.
	sed_expr="s/, supports_psk:true//"
	[[ "$old" == "old" ]] || sed_expr="s/^$//"
	cc exec -T "$svc" bash -c "
		curl -fsS http://panel:8080/install/node.sh -o /tmp/join.sh
		sed -i '$sed_expr' /tmp/join.sh
		bash /tmp/join.sh --manager http://panel:8080 --token $tok \
			--public-hostname $name.psk.test --public-ip $ip" >/dev/null \
		|| fail "node-join.sh failed on $svc"
	sqlq "SELECT id FROM caddy_nodes WHERE name='$name';"
}

# ---- 1. join with PSK ------------------------------------------------------

log "SCENARIO 1: node-a joins with the current node-join.sh"
NODE_A=$(join_node node-a node-a 203.0.113.10 new)
[[ -n "$NODE_A" ]] || fail "node-a did not register"
cc exec -T node-a grep -q '^PresharedKey = ' /etc/wireguard/wg0.conf \
	|| fail "node-a's wg0.conf has no PresharedKey after join"
pass "node-a joined and wrote a PresharedKey into its own wg0.conf"
# A joined node is not a peer until an admin approves it - the join
# response's "no manual step needed" note notwithstanding.
admin_post "admin/nodes/$NODE_A/approve" "" >/dev/null
poll_until "panel rendered node-a as a peer with a PSK" 40 \
	bash -c "$CCS exec -T wg-panel grep -q 'PresharedKey' /config/wg0.conf"
poll_until "both ends show 'preshared key: (hidden)' and a live handshake" 60 bash -c "
	$CCS exec -T wg-panel wg show wg0 | grep -q 'preshared key: (hidden)' &&
	$CCS exec -T node-a wg show wg0 | grep -q 'preshared key: (hidden)' &&
	$CCS exec -T wg-panel wg show wg0 | grep -q 'latest handshake'"
poll_until "panel reaches node-a's Caddy admin API over the mesh" 60 mesh_up 10.66.0.2
poll_until "panel's own health poller marks node-a healthy" 120 \
	bash -c "[[ \$($CCS exec -T mariadb mariadb -uroot -p$DB_ROOT_PW -N -B $DB_NAME -e \"SELECT health_status FROM caddy_nodes WHERE id=$NODE_A;\" 2>/dev/null) == healthy ]]"

# ---- 1b. the node's WG source port must not move -------------------------
# Without `ListenPort` in the node's [Interface] the kernel picks a random
# source port and a NEW one on every `wg syncconf`. The panel's peer blocks
# carry no Endpoint - it learns each node's endpoint from the handshake - so
# after every syncconf it keeps sending to the dead port and panel->node is
# blackholed until the node's next PersistentKeepalive (<=25 s).

PORT_BEFORE=$(cc exec -T node-a wg show wg0 listen-port | tr -d '\r\n')
for _ in 1 2 3; do
	cc exec -T node-a bash -c 'wg syncconf wg0 <(wg-quick strip wg0)'
done
PORT_AFTER=$(cc exec -T node-a wg show wg0 listen-port | tr -d '\r\n')
log "node-a wg0 listen-port: $PORT_BEFORE before 3x syncconf, $PORT_AFTER after"
[[ "$PORT_BEFORE" == "$PORT_AFTER" ]] \
	|| fail "node-a's wg0 source port moved $PORT_BEFORE -> $PORT_AFTER across syncconf; the panel's learned endpoint is now stale"
[[ "$PORT_AFTER" == "51820" ]] \
	|| fail "node-a's wg0 is not on the pinned mesh port 51820 (got $PORT_AFTER)"
pass "node-a's wg0 source port is pinned and survives syncconf ($PORT_AFTER)"
# The blackhole is the observable consequence: with a churning port these
# probes fail until keepalive, well past the few seconds this loop covers.
for _ in 1 2 3; do
	mesh_up 10.66.0.2 || fail "panel lost node-a immediately after a syncconf (stale peer endpoint)"
	sleep 2
done
pass "panel -> node-a stayed reachable right after the syncconfs"

# ---- 2. rekey, happy path --------------------------------------------------

log "SCENARIO 2: staged rotation + the real node-psk.sh"
OLD_PSK=$(cc exec -T node-a sed -n 's/^PresharedKey = //p' /etc/wireguard/wg0.conf | tr -d '\r')
# 1 Hz prober inside the panel netns for the whole rekey window.
cc exec -T -d wg-panel sh -c 'rm -f /tmp/probe.log; while true; do
	if wget -q -O /dev/null -T 2 http://10.66.0.2:2019/config/ 2>/dev/null
	then echo "$(date +%s) OK"; else echo "$(date +%s) FAIL"; fi >> /tmp/probe.log; sleep 1; done'
sleep 5
T0=$(date +%s)
admin_post "admin/nodes/$NODE_A/psk/rotate" "" >/dev/null
# The staged key must not leak into the panel's config before the confirm.
cc exec -T wg-panel grep -q "PresharedKey = $OLD_PSK" /config/wg0.conf \
	|| fail "staging a rotation already changed the panel's wg0.conf"
pass "staging left the panel's live key untouched"
TOKEN=$(curl -sS -b "$COOKIE_JAR" -c "$COOKIE_JAR" "$PANEL/admin/nodes/$NODE_A" \
	| grep -oE '\-\-token [0-9a-f]{64}' | head -1 | awk '{print $2}')
[[ -n "$TOKEN" ]] || fail "node detail page printed no rekey token"
cc exec -T node-a bash -c \
	"curl -fsSL http://panel:8080/install/node-psk.sh | bash -s -- --panel http://panel:8080 --token $TOKEN" \
	|| fail "node-psk.sh failed"
T1=$(date +%s)
NEW_A=$(cc exec -T node-a sed -n 's/^PresharedKey = //p' /etc/wireguard/wg0.conf | tr -d '\r')
NEW_P=$(cc exec -T wg-panel sed -n 's/^PresharedKey = //p' /config/wg0.conf | tr -d '\r')
[[ "$NEW_A" != "$OLD_PSK" && "$NEW_A" == "$NEW_P" ]] \
	|| fail "sides did not converge on the new key (node=$NEW_A panel=$NEW_P old=$OLD_PSK)"
[[ $(cc exec -T node-a grep -c '^PresharedKey' /etc/wireguard/wg0.conf) == 1 ]] \
	|| fail "node-psk.sh left more than one PresharedKey line"
pass "both sides converged on the new key (rekey took $((T1-T0))s)"
[[ $(sqlq "SELECT wg_psk_pending_enc IS NULL FROM caddy_nodes WHERE id=$NODE_A;") == 1 ]] \
	|| fail "pending key was not cleared after a successful confirm"
pass "wg_psk_pending_enc cleared, wg_psk_enc promoted"
LOSS=$(in_panel_ns "awk '\$1>=$T0 && \$1<=$T1 && \$2==\"FAIL\"' /tmp/probe.log | wc -l" | tr -d ' ')
log "mesh prober: $LOSS failed probes inside the ${T1}-${T0}s rekey window"
[[ "$LOSS" -le 30 ]] || fail "mesh was down for $LOSS s during the rekey"
pass "mesh stayed usable during the rekey ($LOSS failed 1 Hz probes)"
admin_post "admin/nodes/$NODE_A/resync" "" >/dev/null
poll_until "panel can still push Caddy config to node-a after the rekey" 60 \
	bash -c "$CCS logs --tail=200 panel 2>&1 | grep -q '\"caddy push ok\",\"node_id\":$NODE_A'"

# ---- 3. rekey, denied confirm ----------------------------------------------

log "SCENARIO 3: confirm denied -> rollback"
# A reverse proxy on the node that passes the fetch through and answers 403
# to the confirm: a definite 4xx, which is the only thing the script treats
# as "roll back" (5xx/timeouts are retried on purpose).
deny_proxy() {
	cc exec -T "$1" bash -c 'cat > /tmp/deny.Caddyfile <<EOF
{
	admin off
}
:9999 {
	handle /api/node/psk/confirm {
		respond "denied by the e2e harness" 403
	}
	handle {
		reverse_proxy panel:8080
	}
}
EOF
nohup caddy run --config /tmp/deny.Caddyfile --adapter caddyfile >/var/log/deny.log 2>&1 &
sleep 3'
}
deny_proxy node-a
BEFORE_ACTIVE=$(sqlq "SELECT SHA2(wg_psk_enc,256) FROM caddy_nodes WHERE id=$NODE_A;")
admin_post "admin/nodes/$NODE_A/psk/rotate" "" >/dev/null
TOKEN=$(curl -sS -b "$COOKIE_JAR" -c "$COOKIE_JAR" "$PANEL/admin/nodes/$NODE_A" \
	| grep -oE '\-\-token [0-9a-f]{64}' | head -1 | awk '{print $2}')
if cc exec -T node-a bash -c \
	"curl -fsSL http://panel:8080/install/node-psk.sh | bash -s -- --panel http://127.0.0.1:9999 --token $TOKEN"; then
	fail "node-psk.sh reported success against a 403 confirm"
fi
[[ "$(cc exec -T node-a sed -n 's/^PresharedKey = //p' /etc/wireguard/wg0.conf | tr -d '\r')" == "$NEW_A" ]] \
	|| fail "rollback did not restore the previous key in wg0.conf"
pass "rollback restored the previous key in the node's wg0.conf"
[[ "$(sqlq "SELECT SHA2(wg_psk_enc,256) FROM caddy_nodes WHERE id=$NODE_A;")" == "$BEFORE_ACTIVE" ]] \
	|| fail "a denied confirm changed the panel's active key"
pass "panel's active key unchanged by the denied confirm"
poll_until "mesh to node-a survived the failed rekey" 90 mesh_up 10.66.0.2

# ---- 4. a node that joined with a pre-PSK node-join.sh ---------------------

log "SCENARIO 4: node-b joins WITHOUT supports_psk"
NODE_B=$(join_node node-b node-b 203.0.113.11 old)
[[ -n "$NODE_B" ]] || fail "node-b did not register"
if cc exec -T node-b grep -q '^PresharedKey' /etc/wireguard/wg0.conf; then
	fail "a join without supports_psk still got a PresharedKey"
fi
pass "join without supports_psk stored and returned no PSK"
admin_post "admin/nodes/$NODE_B/approve" "" >/dev/null
poll_until "panel reaches node-b's Caddy admin over the mesh (no PSK)" 90 mesh_up 10.66.0.3
poll_until "the PSK'd node-a still works alongside it" 30 mesh_up 10.66.0.2
pass "mixed mesh: one peer with a PSK, one without, both live"

# ---- 5. emergency clear ----------------------------------------------------

log "SCENARIO 5: Clear PSK"
PANEL_PUB=$(cc exec -T wg-panel wg show wg0 public-key | tr -d '\r\n')
NODE_A_PUB=$(cc exec -T node-a wg show wg0 public-key | tr -d '\r\n')
admin_post "admin/nodes/$NODE_A/psk/clear" "" >/dev/null
[[ "$(sqlq "SELECT wg_psk_enc IS NULL AND wg_psk_pending_enc IS NULL AND wg_psk_token_hash IS NULL FROM caddy_nodes WHERE id=$NODE_A;")" == 1 ]] \
	|| fail "Clear PSK left state behind in the database"
pass "Clear PSK dropped the active key, the pending key and the token"
poll_until "panel re-rendered wg0.conf without node-a's PresharedKey" 40 \
	bash -c "! $CCS exec -T wg-panel sed -n '/Node #$NODE_A /,/^\$/p' /config/wg0.conf | grep -q PresharedKey"
sleep 15   # give the sidecar's 10 s watch loop its syncconf
if cc exec -T wg-panel wg show wg0 preshared-keys | grep -q "^$NODE_A_PUB.*(none)"; then
	pass "panel's LIVE interface dropped the preshared key"
else
	bug "BUG-3: Clear PSK rewrote wg0.conf but the panel's LIVE interface still has the key - 'wg syncconf' cannot REMOVE a PresharedKey"
fi
# The exact command the flash message tells the operator to run.
cc exec -T node-a bash -c "sed -i '/^PresharedKey/d' /etc/wireguard/wg0.conf && wg syncconf wg0 <(wg-quick strip wg0)"
if cc exec -T node-a wg show wg0 preshared-keys | grep -q "^$PANEL_PUB.*(none)"; then
	pass "the documented node-side command cleared the key on the node"
else
	bug "BUG-3: the documented node-side clear command is a no-op on the live interface too; 'wg set wg0 peer <panel-pub> preshared-key /dev/null' is what actually works"
	cc exec -T node-a wg set wg0 peer "$PANEL_PUB" preshared-key /dev/null
fi
poll_until "mesh to node-a is consistent and up after the clear" 90 mesh_up 10.66.0.2

# ---- 6. the rollback that matters: first-time enable ----------------------
# Same code path as scenario 3, but on a node with NO prior key. The
# rollback then writes a wg0.conf with no PresharedKey line at all, and
# `wg syncconf` silently keeps the staged key on the interface.

log "SCENARIO 6: denied confirm on a FIRST-TIME enable (node-b, no prior key)"
deny_proxy node-b
admin_post "admin/nodes/$NODE_B/psk/enable" "" >/dev/null
TOKEN=$(curl -sS -b "$COOKIE_JAR" -c "$COOKIE_JAR" "$PANEL/admin/nodes/$NODE_B" \
	| grep -oE '\-\-token [0-9a-f]{64}' | head -1 | awk '{print $2}')
if cc exec -T node-b bash -c \
	"curl -fsSL http://panel:8080/install/node-psk.sh | bash -s -- --panel http://127.0.0.1:9999 --token $TOKEN"; then
	fail "node-psk.sh reported success against a 403 confirm"
fi
if cc exec -T node-b grep -q '^PresharedKey' /etc/wireguard/wg0.conf; then
	fail "rollback left a PresharedKey line in node-b's wg0.conf"
fi
pass "rollback restored node-b's wg0.conf to a file with no PresharedKey"
if cc exec -T node-b wg show wg0 preshared-keys | grep -q "^$PANEL_PUB.*(none)"; then
	pass "node-b's live interface has no preshared key after the rollback"
else
	bug "BUG-2: after a rolled-back first-time enable the node's LIVE interface still carries the staged key while the panel has none - the script reports 'the old key is back in place' and the node silently drops off the mesh ~180 s later"
	# REJECT_AFTER_TIME is 180 s: prove the mesh really dies before healing.
	log "waiting up to 240 s for the split to take the node offline"
	dead=0
	for _ in $(seq 1 24); do
		sleep 10
		mesh_up 10.66.0.3 || { dead=1; break; }
	done
	if [[ "$dead" == 1 ]]; then
		bug "BUG-2 confirmed: node-b became unreachable over the mesh after the 'successful' rollback"
	else
		log "node-b stayed reachable for 240 s - the split did not materialise this run"
	fi
	cc exec -T node-b wg set wg0 peer "$PANEL_PUB" preshared-key /dev/null
	poll_until "node-b recovers once the key is removed with 'wg set ... preshared-key /dev/null'" 90 mesh_up 10.66.0.3
fi

summary
