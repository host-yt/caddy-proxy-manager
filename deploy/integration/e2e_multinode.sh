#!/usr/bin/env bash
# 2-node active_active e2e scenario.
#
# Boots the real panel image + mariadb + redis + two STOCK caddy edge nodes
# + a tiny static upstream, then drives the panel almost entirely through
# its public HTTP interfaces (install wizard, admin login, REST API v1) to:
#   node_group(active_active) -> register 2 caddy nodes -> client+service ->
#   route -> both nodes' Caddy configs pick up the route -> both nodes serve
#   real traffic -> kill node B -> panel's health poller marks it down ->
#   node A keeps serving.
#
# This exists because a 2-node active_active fan-out bug (peers pushed
# routes:0, fixed in commit b801e90) shipped without anything exercising a
# real 2-node topology. See docs/TROUBLESHOOTING.md for the "why" and the
# list of product gaps this script had to route around (grep TODO(api-gap)
# below, and the same tag in this repo for a plain-text list).
#
# Usage: deploy/integration/e2e_multinode.sh   (or: make e2e-multinode)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.multinode.yml"
# Explicit project name: the default (directory basename "integration")
# would collide with deploy/integration/docker-compose.yml's project if both
# are ever brought up at once.
COMPOSE=(docker compose -p hpg-e2e-multinode -f "$COMPOSE_FILE")

PANEL="http://127.0.0.1:18080"
CADDY_A_ADMIN="http://127.0.0.1:18091"
CADDY_B_ADMIN="http://127.0.0.1:18092"
CADDY_A_WEB_PORT=18081
CADDY_B_WEB_PORT=18082
TEST_DOMAIN="app.e2e.test"

INSTALL_TOKEN="e2e-install-token"
ADMIN_EMAIL="admin@e2e.test"
ADMIN_PASSWORD="E2eAdminPass1234"
CLIENT_EMAIL="client@e2e.test"
CLIENT_PASSWORD="E2eClientPass1234"

DB_ROOT_PW="e2erootpw"
DB_NAME="hpg_e2e"

COOKIE_JAR="$(mktemp)"
SUMMARY=()

# ---- helpers ---------------------------------------------------------------

log() { printf '==> %s\n' "$1"; }

record_pass() { SUMMARY+=("PASS: $1"); log "PASS: $1"; }

fail() {
	SUMMARY+=("FAIL: $1")
	printf 'FAIL: %s\n' "$1" >&2
	print_summary
	exit 1
}

print_summary() {
	echo
	echo "===== e2e-multinode assertion summary ====="
	local line
	for line in "${SUMMARY[@]}"; do
		echo "$line"
	done
	echo "============================================="
}

cleanup() {
	local ec=$?
	log "tearing down compose stack (exit code so far: $ec)"
	"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
	rm -f "$COOKIE_JAR"
	exit "$ec"
}
trap cleanup EXIT

# req METHOD URL [JSON_BODY]
# Sets HTTP_CODE and RESP_BODY. Sends the API key (if set) as a bearer token.
req() {
	local method="$1" url="$2" data="${3:-}"
	local args=(-sS -w 'HTTPSTATUSCODE:%{http_code}' -X "$method" -b "$COOKIE_JAR" -c "$COOKIE_JAR")
	if [[ -n "${API_KEY:-}" ]]; then
		args+=(-H "Authorization: Bearer $API_KEY")
	fi
	if [[ -n "$data" ]]; then
		args+=(-H "Content-Type: application/json" --data "$data")
	fi
	local raw
	raw=$(curl "${args[@]}" "$url")
	HTTP_CODE="${raw##*HTTPSTATUSCODE:}"
	RESP_BODY="${raw%HTTPSTATUSCODE:*}"
}

require_2xx() {
	if (( HTTP_CODE < 200 || HTTP_CODE >= 300 )); then
		fail "$1 (http $HTTP_CODE): $RESP_BODY"
	fi
}

# install_step PATH FORM_DATA EXPECTED_NEXT_STEP
# Install wizard POSTs are exempt from CSRF (no session exists yet) and
# instead gated by X-Install-Token - see internal/httpserver/middleware/
# install_guard.go and csrf.go.
install_step() {
	local path="$1" data="$2" expect_step="$3"
	local raw code loc
	raw=$(curl -sS -D - -o /dev/null -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
		-H "X-Install-Token: $INSTALL_TOKEN" \
		--data "$data" "$PANEL/install/$path")
	code=$(printf '%s' "$raw" | awk 'NR==1{print $2}')
	loc=$(printf '%s' "$raw" | grep -i '^location:' | tr -d '\r' | awk '{print $2}')
	if [[ "$code" != "303" ]]; then
		fail "install/$path did not redirect (http $code)"
	fi
	if [[ -n "$expect_step" && "$loc" != *"step=$expect_step"* ]]; then
		fail "install/$path redirected to unexpected step: $loc"
	fi
}

# poll_until DESC TIMEOUT_S CHECK_FN [ARGS...]
poll_until() {
	local desc="$1" timeout_s="$2"; shift 2
	local start now
	start=$(date +%s)
	until "$@"; do
		now=$(date +%s)
		if (( now - start >= timeout_s )); then
			fail "$desc (timeout after ${timeout_s}s)"
		fi
		sleep 2
	done
	record_pass "$desc"
}

node_has_route() {
	local admin_url="$1"
	curl -sS -m 3 "$admin_url/config/apps/http/servers/srv0/routes" 2>/dev/null | grep -q "\"$TEST_DOMAIN\""
}

upstream_reachable() {
	local port="$1"
	curl -sS -m 5 -H "Host: $TEST_DOMAIN" "http://127.0.0.1:${port}/" 2>/dev/null | grep -q "Hostname:"
}

node2_marked_down() {
	local status
	status=$("${COMPOSE[@]}" exec -T mariadb mariadb -uroot -p"$DB_ROOT_PW" -N -B "$DB_NAME" \
		-e "SELECT health_status FROM caddy_nodes WHERE name='node-2';" 2>/dev/null || true)
	[[ "$status" == "down" ]]
}

sql_exec() {
	"${COMPOSE[@]}" exec -T mariadb mariadb -uroot -p"$DB_ROOT_PW" "$DB_NAME" -e "$1" >/dev/null
}

# ---- 0. bring up the stack --------------------------------------------------

log "docker compose up (panel image build may take a while on first run)"
"${COMPOSE[@]}" up -d --build

log "waiting for panel /healthz"
poll_until "panel container is up (/healthz)" 120 bash -c "curl -sSf -m 3 '$PANEL/healthz' >/dev/null 2>&1"

# ---- 1. install wizard (public HTTP interface, not a REST endpoint but the
# panel's documented first-run bootstrap surface - not an api-gap) ----------

log "driving install wizard"
install_step "start" "install_token=$INSTALL_TOKEN" "profile"
install_step "profile" "profile=advanced" "db"
install_step "db" "host=mariadb&port=3306&name=$DB_NAME&user=hpg&password=hpge2epw&db_driver=mysql" "admin"
install_step "admin" "full_name=E2E+Admin&email=$ADMIN_EMAIL&password=$ADMIN_PASSWORD&password_confirm=$ADMIN_PASSWORD" "app"
install_step "app" "url=http%3A%2F%2Fpanel.e2e.test%3A8080" "smtp"
install_step "smtp" "skip=1" "caddy"
install_step "caddy" "name=node-1&api_url=http%3A%2F%2Fcaddy-a%3A2019&public_hostname=caddy-a.e2e.test&public_ip=203.0.113.10" "done"
record_pass "install wizard completed (node_group 'default' + node-1 registered)"

# ---- 2. log in, mint an API key via the admin panel -------------------------
# TODO(api-gap): there is no REST endpoint to create the FIRST API key
# (chicken-and-egg: /api/v1 itself requires a bearer key). The only path is
# a logged-in browser session POSTing /admin/api-keys. Scripted here with a
# cookie jar + scraped CSRF token; a one-time INSTALL_TOKEN-gated
# "POST /api/v1/bootstrap" (create super_admin + mint unscoped key) would
# close this gap for headless/IaC installs.

log "logging in as the freshly-created admin"
ADMIN_HTML=$(curl -sS -L -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
	--data "email=$ADMIN_EMAIL&password=$ADMIN_PASSWORD" "$PANEL/auth/login")
CSRF=$(printf '%s' "$ADMIN_HTML" | grep -o 'name="csrf-token" content="[^"]*"' | head -1 | sed -E 's/.*content="([^"]*)".*/\1/')
[[ -n "$CSRF" ]] || fail "login did not yield a CSRF token (session not established)"
record_pass "admin login established a session"

log "minting an API key via /admin/api-keys (leaving scope checkboxes unchecked = unscoped/full key)"
KEY_HTML=$(curl -sS -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
	--data "csrf_token=$CSRF&name=e2e-harness" "$PANEL/admin/api-keys")
API_KEY=$(printf '%s' "$KEY_HTML" | grep -oE 'hpg_[A-Za-z0-9_-]{6,}_[A-Za-z0-9_-]+' | head -1)
[[ -n "$API_KEY" ]] || fail "could not scrape a plaintext API key out of /admin/api-keys response"
record_pass "REST API key minted"

# ---- 3. promote the wizard's 'default' node_group to active_active --------
# The wizard's mandatory /install/caddy step always creates node-1 inside a
# 'default'/single-mode node_group (see wizard.go CaddySubmit) - there is no
# way to skip it. Rather than double-registering caddy-a's admin API under a
# second caddy_nodes row (which would race two independent full-config
# pushes against the same physical Caddy instance), this reuses that group:
# PATCH its mode to active_active and add node-2 (caddy-b) into it.
# TODO(api-gap): there is no REST endpoint to move an EXISTING node between
# node_groups (NodeUpdate only accepts name/is_enabled), so a fresh
# install's mandatory first node is stuck wherever the wizard put it.

log "resolving the 'default' node_pool id"
req GET "$PANEL/api/v1/node-pools"
require_2xx "GET /api/v1/node-pools"
POOL_ID=$(printf '%s' "$RESP_BODY" | jq -r '.node_pools[] | select(.name=="default") | .id')
[[ -n "$POOL_ID" && "$POOL_ID" != "null" ]] || fail "could not find the wizard-created 'default' node_pool"

log "promoting node_pool '$POOL_ID' to active_active"
req PATCH "$PANEL/api/v1/node-pools/$POOL_ID" '{"mode":"active_active"}'
require_2xx "PATCH /api/v1/node-pools/$POOL_ID mode=active_active"
record_pass "node_group promoted to mode=active_active"

log "registering node-2 (caddy-b)"
req POST "$PANEL/api/v1/nodes" "$(jq -nc --arg url "http://caddy-b:2019" --argjson gid "$POOL_ID" \
	'{name:"node-2",api_url:$url,public_hostname:"caddy-b.e2e.test",public_ip:"203.0.113.11",node_group_id:$gid,max_routes:1000,priority:10}')"
require_2xx "POST /api/v1/nodes (node-2)"
NODE2_ID=$(printf '%s' "$RESP_BODY" | jq -r '.id')
[[ -n "$NODE2_ID" && "$NODE2_ID" != "null" ]] || fail "node-2 create did not return an id"

# TODO(api-gap): POST /api/v1/nodes never sets approved_at (unlike the
# wizard's/admin-web node-add flow, which stamps approved_at=NOW() because
# "admin manually added node via form, so trust it" - see wizard.go /
# admin.go). Every route-placement query filters on
# `approved_at IS NOT NULL`, so an API-created node is silently invisible to
# single/active_active/failover placement and route creation dies with
# ErrNoNodeFound ("no node available") - a confusing error totally
# disconnected from the real cause. Falling back to a direct SQL UPDATE.
log "TODO(api-gap): approving node-2 via direct SQL (REST NodeCreate leaves approved_at NULL)"
sql_exec "UPDATE caddy_nodes SET approved_at = NOW() WHERE id = $NODE2_ID;"
record_pass "both caddy nodes (node-1, node-2) registered in the active_active group"

# ---- 4. client + plan + service ---------------------------------------------

log "creating plan"
req POST "$PANEL/api/v1/plans" "$(jq -nc --argjson gid "$POOL_ID" \
	'{name:"e2e-plan",kind:"restricted",max_domains:10,max_ports:10,node_group_id:$gid,ssl_enabled:false,websocket_enabled:false}')"
require_2xx "POST /api/v1/plans"
PLAN_ID=$(printf '%s' "$RESP_BODY" | jq -r '.id')

log "creating client"
req POST "$PANEL/api/v1/clients" "$(jq -nc --arg email "$CLIENT_EMAIL" --arg pw "$CLIENT_PASSWORD" \
	'{email:$email,name:"E2E Client",password:$pw}')"
require_2xx "POST /api/v1/clients"
# TODO(api-gap): the response only returns `user_id` (users.id). Every
# client-scoped endpoint (services.client_id, etc.) actually keys off
# `clients.id`, a DIFFERENT row - the create response gives no way to learn
# it. Callers must immediately GET /api/v1/clients and match by email, an
# easy-to-miss extra round trip for API integrators.
req GET "$PANEL/api/v1/clients"
require_2xx "GET /api/v1/clients (resolving client_id for $CLIENT_EMAIL)"
CLIENT_ID=$(printf '%s' "$RESP_BODY" | jq -r --arg e "$CLIENT_EMAIL" '.clients[] | select(.email==$e) | .id')
[[ -n "$CLIENT_ID" && "$CLIENT_ID" != "null" ]] || fail "could not resolve clients.id for $CLIENT_EMAIL"

log "resolving whoami upstream container IP"
WHOAMI_CID=$("${COMPOSE[@]}" ps -q whoami)
[[ -n "$WHOAMI_CID" ]] || fail "whoami container not found"
WHOAMI_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$WHOAMI_CID")
[[ -n "$WHOAMI_IP" ]] || fail "could not resolve whoami container IP"

log "creating service (backend_ip=$WHOAMI_IP)"
req POST "$PANEL/api/v1/services" "$(jq -nc --argjson cid "$CLIENT_ID" --argjson pid "$PLAN_ID" --arg ip "$WHOAMI_IP" \
	'{client_id:$cid,name:"e2e-svc",backend_ip:$ip,allowed_port_start:80,allowed_port_end:80,plan_id:$pid}')"
require_2xx "POST /api/v1/services"
SERVICE_ID=$(printf '%s' "$RESP_BODY" | jq -r '.id')
[[ -n "$SERVICE_ID" && "$SERVICE_ID" != "null" ]] || fail "service create did not return an id"
record_pass "client + plan + service created (client_id=$CLIENT_ID, service_id=$SERVICE_ID)"

# ---- 5. route (ssl off, per task: keeps the scenario fast/deterministic) --

log "creating route for $TEST_DOMAIN (ssl off)"
req POST "$PANEL/api/v1/routes" "$(jq -nc --argjson sid "$SERVICE_ID" --arg dom "$TEST_DOMAIN" \
	'{service_id:$sid,upstream_port:80,domain:$dom,ssl:false,websocket:false,force_https:false}')"
require_2xx "POST /api/v1/routes"
ROUTE_ID=$(printf '%s' "$RESP_BODY" | jq -r '.id')
[[ -n "$ROUTE_ID" && "$ROUTE_ID" != "null" ]] || fail "route create did not return an id"
record_pass "route created (route_id=$ROUTE_ID, fans out to both active_active nodes)"

# ---- 6. both nodes must receive the route (this is the b801e90 regression) -

poll_until "node-1 (caddy-a) Caddy config contains $TEST_DOMAIN" 90 node_has_route "$CADDY_A_ADMIN"
poll_until "node-2 (caddy-b) Caddy config contains $TEST_DOMAIN" 90 node_has_route "$CADDY_B_ADMIN"

# ---- 7. both nodes actually serve the upstream ------------------------------

poll_until "node-1 (caddy-a) serves the upstream over HTTP" 30 upstream_reachable "$CADDY_A_WEB_PORT"
poll_until "node-2 (caddy-b) serves the upstream over HTTP" 30 upstream_reachable "$CADDY_B_WEB_PORT"

# ---- 8. kill node-2, wait for the panel's health poller to notice ----------

log "killing node-2 (caddy-b) container"
"${COMPOSE[@]}" kill caddy-b >/dev/null
poll_until "panel marks node-2 health_status=down after kill" 120 node2_marked_down

# ---- 9. node-1 still serves traffic -----------------------------------------

poll_until "node-1 (caddy-a) still serves traffic after node-2 is down" 30 upstream_reachable "$CADDY_A_WEB_PORT"

print_summary
log "all assertions passed"
