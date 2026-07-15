#!/usr/bin/env bash
# Single-node SQLite e2e scenario.
#
# Boots the real panel image on the wizard's sqlite3 path (no MySQL anywhere)
# plus one stock caddy edge and a static upstream, then drives the panel
# through its public HTTP interfaces: install wizard -> admin login ->
# group-first add-host form -> config lands in Caddy -> real traffic through
# the edge -> redirect route -> REST API -> every admin nav page.
#
# The final assertion is the reason this harness exists: after the background
# workers (reconciler, alert evaluator, health prober) have run, the panel log
# must contain ZERO SQL errors. The runtime shares one MySQL-dialect query set
# between engines (see internal/store/sqlite_funcs.go), and history shows a
# single unconverted expression is enough to silently break a whole feature -
# migration 18's bare NOW() shipped unnoticed because nothing ran this path.
#
# Usage: deploy/integration/e2e_sqlite.sh   (or: make e2e-sqlite)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.sqlite.yml"
COMPOSE=(docker compose -p hpg-e2e-sqlite -f "$COMPOSE_FILE")

PANEL="http://127.0.0.1:18180"
CADDY_ADMIN="http://127.0.0.1:18191"
CADDY_WEB_PORT=18181
TEST_DOMAIN="app.e2e.test"
REDIRECT_DOMAIN="redirect.e2e.test"

INSTALL_TOKEN="e2e-install-token"
ADMIN_EMAIL="admin@e2e.test"
ADMIN_PASSWORD="E2eAdminPass1234"

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
	echo "===== e2e-sqlite assertion summary ====="
	local line
	for line in "${SUMMARY[@]}"; do
		echo "$line"
	done
	echo "========================================="
}

cleanup() {
	local ec=$?
	log "tearing down compose stack (exit code so far: $ec)"
	"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
	rm -f "$COOKIE_JAR"
	exit "$ec"
}
trap cleanup EXIT

# install_step PATH FORM_DATA EXPECTED_NEXT_STEP - same contract as the
# multinode harness: wizard POSTs are CSRF-exempt, gated by X-Install-Token.
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

caddy_has_domain() {
	curl -sS -m 3 "$CADDY_ADMIN/config/apps/http/servers" 2>/dev/null | grep -q "\"$1\""
}

# csrf_from PAGE - scrape the form token out of an authed page.
csrf_from() {
	curl -sS -b "$COOKIE_JAR" -c "$COOKIE_JAR" "$1" \
		| grep -o 'name="csrf_token" value="[^"]*"' | head -1 \
		| sed -E 's/.*value="([^"]*)".*/\1/'
}

# ---- 0. bring up the stack --------------------------------------------------

log "docker compose up (panel image build may take a while on first run)"
"${COMPOSE[@]}" up -d --build

log "waiting for panel /healthz"
poll_until "panel container is up (/healthz)" 120 bash -c "curl -sSf -m 3 '$PANEL/healthz' >/dev/null 2>&1"

# ---- 1. install wizard, down the sqlite3 path -------------------------------

log "driving install wizard (profile=homelab, db_driver=sqlite3)"
install_step "start" "install_token=$INSTALL_TOKEN" "profile"
install_step "profile" "profile=homelab" "db"
install_step "db" "db_driver=sqlite3&sqlite_path=data/hpg.db" "admin"
install_step "admin" "full_name=E2E+Admin&email=$ADMIN_EMAIL&password=$ADMIN_PASSWORD&password_confirm=$ADMIN_PASSWORD" "app"
install_step "app" "url=http%3A%2F%2Fpanel.e2e.test%3A8080" "smtp"
install_step "smtp" "skip=1" "caddy"
install_step "caddy" "name=node-1&api_url=http%3A%2F%2Fcaddy-a%3A2019&public_hostname=caddy-a.e2e.test&public_ip=203.0.113.10" "done"
record_pass "install wizard completed on sqlite (migrations applied, node-1 registered)"

# ---- 2. admin login ----------------------------------------------------------

log "logging in as the freshly-created admin"
ADMIN_HTML=$(curl -sS -L -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
	--data "email=$ADMIN_EMAIL&password=$ADMIN_PASSWORD" "$PANEL/auth/login")
CSRF=$(printf '%s' "$ADMIN_HTML" | grep -o 'name="csrf-token" content="[^"]*"' | head -1 | sed -E 's/.*content="([^"]*)".*/\1/')
[[ -n "$CSRF" ]] || fail "login did not yield a CSRF token (session not established)"
record_pass "admin login established a session"

# ---- 3. add a proxy host via the group-first admin form ----------------------

log "adding $TEST_DOMAIN -> whoami:80 via /admin/hosts/new (node_group_id form)"
FORM_CSRF=$(csrf_from "$PANEL/admin/hosts/new")
[[ -n "$FORM_CSRF" ]] || fail "could not scrape csrf_token from /admin/hosts/new"
HTTP_CODE=$(curl -sS -o /dev/null -w '%{http_code}' -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
	--data "csrf_token=$FORM_CSRF&kind=proxy&domain=$TEST_DOMAIN&upstream_scheme=http&backend_ip=whoami&port=80&node_group_id=1&websocket=1" \
	"$PANEL/admin/hosts/new")
[[ "$HTTP_CODE" == "303" ]] || fail "add-host POST returned $HTTP_CODE (want 303)"
record_pass "proxy host created through the admin form"

poll_until "route reached Caddy's config" 90 caddy_has_domain "$TEST_DOMAIN"

log "requesting the domain through the edge"
poll_until "edge serves the upstream over HTTP" 30 bash -c \
	"curl -sS -m 5 -H 'Host: $TEST_DOMAIN' 'http://127.0.0.1:$CADDY_WEB_PORT/' 2>/dev/null | grep -q 'Hostname:'"

# ---- 4. redirect route --------------------------------------------------------

log "adding $REDIRECT_DOMAIN as a 308 redirect"
FORM_CSRF=$(csrf_from "$PANEL/admin/hosts/new")
HTTP_CODE=$(curl -sS -o /dev/null -w '%{http_code}' -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
	--data "csrf_token=$FORM_CSRF&kind=redirect&domain=$REDIRECT_DOMAIN&redirect_url=https%3A%2F%2Fexample.com&redirect_code=308&node_group_id=1" \
	"$PANEL/admin/hosts/new")
[[ "$HTTP_CODE" == "303" ]] || fail "add-redirect POST returned $HTTP_CODE (want 303)"

poll_until "redirect route reached Caddy's config" 90 caddy_has_domain "$REDIRECT_DOMAIN"
LOC=$(curl -sS -m 5 -o /dev/null -w '%{redirect_url}' -H "Host: $REDIRECT_DOMAIN" "http://127.0.0.1:$CADDY_WEB_PORT/x")
[[ "$LOC" == "https://example.com"* ]] || fail "redirect route sent Location=$LOC (want https://example.com...)"
record_pass "redirect route serves 308 through the edge"

# ---- 5. REST API --------------------------------------------------------------

log "minting an API key and listing routes"
FORM_CSRF=$(csrf_from "$PANEL/admin/api-keys")
API_KEY=$(curl -sS -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
	--data "csrf_token=$FORM_CSRF&name=e2e-sqlite" "$PANEL/admin/api-keys" \
	| grep -oE 'hpg_[A-Za-z0-9_-]{6,}_[A-Za-z0-9_-]+' | head -1)
[[ -n "$API_KEY" ]] || fail "could not mint an API key"
HTTP_CODE=$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $API_KEY" "$PANEL/api/v1/routes")
[[ "$HTTP_CODE" == "200" ]] || fail "GET /api/v1/routes returned $HTTP_CODE"
record_pass "REST API serves route list on sqlite"

# ---- 5b. backup + restore drill on the sqlite engine ------------------------
# The dump/restore path is engine-specific (sqlite has no information_schema/
# SHOW CREATE and doubles quotes instead of backslash-escaping), so it gets its
# own coverage here rather than relying on the MySQL harness.

# panel_log_has PATTERN - grep the panel container's log. Wraps the compose
# array in a helper so poll_until's check runs in this shell (a bash -c subshell
# can't see the COMPOSE array).
panel_log_has() {
	"${COMPOSE[@]}" logs panel 2>/dev/null | grep -q "$1"
}

log "creating a local backup destination and running a backup"
# The panel writes into /app/data (tmpfs, mode 0777) so the nonroot process can
# create the backups dir itself - no chown needed.
FORM_CSRF=$(csrf_from "$PANEL/admin/backups")
curl -sS -o /dev/null -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
	--data "csrf_token=$FORM_CSRF&kind=local&name=e2e-local&cfg_path=/app/data/backups" \
	"$PANEL/admin/backups/destinations"
FORM_CSRF=$(csrf_from "$PANEL/admin/backups")
curl -sS -o /dev/null -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
	--data "csrf_token=$FORM_CSRF&destination_id=1" "$PANEL/admin/backups/run-now"

# run-now is async; poll the log for the ok line rather than sleeping blind.
poll_until "backup produced an artifact on sqlite" 30 panel_log_has '"msg":"backup: ok"'

log "running a restore drill against the sqlite artifact"
FORM_CSRF=$(csrf_from "$PANEL/admin/backups")
curl -sS -o /dev/null -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
	--data "csrf_token=$FORM_CSRF" "$PANEL/admin/backups/drill/run"
poll_until "restore drill verified core tables on sqlite" 45 panel_log_has "backup-drill: ok"

# ---- 6. every admin nav page renders ------------------------------------------

log "sweeping every sidebar link for a 200"
NAV_LINKS=$(curl -sS -b "$COOKIE_JAR" "$PANEL/admin" \
	| grep -oE 'href="/admin[^"#?]*"' | sed 's/href="//;s/"//' | sort -u)
BAD=0
while IFS= read -r u; do
	[[ -z "$u" ]] && continue
	code=$(curl -sS -o /dev/null -w '%{http_code}' -b "$COOKIE_JAR" -m 10 "$PANEL$u")
	if [[ "$code" != "200" ]]; then
		printf '   non-200: %s -> %s\n' "$u" "$code" >&2
		BAD=$((BAD+1))
	fi
done <<< "$NAV_LINKS"
[[ "$BAD" == "0" ]] || fail "$BAD admin page(s) did not return 200"
record_pass "every admin nav page renders (200)"

# ---- 7. THE point of this harness: zero SQL errors after workers ran ----------

log "waiting out two background-worker cycles (~70s) before the log audit"
sleep 70

log "auditing panel logs for SQL errors"
SQL_ERRORS=$("${COMPOSE[@]}" logs panel 2>/dev/null \
	| grep -cE 'SQL logic error|no such function|no such column|syntax error' || true)
if [[ "$SQL_ERRORS" != "0" ]]; then
	"${COMPOSE[@]}" logs panel 2>/dev/null \
		| grep -E 'SQL logic error|no such function|no such column|syntax error' | head -10 >&2
	fail "panel logged $SQL_ERRORS SQL error line(s) on sqlite - a MySQL-ism slipped through"
fi
record_pass "zero SQL errors in panel logs after background workers ran"

print_summary
