// Preflight doctor: read-only checks an operator can run before/instead of
// booting the panel, to turn "multi-node install is a chain of pitfalls"
// into actionable PASS/WARN/FAIL rows instead of opaque container logs.
package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
	"github.com/host-yt/caddy-proxy-manager/internal/config"
	"github.com/host-yt/caddy-proxy-manager/internal/installstate"
	"github.com/host-yt/caddy-proxy-manager/internal/security"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

type checkStatus string

const (
	statusPass checkStatus = "PASS"
	statusWarn checkStatus = "WARN"
	statusFail checkStatus = "FAIL"
)

// check is one preflight row: a name, a status, and a one-line detail that
// doubles as the remediation hint on WARN/FAIL.
type check struct {
	name   string
	status checkStatus
	detail string
}

// runDoctor executes every panel preflight check and prints a PASS/WARN/FAIL
// table. Returns the process exit code (1 if any check FAILed).
func runDoctor() int {
	fmt.Println("Hostyt Proxy Gateway - panel preflight doctor")
	fmt.Println()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, cfgErr := config.Load()
	rawCfg := config.LoadUnvalidated()

	var checks []check
	checks = append(checks, doctorConfigCheck(cfgErr))
	checks = append(checks, doctorRequiredEnv()...)
	checks = append(checks, doctorSecretFiles()...)

	dbChecks, db := doctorDB(ctx, rawCfg)
	checks = append(checks, dbChecks...)
	if db != nil {
		defer db.Close()
	}

	checks = append(checks, doctorRedis(ctx, rawCfg)...)
	checks = append(checks, doctorPorts(rawCfg)...)
	checks = append(checks, doctorNodes(ctx, db, rawCfg)...)
	checks = append(checks, doctorSSORoutes(ctx, db)...)
	checks = append(checks, doctorWireGuardHost()...)

	printChecks(checks)
	return summarize(checks)
}

// doctorSSORoutes names every SSO route that gates page loads only. Run
// before the upgrade it is the list of routes the backfill will switch to
// strict; run after it, the list of deliberate opt-outs left to review.
func doctorSSORoutes(ctx context.Context, db *sql.DB) []check {
	if db == nil {
		return nil
	}
	qCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rows, err := db.QueryContext(qCtx,
		`SELECT id, domain FROM routes
		  WHERE COALESCE(sso_provider_url,'') <> '' AND COALESCE(sso_strict_mode,0) = 0
		  ORDER BY id`)
	if err != nil {
		return nil // pre-install, or a schema older than the SSO columns
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var id int64
		var domain string
		if err := rows.Scan(&id, &domain); err == nil {
			names = append(names, fmt.Sprintf("#%d %s", id, domain))
		}
	}
	if len(names) == 0 {
		return []check{{"routes: SSO strict mode", statusPass,
			"no SSO route runs in permissive (document-only) mode"}}
	}
	shown := names
	if len(shown) > 10 {
		shown = append(shown[:10:10], fmt.Sprintf("and %d more", len(names)-10))
	}
	return []check{{"routes: SSO strict mode", statusWarn, fmt.Sprintf(
		"%d SSO route(s) gate GET/HEAD only: %s - upgrading moves them to strict, so requests with other methods will need authentication. Review these applications first; strict can be turned off per route afterwards",
		len(names), strings.Join(shown, ", "))}}
}

func doctorConfigCheck(err error) check {
	if err != nil {
		return check{"config: environment variables", statusFail,
			err.Error() + " - set required env vars, see docs/INSTALL.md"}
	}
	return check{"config: environment variables", statusPass, "APP_SECRET/APP_URL set, config loaded"}
}

// doctorDB pings the DB with the DSN built from env (DB_HOST/DB_USER/...),
// same source docker-compose feeds the app + mariadb containers with. This is
// independent of install_state.json, so it works even pre-install.
func doctorDB(ctx context.Context, cfg *config.Config) ([]check, *sql.DB) {
	driver := cfg.DB.Driver
	if driver == "" {
		driver = "mysql"
	}
	dsn := cfg.DB.BuildDSN()
	target := fmt.Sprintf("%s@tcp(%s:%d)/%s", cfg.DB.User, cfg.DB.Host, cfg.DB.Port, cfg.DB.Name)
	if driver == "sqlite3" {
		dsn = cfg.DB.BuildSQLiteDSN()
		target = cfg.DB.SQLitePath
	}

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	db, err := store.Open(pingCtx, driver, dsn, 5*time.Second)
	if err != nil {
		return []check{{"database: reachable", statusFail,
			err.Error() + " - verify DB_HOST/DB_PORT/DB_USER/DB_PASSWORD (or DB_DSN) and that the database is running"}}, nil
	}

	checks := []check{{"database: reachable", statusPass, driver + " at " + target}}

	qCtx, qCancel := context.WithTimeout(ctx, 5*time.Second)
	defer qCancel()

	var version int64
	if err := db.QueryRowContext(qCtx,
		"SELECT COALESCE(MAX(version_id),0) FROM goose_db_version WHERE is_applied = 1").Scan(&version); err != nil {
		checks = append(checks, check{"database: migrations", statusWarn,
			"goose_db_version unreadable (" + err.Error() + ") - fresh DB, run the install wizard"})
	} else {
		checks = append(checks, check{"database: migrations", statusPass, fmt.Sprintf("version %d applied", version)})
	}

	if driver == "sqlite3" {
		checks = append(checks, check{"database: server version", statusPass, "sqlite3 (embedded, no server process)"})
	} else {
		var v string
		if err := db.QueryRowContext(qCtx, "SELECT VERSION()").Scan(&v); err != nil {
			checks = append(checks, check{"database: server version", statusWarn, "VERSION() query failed: " + err.Error()})
		} else {
			checks = append(checks, check{"database: server version", statusPass, v})
		}
	}

	return checks, db
}

// doctorRedis pings Redis once with a short deadline (not the boot-time retry
// loop in run()) so a down Redis reports FAIL quickly instead of hanging.
func doctorRedis(ctx context.Context, cfg *config.Config) []check {
	if cfg.Redis.Addr == "" {
		return nil
	}
	// go-redis logs its own internal dial retries to stderr by default; a
	// down Redis would otherwise spam the table with noise before the FAIL row.
	redis.SetLogger(discardLogger{})
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Addr,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})
	defer rdb.Close()

	pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := rdb.Ping(pctx).Err(); err != nil {
		return []check{{"redis: reachable", statusFail,
			err.Error() + " - verify REDIS_ADDR/REDIS_PASSWORD and that Redis is running"}}
	}
	return []check{{"redis: reachable", statusPass, cfg.Redis.Addr}}
}

// doctorPorts verifies the panel's own bind address is free. Must be run
// before the panel itself is listening - a live instance holding the port is
// reported the same as any other occupant (that's the point of a preflight).
func doctorPorts(cfg *config.Config) []check {
	addr := cfg.App.Bind
	if addr == "" {
		return nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return []check{{"port: panel bind (APP_BIND)", statusFail,
			err.Error() + " - stop whatever holds " + addr + ", or run doctor before starting the panel"}}
	}
	ln.Close()
	return []check{{"port: panel bind (APP_BIND)", statusPass, addr + " is bindable"}}
}

// doctorNodeClient builds the admin client doctor probes with: authenticated
// when the node carries an admin-proxy key, direct otherwise. A key that cannot
// be decrypted (wrong APP_SECRET) falls back to a direct probe, which then
// reports the 401 - that is the useful diagnostic.
func doctorNodeClient(apiURL string, keyEnc sql.NullString, rawCfg *config.Config) *caddyapi.Client {
	if !keyEnc.Valid || keyEnc.String == "" || rawCfg == nil || rawCfg.App.Secret == "" {
		return caddyapi.New(apiURL)
	}
	state, err := installstate.New(stateDir, rawCfg.App.Secret)
	if err != nil {
		return caddyapi.New(apiURL)
	}
	key, err := state.Decrypt(keyEnc.String)
	if err != nil || key == "" {
		return caddyapi.New(apiURL)
	}
	return caddyapi.NewAuthed(apiURL, key)
}

// doctorNodes probes every enabled caddy_node: admin API reachability, the
// last module-probe result, and (when tunnel-enabled) wstunnel health.
// Requires a live db - degrades to a single WARN row when DB is unreachable.
func doctorNodes(ctx context.Context, db *sql.DB, rawCfg *config.Config) []check {
	if db == nil {
		return []check{{"caddy nodes", statusWarn, "skipped: database unreachable, cannot enumerate nodes"}}
	}

	qCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rows, err := db.QueryContext(qCtx, `
		SELECT id, name, api_url, has_waf, has_l4, has_dns_module, has_rate_limit, has_geoip,
		       caddy_version, modules_probed_at, tunnel_enabled, tunnel_transport, tunnel_wstunnel_healthy,
		       admin_proxy_key_enc
		FROM caddy_nodes WHERE is_enabled = 1 ORDER BY id`)
	if err != nil {
		return []check{{"caddy nodes", statusWarn,
			"listing failed (" + err.Error() + ") - schema may be behind; run pending migrations"}}
	}
	defer rows.Close()

	type node struct {
		id                    int64
		name, apiURL          string
		hasWAF, hasL4         bool
		hasDNS, hasRateLimit  bool
		hasGeoIP              bool
		caddyVersion          sql.NullString
		modulesProbedAt       sql.NullTime
		tunnelEnabled         bool
		tunnelTransport       string
		tunnelWstunnelHealthy sql.NullBool
		adminProxyKeyEnc      sql.NullString
	}
	var nodes []node
	for rows.Next() {
		var n node
		if err := rows.Scan(&n.id, &n.name, &n.apiURL, &n.hasWAF, &n.hasL4, &n.hasDNS, &n.hasRateLimit, &n.hasGeoIP,
			&n.caddyVersion, &n.modulesProbedAt, &n.tunnelEnabled, &n.tunnelTransport, &n.tunnelWstunnelHealthy,
			&n.adminProxyKeyEnc); err == nil {
			nodes = append(nodes, n)
		}
	}
	if len(nodes) == 0 {
		return []check{{"caddy nodes", statusWarn, "no enabled nodes found - add one in Admin -> Caddy nodes"}}
	}

	var checks []check
	for _, n := range nodes {
		label := fmt.Sprintf("caddy node %q", n.name)

		// A node whose agent fronts the admin API answers 401 to an
		// unauthenticated probe, so use the same key the panel does - else
		// doctor reports a healthy node as unreachable.
		probeCtx, pcancel := context.WithTimeout(ctx, 3*time.Second)
		_, admErr := doctorNodeClient(n.apiURL, n.adminProxyKeyEnc, rawCfg).GetRaw(probeCtx, "/config/")
		pcancel()
		if admErr != nil {
			checks = append(checks, check{label + ": admin API", statusFail,
				admErr.Error() + " - verify the node's Caddy container is up and reachable at " + n.apiURL})
		} else {
			checks = append(checks, check{label + ": admin API", statusPass, n.apiURL + " reachable"})
			checks = append(checks, doctorNodeAdminBind(ctx, doctorNodeClient(n.apiURL, n.adminProxyKeyEnc, rawCfg), label))
		}

		// SEC-002: Caddy's admin API authenticates nothing. A node addressed at
		// a remote :2019 is owned by whatever can route to it.
		if security.UnauthenticatedNodeAdminURL(n.apiURL) {
			checks = append(checks, check{label + ": admin API auth", statusWarn,
				n.apiURL + " is Caddy's unauthenticated admin API - front it with the node-agent " +
					"admin proxy and repoint api_url at http://<wg-ip>:2021 (docs/MULTI_NODE.md)"})
		} else if n.adminProxyKeyEnc.Valid && n.adminProxyKeyEnc.String != "" {
			checks = append(checks, check{label + ": admin API auth", statusPass, "agent admin proxy, bearer key issued"})
		}

		if !n.modulesProbedAt.Valid {
			checks = append(checks, check{label + ": module probe", statusWarn,
				"not yet probed - populates after the next health-probe cycle"})
		} else {
			checks = append(checks, check{label + ": module probe", statusPass,
				fmt.Sprintf("waf=%v l4=%v dns=%v ratelimit=%v geoip=%v version=%s (probed %s)",
					n.hasWAF, n.hasL4, n.hasDNS, n.hasRateLimit, n.hasGeoIP,
					nullStringOr(n.caddyVersion, "?"), n.modulesProbedAt.Time.Format(time.RFC3339))})
		}

		if n.tunnelEnabled {
			switch {
			case n.tunnelTransport == "udp":
				checks = append(checks, check{label + ": tunnel", statusPass, "udp transport, wstunnel not required"})
			case !n.tunnelWstunnelHealthy.Valid || !n.tunnelWstunnelHealthy.Bool:
				checks = append(checks, check{label + ": tunnel", statusWarn,
					"transport=" + n.tunnelTransport + " but wstunnel not reported healthy - check the node-agent"})
			default:
				checks = append(checks, check{label + ": tunnel", statusPass,
					"transport=" + n.tunnelTransport + ", wstunnel healthy"})
			}
		}
	}
	return checks
}

// doctorNodeAdminBind reports where the node's Caddy admin endpoint is bound,
// read back from the node itself rather than from what the panel intended to
// push. Run it before removing a node's published admin port: it is the proof
// that the node is on the socket and the panel still reaches it.
func doctorNodeAdminBind(ctx context.Context, c *caddyapi.Client, label string) check {
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	raw, err := c.GetRaw(probeCtx, "/config/admin/listen")
	if err != nil {
		// Caddy answers 400 for a path its config does not contain, which is
		// what a node running an admin-less config looks like. Reachability
		// was already proven by the check above, so this is not a failure.
		return check{label + ": admin endpoint", statusPass, "Caddy default bind (not set in the node's config)"}
	}
	listen := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	switch {
	case listen == "" || listen == "null":
		return check{label + ": admin endpoint", statusPass, "Caddy default bind"}
	case strings.HasPrefix(strings.ToLower(listen), "unix/"):
		return check{label + ": admin endpoint", statusPass,
			"filesystem socket " + listen + " - no TCP port; the published :2019 port can be removed"}
	default:
		return check{label + ": admin endpoint", statusPass,
			"TCP " + listen + " - see docs/MULTI_NODE.md to move it onto a socket"}
	}
}

// discardLogger silences go-redis's internal dial-retry logging (implements
// internal.Logging without importing that internal package).
type discardLogger struct{}

func (discardLogger) Printf(context.Context, string, ...any) {}

func nullStringOr(s sql.NullString, def string) string {
	if s.Valid && s.String != "" {
		return s.String
	}
	return def
}

// doctorWireGuardHost checks the panel host's own WireGuard prerequisites
// (used for the manager<->remote-node mesh). Both rows are WARN-only: a
// single-node / all-local-Caddy deployment never needs WireGuard.
func doctorWireGuardHost() []check {
	var checks []check
	if _, err := exec.LookPath("wg"); err != nil {
		checks = append(checks, check{"wireguard: wg binary", statusWarn,
			"not found on PATH - install wireguard-tools if you plan to join remote nodes"})
	} else {
		checks = append(checks, check{"wireguard: wg binary", statusPass, "found"})
	}

	if _, err := os.Stat("/sys/module/wireguard"); err == nil {
		checks = append(checks, check{"wireguard: kernel module", statusPass, "loaded"})
	} else if _, err := exec.LookPath("wireguard-go"); err == nil {
		checks = append(checks, check{"wireguard: kernel module", statusWarn,
			"kernel module not loaded, but userspace fallback (wireguard-go) is present"})
	} else {
		checks = append(checks, check{"wireguard: kernel module", statusWarn,
			"no kernel module and no wireguard-go fallback - remote node mesh will not work"})
	}
	return checks
}

func printChecks(checks []check) {
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "STATUS\tCHECK\tDETAIL")
	for _, c := range checks {
		fmt.Fprintf(w, "%s\t%s\t%s\n", c.status, c.name, c.detail)
	}
	w.Flush()
}

// summarize prints the pass/warn/fail totals and returns the process exit code.
func summarize(checks []check) int {
	var pass, warn, fail int
	for _, c := range checks {
		switch c.status {
		case statusPass:
			pass++
		case statusWarn:
			warn++
		case statusFail:
			fail++
		}
	}
	fmt.Printf("\n%d passed, %d warned, %d failed\n", pass, warn, fail)
	if fail > 0 {
		return 1
	}
	return 0
}

// runHealthcheck probes the panel's own /readyz over loopback and returns a
// process exit code. This is the container HEALTHCHECK: the runtime image is
// distroless, so no shell, curl or wget exists to do it from Compose.
func runHealthcheck() int {
	bind := os.Getenv("APP_BIND")
	if bind == "" {
		bind = "0.0.0.0:8080"
	}
	_, port, err := net.SplitHostPort(bind)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: APP_BIND %q is not host:port\n", bind)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:"+port+"/readyz", nil)
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "healthcheck: /readyz returned %d\n", resp.StatusCode)
		return 1
	}
	return 0
}

// requiredEnv is every variable deploy/docker-compose.yml marks `:?` plus the
// two config.Load() refuses to start without. Compose fails on the first one
// it hits, deep inside interpolation; doctor names them all at once (OPS-004).
var requiredEnv = []struct {
	name   string
	secret bool // generate a value to paste when it is missing
}{
	{"APP_URL", false},
	{"APP_SECRET", true},
	{"DB_NAME", false},
	{"DB_USER", false},
	{"DB_PASSWORD", true},
	{"REDIS_PASSWORD", true},
	{"MARIADB_ROOT_PASSWORD", true},
	{"INSTALL_TOKEN", true},
}

// envFilePath is the .env doctor reads when it runs from a compose checkout
// rather than inside the container. HPG_ENV_FILE overrides it.
func envFilePath() string {
	if p := os.Getenv("HPG_ENV_FILE"); p != "" {
		return p
	}
	return ".env"
}

// parseEnvFile reads KEY=VALUE lines. Deliberately dumb - it exists to answer
// "is this var set and non-empty", never to interpolate.
func parseEnvFile(path string) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
	return out, nil
}

// doctorRequiredEnv fails when a required variable is missing or empty, naming
// every one of them and offering a generated value for the secrets. An empty
// required var is a failure, not a default: `docker compose up` would abort.
func doctorRequiredEnv() []check {
	fileVals, ferr := parseEnvFile(envFilePath())
	var missing []string
	var gen []string
	for _, v := range requiredEnv {
		val := fileVals[v.name]
		if val == "" {
			val = os.Getenv(v.name)
		}
		if val != "" {
			continue
		}
		missing = append(missing, v.name)
		if v.secret {
			gen = append(gen, v.name+"="+randomSecret())
		}
	}
	src := envFilePath()
	if ferr != nil {
		src = "process environment (" + envFilePath() + " not readable)"
	}
	if len(missing) == 0 {
		return []check{{"config: required variables", statusPass, "all set in " + src}}
	}
	detail := "missing or empty in " + src + ": " + strings.Join(missing, ", ")
	if len(gen) > 0 {
		detail += " | paste: " + strings.Join(gen, "  ")
	}
	return []check{{"config: required variables", statusFail, detail}}
}

// randomSecret returns 32 bytes of hex - the same shape as
// `openssl rand -hex 32`, which the compose file's error message suggests.
func randomSecret() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "<generate with: openssl rand -hex 32>"
	}
	return hex.EncodeToString(b[:])
}

// doctorSecretFiles reports the permissions of the two files that hold panel
// secrets. Group/other-readable means any other local account can read the
// credentials (OPS-003).
func doctorSecretFiles() []check {
	var checks []check
	for _, path := range []string{envFilePath(), stateDir + "/install_state.json"} {
		fi, err := os.Stat(path)
		if err != nil {
			continue // not this deployment's layout; nothing to report
		}
		mode := fi.Mode().Perm()
		label := "secrets: " + path
		if mode&0o077 != 0 {
			checks = append(checks, check{label, statusWarn,
				fmt.Sprintf("mode %04o is readable by other local accounts - chmod 600 %s (and umask 077 before creating it)", mode, path)})
			continue
		}
		checks = append(checks, check{label, statusPass, fmt.Sprintf("mode %04o", mode)})
	}
	if u, ok := procUmask(); ok && u&0o077 != 0o077 {
		checks = append(checks, check{"secrets: umask", statusWarn,
			fmt.Sprintf("umask %04o lets newly created files be group/other-readable - set umask 077 in the shell that runs the installer", u)})
	}
	return checks
}

// procUmask reads the current umask from /proc/self/status (Linux). Returns
// ok=false elsewhere - reading it via syscall would mean setting it first.
func procUmask() (int, bool) {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "Umask:"); ok {
			n, err := strconv.ParseInt(strings.TrimSpace(v), 8, 32)
			if err != nil {
				return 0, false
			}
			return int(n), true
		}
	}
	return 0, false
}
