// Preflight doctor: read-only checks an operator can run before/instead of
// booting the panel, to turn "multi-node install is a chain of pitfalls"
// into actionable PASS/WARN/FAIL rows instead of opaque container logs.
package main

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"os/exec"
	"text/tabwriter"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
	"github.com/host-yt/caddy-proxy-manager/internal/config"
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

	dbChecks, db := doctorDB(ctx, rawCfg)
	checks = append(checks, dbChecks...)
	if db != nil {
		defer db.Close()
	}

	checks = append(checks, doctorRedis(ctx, rawCfg)...)
	checks = append(checks, doctorPorts(rawCfg)...)
	checks = append(checks, doctorNodes(ctx, db)...)
	checks = append(checks, doctorWireGuardHost()...)

	printChecks(checks)
	return summarize(checks)
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

// doctorNodes probes every enabled caddy_node: admin API reachability, the
// last module-probe result, and (when tunnel-enabled) wstunnel health.
// Requires a live db - degrades to a single WARN row when DB is unreachable.
func doctorNodes(ctx context.Context, db *sql.DB) []check {
	if db == nil {
		return []check{{"caddy nodes", statusWarn, "skipped: database unreachable, cannot enumerate nodes"}}
	}

	qCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rows, err := db.QueryContext(qCtx, `
		SELECT id, name, api_url, has_waf, has_l4, has_dns_module, has_rate_limit, has_geoip,
		       caddy_version, modules_probed_at, tunnel_enabled, tunnel_transport, tunnel_wstunnel_healthy
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
	}
	var nodes []node
	for rows.Next() {
		var n node
		if err := rows.Scan(&n.id, &n.name, &n.apiURL, &n.hasWAF, &n.hasL4, &n.hasDNS, &n.hasRateLimit, &n.hasGeoIP,
			&n.caddyVersion, &n.modulesProbedAt, &n.tunnelEnabled, &n.tunnelTransport, &n.tunnelWstunnelHealthy); err == nil {
			nodes = append(nodes, n)
		}
	}
	if len(nodes) == 0 {
		return []check{{"caddy nodes", statusWarn, "no enabled nodes found - add one in Admin -> Caddy nodes"}}
	}

	var checks []check
	for _, n := range nodes {
		label := fmt.Sprintf("caddy node %q", n.name)

		probeCtx, pcancel := context.WithTimeout(ctx, 3*time.Second)
		_, admErr := caddyapi.New(n.apiURL).GetRaw(probeCtx, "/config/")
		pcancel()
		if admErr != nil {
			checks = append(checks, check{label + ": admin API", statusFail,
				admErr.Error() + " - verify the node's Caddy container is up and reachable at " + n.apiURL})
		} else {
			checks = append(checks, check{label + ": admin API", statusPass, n.apiURL + " reachable"})
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
