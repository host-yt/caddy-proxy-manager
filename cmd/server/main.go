// Hostyt Proxy Gateway — entrypoint.
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	proxygateway "github.com/host-yt/caddy-proxy-manager"
	"github.com/host-yt/caddy-proxy-manager/internal/accesslog"
	"github.com/host-yt/caddy-proxy-manager/internal/adminscope"
	"github.com/host-yt/caddy-proxy-manager/internal/alert"
	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	"github.com/host-yt/caddy-proxy-manager/internal/backup"
	"github.com/host-yt/caddy-proxy-manager/internal/captcha"
	"github.com/host-yt/caddy-proxy-manager/internal/cloudflare"
	"github.com/host-yt/caddy-proxy-manager/internal/config"
	"github.com/host-yt/caddy-proxy-manager/internal/domain/routes"
	"github.com/host-yt/caddy-proxy-manager/internal/domain/wgpeer"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/handlers"
	"github.com/host-yt/caddy-proxy-manager/internal/installstate"
	"github.com/host-yt/caddy-proxy-manager/internal/jobs"
	"github.com/host-yt/caddy-proxy-manager/internal/leader"
	"github.com/host-yt/caddy-proxy-manager/internal/mail"
	"github.com/host-yt/caddy-proxy-manager/internal/metrics"
	"github.com/host-yt/caddy-proxy-manager/internal/nodejoin"
	"github.com/host-yt/caddy-proxy-manager/internal/notify"
	"github.com/host-yt/caddy-proxy-manager/internal/obs"
	hpgoidc "github.com/host-yt/caddy-proxy-manager/internal/oidc"
	"github.com/host-yt/caddy-proxy-manager/internal/sms"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
	"github.com/host-yt/caddy-proxy-manager/internal/view"
	"github.com/host-yt/caddy-proxy-manager/internal/wafevents"
	"github.com/host-yt/caddy-proxy-manager/internal/webhook"
	"github.com/host-yt/caddy-proxy-manager/internal/wireguard"
)

const (
	stateDir   = "data"
	sessionTTL = 12 * time.Hour
)

func main() {
	logger := newLogger(os.Getenv("LOG_LEVEL"))
	slog.SetDefault(logger)

	cfg, err := config.Load()
	if err != nil {
		logger.Error("config load failed", "err", err)
		os.Exit(1)
	}

	// API key fast-path HMAC needs a stable key. Derive from APP_SECRET.
	// Empty APP_SECRET falls back to slow Argon2id verify (legacy only).
	if cfg.App.Secret != "" {
		auth.SetHMACKey([]byte("hpg/apikey/v1:" + cfg.App.Secret))
	}

	if err := run(cfg, logger); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server exited with error", "err", err)
		os.Exit(1)
	}
}

func run(cfg *config.Config, logger *slog.Logger) error {
	rootCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// bgCtx is cancelled AFTER HTTP shutdown so fire-and-forget background
	// pushes drain cleanly instead of being killed mid-flight by SIGTERM.
	bgCtx, bgCancel := context.WithCancel(context.Background())
	defer bgCancel()

	state, err := installstate.New(stateDir, cfg.App.Secret)
	if err != nil {
		return err
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Addr,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})
	if err := pingRedis(rootCtx, rdb, 15*time.Second); err != nil {
		return err
	}
	logger.Info("redis connected", "addr", cfg.Redis.Addr)

	sessions := auth.NewSessionManager(
		rdb,
		cfg.Security.SessionCookieName,
		cfg.Security.SessionCookieSecure,
		cfg.Security.SessionCookieSameSite,
		sessionTTL,
	)

	installTpls, err := view.LoadInstallTemplates()
	if err != nil {
		return err
	}
	authTpls, err := view.LoadAuthTemplates()
	if err != nil {
		return err
	}
	adminTpls, err := view.LoadAdminTemplates()
	if err != nil {
		return err
	}
	appTpls, err := view.LoadAppTemplates()
	if err != nil {
		return err
	}
	statusTpls, err := view.LoadStatusTemplates()
	if err != nil {
		return err
	}

	wizard := &handlers.Wizard{
		State:      state,
		Templates:  installTpls,
		Logger:     logger,
		Migrations: proxygateway.MigrationsFS,
		MigDir:     "migrations",
	}

	if s := state.Get(); s.DB != nil {
		if err := wizard.Connect(rootCtx); err != nil {
			logger.Warn("reconnect db failed (wizard can retry)", "err", err)
		} else {
			logger.Info("db reconnected from saved state", "host", s.DB.Host, "name", s.DB.Name)
			if err := store.RunMigrations(rootCtx, wizard.DB(), proxygateway.MigrationsFS, "migrations"); err != nil {
				// Fatal: a half-migrated schema causes opaque 500s in
				// features that depend on new tables (e.g. passkeys).
				// Fail loudly so the operator notices immediately.
				logger.Error("auto-migrate on boot failed — refusing to start", "err", err)
				return fmt.Errorf("migrate: %w", err)
			}
			logger.Info("migrations up-to-date")
		}
	}

	routesSvc := &routes.Service{
		DB:                       wizard.DB(),
		Logger:                   logger,
		AskURL:                   buildAskURL(cfg),
		ACMEEmail:                cfg.Caddy.ACMEEmail,
		ACMEStaging:              cfg.Caddy.ACMEStaging,
		PanelPublicHost:          panelPublicHost(cfg.App.URL),
		PanelInternalHost:        cfg.App.PanelInternalHost,
		PanelInternalPort:        cfg.App.PanelInternalPort,
		CacheModuleAvailable:     cfg.Caddy.CacheHandlerAvailable,
		Layer4ModuleAvailable:    cfg.Caddy.Layer4Available,
		WeightedLBAvailable:      cfg.Caddy.WeightedLBAvailable,
		RateLimitModuleAvailable: cfg.Caddy.RateLimitAvailable,
		WAFModuleAvailable:       cfg.Caddy.WAFModuleAvailable,
		DNS01ModuleAvailable:     cfg.Caddy.DNS01Available,
		// External-HTTPS-upstream routes: at-rest secret crypto + host allowlist.
		EncryptSecret:             state.Encrypt,
		DecryptSecret:             state.Decrypt,
		ExternalUpstreamAllowlist: cfg.Security.ExternalUpstreamAllowlist,
		// Incremental per-route Caddy push (PATCH/POST/DELETE by @id) for
		// single-route changes; INCREMENTAL_PATCH=0 reverts to full /load.
		IncrementalPush: os.Getenv("INCREMENTAL_PATCH") != "0",
		// Coalesce rapid config pushes per node within this window (ms).
		// HPG_PUSH_DEBOUNCE_MS=0 disables; default 500.
		PushDebounceMs: pushDebounceMs(),
		BgCtx:          bgCtx,
		// AccessLogURL: when set, every Caddy node's config gains a logging
		// block that POSTs per-request JSON to HPG's ingest endpoint.
		// Env: ACCESS_LOG_URL (e.g. "http://app:8080/internal/access-log").
		AccessLogURL: os.Getenv("ACCESS_LOG_URL"),
	}
	// bindDBWhenReady binds the live pool to a service. If the pool already
	// exists (already-installed boot) it binds now; otherwise it queues the
	// binder and the wizard fires it synchronously the moment it connects the
	// pool mid-install (OnDBReady) - a poll would race a fast install and leave
	// e.g. routesSvc.DB nil when the Caddy step pushes config.
	var dbBinders []func(*sql.DB)
	bindDBWhenReady := func(assign func(*sql.DB)) {
		if db := wizard.DB(); db != nil {
			assign(db)
			return
		}
		dbBinders = append(dbBinders, assign)
	}
	wizard.OnDBReady = func(db *sql.DB) {
		for _, b := range dbBinders {
			b(db)
		}
	}

	// If DB wasn't ready at boot, swap it in once available.
	bindDBWhenReady(func(db *sql.DB) { routesSvc.DB = db })

	// Wire the wizard's self-bootstrap hook now that routesSvc exists.
	// CaddySubmit will call this once the operator's first node is inserted.
	wizard.ResyncNode = routesSvc.Resync

	mailer := &mail.Mailer{
		DB:     wizard.DB(),
		State:  state,
		Logger: logger,
	}
	// Refresh mailer DB once pool is live (covers slow boot).
	bindDBWhenReady(func(db *sql.DB) { mailer.DB = db })

	captchaV := captcha.New(cfg.Security.CaptchaProvider, cfg.Security.CaptchaSecret)
	captchaV.SetSiteKey(cfg.Security.CaptchaSiteKey)
	captchaV.DB = wizard.DB
	captchaV.State = state

	oidcSvc := &hpgoidc.Service{DB: wizard.DB(), State: state}
	// Bind DB lazily if pool not ready yet.
	bindDBWhenReady(func(db *sql.DB) { oidcSvc.DB = db })

	wgSvc := &wireguard.Service{DB: wizard.DB, State: state}
	wgCW := &wireguard.ConfigWriter{Dir: "/app/wg"}
	writeWG := func(ctx context.Context) error {
		db := wizard.DB()
		if db == nil {
			return errors.New("db not ready")
		}
		cp, err := wgSvc.Get(ctx)
		if err != nil {
			return err
		}
		if !cp.Enabled {
			return errors.New("wireguard mode disabled in Settings")
		}
		return wgCW.Write(ctx, db, cp)
	}
	joinSvc := &nodejoin.Service{DB: wizard.DB, WG: wgSvc, WriteWGConfig: writeWG}

	cfSvc := cloudflare.New(wizard.DB, state)
	// Seed refresh so middleware has correct trust flag on first request.
	go func() {
		time.Sleep(2 * time.Second)
		ctx, cancel := context.WithTimeout(rootCtx, 3*time.Second)
		defer cancel()
		cfSvc.Refresh(ctx)
		captchaV.Refresh(ctx)
	}()

	// Construct Prometheus metrics early so handler structs can hold a pointer
	// at init time. Route/WG gauges that need DB-backed funcs are wired later.
	mtr := obs.New()

	authH := &handlers.AuthHandlers{
		DB: wizard.DB, Sessions: sessions, Templates: authTpls, Logger: logger,
		RDB: rdb, Mailer: mailer, Captcha: captchaV, OIDC: oidcSvc, AppURL: cfg.App.URL,
		State: state, Metrics: mtr,
		// SMS wired after smsSvc is declared below; see lazy assignment.
	}
	backupSvc := &backup.Service{
		DB:            wizard.DB,
		State:         state,
		Logger:        logger,
		StateFilePath: stateDir + "/install_state.json",
		WGConfigDir:   "/app/wg",
	}
	// Wire the webhook emitter once whSvc exists (declared a few lines below).
	// Pointer set after construction; backup.Run reads it lazily.

	whSvc := webhook.New(wizard.DB, state, logger)
	backupSvc.Webhooks = whSvc
	smsSvc := sms.New(wizard.DB(), logger)
	smsSvc.State = state
	authH.SMS = smsSvc
	notifier := &notify.Customer{DB: wizard.DB, Mail: mailer, SMS: smsSvc, Logger: logger}
	routesSvc.Notifier = notifier
	// Alert evaluator (leader-only ticker wired below; deduped via alert_log).
	alertEval := &alert.Evaluator{
		DB: wizard.DB, Logger: logger,
		Webhooks: whSvc, Mailer: mailer, SMS: smsSvc,
		Cfg: alert.LoadConfig(),
	}
	// SIEM audit forwarder (nil-safe; disabled when AUDIT_SIEM_WEBHOOK empty).
	siemFwd, err := audit.NewForwarder(cfg.Security.SIEMWebhook, logger)
	if err != nil {
		return fmt.Errorf("AUDIT_SIEM_WEBHOOK invalid: %w", err)
	}
	// Register process-wide so every audit.Write forwards (149 call-sites).
	audit.SetDefaultForwarder(siemFwd)
	// Access log store + live-tail broker. RouteByDomain resolves the host to a
	// route_id so the ingest handler can tag each log line.
	alStore := accesslog.New(wizard.DB)
	alBroker := accesslog.NewBroker()
	alIngest := &accesslog.IngestHandler{
		Store:  alStore,
		Broker: alBroker,
		Logger: logger,
		RouteByDomain: func(ctx context.Context, domain string) (int64, bool) {
			db := wizard.DB()
			if db == nil {
				return 0, false
			}
			var id int64
			if err := db.QueryRowContext(ctx,
				"SELECT id FROM routes WHERE domain = ? LIMIT 1", domain,
			).Scan(&id); err != nil {
				return 0, false
			}
			return id, true
		},
		// Validate the per-node agent token against caddy_nodes.agent_token_hash,
		// the same credential the WG/stats node endpoints use.
		AuthNode: func(ctx context.Context, token string) bool {
			db := wizard.DB()
			if db == nil {
				return false
			}
			var id int64
			err := db.QueryRowContext(ctx,
				`SELECT id FROM caddy_nodes WHERE agent_token_hash IS NOT NULL AND agent_token_hash = SHA2(?, 256) LIMIT 1`,
				token,
			).Scan(&id)
			return err == nil && id > 0
		},
	}

	wafStore := wafevents.New(wizard.DB)
	adminH := &handlers.AdminHandlers{
		DB: wizard.DB, Sessions: sessions, Templates: adminTpls, Logger: logger,
		State: state, Mailer: mailer, OIDC: oidcSvc, Cloudflare: cfSvc, Captcha: captchaV,
		Joiner: joinSvc, WG: wgSvc, Backups: backupSvc, Webhooks: whSvc, SMS: smsSvc,
		RDB: rdb, Metrics: mtr,
		SIEMForwarder:   siemFwd,
		Enforce2FAEnv:   cfg.Security.RequireAdmin2FA,
		AdminScope:      adminscope.New(wizard.DB),
		AccessLogs:      alStore,
		AccessLogBroker: alBroker,
		WAFEvents:       wafStore,
	}

	// Bash bootstrap script served at GET /install/node.sh.
	scriptBody, err := handlers.LoadScriptFromFS(proxygateway.ScriptsFS, "scripts/node-join.sh")
	if err != nil {
		return err
	}
	joinH := &handlers.NodeJoinHandler{
		DB:          wizard.DB,
		Logger:      logger,
		Joiner:      joinSvc,
		AskURL:      buildAskURL(cfg),
		ACMEEmail:   cfg.Caddy.ACMEEmail,
		ScriptBody:  scriptBody,
		ScriptName:  "node-join.sh",
		RDB:         rdb,
		PerIPPerMin: 10,
		Webhooks:    whSvc,
	}
	adminH.SetConfigRefs(&routesSvc.ACMEEmail, &routesSvc.ACMEStaging)
	adminH.ResyncNode = routesSvc.Resync
	adminH.Routes = routesSvc
	adminH.WriteWGConfig = writeWG
	clientH := &handlers.ClientHandlers{
		DB: wizard.DB, Sessions: sessions, Templates: appTpls, Routes: routesSvc, Logger: logger,
		State: state, SMS: smsSvc, Mailer: mailer,
	}

	// Passkey/WebAuthn (nil-safe). Requires a valid App.URL to derive RPID.
	var passkeyH *handlers.PasskeyHandlers
	if wa, err := auth.NewWebAuthn(cfg.App.URL, "Hostyt Proxy Gateway"); err != nil {
		logger.Warn("passkeys disabled: bad App.URL for WebAuthn RPID", "err", err)
	} else {
		passkeyH = &handlers.PasskeyHandlers{
			DB: wizard.DB, RDB: rdb, Sessions: sessions, Logger: logger, WA: wa,
			Metrics: mtr,
		}
		authH.PasskeyEnabled = true
	}
	askH := &handlers.AskHandler{
		DB:          wizard.DB,
		RDB:         rdb,
		Logger:      logger,
		Metrics:     mtr,
		PerIPPerMin: cfg.Security.RateLimitAskPerMin,
	}
	apiH := &handlers.APIHandlers{
		DB:     wizard.DB,
		Logger: logger,
		Routes: routesSvc,
	}

	// Customer-WG bootstrap + node-agent endpoints.
	wgPeerSvc := &wgpeer.Service{
		DB:     wizard.DB(),
		Logger: logger,
		Enc:    state,
	}
	wgBootH := &handlers.WGBootstrapHandler{
		DB:          wizard.DB,
		Logger:      logger,
		Peers:       wgPeerSvc,
		RDB:         rdb,
		PerIPPerMin: 60,
		AppURL:      cfg.App.URL,
		// wstunnel health changed: resync so the WSS /wg-tunnel route is added
		// (healthy) or the stale route removed (unhealthy) - drift won't.
		OnWstunnelHealthy: func(nodeID int64) {
			go func() {
				defer func() { _ = recover() }()
				ctx, cancel := context.WithTimeout(routesSvc.BackgroundCtx(), 30*time.Second)
				defer cancel()
				if err := routesSvc.Resync(ctx, nodeID); err != nil {
					logger.Error("wstunnel health resync failed", "node_id", nodeID, "err", err)
				}
			}()
		},
	}
	adminH.WGPeers = wgPeerSvc
	clientH.SetWGPeers(wgPeerSvc)

	// Panel observability: route/WG gauges wired now that DB-backed funcs exist.
	mtr.SetRouteGauges(
		func() int {
			db := wizard.DB()
			if db == nil {
				return 0
			}
			// Bound the scrape query: a slow/deadlocked DB must not pin the
			// Prometheus scrape goroutine on a pool conn indefinitely.
			ctx, cancel := context.WithTimeout(rootCtx, 2*time.Second)
			defer cancel()
			var n int
			_ = db.QueryRowContext(ctx,
				"SELECT COUNT(*) FROM routes WHERE status IN ('active','dns_ok','pending_ssl')").Scan(&n)
			return n
		},
		func() int {
			db := wizard.DB()
			if db == nil {
				return 0
			}
			ctx, cancel := context.WithTimeout(rootCtx, 2*time.Second)
			defer cancel()
			var n int
			_ = db.QueryRowContext(ctx,
				"SELECT COUNT(*) FROM caddy_nodes WHERE is_enabled = 1 AND health_status = 'healthy'").Scan(&n)
			return n
		},
	)
	routesSvc.Metrics = mtr
	// DB pool saturation gauges (pool is 50/15); alert on wait_count climbing.
	mtr.SetDBPoolGauges(func() sql.DBStats {
		if db := wizard.DB(); db != nil {
			return db.Stats()
		}
		return sql.DBStats{}
	})

	// WG observability: active peer count + worst handshake-age. Wired
	// here so the Prometheus scrape can alert on stale tunnels.
	mtr.SetWGGauges(
		func() int {
			db := wizard.DB()
			if db == nil {
				return 0
			}
			ctx, cancel := context.WithTimeout(rootCtx, 2*time.Second)
			defer cancel()
			var n int
			_ = db.QueryRowContext(ctx,
				`SELECT COUNT(*) FROM customer_wg_peer WHERE status='active'`).Scan(&n)
			return n
		},
		func() float64 {
			db := wizard.DB()
			if db == nil {
				return 0
			}
			ctx, cancel := context.WithTimeout(rootCtx, 2*time.Second)
			defer cancel()
			var v sql.NullFloat64
			_ = db.QueryRowContext(ctx,
				`SELECT MAX(TIMESTAMPDIFF(SECOND, last_handshake_at, NOW()))
				   FROM customer_wg_peer
				  WHERE status='active' AND last_handshake_at IS NOT NULL`).Scan(&v)
			if v.Valid {
				return v.Float64
			}
			return 0
		},
	)

	// Leader election: in a multi-replica deploy only the leader runs
	// background workers (health probe, metrics poller, reconciler, drift
	// probe, backup scheduler). Single-replica deploys always lead.
	leaderElec := leader.New(rdb)
	go leaderElec.Run(rootCtx)

	health := &obs.Health{
		DB:        wizard.DB,
		RDB:       rdb,
		IsLeader:  leaderElec.IsLeader,
		Installed: state.IsInstalled,
	}

	// Boot push: re-pushes DB config to every enabled node so a Caddy
	// restart (lost autosave) self-heals without waiting for drift probe.
	go func() {
		select {
		case <-rootCtx.Done():
			return
		case <-time.After(10 * time.Second):
		}
		if !leaderElec.IsLeader() {
			return
		}
		guard(logger, "boot-push", routesSvc.PushAll)(rootCtx)
	}()

	// Background node health probe — leader-only.
	go runTicker(rootCtx, 30*time.Second, leaderElec, guard(logger, "health-probe", routesSvc.HealthProbe))

	// Background route reconciler — leader-only, picks up stuck routes.
	go runTicker(rootCtx, 60*time.Second, leaderElec, guard(logger, "reconcile", routesSvc.Reconcile))

	// Background drift probe — leader-only, 5 min cadence.
	go runTicker(rootCtx, 5*time.Minute, leaderElec, guard(logger, "drift", routesSvc.ReconcileDrift))

	// Auto-failover: routes on down nodes (≥5 min) migrate to healthy
	// peers in the same group; leader-only, 2 min cadence.
	go runTicker(rootCtx, 2*time.Minute, leaderElec, guard(logger, "failover", routesSvc.AutoFailover))

	// Webhook dispatcher — leader-only, 30s cadence.
	go runTicker(rootCtx, 30*time.Second, leaderElec, guard(logger, "webhooks", whSvc.Dispatch))
	// Alert evaluator - leader-only, 60s cadence; deduped via alert_log.
	go runTicker(rootCtx, 60*time.Second, leaderElec, guard(logger, "alert-eval", alertEval.Tick))
	routesSvc.Webhooks = whSvc

	// Audit + webhook retention prune — leader-only, hourly.
	go runTicker(rootCtx, time.Hour, leaderElec, guard(logger, "audit-prune", func(ctx context.Context) {
		db := wizard.DB()
		if db == nil {
			return
		}
		if n, err := audit.Prune(ctx, db); err == nil && n > 0 {
			logger.Info("audit retention prune", "rows", n)
		}
	}))

	// Background Caddy metrics poller (60s interval) — leader-only.
	go runLeaderOnly(rootCtx, leaderElec, guard(logger, "metrics-poller", func(ctx context.Context) {
		metrics.New(wizard.DB, logger).Run(ctx)
	}))

	// Background backup scheduler (interval setting in DB; 0 = disabled) —
	// leader-only.
	go runLeaderOnly(rootCtx, leaderElec, guard(logger, "backup-scheduler", func(ctx context.Context) {
		(&backup.Scheduler{Service: backupSvc}).Run(ctx)
	}))

	// Backup restore drill — leader-only, 72h cadence.
	drillJob := &jobs.BackupDrillJob{DB: wizard.DB, State: state, Logger: logger}
	adminH.DrillJob = drillJob
	go runLeaderOnly(rootCtx, leaderElec, guard(logger, "backup-drill", drillJob.Run))

	// WG peer key rotation — leader-only, 6h cadence.
	go runLeaderOnly(rootCtx, leaderElec, guard(logger, "wg-key-rotation", func(ctx context.Context) {
		(&jobs.WGKeyRotationJob{DB: wizard.DB, Logger: logger, Peers: wgPeerSvc}).Run(ctx)
	}))

	statusPageH := &handlers.StatusPageHandlers{
		DB:        wizard.DB,
		Templates: statusTpls,
		Logger:    logger,
	}
	srv := httpserver.New(httpserver.Deps{
		Config:          cfg,
		Logger:          logger,
		InstallState:    state,
		Sessions:        sessions,
		Wizard:          wizard,
		Auth:            authH,
		Admin:           adminH,
		Client:          clientH,
		Ask:             askH,
		API:             apiH,
		APIDocs:         &handlers.APIDocsHandler{DB: wizard.DB},
		Passkey:         passkeyH,
		NodeJoin:        joinH,
		WGBoot:          wgBootH,
		TrustCFIP:       cfSvc.TrustConnectingIP,
		Metrics:         mtr,
		Health:          health,
		RDB:             rdb,
		StaticFS:        proxygateway.StaticFS,
		StatusPage:      statusPageH,
		AccessLogIngest: alIngest,
		FOSSBilling: &handlers.FOSSBillingHandlers{
			DB:     wizard.DB,
			Routes: routesSvc,
		},
	})

	httpSrv := &http.Server{
		Addr:              cfg.App.Bind,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		logger.Info("http server starting", "addr", cfg.App.Bind, "env", cfg.App.Env, "installed", state.IsInstalled())
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("http server error", "err", err)
			stop()
		}
	}()

	<-rootCtx.Done()
	logger.Info("shutdown signal received")

	// Drain longer than WriteTimeout (30s) so a request admitted just before
	// SIGTERM isn't cut mid-response.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	err = httpSrv.Shutdown(shutdownCtx)
	// HTTP drained: now cancel background pushes so they don't outlive exit.
	bgCancel()
	return err
}

// guard wraps a background task so a panic is logged and swallowed instead
// of crashing the whole process. Unlike HTTP handlers, background goroutines
// have no Recoverer middleware, so one nil-deref in a reconciler/poller would
// otherwise take down the entire control plane.
func guard(logger *slog.Logger, name string, fn func(context.Context)) func(context.Context) {
	return func(ctx context.Context) {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("background task panicked", "task", name, "panic", r, "stack", string(debug.Stack()))
			}
		}()
		fn(ctx)
	}
}

// runTicker fires fn on every interval tick, but only when leaderElec says
// this replica is the leader. Non-leader ticks are skipped silently, so a
// hot standby just waits.
func runTicker(ctx context.Context, interval time.Duration, le *leader.Election, fn func(context.Context)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if le.IsLeader() {
				fn(ctx)
			}
		}
	}
}

// runLeaderOnly invokes `fn` (a blocking loop, e.g. metrics.Poller.Run) only
// while this replica is the leader. On lose-leadership the inner ctx is
// cancelled; on re-acquire fn is invoked again. Use for long-running
// goroutines, not per-tick callbacks (those go through runTicker).
func runLeaderOnly(parent context.Context, le *leader.Election, fn func(context.Context)) {
	for {
		select {
		case <-parent.Done():
			return
		default:
		}
		if !le.IsLeader() {
			time.Sleep(2 * time.Second)
			continue
		}
		runOneLeaderTerm(parent, le, fn)
	}
}

// runOneLeaderTerm starts `fn` and tears it down when either the parent ctx
// ends, fn returns on its own, or we lose leadership. cancel is always
// invoked exactly once via defer so no derived context leaks.
func runOneLeaderTerm(parent context.Context, le *leader.Election, fn func(context.Context)) {
	innerCtx, cancel := context.WithCancel(parent)
	defer cancel()
	done := make(chan struct{})
	go func() {
		fn(innerCtx)
		close(done)
	}()
	watch := time.NewTicker(2 * time.Second)
	defer watch.Stop()
	for {
		select {
		case <-parent.Done():
			cancel()
			<-done
			return
		case <-done:
			return
		case <-watch.C:
			if !le.IsLeader() {
				cancel()
				<-done
				return
			}
		}
	}
}

// buildAskURL points Caddy nodes at this app's /internal/ask endpoint.
// In Docker Compose this is "http://app:8080/internal/ask". Fall back to
// APP_URL if APP_INTERNAL_URL is unset.
// pushDebounceMs reads HPG_PUSH_DEBOUNCE_MS; returns 500 when unset or invalid.
func pushDebounceMs() int {
	v := os.Getenv("HPG_PUSH_DEBOUNCE_MS")
	if v == "" {
		return 500
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 500
	}
	return n
}

func buildAskURL(cfg *config.Config) string {
	if v := os.Getenv("APP_INTERNAL_URL"); v != "" {
		return v + "/internal/ask"
	}
	// app service name on the internal Docker network.
	return "http://app:8080/internal/ask"
}

// panelPublicHost extracts the bare hostname from APP_URL ("https://proxy.example.com"
// → "proxy.example.com"). Returns "" if APP_URL is malformed or missing, in
// which case the self-bootstrap route is skipped and the operator must
// add the panel's host manually after install.
func panelPublicHost(appURL string) string {
	if appURL == "" {
		return ""
	}
	u, err := url.Parse(appURL)
	if err != nil || u.Host == "" {
		return ""
	}
	// Strip the optional :port suffix — Caddy matches on host only and the
	// public port is fixed at 80/443 by the listener config.
	if i := strings.IndexByte(u.Host, ':'); i >= 0 {
		return u.Host[:i]
	}
	return u.Host
}

func pingRedis(ctx context.Context, rdb *redis.Client, timeout time.Duration) error {
	pingCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		if err := rdb.Ping(pingCtx).Err(); err == nil {
			return nil
		}
		if pingCtx.Err() != nil {
			return errors.New("redis ping timeout")
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}
