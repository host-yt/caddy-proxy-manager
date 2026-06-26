// Package obs centralises the panel's own observability surface:
// Prometheus metrics + deep liveness/readiness checks. Distinct from
// `internal/metrics` (which scrapes Caddy nodes from the control plane).
package obs

import (
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics aggregates every panel-side gauge/counter/histogram. One global
// instance per process; constructed once in main.go and shared.
type Metrics struct {
	reg          *prometheus.Registry
	requestCount *prometheus.CounterVec
	requestDur   *prometheus.HistogramVec
	requestSize  *prometheus.HistogramVec
	respSize     *prometheus.HistogramVec
	inflight     prometheus.Gauge

	caddyPush     *prometheus.CounterVec
	caddyPushDur  *prometheus.HistogramVec
	caddyDrift    prometheus.Counter
	nodeProbeFail *prometheus.CounterVec

	routeReady   prometheus.GaugeFunc
	nodesHealthy prometheus.GaugeFunc
	backupRuns   *prometheus.CounterVec
	backupBytes  *prometheus.CounterVec
	backupLast   *prometheus.GaugeVec
	leaderGauge  *prometheus.GaugeVec
	apiKeyDenied *prometheus.CounterVec

	// Auth + 2FA + passkeys
	loginEvents    *prometheus.CounterVec // labels: outcome, via, mfa
	otpAttempts    *prometheus.CounterVec // labels: kind, outcome
	sessionEvents  *prometheus.CounterVec // labels: event
	passkeyOps     *prometheus.CounterVec // labels: op, outcome
	csrfDenied     prometheus.Counter
	bruteforceLock prometheus.Counter

	// Cache + node ops
	cacheOps *prometheus.CounterVec // labels: op, outcome

	// Email + SMS
	mailSends *prometheus.CounterVec // labels: template, outcome
	smsSends  *prometheus.CounterVec // labels: provider, outcome

	// Routes / DNS / SSL
	routeOps *prometheus.CounterVec // labels: op, outcome
	dnsCheck *prometheus.CounterVec // labels: outcome

	// Webhooks
	webhookDeliveries *prometheus.CounterVec // labels: outcome
	webhookDur        prometheus.Histogram

	// Rate-limit / abuse
	rateLimitHits *prometheus.CounterVec // labels: bucket

	// On-Demand TLS /internal/ask
	askDecisions *prometheus.CounterVec // labels: host, outcome
}

// New returns a Metrics with all collectors registered against a fresh
// registry. The Go runtime collector + process collector are intentionally
// excluded — the panel is small, default scrape interval covers it.
func New() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{reg: reg}

	m.requestCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "hpg_http_requests_total",
		Help: "HTTP requests handled by the panel, by method and status class.",
	}, []string{"method", "status"})

	m.requestDur = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "hpg_http_request_seconds",
		Help:    "Wall time spent in the HTTP handler chain.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method"})

	m.caddyPush = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "hpg_caddy_push_total",
		Help: "Caddy admin /load calls from the control plane, by outcome.",
	}, []string{"outcome"})

	m.caddyDrift = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "hpg_caddy_drift_resync_total",
		Help: "Drift-detection-triggered resyncs.",
	})

	m.backupRuns = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "hpg_backup_runs_total",
		Help: "Backup runs, by destination kind and outcome.",
	}, []string{"kind", "outcome"})

	m.leaderGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "hpg_leader",
		Help: "1 if this replica currently holds the singleton lock, 0 otherwise.",
	}, []string{"replica"})

	m.apiKeyDenied = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "hpg_api_key_denied_total",
		Help: "API requests rejected, by reason.",
	}, []string{"reason"})

	m.requestSize = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "hpg_http_request_bytes",
		Help:    "Request body size (bytes) per route group.",
		Buckets: prometheus.ExponentialBuckets(64, 4, 8),
	}, []string{"method"})
	m.respSize = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "hpg_http_response_bytes",
		Help:    "Response body size (bytes) per method.",
		Buckets: prometheus.ExponentialBuckets(64, 4, 8),
	}, []string{"method"})
	m.inflight = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "hpg_http_inflight_requests",
		Help: "HTTP requests currently being handled.",
	})

	m.caddyPushDur = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "hpg_caddy_push_seconds",
		Help:    "Wall time of Caddy admin /load calls, by node id.",
		Buckets: prometheus.DefBuckets,
	}, []string{"node_id"})
	m.nodeProbeFail = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "hpg_caddy_node_probe_failures_total",
		Help: "Health-probe failures per Caddy node.",
	}, []string{"node_id"})

	m.backupBytes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "hpg_backup_bytes_total",
		Help: "Total compressed bytes shipped to a backup destination.",
	}, []string{"kind"})
	m.backupLast = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "hpg_backup_last_success_unixtime",
		Help: "Unix timestamp of the last successful backup, by destination kind.",
	}, []string{"kind"})

	m.loginEvents = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "hpg_login_events_total",
		Help: "Login attempts by outcome, entry path, and MFA factor.",
	}, []string{"outcome", "via", "mfa"})
	m.otpAttempts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "hpg_otp_attempts_total",
		Help: "OTP verifications by kind and outcome.",
	}, []string{"kind", "outcome"})
	m.sessionEvents = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "hpg_session_events_total",
		Help: "Session lifecycle events.",
	}, []string{"event"})
	m.passkeyOps = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "hpg_passkey_ops_total",
		Help: "Passkey (WebAuthn) operations by op and outcome.",
	}, []string{"op", "outcome"})
	m.csrfDenied = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "hpg_csrf_denied_total",
		Help: "Requests rejected by the CSRF middleware.",
	})
	m.bruteforceLock = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "hpg_login_lockout_total",
		Help: "Number of login attempts blocked by brute-force lockout.",
	})

	m.cacheOps = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "hpg_cache_ops_total",
		Help: "Cache control-plane operations by op and outcome.",
	}, []string{"op", "outcome"})

	m.mailSends = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "hpg_mail_sends_total",
		Help: "Email sends by template name and outcome.",
	}, []string{"template", "outcome"})
	m.smsSends = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "hpg_sms_sends_total",
		Help: "SMS sends by provider and outcome.",
	}, []string{"provider", "outcome"})

	m.routeOps = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "hpg_route_ops_total",
		Help: "Route CRUD and lifecycle ops by op and outcome.",
	}, []string{"op", "outcome"})
	m.dnsCheck = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "hpg_dns_check_total",
		Help: "Route DNS preflight checks by outcome.",
	}, []string{"outcome"})

	m.webhookDeliveries = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "hpg_webhook_deliveries_total",
		Help: "Outbound webhook deliveries by outcome.",
	}, []string{"outcome"})
	m.webhookDur = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "hpg_webhook_seconds",
		Help:    "Webhook delivery wall time.",
		Buckets: prometheus.DefBuckets,
	})

	m.rateLimitHits = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "hpg_rate_limit_hits_total",
		Help: "Rate-limit rejections by bucket name.",
	}, []string{"bucket"})

	m.askDecisions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "hpg_ask_decisions_total",
		Help: "/internal/ask On-Demand TLS decisions by outcome.",
	}, []string{"outcome"})

	reg.MustRegister(m.requestCount, m.requestDur, m.requestSize, m.respSize, m.inflight,
		m.caddyPush, m.caddyPushDur, m.caddyDrift, m.nodeProbeFail,
		m.backupRuns, m.backupBytes, m.backupLast,
		m.leaderGauge, m.apiKeyDenied,
		m.loginEvents, m.otpAttempts, m.sessionEvents, m.passkeyOps, m.csrfDenied, m.bruteforceLock,
		m.cacheOps, m.mailSends, m.smsSends,
		m.routeOps, m.dnsCheck,
		m.webhookDeliveries, m.webhookDur,
		m.rateLimitHits, m.askDecisions)
	// Runtime collectors: enables go_goroutines + process_resident_memory_bytes
	// + GC stats — required to spot leaks during soak.
	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return m
}

// Handler returns an HTTP handler that serves Prometheus text format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{Registry: m.reg})
}

// Middleware records request count + duration + sizes + inflight. Wrap once.
func (m *Metrics) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		m.inflight.Inc()
		start := time.Now()
		next.ServeHTTP(rec, r)
		dur := time.Since(start).Seconds()
		m.inflight.Dec()
		m.requestDur.WithLabelValues(r.Method).Observe(dur)
		m.requestCount.WithLabelValues(r.Method, statusClass(rec.status)).Inc()
		if r.ContentLength > 0 {
			m.requestSize.WithLabelValues(r.Method).Observe(float64(r.ContentLength))
		}
		if rec.bytes > 0 {
			m.respSize.WithLabelValues(r.Method).Observe(float64(rec.bytes))
		}
	})
}

// ---- Domain helpers — keep handler code free of prometheus imports. ----

// LoginEvent records the outcome of a login attempt. outcome=success|fail.
func (m *Metrics) LoginEvent(outcome, via, mfa string) {
	if m == nil {
		return
	}
	m.loginEvents.WithLabelValues(outcome, via, mfa).Inc()
}

// OTPAttempt records an OTP verification (totp|sms|email|recovery|passkey).
func (m *Metrics) OTPAttempt(kind, outcome string) {
	if m == nil {
		return
	}
	m.otpAttempts.WithLabelValues(kind, outcome).Inc()
}

// SessionEvent records a session lifecycle event (create|destroy|bulk_kill).
func (m *Metrics) SessionEvent(event string) {
	if m == nil {
		return
	}
	m.sessionEvents.WithLabelValues(event).Inc()
}

// PasskeyOp records a passkey op (register|login) with outcome.
func (m *Metrics) PasskeyOp(op, outcome string) {
	if m == nil {
		return
	}
	m.passkeyOps.WithLabelValues(op, outcome).Inc()
}

// CSRFDenied increments the CSRF rejection counter.
func (m *Metrics) CSRFDenied() {
	if m == nil {
		return
	}
	m.csrfDenied.Inc()
}

// BruteforceLock increments the lockout counter.
func (m *Metrics) BruteforceLock() {
	if m == nil {
		return
	}
	m.bruteforceLock.Inc()
}

// CacheOp records a cache control-plane op (purge|introspect).
func (m *Metrics) CacheOp(op, outcome string) {
	if m == nil {
		return
	}
	m.cacheOps.WithLabelValues(op, outcome).Inc()
}

// MailSend records a Mailer send by template name + outcome.
func (m *Metrics) MailSend(template, outcome string) {
	if m == nil {
		return
	}
	m.mailSends.WithLabelValues(template, outcome).Inc()
}

// SMSSend records a Sender send by provider + outcome.
func (m *Metrics) SMSSend(provider, outcome string) {
	if m == nil {
		return
	}
	m.smsSends.WithLabelValues(provider, outcome).Inc()
}

// RouteOp records a route CRUD or lifecycle operation.
func (m *Metrics) RouteOp(op, outcome string) {
	if m == nil {
		return
	}
	m.routeOps.WithLabelValues(op, outcome).Inc()
}

// DNSCheck records a route DNS preflight outcome.
func (m *Metrics) DNSCheck(outcome string) {
	if m == nil {
		return
	}
	m.dnsCheck.WithLabelValues(outcome).Inc()
}

// WebhookDelivery records a webhook delivery outcome (and its duration).
func (m *Metrics) WebhookDelivery(outcome string, seconds float64) {
	if m == nil {
		return
	}
	m.webhookDeliveries.WithLabelValues(outcome).Inc()
	m.webhookDur.Observe(seconds)
}

// RateLimitHit records a rate-limit rejection by bucket name.
func (m *Metrics) RateLimitHit(bucket string) {
	if m == nil {
		return
	}
	m.rateLimitHits.WithLabelValues(bucket).Inc()
}

// AskDecision records a /internal/ask outcome. Label is outcome only
// (allow|deny|rate_limited): the endpoint is public and pre-auth, so labeling
// by the raw requested domain would let an attacker explode metric cardinality.
func (m *Metrics) AskDecision(outcome string) {
	if m == nil {
		return
	}
	m.askDecisions.WithLabelValues(outcome).Inc()
}

// NodePushDuration records the wall time of a Caddy push to a specific node.
func (m *Metrics) NodePushDuration(nodeID string, seconds float64) {
	if m == nil {
		return
	}
	m.caddyPushDur.WithLabelValues(nodeID).Observe(seconds)
}

// NodeProbeFail records a per-node health-probe failure.
func (m *Metrics) NodeProbeFail(nodeID string) {
	if m == nil {
		return
	}
	m.nodeProbeFail.WithLabelValues(nodeID).Inc()
}

// BackupBytes records bytes shipped to a destination kind.
func (m *Metrics) BackupBytes(kind string, n int64) {
	if m == nil {
		return
	}
	m.backupBytes.WithLabelValues(kind).Add(float64(n))
}

// BackupLastSuccess stamps the last successful unix timestamp for a kind.
func (m *Metrics) BackupLastSuccess(kind string, unix int64) {
	if m == nil {
		return
	}
	m.backupLast.WithLabelValues(kind).Set(float64(unix))
}

// SetWGGauges binds WireGuard tunnel observability gauges. activePeers
// returns the count of customer_wg_peer rows in `active` status;
// staleAgeMax returns the largest last_handshake_at age (in seconds)
// across active peers — > 180s typically means the customer-side
// wg-quick died. Pass nil to skip a gauge.
func (m *Metrics) SetWGGauges(activePeers func() int, staleAgeMax func() float64) {
	if activePeers != nil {
		g := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "hpg_wg_active_peers",
			Help: "Customer WG tunnel peers in 'active' status.",
		}, func() float64 { return float64(activePeers()) })
		m.reg.MustRegister(g)
	}
	if staleAgeMax != nil {
		g := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "hpg_wg_handshake_age_max_seconds",
			Help: "Largest WG handshake age across active peers (seconds since last_handshake_at).",
		}, staleAgeMax)
		m.reg.MustRegister(g)
	}
}

// SetRouteGauges binds runtime gauges that pull counts from supplied funcs.
// Pass nil to skip a gauge.
func (m *Metrics) SetRouteGauges(active func() int, healthy func() int) {
	if active != nil {
		m.routeReady = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "hpg_routes_active",
			Help: "Routes currently in active or dns_ok/pending_ssl state.",
		}, func() float64 { return float64(active()) })
		m.reg.MustRegister(m.routeReady)
	}
	if healthy != nil {
		m.nodesHealthy = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "hpg_caddy_nodes_healthy",
			Help: "Enabled nodes whose last probe returned healthy.",
		}, func() float64 { return float64(healthy()) })
		m.reg.MustRegister(m.nodesHealthy)
	}
}

// SetDBPoolGauges registers GaugeFuncs over sql.DB.Stats() so pool saturation
// (in-use vs open, wait count) is visible in Prometheus. stats is called on
// each scrape; nil-safe (skips registration).
func (m *Metrics) SetDBPoolGauges(stats func() sql.DBStats) {
	if stats == nil {
		return
	}
	reg := func(name, help string, pick func(sql.DBStats) float64) {
		m.reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: name, Help: help,
		}, func() float64 { return pick(stats()) }))
	}
	reg("hpg_db_open_connections", "Open DB connections (in use + idle).",
		func(s sql.DBStats) float64 { return float64(s.OpenConnections) })
	reg("hpg_db_in_use_connections", "DB connections currently in use.",
		func(s sql.DBStats) float64 { return float64(s.InUse) })
	reg("hpg_db_idle_connections", "Idle DB connections in the pool.",
		func(s sql.DBStats) float64 { return float64(s.Idle) })
	reg("hpg_db_wait_count_total", "Total connection waits (pool exhausted).",
		func(s sql.DBStats) float64 { return float64(s.WaitCount) })
	reg("hpg_db_wait_seconds_total", "Total time blocked waiting for a connection.",
		func(s sql.DBStats) float64 { return s.WaitDuration.Seconds() })
}

// Caddy push outcome counter. Wire from routes.Service via Inc helpers below.
func (m *Metrics) CaddyPushOK()      { m.caddyPush.WithLabelValues("ok").Inc() }
func (m *Metrics) CaddyPushFail()    { m.caddyPush.WithLabelValues("fail").Inc() }
func (m *Metrics) CaddyDriftResync() { m.caddyDrift.Inc() }

// Backup run outcome counter.
func (m *Metrics) BackupRun(kind, outcome string) {
	m.backupRuns.WithLabelValues(kind, outcome).Inc()
}

// Leader gauge — flip when election state changes.
func (m *Metrics) Leader(replica string, isLeader bool) {
	if isLeader {
		m.leaderGauge.WithLabelValues(replica).Set(1)
	} else {
		m.leaderGauge.WithLabelValues(replica).Set(0)
	}
}

// APIKeyDenied increments the rejection counter.
func (m *Metrics) APIKeyDenied(reason string) {
	m.apiKeyDenied.WithLabelValues(reason).Inc()
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
	bytes  int64
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wrote {
		s.status = code
		s.wrote = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wrote {
		s.status = 200
		s.wrote = true
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += int64(n)
	return n, err
}

// Unwrap exposes the wrapped writer so http.NewResponseController can reach
// the underlying Flusher/Hijacker - SSE streams (live tail) need Flush.
func (s *statusRecorder) Unwrap() http.ResponseWriter {
	return s.ResponseWriter
}

func statusClass(code int) string {
	switch {
	case code < 200:
		return "1xx"
	case code < 300:
		return "2xx"
	case code < 400:
		return "3xx"
	case code < 500:
		return "4xx"
	default:
		return "5xx"
	}
}

// _ keeps strconv usage stable if we extend status labels later.
var _ = strconv.Itoa
