package obs

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// Health wraps deep liveness/readiness checks against DB + Redis + the
// leader-election state. /healthz returns 200 only when the panel can
// actually serve requests; /readyz indicates "fully wired up" (DB has
// migrations applied; leader designation resolved at least once).
type Health struct {
	DB        func() *sql.DB
	RDB       *redis.Client
	IsLeader  func() bool
	Installed func() bool
	ReadySeen atomic.Bool // set true after first successful boot
	// Logger, when set, receives the raw check error server-side; the
	// unauthenticated /readyz response only ever gets "ok"/"fail".
	Logger *slog.Logger
}

// HealthResponse is the JSON body returned by /healthz/readyz.
type HealthResponse struct {
	Status string            `json:"status"`
	Checks map[string]string `json:"checks"`
}

// Live is a cheap "process alive" check — used by container orchestrators
// for restart-on-stuck. It is fast and intentionally shallow.
func (h *Health) Live(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, HealthResponse{Status: "ok", Checks: map[string]string{"process": "ok"}})
}

// Ready is the "I can serve traffic" probe. Verifies DB ping + Redis ping
// and that the install state is healthy. 503 on any check failure.
func (h *Health) Ready(w http.ResponseWriter, r *http.Request) {
	checks := map[string]string{}
	allOK := true
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	// DB.
	if db := h.DB(); db != nil {
		if err := db.PingContext(ctx); err != nil {
			h.logCheckFail("db", err)
			checks["db"] = "fail"
			allOK = false
		} else {
			checks["db"] = "ok"
		}
	} else if h.Installed != nil && h.Installed() {
		checks["db"] = "fail"
		allOK = false
	} else {
		checks["db"] = "skip: pre-install"
	}

	// Redis.
	if h.RDB != nil {
		if err := h.RDB.Ping(ctx).Err(); err != nil {
			h.logCheckFail("redis", err)
			checks["redis"] = "fail"
			allOK = false
		} else {
			checks["redis"] = "ok"
		}
	}

	// Install state.
	if h.Installed != nil {
		if h.Installed() {
			checks["install"] = "ok"
		} else {
			checks["install"] = "pending"
			// Pre-install panel is still "ready to serve the wizard",
			// just not the full app. Don't fail readyz for it.
		}
	}

	// Leader designation. Not required to be leader to serve HTTP; report
	// for observability only.
	if h.IsLeader != nil {
		if h.IsLeader() {
			checks["leader"] = "leader"
		} else {
			checks["leader"] = "standby"
		}
	}

	if allOK {
		h.ReadySeen.Store(true)
		writeJSON(w, http.StatusOK, HealthResponse{Status: "ok", Checks: checks})
		return
	}
	writeJSON(w, http.StatusServiceUnavailable, HealthResponse{Status: "degraded", Checks: checks})
}

// logCheckFail keeps infra error detail (hostnames, ports, driver errors)
// out of the unauthenticated /readyz body while still surfacing it to ops.
func (h *Health) logCheckFail(check string, err error) {
	if h.Logger != nil {
		h.Logger.Warn("readyz check failed", "check", check, "err", err)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
