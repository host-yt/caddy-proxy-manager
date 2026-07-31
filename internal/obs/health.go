package obs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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
	// GenerationCheck returns nil while this replica may admit traffic under
	// the fleet session-generation fence, and an error while it may not (own
	// heartbeat unpublished, or a newer generation live that enforces
	// Restricted/Epoch more strictly). Optional - nil skips the check.
	GenerationCheck func(ctx context.Context) error
	// Serving reports whether this process actually owns and serves its HTTP
	// listener. Part of the local prerequisites so a replica that failed to
	// bind never advertises its generation. Optional - nil skips the check.
	Serving   func(ctx context.Context) error
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
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	allOK := h.checkLocal(ctx, checks) == nil

	// Fleet generation. Serving while a newer generation is live would let a
	// confined admin reach this more lenient replica; not being visible to the
	// fleet at all means peers cannot fence against us either.
	if h.GenerationCheck != nil {
		if err := h.GenerationCheck(ctx); err != nil {
			h.logCheckFail("cluster-generation", err)
			checks["cluster-generation"] = "fail"
			allOK = false
		} else {
			checks["cluster-generation"] = "ok"
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

// LocalServingReady reports this process's own serving prerequisites, i.e.
// everything /readyz checks except the fleet fence. The generation beacon uses
// it so a replica that cannot serve never advertises its generation and so
// cannot wedge healthy older replicas into permanent unreadiness.
func (h *Health) LocalServingReady(ctx context.Context) error {
	return h.checkLocal(ctx, nil)
}

// checkLocal runs the DB/Redis/install prerequisites, recording each outcome in
// checks when non-nil, and returns the first failure.
func (h *Health) checkLocal(ctx context.Context, checks map[string]string) error {
	set := func(k, v string) {
		if checks != nil {
			checks[k] = v
		}
	}
	var firstErr error
	fail := func(name string, err error) {
		h.logCheckFail(name, err)
		set(name, "fail")
		if firstErr == nil {
			firstErr = fmt.Errorf("%s: %w", name, err)
		}
	}

	var db *sql.DB
	if h.DB != nil {
		db = h.DB()
	}
	switch {
	case db != nil:
		if err := db.PingContext(ctx); err != nil {
			fail("db", err)
		} else {
			set("db", "ok")
		}
	case h.Installed != nil && h.Installed():
		fail("db", errors.New("no pool after install"))
	default:
		set("db", "skip: pre-install")
	}

	if h.Serving != nil {
		if err := h.Serving(ctx); err != nil {
			fail("serving", err)
		} else {
			set("serving", "ok")
		}
	}

	if h.RDB != nil {
		if err := h.RDB.Ping(ctx).Err(); err != nil {
			fail("redis", err)
		} else {
			set("redis", "ok")
		}
	}

	// Pre-install panel is still "ready to serve the wizard", just not the
	// full app - not a failure.
	if h.Installed != nil {
		if h.Installed() {
			set("install", "ok")
		} else {
			set("install", "pending")
		}
	}
	return firstErr
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
