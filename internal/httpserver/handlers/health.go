// Package handlers contains HTTP handlers grouped by concern.
//
// Handlers are kept thin: parse request, call domain service, render response.
// All business logic lives in internal/domain/*.
package handlers

import (
	"encoding/json"
	"net/http"
)

func Health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Ready is a 503 stub. Real impl lives in obs.Health.Ready and is wired
// by main.go. This fallback fires only if deps.Health is nil (tests
// without full bootstrap) — return 503 so a misconfigured deploy fails
// loud instead of silently reporting healthy.
func Ready(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusServiceUnavailable, map[string]any{
		"status": "degraded",
		"error":  "health checks not wired",
	})
}

func APIHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": "0.1.174"})
}

// Favicon returns 204 No Content so browsers stop logging 404s for /favicon.ico.
func Favicon(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func notImplemented(w http.ResponseWriter, name string) {
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error":   "not_implemented",
		"handler": name,
	})
}
