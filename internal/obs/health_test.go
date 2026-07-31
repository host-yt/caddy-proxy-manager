package obs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// noDB stands in for the real DB() accessor; Health.Ready calls it
// unconditionally, so tests that don't care about the DB check still need it.
func noDB() *sql.DB { return nil }

// TestReadyFailsOnIncompatibleGeneration guards the rolling-upgrade fence:
// Ready() must refuse traffic while a newer session generation owns the
// fleet, since this replica may not enforce the same Restricted/Epoch rules.
func TestReadyFailsOnIncompatibleGeneration(t *testing.T) {
	h := &Health{
		DB:              noDB,
		GenerationCheck: func(context.Context) error { return errors.New("newer generation live") },
	}
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()
	h.Ready(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
	var resp HealthResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Checks["cluster-generation"] != "fail" {
		t.Fatalf("checks[cluster-generation] = %q, want fail", resp.Checks["cluster-generation"])
	}
}

// TestReadyFailsOnGenerationCheckError mirrors the legacy-watch rule: an
// unreadable fleet state must not be treated as "no incompatible peer".
func TestReadyFailsOnGenerationCheckError(t *testing.T) {
	h := &Health{
		DB:              noDB,
		GenerationCheck: func(context.Context) error { return errors.New("scan failed") },
	}
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()
	h.Ready(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

// TestLocalServingReadyGatesTheBeacon: the generation beacon must advertise
// only when this process can serve on its own merits, and must ignore the
// fence itself (otherwise a fenced replica could never withdraw cleanly).
func TestLocalServingReadyGatesTheBeacon(t *testing.T) {
	installed := true
	h := &Health{
		DB:              noDB,
		Installed:       func() bool { return installed },
		GenerationCheck: func(context.Context) error { return errors.New("newer generation live") },
	}
	if err := h.LocalServingReady(context.Background()); err == nil {
		t.Fatal("installed panel without a DB pool must not advertise a generation")
	}

	installed = false
	if err := h.LocalServingReady(context.Background()); err != nil {
		t.Fatalf("pre-install panel serves the wizard and must advertise, got %v", err)
	}
}

// TestReadyOKWithoutIncompatiblePeer confirms a clean fleet (or no check
// wired at all) still passes readiness.
func TestReadyOKWithoutIncompatiblePeer(t *testing.T) {
	h := &Health{
		DB:              noDB,
		GenerationCheck: func(context.Context) error { return nil },
	}
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()
	h.Ready(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
}
