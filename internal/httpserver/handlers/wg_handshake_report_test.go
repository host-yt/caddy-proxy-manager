package handlers

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNodeHandshakeReportJSONAndEmpty(t *testing.T) {
	db := openTestDBHandlers(t)
	nodeID, token := insertPSKNode(t, db, 0)
	h := pskTestHandler(db)
	post := func(ct, body string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/node/wg/handshakes", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", ct)
		rec := httptest.NewRecorder()
		h.NodeHandshakeReport(rec, req)
		return rec.Code
	}

	if c := post("application/json", `{"reports":[]}`); c != http.StatusBadRequest {
		t.Fatalf("empty JSON: %d, want 400", c)
	}
	if c := post("application/x-www-form-urlencoded", ``); c != http.StatusBadRequest {
		t.Fatalf("empty form: %d, want 400", c)
	}
	if c := post("application/json", `{"reports":[{"pubkey":"PUBKEY","last_handshake":"nope"}]}`); c != http.StatusBadRequest {
		t.Fatalf("bad timestamp: %d, want 400", c)
	}
	if c := post("application/json", `{"reports":[{"pubkey":"PUBKEY","last_handshake":"2026-06-24T10:00:00Z"}]}`); c != http.StatusNoContent {
		t.Fatalf("JSON report: %d, want 204", c)
	}
	var hs sql.NullTime
	if err := db.QueryRow("SELECT last_handshake_at FROM customer_wg_peer WHERE node_id = ?", nodeID).Scan(&hs); err != nil {
		t.Fatal(err)
	}
	if !hs.Valid || hs.Time.UTC().Format("2006-01-02T15:04") != "2026-06-24T10:00" {
		t.Fatalf("last_handshake_at = %v, want 2026-06-24T10:00Z", hs)
	}
}
