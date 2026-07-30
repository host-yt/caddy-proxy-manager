package middleware

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	_ "modernc.org/sqlite"
)

// ownerTestDB seeds users covering every tenancy shape the gate must classify.
func ownerTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	for _, s := range []string{
		`CREATE TABLE users (id INTEGER PRIMARY KEY, reseller_id INTEGER, is_restricted INTEGER DEFAULT 0, role TEXT DEFAULT 'admin')`,
		`INSERT INTO users (id, reseller_id, is_restricted, role) VALUES
		   (1, NULL, 0, 'admin'),
		   (2, NULL, 1, 'admin'),
		   (3, 4,    0, 'reseller'),
		   (5, NULL, 0, 'super_admin')`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("exec %q: %v", s, err)
		}
	}
	return db
}

func TestRequireUnrestrictedAPIOwner(t *testing.T) {
	good := ownerTestDB(t)
	// Broken schema stands in for a DB error on the owner lookup.
	broken, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer broken.Close()

	cases := []struct {
		name       string
		caller     *APICaller
		db         func() *sql.DB
		wantStatus int
	}{
		{"unrestricted admin allowed", &APICaller{UserID: 1, Role: "admin", Scopes: []string{"admin:write"}}, func() *sql.DB { return good }, http.StatusOK},
		{"unscoped key of unrestricted admin allowed", &APICaller{UserID: 1, Role: "admin"}, func() *sql.DB { return good }, http.StatusOK},
		{"restricted owner denied", &APICaller{UserID: 2, Role: "admin", Scopes: []string{"admin:write"}}, func() *sql.DB { return good }, http.StatusForbidden},
		{"unscoped key of restricted owner denied", &APICaller{UserID: 2, Role: "admin"}, func() *sql.DB { return good }, http.StatusForbidden},
		{"reseller-bound owner denied", &APICaller{UserID: 3, Role: "reseller", Scopes: []string{"admin:write"}}, func() *sql.DB { return good }, http.StatusForbidden},
		{"super_admin allowed", &APICaller{UserID: 5, Role: "super_admin"}, func() *sql.DB { return good }, http.StatusOK},
		{"unknown owner denied", &APICaller{UserID: 999, Role: "admin"}, func() *sql.DB { return good }, http.StatusForbidden},
		{"db error denied", &APICaller{UserID: 1, Role: "admin"}, func() *sql.DB { return broken }, http.StatusForbidden},
		{"nil db denied", &APICaller{UserID: 1, Role: "admin"}, func() *sql.DB { return nil }, http.StatusServiceUnavailable},
		{"no caller denied", nil, func() *sql.DB { return good }, http.StatusForbidden},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var reached bool
			h := RequireUnrestrictedAPIOwner(tc.db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				w.WriteHeader(http.StatusOK)
			}))
			req := httptest.NewRequest(http.MethodPost, "/api/v1/provisioning/service", nil)
			if tc.caller != nil {
				req = req.WithContext(ContextWithAPICaller(req.Context(), tc.caller))
			}
			rw := httptest.NewRecorder()
			h.ServeHTTP(rw, req)
			if rw.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rw.Code, tc.wantStatus)
			}
			if wantReach := tc.wantStatus == http.StatusOK; reached != wantReach {
				t.Fatalf("handler reached = %v, want %v", reached, wantReach)
			}
		})
	}
}
