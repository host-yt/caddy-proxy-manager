package routes

import (
	"context"
	"testing"
)

// TestCreate_DefaultsSSOStrictMode is the regression for HPG-SEC-003: a new
// route must default to the only SSO mode that authenticates every request,
// so an operator who later configures SSO gets a secure gate unless they
// deliberately opt out. This must not touch any existing row's value -
// covered separately by not running any UPDATE/migration here at all.
func TestCreate_DefaultsSSOStrictMode(t *testing.T) {
	db := newPushTestDB(t)
	seedCapacityFixture(t, db, 10)

	routeID, err := newMTLSCreateSvc(t, db).Create(context.Background(), 0, CreateInput{
		ServiceID: 1, UpstreamPort: 10008, Domain: "newroute.example",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	var strict int
	if err := db.QueryRow("SELECT sso_strict_mode FROM routes WHERE id = ?", routeID).Scan(&strict); err != nil {
		t.Fatal(err)
	}
	if strict != 1 {
		t.Errorf("sso_strict_mode = %d, want 1 (new routes must default to strict)", strict)
	}
}
