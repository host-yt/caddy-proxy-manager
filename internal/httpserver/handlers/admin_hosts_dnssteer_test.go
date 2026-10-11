package handlers

import (
	"context"
	"database/sql"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
)

// Global DNS provider credentials are offered for steering only to super_admin;
// a scoped or reseller admin gets no options (and its save skips the fields).
func TestDNSProviderOptionsSuperAdminOnly(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	for _, s := range []string{
		`CREATE TABLE dns_providers (id INTEGER PRIMARY KEY, name TEXT)`,
		`INSERT INTO dns_providers (id, name) VALUES (1, 'example.com')`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("exec %q: %v", s, err)
		}
	}
	ctx := context.Background()
	for _, sess := range []*auth.Session{nil, {Role: "admin"}, {Role: "admin", ResellerID: 7}, {Role: "support"}} {
		if got := loadDNSProviderOptions(ctx, db, sess); got != nil {
			t.Errorf("session %+v: want no providers, got %+v", sess, got)
		}
	}
	if got := loadDNSProviderOptions(ctx, db, &auth.Session{Role: "super_admin"}); len(got) != 1 {
		t.Errorf("super_admin: want 1 provider, got %+v", got)
	}
}
