package handlers

import (
	"context"
	"database/sql"
	"log/slog"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/adminscope"
	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	_ "modernc.org/sqlite"
)

// A tenant-scoped session must never resolve to "all clients" when the scope
// service is unwired or its lookup fails.
func TestAdminClientScopeFailsClosed(t *testing.T) {
	empty, err := sql.Open("sqlite", ":memory:") // no tables: ScopeFilter errors
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { empty.Close() })
	noScope := &AdminHandlers{Logger: slog.Default()}
	broken := &AdminHandlers{AdminScope: adminscope.New(func() *sql.DB { return empty }), Logger: slog.Default()}
	ctx := context.Background()

	cases := []struct {
		name    string
		h       *AdminHandlers
		sess    *auth.Session
		wantAll bool
		wantOK  bool
	}{
		{"super_admin unwired", noScope, &auth.Session{UserID: 1, Role: "super_admin"}, true, true},
		{"platform admin unwired", noScope, &auth.Session{UserID: 2, Role: "admin"}, true, true},
		{"restricted unwired", noScope, &auth.Session{UserID: 3, Role: "admin", Restricted: true}, false, false},
		{"reseller admin unwired", noScope, &auth.Session{UserID: 4, Role: "admin", ResellerID: 7}, false, false},
		{"restricted scope error", broken, &auth.Session{UserID: 3, Role: "admin", Restricted: true}, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, all, ok := c.h.adminClientScope(ctx, c.sess)
			if all != c.wantAll || ok != c.wantOK {
				t.Fatalf("adminClientScope = all %v ok %v, want all %v ok %v", all, ok, c.wantAll, c.wantOK)
			}
			if got := c.h.scopeCheckClient(ctx, c.sess, 1); got != c.wantOK {
				t.Fatalf("scopeCheckClient = %v, want %v", got, c.wantOK)
			}
			if sc := c.h.dashboardScope(ctx, c.sess); sc.scoped == c.wantAll {
				t.Fatalf("dashboardScope.scoped = %v, want %v", sc.scoped, !c.wantAll)
			}
		})
	}
}
