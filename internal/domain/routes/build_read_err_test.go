package routes

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/go-sql-driver/mysql"

	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
)

// closedDB returns a handle whose every query fails, standing in for a transient DB error.
func closedDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("mysql", "root@tcp(127.0.0.1:1)/x")
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	return db
}

// A failed upstream read must abort the build, not fall back to the legacy single backend.
func TestAttachStreamUpstreamsPropagatesReadError(t *testing.T) {
	s := &Service{DB: closedDB(t)}
	built := []caddyapi.StreamRoute{{ID: 1}}
	if err := s.attachStreamUpstreams(context.Background(), built); err == nil {
		t.Fatal("want error on upstream read failure")
	}
}

// A failed suppression read must abort the build, not publish a ruleset without them.
func TestLoadWAFSuppressionsPropagatesReadError(t *testing.T) {
	s := &Service{DB: closedDB(t)}
	if _, err := s.loadWAFSuppressions(context.Background()); err == nil {
		t.Fatal("want error on suppression read failure")
	}
}
