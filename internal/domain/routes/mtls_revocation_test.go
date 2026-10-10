package routes

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
	"github.com/host-yt/caddy-proxy-manager/internal/mtls"
)

// A revoked leaf must reach the node config of every route trusting its CA,
// and those nodes must be discoverable for the immediate push.
func TestMTLSRevocationReachesRouteAndNodes(t *testing.T) {
	db := newPushTestDB(t)
	ctx := context.Background()
	nodeID := seedNodeAndRoute(t, db, "http://127.0.0.1:1", "secure.example")

	ident := func(s string) (string, error) { return s, nil }
	ms := &mtls.Service{DB: func() *sql.DB { return db }, Encrypt: ident, Decrypt: ident}
	caID, err := ms.CreateCA(ctx, mtls.CreateCAInput{Name: "ca"})
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	bad, err := ms.Issue(ctx, mtls.IssueInput{CAID: caID, Subject: "dev"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	good, err := ms.Issue(ctx, mtls.IssueInput{CAID: caID, Subject: "dev"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if got, err := ms.Revoke(ctx, bad.ID); err != nil || got != caID {
		t.Fatalf("revoke = %d, %v", got, err)
	}
	var routeID int64
	if err := db.QueryRow(`SELECT id FROM routes WHERE domain = 'secure.example'`).Scan(&routeID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE routes SET require_client_cert = 1, mtls_ca_id = ? WHERE id = ?`, caID, routeID); err != nil {
		t.Fatal(err)
	}

	svc := &Service{DB: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	built := make([]caddyapi.Route, 1)
	if err := svc.attachMTLSRevocations(ctx, built, []int64{routeID}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	fp := func(p string) string {
		c, err := mtls.ParseCert(p)
		if err != nil {
			t.Fatal(err)
		}
		return mtls.FingerprintOf(c)
	}
	got := built[0].MTLSRevokedFingerprints
	if len(got) != 1 || got[0] != fp(bad.CertPEM) || got[0] == fp(good.CertPEM) {
		t.Fatalf("revoked fingerprints = %v, want only the revoked leaf", got)
	}

	nodes, err := svc.MTLSCANodes(ctx, caID)
	if err != nil || len(nodes) != 1 || nodes[0] != nodeID {
		t.Fatalf("MTLSCANodes = %v, %v; want [%d]", nodes, err, nodeID)
	}
}
