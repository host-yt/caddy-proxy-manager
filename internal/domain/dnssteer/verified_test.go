package dnssteer

import (
	"context"
	"testing"
)

// A route whose domain ownership is unproven must never get records published,
// and losing verification withdraws what was published.
func TestReconcile_SkipsUnverifiedDomain(t *testing.T) {
	db := newTestDB(t)
	mustExec(t, db,
		`INSERT INTO caddy_nodes (id, public_ip, is_enabled, health_status) VALUES (1,'10.0.0.1',1,'healthy')`,
		`INSERT INTO dns_providers (id, name, provider, api_token_enc) VALUES (1,'example.com','cloudflare','{"api_token":"tok"}')`,
		`INSERT INTO routes (id, domain, caddy_node_id, dns_steering_enabled, dns_provider_id, domain_verified, status) VALUES
			(1,'pending.example.com',1,1,1,0,'pending_dns'), (2,'ok.example.com',1,1,1,1,'active')`)
	fp := &fakeProvider{}
	rc := newTestReconciler(db, fp)
	ctx := context.Background()
	rc.Reconcile(ctx)
	if len(fp.records) != 1 || fp.records[0].Name != "ok.example.com" {
		t.Fatalf("want only the verified route steered, got %+v", fp.records)
	}

	mustExec(t, db, `UPDATE routes SET domain_verified=0 WHERE id=2`)
	rc.Reconcile(ctx)
	if len(fp.records) != 0 {
		t.Fatalf("unverified route must lose its records, got %+v", fp.records)
	}
}
