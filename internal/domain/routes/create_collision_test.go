package routes

import (
	"context"
	"errors"
	"testing"
)

// TestCreate_RefusesForeignTenantHost: a verified host of another tenant (any
// path, primary or alias) cannot be claimed, even from admin context.
func TestCreate_RefusesForeignTenantHost(t *testing.T) {
	db := newPushTestDB(t)
	seedCapacityFixture(t, db, 50)
	for _, q := range []string{
		`UPDATE plans SET path_routing_enabled = 1`,
		`INSERT INTO users (id, email, password_hash, role) VALUES (2, 'b@b.c', 'x', 'client')`,
		`INSERT INTO clients (id, user_id, display_name) VALUES (2, 2, 'other')`,
		`INSERT INTO services (id, client_id, name, backend_ip, allowed_port_start, allowed_port_end, plan_id, node_group_id)
		 VALUES (2, 2, 'svc2', '10.9.9.8', 10000, 20000, 1, 1)`,
		`INSERT INTO routes (service_id, caddy_node_id, domain, path_prefix, upstream_port, status, domain_verified, aliases)
		 VALUES (2, 1, 'taken.example', '', 10001, 'active', 1, 'alias.example')`,
		`INSERT INTO routes (service_id, caddy_node_id, domain, path_prefix, upstream_port, status, domain_verified)
		 VALUES (2, 1, 'squat.example', '', 10002, 'pending_dns', 0)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	svc := newMTLSCreateSvc(t, db)
	port := 10010
	try := func(domain, path string) error {
		port++
		_, err := svc.Create(context.Background(), 0, CreateInput{
			ServiceID: 1, UpstreamPort: port, Domain: domain, PathPrefix: path,
		})
		return err
	}
	for _, c := range []struct{ domain, path string }{
		{"taken.example", "/api"}, {"alias.example", ""}, {"taken.example", ""},
	} {
		if err := try(c.domain, c.path); !errors.Is(err, ErrDomainTaken) {
			t.Errorf("%s%s: err = %v, want ErrDomainTaken", c.domain, c.path, err)
		}
	}
	// Unverified foreign row on the same host+path is still evicted (anti-squat).
	if err := try("squat.example", ""); err != nil {
		t.Errorf("anti-squat create: %v", err)
	}
	if err := try("free.example", ""); err != nil {
		t.Errorf("free host: %v", err)
	}
}
