package quota

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	_ "modernc.org/sqlite"
)

// openDB: reseller 7 subscribed to package 1 (2 clients, 3 services, 5 domains),
// overselling OFF. reseller 8 has no package (unlimited). Client 100/101 under
// reseller 7; plan 10 = 2-domain retail plan, plan 20 = internal npm plan.
func openDB(t *testing.T) *Service {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	for _, s := range []string{
		`CREATE TABLE reseller_plans (id INTEGER PRIMARY KEY, max_clients INTEGER, max_services_total INTEGER, max_domains_total INTEGER)`,
		`CREATE TABLE resellers (id INTEGER PRIMARY KEY, reseller_plan_id INTEGER, overselling_allowed INTEGER DEFAULT 0)`,
		`CREATE TABLE clients (id INTEGER PRIMARY KEY, reseller_id INTEGER)`,
		`CREATE TABLE plans (id INTEGER PRIMARY KEY, max_domains INTEGER, kind TEXT)`,
		`CREATE TABLE services (id INTEGER PRIMARY KEY, client_id INTEGER, plan_id INTEGER)`,
		`CREATE TABLE routes (id INTEGER PRIMARY KEY, service_id INTEGER)`,
		`INSERT INTO reseller_plans VALUES (1, 2, 3, 5)`,
		`INSERT INTO resellers (id, reseller_plan_id, overselling_allowed) VALUES (7, 1, 0), (8, NULL, 0)`,
		`INSERT INTO clients (id, reseller_id) VALUES (100, 7), (101, 7), (300, NULL)`,
		`INSERT INTO plans (id, max_domains, kind) VALUES (10, 2, ''), (20, 1000000, 'npm')`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("exec %q: %v", s, err)
		}
	}
	return &Service{DB: func() *sql.DB { return db }}
}

func db(s *Service) *sql.DB { return s.DB() }

func TestClientQuota(t *testing.T) {
	s := openDB(t)
	ctx := context.Background()
	// 2 clients exist, max_clients=2 -> full.
	if err := s.CanCreateClient(ctx, 7); !errors.Is(err, ErrClientQuota) {
		t.Fatalf("want ErrClientQuota, got %v", err)
	}
	// No package -> unlimited.
	if err := s.CanCreateClient(ctx, 8); err != nil {
		t.Fatalf("unlimited reseller blocked: %v", err)
	}
	// No reseller -> never limited.
	if err := s.CanCreateClient(ctx, 0); err != nil {
		t.Fatalf("platform-direct blocked: %v", err)
	}
}

func TestServiceQuotaCountAndAllocation(t *testing.T) {
	s := openDB(t)
	ctx := context.Background()
	// Allocation: cap 5, plan 10 allocates 2. Two services fit (4), third would
	// exceed (6) -> ErrDomainQuota before the service-count cap (3) triggers.
	if err := s.CanCreateService(ctx, 7, 10); err != nil {
		t.Fatalf("first service should fit: %v", err)
	}
	db(s).Exec(`INSERT INTO services (id, client_id, plan_id) VALUES (1, 100, 10)`)
	if err := s.CanCreateService(ctx, 7, 10); err != nil {
		t.Fatalf("second service should fit: %v", err)
	}
	db(s).Exec(`INSERT INTO services (id, client_id, plan_id) VALUES (2, 101, 10)`)
	if err := s.CanCreateService(ctx, 7, 10); !errors.Is(err, ErrDomainQuota) {
		t.Fatalf("third service: want ErrDomainQuota (alloc 6>5), got %v", err)
	}
	// npm plan skips allocation; only the service-count cap applies (2<3 ok).
	if err := s.CanCreateService(ctx, 7, 20); err != nil {
		t.Fatalf("npm service should skip allocation: %v", err)
	}
	db(s).Exec(`INSERT INTO services (id, client_id, plan_id) VALUES (3, 100, 20)`)
	// Now 3 services >= max_services_total=3.
	if err := s.CanCreateService(ctx, 7, 20); !errors.Is(err, ErrServiceQuota) {
		t.Fatalf("want ErrServiceQuota, got %v", err)
	}
}

func TestRouteQuotaOversellAndNPM(t *testing.T) {
	s := openDB(t)
	ctx := context.Background()
	db(s).Exec(`INSERT INTO services (id, client_id, plan_id) VALUES (1, 100, 10), (2, 100, 20)`)

	// Overselling OFF + retail plan: no aggregate route check (allocation covers it).
	if err := s.CanCreateRoute(ctx, 7, 1); err != nil {
		t.Fatalf("retail route (no oversell) should pass: %v", err)
	}
	// Overselling OFF + npm service: REAL count enforced. Fill to cap (5).
	for i := 0; i < 5; i++ {
		db(s).Exec(`INSERT INTO routes (service_id) VALUES (2)`)
	}
	if err := s.CanCreateRoute(ctx, 7, 2); !errors.Is(err, ErrDomainQuota) {
		t.Fatalf("npm route at cap: want ErrDomainQuota, got %v", err)
	}
	// Overselling ON: retail service also real-counted.
	db(s).Exec(`UPDATE resellers SET overselling_allowed=1 WHERE id=7`)
	if err := s.CanCreateRoute(ctx, 7, 1); !errors.Is(err, ErrDomainQuota) {
		t.Fatalf("oversell at cap: want ErrDomainQuota, got %v", err)
	}
}

func TestUsageFor(t *testing.T) {
	s := openDB(t)
	ctx := context.Background()
	db(s).Exec(`INSERT INTO services (id, client_id, plan_id) VALUES (1, 100, 10)`)
	db(s).Exec(`INSERT INTO routes (service_id) VALUES (1), (1)`)
	u, err := s.UsageFor(ctx, 7)
	if err != nil {
		t.Fatalf("usage: %v", err)
	}
	if !u.Limited || u.Clients != 2 || u.Services != 1 || u.Domains != 2 ||
		u.MaxClients != 2 || u.MaxServices != 3 || u.MaxDomains != 5 {
		t.Fatalf("unexpected usage: %+v", u)
	}
}
