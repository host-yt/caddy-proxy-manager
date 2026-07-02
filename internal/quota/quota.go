// Package quota enforces a reseller's aggregate package limits (reseller_plans)
// at the create surfaces: clients, services (subscriptions) and routes (domains).
// It is a business limit, not a security boundary - tenant isolation lives in
// adminscope. Platform-direct resources (reseller_id NULL) are never limited.
//
// Overselling semantics (per-reseller flag, WHM-style):
//   - OFF (default): capacity is ALLOCATED at service-create - the sum of the
//     attached plans' max_domains must fit max_domains_total. Route creation is
//     then bounded by each plan's own max_domains, so the aggregate holds.
//   - ON: allocation is unchecked; the REAL route count is enforced instead.
package quota

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// Service resolves and enforces reseller package limits.
type Service struct {
	DB func() *sql.DB
}

// Typed errors so handlers/API can map them to friendly 4xx messages.
var (
	ErrClientQuota  = errors.New("reseller quota: client limit reached")
	ErrServiceQuota = errors.New("reseller quota: service limit reached")
	ErrDomainQuota  = errors.New("reseller quota: domain limit reached")
)

// limits is the resolved package + policy for one reseller.
type limits struct {
	maxClients  int
	maxServices int
	maxDomains  int
	overselling bool
}

// limitsFor resolves the reseller's package. ok=false means "not limited"
// (no reseller, or no package subscribed - the Unlimited backfill covers
// normal installs, so a missing package behaves as unlimited, never bricks).
func (s *Service) limitsFor(ctx context.Context, resellerID int64) (limits, bool, error) {
	if resellerID == 0 || s == nil || s.DB == nil {
		return limits{}, false, nil
	}
	db := s.DB()
	if db == nil {
		return limits{}, false, nil
	}
	var l limits
	var planID sql.NullInt64
	err := db.QueryRowContext(ctx,
		`SELECT r.reseller_plan_id, COALESCE(r.overselling_allowed,0)
		 FROM resellers r WHERE r.id=?`, resellerID).Scan(&planID, &l.overselling)
	if errors.Is(err, sql.ErrNoRows) {
		return limits{}, false, nil
	}
	if err != nil {
		return limits{}, false, fmt.Errorf("quota: reseller lookup: %w", err)
	}
	if !planID.Valid {
		return limits{}, false, nil
	}
	err = db.QueryRowContext(ctx,
		`SELECT max_clients, max_services_total, max_domains_total
		 FROM reseller_plans WHERE id=?`, planID.Int64).Scan(&l.maxClients, &l.maxServices, &l.maxDomains)
	if errors.Is(err, sql.ErrNoRows) {
		return limits{}, false, nil
	}
	if err != nil {
		return limits{}, false, fmt.Errorf("quota: plan lookup: %w", err)
	}
	return l, true, nil
}

// CanCreateClient gates adding one more client under the reseller.
func (s *Service) CanCreateClient(ctx context.Context, resellerID int64) error {
	l, ok, err := s.limitsFor(ctx, resellerID)
	if err != nil || !ok || l.maxClients <= 0 {
		return err
	}
	var n int
	if err := s.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM clients WHERE reseller_id=?`, resellerID).Scan(&n); err != nil {
		return fmt.Errorf("quota: client count: %w", err)
	}
	if n >= l.maxClients {
		return ErrClientQuota
	}
	return nil
}

// CanCreateService gates adding one more subscription. planID is the service
// plan being attached; without overselling its max_domains allocation must fit
// the package's aggregate domain capacity.
func (s *Service) CanCreateService(ctx context.Context, resellerID, planID int64) error {
	l, ok, err := s.limitsFor(ctx, resellerID)
	if err != nil || !ok {
		return err
	}
	db := s.DB()
	if l.maxServices > 0 {
		var n int
		if err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM services sv JOIN clients c ON c.id = sv.client_id
			 WHERE c.reseller_id=?`, resellerID).Scan(&n); err != nil {
			return fmt.Errorf("quota: service count: %w", err)
		}
		if n >= l.maxServices {
			return ErrServiceQuota
		}
	}
	if !l.overselling && l.maxDomains > 0 {
		var newAlloc int
		var newKind string
		if err := db.QueryRowContext(ctx,
			`SELECT max_domains, COALESCE(kind,'') FROM plans WHERE id=?`, planID).Scan(&newAlloc, &newKind); err != nil {
			return fmt.Errorf("quota: plan alloc: %w", err)
		}
		// kind='npm' plans are internal hosts-flow plumbing with a huge
		// max_domains - their routes are REAL-counted at route-create instead
		// of allocated here (see CanCreateRoute).
		if newKind != "npm" {
			// A plan with unlimited domains (0) cannot be allocated under a
			// finite aggregate cap - it would make the cap meaningless.
			if newAlloc <= 0 {
				return ErrDomainQuota
			}
			var allocated sql.NullInt64
			if err := db.QueryRowContext(ctx,
				`SELECT SUM(p.max_domains) FROM services sv
				 JOIN clients c ON c.id = sv.client_id
				 JOIN plans p ON p.id = sv.plan_id
				 WHERE c.reseller_id=? AND COALESCE(p.kind,'') <> 'npm'`, resellerID).Scan(&allocated); err != nil {
				return fmt.Errorf("quota: allocation sum: %w", err)
			}
			if int(allocated.Int64)+newAlloc > l.maxDomains {
				return ErrDomainQuota
			}
		}
	}
	return nil
}

// CanCreateRoute gates adding one more domain (route) to serviceID. The real
// route count is enforced when overselling is ON, and always for services on
// internal kind='npm' plans (hosts flow) whose capacity is never allocated -
// otherwise the allocation check at service-create plus the per-plan
// max_domains bound already cap real usage.
func (s *Service) CanCreateRoute(ctx context.Context, resellerID, serviceID int64) error {
	l, ok, err := s.limitsFor(ctx, resellerID)
	if err != nil || !ok || l.maxDomains <= 0 {
		return err
	}
	db := s.DB()
	if !l.overselling {
		var kind string
		if err := db.QueryRowContext(ctx,
			`SELECT COALESCE(p.kind,'') FROM services sv JOIN plans p ON p.id = sv.plan_id
			 WHERE sv.id=?`, serviceID).Scan(&kind); err != nil {
			return fmt.Errorf("quota: service plan kind: %w", err)
		}
		if kind != "npm" {
			return nil // bounded by allocation + per-plan cap
		}
	}
	var n int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM routes rt
		 JOIN services sv ON sv.id = rt.service_id
		 JOIN clients c ON c.id = sv.client_id
		 WHERE c.reseller_id=?`, resellerID).Scan(&n); err != nil {
		return fmt.Errorf("quota: route count: %w", err)
	}
	if n >= l.maxDomains {
		return ErrDomainQuota
	}
	return nil
}

// ResellerOfClient resolves which reseller (if any) owns a client. 0 = none.
func (s *Service) ResellerOfClient(ctx context.Context, clientID int64) (int64, error) {
	if s == nil || s.DB == nil {
		return 0, nil
	}
	db := s.DB()
	if db == nil || clientID == 0 {
		return 0, nil
	}
	var rid sql.NullInt64
	err := db.QueryRowContext(ctx,
		`SELECT reseller_id FROM clients WHERE id=?`, clientID).Scan(&rid)
	if errors.Is(err, sql.ErrNoRows) || !rid.Valid {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("quota: client reseller: %w", err)
	}
	return rid.Int64, nil
}

// Usage summarizes consumption vs limits for dashboards. Max* of 0 = unlimited.
type Usage struct {
	Clients, MaxClients   int
	Services, MaxServices int
	Domains, MaxDomains   int
	Overselling           bool
	Limited               bool // false = no package (unlimited)
}

// UsageFor reports current consumption for a reseller dashboard.
func (s *Service) UsageFor(ctx context.Context, resellerID int64) (Usage, error) {
	var u Usage
	l, ok, err := s.limitsFor(ctx, resellerID)
	if err != nil {
		return u, err
	}
	u.Limited, u.Overselling = ok, l.overselling
	u.MaxClients, u.MaxServices, u.MaxDomains = l.maxClients, l.maxServices, l.maxDomains
	db := s.DB()
	if db == nil {
		return u, nil
	}
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM clients WHERE reseller_id=?`, resellerID).Scan(&u.Clients)
	_ = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM services sv JOIN clients c ON c.id=sv.client_id WHERE c.reseller_id=?`,
		resellerID).Scan(&u.Services)
	_ = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM routes rt JOIN services sv ON sv.id=rt.service_id
		 JOIN clients c ON c.id=sv.client_id WHERE c.reseller_id=?`, resellerID).Scan(&u.Domains)
	return u, nil
}
