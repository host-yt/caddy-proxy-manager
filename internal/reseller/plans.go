package reseller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// Plan is a reseller package: aggregate quota + resource grants shared by every
// reseller subscribed to it. 0 on any limit = unlimited/uncapped.
type Plan struct {
	ID              int64
	Name            string
	MaxClients      int
	MaxDomainsTotal int
	MaxServices     int
	RateLimitCap    int
	NodeGroupIDs    []int64
	Features        []string
}

// KnownFeatures is the grantable feature vocabulary (mirrors plans' flag
// columns + module-gated route features). Kept in one place so UI + validation
// agree.
var KnownFeatures = []string{
	"ssl", "wildcard", "websocket", "path", "external",
	"waf", "geo", "l4", "cache", "rate_limit", "dns01", "weighted_lb",
}

// PlansList returns all packages with their grants.
func (s *Store) PlansList(ctx context.Context) ([]Plan, error) {
	db := s.db()
	if db == nil {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx,
		`SELECT id, name, max_clients, max_domains_total, max_services_total, rate_limit_rpm_cap
		 FROM reseller_plans ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("reseller plans: list: %w", err)
	}
	defer rows.Close()
	var out []Plan
	for rows.Next() {
		var p Plan
		if err := rows.Scan(&p.ID, &p.Name, &p.MaxClients, &p.MaxDomainsTotal, &p.MaxServices, &p.RateLimitCap); err != nil {
			return nil, fmt.Errorf("reseller plans: scan: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if err := s.loadPlanGrants(ctx, &out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Store) loadPlanGrants(ctx context.Context, p *Plan) error {
	db := s.db()
	rows, err := db.QueryContext(ctx,
		`SELECT node_group_id FROM reseller_plan_node_groups WHERE reseller_plan_id=? ORDER BY node_group_id`, p.ID)
	if err != nil {
		return fmt.Errorf("reseller plans: pools: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		if rows.Scan(&id) == nil {
			p.NodeGroupIDs = append(p.NodeGroupIDs, id)
		}
	}
	frows, err := db.QueryContext(ctx,
		`SELECT feature FROM reseller_plan_features WHERE reseller_plan_id=? ORDER BY feature`, p.ID)
	if err != nil {
		return fmt.Errorf("reseller plans: features: %w", err)
	}
	defer frows.Close()
	for frows.Next() {
		var f string
		if frows.Scan(&f) == nil {
			p.Features = append(p.Features, f)
		}
	}
	return nil
}

// PlanSave inserts (ID==0) or updates a package plus its grant sets.
func (s *Store) PlanSave(ctx context.Context, p Plan) (int64, error) {
	db := s.db()
	if db == nil {
		return 0, errors.New("reseller plans: no db")
	}
	name := strings.TrimSpace(p.Name)
	if name == "" {
		return 0, errors.New("reseller plans: name required")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("reseller plans: tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	if p.ID == 0 {
		res, err := tx.ExecContext(ctx,
			`INSERT INTO reseller_plans (name, max_clients, max_domains_total, max_services_total, rate_limit_rpm_cap)
			 VALUES (?, ?, ?, ?, ?)`,
			name, p.MaxClients, p.MaxDomainsTotal, p.MaxServices, p.RateLimitCap)
		if err != nil {
			if isDuplicate(err) {
				return 0, ErrDuplicate
			}
			return 0, fmt.Errorf("reseller plans: insert: %w", err)
		}
		p.ID, _ = res.LastInsertId()
	} else {
		if _, err := tx.ExecContext(ctx,
			`UPDATE reseller_plans SET name=?, max_clients=?, max_domains_total=?, max_services_total=?, rate_limit_rpm_cap=?
			 WHERE id=?`,
			name, p.MaxClients, p.MaxDomainsTotal, p.MaxServices, p.RateLimitCap, p.ID); err != nil {
			if isDuplicate(err) {
				return 0, ErrDuplicate
			}
			return 0, fmt.Errorf("reseller plans: update: %w", err)
		}
	}
	// Replace grant sets wholesale (small sets, simplest correct form).
	if _, err := tx.ExecContext(ctx, `DELETE FROM reseller_plan_node_groups WHERE reseller_plan_id=?`, p.ID); err != nil {
		return 0, fmt.Errorf("reseller plans: clear pools: %w", err)
	}
	for _, ng := range p.NodeGroupIDs {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO reseller_plan_node_groups (reseller_plan_id, node_group_id) VALUES (?, ?)`, p.ID, ng); err != nil {
			return 0, fmt.Errorf("reseller plans: grant pool: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM reseller_plan_features WHERE reseller_plan_id=?`, p.ID); err != nil {
		return 0, fmt.Errorf("reseller plans: clear features: %w", err)
	}
	known := make(map[string]bool, len(KnownFeatures))
	for _, f := range KnownFeatures {
		known[f] = true
	}
	for _, f := range p.Features {
		if !known[f] {
			continue // never persist an unknown token
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO reseller_plan_features (reseller_plan_id, feature) VALUES (?, ?)`, p.ID, f); err != nil {
			return 0, fmt.Errorf("reseller plans: grant feature: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("reseller plans: commit: %w", err)
	}
	return p.ID, nil
}

// ErrPlanInUse blocks deleting a package that resellers still subscribe to.
var ErrPlanInUse = errors.New("reseller plans: in use")

// PlanDelete removes an unused package (grants cascade via FK).
func (s *Store) PlanDelete(ctx context.Context, id int64) error {
	db := s.db()
	if db == nil {
		return errors.New("reseller plans: no db")
	}
	var n int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM resellers WHERE reseller_plan_id=?`, id).Scan(&n); err != nil {
		return fmt.Errorf("reseller plans: usage check: %w", err)
	}
	if n > 0 {
		return ErrPlanInUse
	}
	res, err := db.ExecContext(ctx, `DELETE FROM reseller_plans WHERE id=?`, id)
	if err != nil {
		return fmt.Errorf("reseller plans: delete: %w", err)
	}
	if aff, _ := res.RowsAffected(); aff == 0 {
		return ErrNotFound
	}
	return nil
}

// Policy mirrors the per-reseller policy columns (super_admin sets them).
type Policy struct {
	PlanID         int64 // 0 = none (unlimited)
	Overselling    bool
	CanCreatePlans bool
}

// SetPolicy assigns the package + policy flags for one reseller.
func (s *Store) SetPolicy(ctx context.Context, resellerID int64, pol Policy) error {
	db := s.db()
	if db == nil {
		return errors.New("reseller: no db")
	}
	var plan sql.NullInt64
	if pol.PlanID > 0 {
		plan = sql.NullInt64{Int64: pol.PlanID, Valid: true}
	}
	res, err := db.ExecContext(ctx,
		`UPDATE resellers SET reseller_plan_id=?, overselling_allowed=?, can_create_plans=? WHERE id=?`,
		plan, pol.Overselling, pol.CanCreatePlans, resellerID)
	if err != nil {
		return fmt.Errorf("reseller: set policy: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// PolicyFor reads a reseller's package + policy flags.
func (s *Store) PolicyFor(ctx context.Context, resellerID int64) (Policy, error) {
	db := s.db()
	if db == nil {
		return Policy{}, errors.New("reseller: no db")
	}
	var pol Policy
	var plan sql.NullInt64
	err := db.QueryRowContext(ctx,
		`SELECT reseller_plan_id, COALESCE(overselling_allowed,0), COALESCE(can_create_plans,0)
		 FROM resellers WHERE id=?`, resellerID).Scan(&plan, &pol.Overselling, &pol.CanCreatePlans)
	if errors.Is(err, sql.ErrNoRows) {
		return Policy{}, ErrNotFound
	}
	if err != nil {
		return Policy{}, fmt.Errorf("reseller: policy: %w", err)
	}
	pol.PlanID = plan.Int64
	return pol, nil
}
