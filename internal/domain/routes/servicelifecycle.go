// Service lifecycle: the single implementation of suspend / resume / terminate.
// Every transport (panel form, bulk action, REST API, FOSSBilling) calls these;
// none of them writes services.status or routes.status on its own, so the three
// entry points cannot drift into three different operations again (HPG-007).
package routes

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// Why a route sits in status 'disabled'. NULL/"" means an operator turned it
// off by hand and only an operator may turn it back on.
const (
	DisabledByServiceSuspend    = "service_suspended"
	DisabledByServiceTerminated = "service_terminated"
)

var (
	// ErrServiceNotFound: no services row with that id.
	ErrServiceNotFound = errors.New("service not found")
	// ErrServiceTerminated: a terminated service is final - it neither
	// suspends nor resumes.
	ErrServiceTerminated = errors.New("service is terminated")
	// ErrServiceNotSuspended: resume was asked for a service that is not
	// suspended.
	ErrServiceNotSuspended = errors.New("service is not suspended")
)

// servingStatuses are the route statuses that reach (or are about to reach) a
// node's config. Suspending flips exactly these to 'disabled'.
var servingStatuses = []any{"active", "dns_ok", "pending_ssl"}

// SuspendService stops serving every route of the service and records that the
// service, not an operator, disabled them. Route rows are never deleted.
func (s *Service) SuspendService(ctx context.Context, serviceID int64) error {
	return s.setServiceState(ctx, serviceID, "suspended")
}

// ResumeService puts a suspended service back to active and re-enables only the
// routes SuspendService disabled - a route an operator disabled by hand stays
// disabled.
func (s *Service) ResumeService(ctx context.Context, serviceID int64) error {
	return s.setServiceState(ctx, serviceID, "active")
}

// TerminateService is the terminal form of suspend: routes stop serving and
// resume can never bring them back, but their definitions survive so an
// operator can still inspect or export them.
func (s *Service) TerminateService(ctx context.Context, serviceID int64) error {
	return s.setServiceState(ctx, serviceID, "terminated")
}

// setServiceState is the whole contract: one transaction for the service row
// and its routes, one computation of every affected node, one push per node
// after commit.
func (s *Service) setServiceState(ctx context.Context, serviceID int64, target string) error {
	if s == nil || s.DB == nil {
		return errors.New("route service not ready")
	}
	// Nodes are collected before the transaction and cover every route of the
	// service (any status, primary node plus fan-out peers): after a suspend the
	// node must be rebuilt even for a route that was not serving.
	nodes, err := s.serviceNodes(ctx, serviceID)
	if err != nil {
		return err
	}

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	var cur string
	switch err := tx.QueryRowContext(ctx, "SELECT status FROM services WHERE id = ?", serviceID).Scan(&cur); {
	case errors.Is(err, sql.ErrNoRows):
		return ErrServiceNotFound
	case err != nil:
		return fmt.Errorf("service lookup: %w", err)
	}
	if cur == "terminated" {
		return ErrServiceTerminated
	}
	if target == "active" && cur != "suspended" {
		return ErrServiceNotSuspended
	}

	if _, err := tx.ExecContext(ctx, "UPDATE services SET status = ? WHERE id = ?", target, serviceID); err != nil {
		return fmt.Errorf("service status: %w", err)
	}

	if target == "active" {
		// Only what the suspend disabled. disabled_reason is the difference
		// between "billing turned this off" and "the operator turned it off".
		if _, err := tx.ExecContext(ctx,
			`UPDATE routes SET status = 'active', disabled_reason = NULL, updated_at = NOW()
			  WHERE service_id = ? AND status = 'disabled' AND disabled_reason = ?`,
			serviceID, DisabledByServiceSuspend); err != nil {
			return fmt.Errorf("route enable: %w", err)
		}
	} else {
		reason := DisabledByServiceSuspend
		if target == "terminated" {
			reason = DisabledByServiceTerminated
		}
		args := append([]any{reason, serviceID}, servingStatuses...)
		if _, err := tx.ExecContext(ctx,
			`UPDATE routes SET status = 'disabled', disabled_reason = ?, updated_at = NOW()
			  WHERE service_id = ? AND status IN (?, ?, ?)`, args...); err != nil {
			return fmt.Errorf("route disable: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	for _, n := range nodes {
		s.SchedulePush(n)
	}
	return nil
}

// serviceNodes returns every node holding a copy of any route of this service:
// the primary placement plus fan-out assignments.
func (s *Service) serviceNodes(ctx context.Context, serviceID int64) ([]int64, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT caddy_node_id FROM routes WHERE service_id = ? AND caddy_node_id IS NOT NULL
		 UNION
		 SELECT rna.node_id FROM route_node_assignments rna
		   JOIN routes r ON r.id = rna.route_id WHERE r.service_id = ?`,
		serviceID, serviceID)
	if err != nil {
		return nil, fmt.Errorf("affected nodes: %w", err)
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("affected nodes: %w", err)
		}
		if id != 0 {
			out = append(out, id)
		}
	}
	return out, rows.Err()
}

// serviceServing reports whether the service owning routeID is active. A route
// of a suspended or terminated service must never be walked back into a serving
// status by any background path.
func (s *Service) serviceServing(ctx context.Context, routeID int64) (bool, error) {
	var status string
	err := s.DB.QueryRowContext(ctx,
		"SELECT sv.status FROM routes r JOIN services sv ON sv.id = r.service_id WHERE r.id = ?",
		routeID).Scan(&status)
	if err != nil {
		return false, err
	}
	return status == "active", nil
}
