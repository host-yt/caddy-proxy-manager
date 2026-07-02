package adminscope

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

type Service struct {
	db func() *sql.DB
}

func New(db func() *sql.DB) *Service {
	return &Service{db: db}
}

func (s *Service) CanAccessClient(ctx context.Context, adminUserID, clientID int64) (bool, error) {
	db := s.db()
	if db == nil {
		return false, nil
	}
	var count int
	err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM admin_client_scope WHERE admin_user_id=? AND client_id=?`,
		adminUserID, clientID,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("adminscope: %w", err)
	}
	return count > 0, nil
}

func (s *Service) CanAccessPeer(ctx context.Context, adminUserID, peerID int64) (bool, error) {
	db := s.db()
	if db == nil {
		return false, nil
	}
	var count int
	err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM admin_client_scope acs
		 JOIN customer_wg_peer p ON p.client_id = acs.client_id
		 WHERE acs.admin_user_id=? AND p.id=?`,
		adminUserID, peerID,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("adminscope: %w", err)
	}
	return count > 0, nil
}

func (s *Service) CanAccessRoute(ctx context.Context, adminUserID, routeID int64) (bool, error) {
	db := s.db()
	if db == nil {
		return false, nil
	}
	var count int
	err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM admin_client_scope acs
		 JOIN services sv ON sv.client_id = acs.client_id
		 JOIN routes r ON r.service_id = sv.id
		 WHERE acs.admin_user_id=? AND r.id=?`,
		adminUserID, routeID,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("adminscope: %w", err)
	}
	return count > 0, nil
}

func (s *Service) AssignedClientIDs(ctx context.Context, adminUserID int64) ([]int64, error) {
	db := s.db()
	if db == nil {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx,
		`SELECT client_id FROM admin_client_scope WHERE admin_user_id=? ORDER BY client_id`,
		adminUserID,
	)
	if err != nil {
		return nil, fmt.Errorf("adminscope: %w", err)
	}
	defer rows.Close()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("adminscope: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("adminscope: %w", err)
	}
	return ids, nil
}

func (s *Service) Assign(ctx context.Context, adminUserID, clientID int64) error {
	db := s.db()
	if db == nil {
		return nil
	}
	_, err := db.ExecContext(ctx,
		store.InsertOrIgnore()+` INTO admin_client_scope (admin_user_id, client_id) VALUES (?, ?)`,
		adminUserID, clientID,
	)
	if err != nil {
		return fmt.Errorf("adminscope: %w", err)
	}
	return nil
}

func (s *Service) Unassign(ctx context.Context, adminUserID, clientID int64) error {
	db := s.db()
	if db == nil {
		return nil
	}
	_, err := db.ExecContext(ctx,
		`DELETE FROM admin_client_scope WHERE admin_user_id=? AND client_id=?`,
		adminUserID, clientID,
	)
	if err != nil {
		return fmt.Errorf("adminscope: %w", err)
	}
	return nil
}

// ScopeFilter returns the set of client ids an admin may act on. super_admin
// (adminUserID=0) gets (nil, true) so callers skip WHERE filtering. A
// reseller-admin (users.reseller_id set) is scoped to that reseller's owned
// clients - dynamic ownership, never "all" and never the manual
// admin_client_scope assignment. Any other admin gets its assigned client list.
func (s *Service) ScopeFilter(ctx context.Context, adminUserID int64) (clientIDs []int64, all bool, err error) {
	if adminUserID == 0 {
		return nil, true, nil
	}
	db := s.db()
	if db == nil {
		return nil, false, nil
	}
	// Reseller-admin ownership takes precedence over manual scope assignment.
	var rid sql.NullInt64
	e := db.QueryRowContext(ctx, `SELECT reseller_id FROM users WHERE id = ?`, adminUserID).Scan(&rid)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return nil, false, fmt.Errorf("adminscope: reseller lookup: %w", e)
	}
	if rid.Valid {
		ids, err := s.resellerClientIDs(ctx, rid.Int64)
		if err != nil {
			return nil, false, err
		}
		return ids, false, nil
	}
	ids, err := s.AssignedClientIDs(ctx, adminUserID)
	if err != nil {
		return nil, false, err
	}
	return ids, false, nil
}

// resellerClientIDs lists the clients owned by a reseller (a reseller-admin's
// dynamic scope). Empty result -> the admin sees no client data yet, never all.
func (s *Service) resellerClientIDs(ctx context.Context, resellerID int64) ([]int64, error) {
	db := s.db()
	if db == nil {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx,
		`SELECT id FROM clients WHERE reseller_id = ? ORDER BY id`, resellerID)
	if err != nil {
		return nil, fmt.Errorf("adminscope: reseller clients: %w", err)
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("adminscope: reseller clients scan: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
