package adminscope

import (
	"context"
	"database/sql"
	"fmt"
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
		`INSERT IGNORE INTO admin_client_scope (admin_user_id, client_id) VALUES (?, ?)`,
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

// ScopeFilter returns (nil, true, nil) for super_admin (adminUserID=0) so callers
// skip WHERE filtering entirely; otherwise returns the assigned client list.
func (s *Service) ScopeFilter(ctx context.Context, adminUserID int64) (clientIDs []int64, all bool, err error) {
	if adminUserID == 0 {
		return nil, true, nil
	}
	ids, err := s.AssignedClientIDs(ctx, adminUserID)
	if err != nil {
		return nil, false, err
	}
	return ids, false, nil
}
