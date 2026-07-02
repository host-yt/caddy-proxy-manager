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

// userReseller resolves a user's reseller (0 = none) and whether that reseller is
// active. Reseller-admins are scoped by ownership, not admin_client_scope rows. A
// suspended reseller returns active=false so scope resolution can fail closed.
func (s *Service) userReseller(ctx context.Context, adminUserID int64) (rid int64, active bool, err error) {
	db := s.db()
	if db == nil {
		return 0, false, nil
	}
	var id sql.NullInt64
	var role string
	if err = db.QueryRowContext(ctx, `SELECT reseller_id, role FROM users WHERE id=?`, adminUserID).Scan(&id, &role); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("adminscope: reseller lookup: %w", err)
	}
	if !id.Valid {
		// role=reseller with no reseller binding is a broken row - report a
		// dangling binding (rid=-1) so resolveMode fails closed instead of
		// falling through to the unrestricted-platform-admin branch.
		if role == "reseller" {
			return -1, false, nil
		}
		return 0, false, nil
	}
	// Second query only when the user IS a reseller-admin, so DBs without a
	// resellers table (non-reseller code paths) never touch it.
	var status sql.NullString
	if err = db.QueryRowContext(ctx, `SELECT status FROM resellers WHERE id=?`, id.Int64).Scan(&status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return id.Int64, false, nil // dangling FK: fail closed
		}
		return 0, false, fmt.Errorf("adminscope: reseller status: %w", err)
	}
	return id.Int64, status.String == "active", nil
}

// scopeMode classifies an admin. Restriction is OPT-IN and now EXPLICIT
// (users.is_restricted), not inferred from admin_client_scope row count.
type scopeMode struct {
	all        bool  // unrestricted platform admin
	resellerID int64 // >0 = reseller-scoped
	denied     bool  // hard-empty scope (e.g. suspended reseller): sees nothing
}

// resolveMode determines whether an admin is unrestricted, reseller-scoped, or
// client-scoped. reseller_id wins; otherwise users.is_restricted decides. A
// restricted admin with zero admin_client_scope rows sees nothing (fail-safe),
// which is why the flag is explicit rather than inferred from the row count.
func (s *Service) resolveMode(ctx context.Context, adminUserID int64) (scopeMode, error) {
	rid, active, err := s.userReseller(ctx, adminUserID)
	if err != nil {
		return scopeMode{}, err
	}
	if rid != 0 {
		// Suspended reseller: hard-empty scope. Must NOT fall through to the
		// is_restricted branch (would grant `all`) nor to admin_client_scope (a
		// stray assignment would leak a client). Sees/manages nothing.
		if !active {
			return scopeMode{denied: true}, nil
		}
		return scopeMode{resellerID: rid}, nil
	}
	db := s.db()
	if db == nil {
		return scopeMode{}, nil
	}
	var restricted bool
	if err := db.QueryRowContext(ctx,
		`SELECT COALESCE(is_restricted,0) FROM users WHERE id=?`, adminUserID).Scan(&restricted); err != nil {
		return scopeMode{}, fmt.Errorf("adminscope: mode: %w", err)
	}
	if restricted {
		return scopeMode{}, nil // client-scoped (empty scope = sees nothing)
	}
	return scopeMode{all: true}, nil // unrestricted
}

func (s *Service) CanAccessClient(ctx context.Context, adminUserID, clientID int64) (bool, error) {
	db := s.db()
	if db == nil {
		return false, nil
	}
	m, err := s.resolveMode(ctx, adminUserID)
	if err != nil {
		return false, err
	}
	if m.all {
		return true, nil
	}
	if m.denied {
		return false, nil
	}
	var count int
	if m.resellerID != 0 {
		err = db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM clients WHERE id=? AND reseller_id=?`, clientID, m.resellerID).Scan(&count)
	} else {
		err = db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM admin_client_scope WHERE admin_user_id=? AND client_id=?`,
			adminUserID, clientID).Scan(&count)
	}
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
	m, err := s.resolveMode(ctx, adminUserID)
	if err != nil {
		return false, err
	}
	if m.all {
		return true, nil
	}
	if m.denied {
		return false, nil
	}
	var count int
	if m.resellerID != 0 {
		err = db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM customer_wg_peer p
			 JOIN clients c ON c.id = p.client_id
			 WHERE p.id=? AND c.reseller_id=?`, peerID, m.resellerID).Scan(&count)
	} else {
		err = db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM admin_client_scope acs
			 JOIN customer_wg_peer p ON p.client_id = acs.client_id
			 WHERE acs.admin_user_id=? AND p.id=?`,
			adminUserID, peerID).Scan(&count)
	}
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
	m, err := s.resolveMode(ctx, adminUserID)
	if err != nil {
		return false, err
	}
	if m.all {
		return true, nil
	}
	if m.denied {
		return false, nil
	}
	var count int
	if m.resellerID != 0 {
		err = db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM routes r
			 JOIN services sv ON sv.id = r.service_id
			 JOIN clients c ON c.id = sv.client_id
			 WHERE r.id=? AND c.reseller_id=?`, routeID, m.resellerID).Scan(&count)
	} else {
		err = db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM admin_client_scope acs
			 JOIN services sv ON sv.client_id = acs.client_id
			 JOIN routes r ON r.service_id = sv.id
			 WHERE acs.admin_user_id=? AND r.id=?`,
			adminUserID, routeID).Scan(&count)
	}
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

// ScopeFilter returns the client ids an admin may act on. super_admin
// (adminUserID=0) and an unrestricted platform admin get (nil, true) so callers
// skip WHERE filtering. A reseller-admin is scoped to its reseller's owned
// clients; a client-scoped admin to its admin_client_scope assignment.
func (s *Service) ScopeFilter(ctx context.Context, adminUserID int64) (clientIDs []int64, all bool, err error) {
	if adminUserID == 0 {
		return nil, true, nil
	}
	m, err := s.resolveMode(ctx, adminUserID)
	if err != nil {
		return nil, false, err
	}
	if m.all {
		return nil, true, nil
	}
	if m.denied {
		return []int64{}, false, nil
	}
	if m.resellerID != 0 {
		ids, err := s.resellerClientIDs(ctx, m.resellerID)
		return ids, false, err
	}
	ids, err := s.AssignedClientIDs(ctx, adminUserID)
	return ids, false, err
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
