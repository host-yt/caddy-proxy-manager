// Package portal implements the built-in forward-auth access portal: local
// access groups, per-route grants, and the allow/deny decision used by the
// verify endpoint. It reuses the existing users table for identities (members
// are users) so there is no parallel credential store.
package portal

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

type Service struct {
	db func() *sql.DB
}

func New(db func() *sql.DB) *Service { return &Service{db: db} }

// Group is one local access group.
type Group struct {
	ID          int64
	Name        string
	Description string
	ClientID    sql.NullInt64
	MemberCount int
}

// Member is a user that belongs to a group.
type Member struct {
	UserID int64
	Email  string
	Name   string
}

// ListGroups returns groups visible to the caller. When clientIDs is nil and
// all is true (super_admin) every group is returned; otherwise only groups
// owned by one of the caller's clients.
func (s *Service) ListGroups(ctx context.Context, clientIDs []int64, all bool) ([]Group, error) {
	db := s.db()
	if db == nil {
		return nil, nil
	}
	q := `SELECT g.id, g.name, g.description, g.client_id,
	             (SELECT COUNT(*) FROM access_group_members m WHERE m.group_id = g.id)
	      FROM access_groups g`
	args := []any{}
	if !all {
		if len(clientIDs) == 0 {
			return nil, nil
		}
		q += " WHERE g.client_id IN (" + placeholders(len(clientIDs)) + ")"
		for _, id := range clientIDs {
			args = append(args, id)
		}
	}
	q += " ORDER BY g.name ASC"
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("portal: list groups: %w", err)
	}
	defer rows.Close()
	var out []Group
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.ClientID, &g.MemberCount); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// GroupsForGrant returns the groups grantable to a route: those owned by the
// route's client, plus (when includeGlobal) global groups. Used by the host
// editor's Portal tab.
func (s *Service) GroupsForGrant(ctx context.Context, clientID int64, includeGlobal bool) ([]Group, error) {
	db := s.db()
	if db == nil {
		return nil, nil
	}
	q := `SELECT g.id, g.name, g.description, g.client_id,
	             (SELECT COUNT(*) FROM access_group_members m WHERE m.group_id = g.id)
	      FROM access_groups g WHERE g.client_id = ?`
	if includeGlobal {
		q += " OR g.client_id IS NULL"
	}
	q += " ORDER BY g.name ASC"
	rows, err := db.QueryContext(ctx, q, clientID)
	if err != nil {
		return nil, fmt.Errorf("portal: groups for grant: %w", err)
	}
	defer rows.Close()
	var out []Group
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.ClientID, &g.MemberCount); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// GroupClientID returns the owning client_id of a group (NULL -> 0, false).
func (s *Service) GroupClientID(ctx context.Context, groupID int64) (int64, bool, error) {
	db := s.db()
	if db == nil {
		return 0, false, nil
	}
	var cid sql.NullInt64
	err := db.QueryRowContext(ctx, `SELECT client_id FROM access_groups WHERE id = ?`, groupID).Scan(&cid)
	if err != nil {
		return 0, false, err
	}
	return cid.Int64, cid.Valid, nil
}

// CreateGroup inserts a group. clientID<=0 stores NULL (global, super-admin only).
func (s *Service) CreateGroup(ctx context.Context, name, description string, clientID int64) (int64, error) {
	db := s.db()
	if db == nil {
		return 0, nil
	}
	var cid any
	if clientID > 0 {
		cid = clientID
	}
	res, err := db.ExecContext(ctx,
		`INSERT INTO access_groups (name, description, client_id) VALUES (?, ?, ?)`,
		name, description, cid)
	if err != nil {
		return 0, fmt.Errorf("portal: create group: %w", err)
	}
	return res.LastInsertId()
}

// DeleteGroup removes a group; cascades drop members + grants.
func (s *Service) DeleteGroup(ctx context.Context, groupID int64) error {
	db := s.db()
	if db == nil {
		return nil
	}
	_, err := db.ExecContext(ctx, `DELETE FROM access_groups WHERE id = ?`, groupID)
	return err
}

// Members lists the users in a group.
func (s *Service) Members(ctx context.Context, groupID int64) ([]Member, error) {
	db := s.db()
	if db == nil {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx,
		`SELECT u.id, u.email, COALESCE(u.full_name,'')
		   FROM access_group_members m JOIN users u ON u.id = m.user_id
		  WHERE m.group_id = ? ORDER BY u.email ASC`, groupID)
	if err != nil {
		return nil, fmt.Errorf("portal: members: %w", err)
	}
	defer rows.Close()
	var out []Member
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.UserID, &m.Email, &m.Name); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// AddMemberByEmail adds an existing user to a group by email. Returns false
// when no such (active) user exists - we never create portal identities here.
func (s *Service) AddMemberByEmail(ctx context.Context, groupID int64, email string) (bool, error) {
	db := s.db()
	if db == nil {
		return false, nil
	}
	var uid int64
	err := db.QueryRowContext(ctx, `SELECT id FROM users WHERE email = ? AND is_active = 1`, email).Scan(&uid)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	_, err = db.ExecContext(ctx,
		store.InsertOrIgnore()+` INTO access_group_members (group_id, user_id) VALUES (?, ?)`, groupID, uid)
	return err == nil, err
}

// RemoveMember drops a user from a group.
func (s *Service) RemoveMember(ctx context.Context, groupID, userID int64) error {
	db := s.db()
	if db == nil {
		return nil
	}
	_, err := db.ExecContext(ctx,
		`DELETE FROM access_group_members WHERE group_id = ? AND user_id = ?`, groupID, userID)
	return err
}

// RouteGrants returns the group IDs granted access to a route.
func (s *Service) RouteGrants(ctx context.Context, routeID int64) ([]int64, error) {
	db := s.db()
	if db == nil {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx,
		`SELECT group_id FROM route_access_grants WHERE route_id = ? ORDER BY group_id`, routeID)
	if err != nil {
		return nil, fmt.Errorf("portal: route grants: %w", err)
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// SetRouteGrants replaces the grant set for a route atomically. Only groupIDs
// that the caller may use (visibleGroupIDs, nil+all for super_admin) are
// written - this prevents a scoped admin from granting another tenant's group.
func (s *Service) SetRouteGrants(ctx context.Context, routeID int64, groupIDs []int64, visibleGroupIDs map[int64]bool, all bool) error {
	db := s.db()
	if db == nil {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM route_access_grants WHERE route_id = ?`, routeID); err != nil {
		_ = tx.Rollback()
		return err
	}
	for _, gid := range groupIDs {
		if !all && !visibleGroupIDs[gid] {
			continue // skip groups the caller is not allowed to reference
		}
		if _, err := tx.ExecContext(ctx,
			store.InsertOrIgnore()+` INTO route_access_grants (route_id, group_id) VALUES (?, ?)`, routeID, gid); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// IsAllowed reports whether a user is a member of any group granted access to
// the route. Fail closed: a query error returns (false, err) and the caller
// must deny.
func (s *Service) IsAllowed(ctx context.Context, routeID, userID int64) (bool, error) {
	db := s.db()
	if db == nil {
		return false, fmt.Errorf("portal: no db")
	}
	var n int
	err := db.QueryRowContext(ctx,
		`SELECT COUNT(*)
		   FROM route_access_grants g
		   JOIN access_group_members m ON m.group_id = g.group_id
		  WHERE g.route_id = ? AND m.user_id = ?`, routeID, userID).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// RouteByHost resolves the route id + portal_protect flag for a hostname. The
// verify endpoint uses this to map the protected host to its route. Matches the
// primary domain or any alias (aliases stored as a comma/space list).
func (s *Service) RouteByHost(ctx context.Context, host string) (routeID int64, portalProtect bool, err error) {
	db := s.db()
	if db == nil {
		return 0, false, fmt.Errorf("portal: no db")
	}
	err = db.QueryRowContext(ctx,
		`SELECT id, COALESCE(portal_protect,0) FROM routes
		  WHERE domain = ?
		     OR FIND_IN_SET(?, REPLACE(REPLACE(COALESCE(aliases,''),' ',''),'\n',',')) > 0
		  ORDER BY (domain = ?) DESC LIMIT 1`, host, host, host).Scan(&routeID, &portalProtect)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	return routeID, portalProtect, err
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	b := make([]byte, 0, 2*n)
	for i := 0; i < n; i++ {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, '?')
	}
	return string(b)
}
