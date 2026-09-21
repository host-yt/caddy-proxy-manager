// Package portal implements the built-in forward-auth access portal: local
// access groups, per-route grants, and the allow/deny decision used by the
// verify endpoint. It reuses the existing users table for identities (members
// are users) so there is no parallel credential store.
package portal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
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
		// A silent no-op on a security write would report success while the
		// old grant set stays live.
		return errors.New("portal: no db")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := replaceGrantsTx(ctx, tx, routeID, groupIDs, visibleGroupIDs, all); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// SetRouteProtection writes the portal flag and the grant set in ONE
// transaction. Split writes can leave a route flagged protected with an empty
// grant set (or the reverse), and either half-state changes who gets in.
func (s *Service) SetRouteProtection(ctx context.Context, routeID int64, protect bool, groupIDs []int64, visibleGroupIDs map[int64]bool, all bool) error {
	db := s.db()
	if db == nil {
		return errors.New("portal: no db")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE routes SET portal_protect = ? WHERE id = ?`, protect, routeID); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := replaceGrantsTx(ctx, tx, routeID, groupIDs, visibleGroupIDs, all); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func replaceGrantsTx(ctx context.Context, tx *sql.Tx, routeID int64, groupIDs []int64, visibleGroupIDs map[int64]bool, all bool) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM route_access_grants WHERE route_id = ?`, routeID); err != nil {
		return err
	}
	for _, gid := range groupIDs {
		if !all && !visibleGroupIDs[gid] {
			continue // skip groups the caller is not allowed to reference
		}
		if _, err := tx.ExecContext(ctx,
			store.InsertOrIgnore()+` INTO route_access_grants (route_id, group_id) VALUES (?, ?)`, routeID, gid); err != nil {
			return err
		}
	}
	return nil
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

// ErrNoRoute means no serving route matches the request. ErrAmbiguousRoute
// means two equally specific routes do, so there is no single policy to apply.
// Both are deny conditions for the verifier.
var (
	ErrNoRoute        = errors.New("portal: no route for request")
	ErrAmbiguousRoute = errors.New("portal: ambiguous route for request")
)

// RouteForRequest resolves the EXACT route a request lands on, mirroring the
// node's own matching: a proven host matcher plus the longest path prefix,
// which is the order routes are emitted in. Host alone is not an identity -
// several routes can share a hostname with different grants, and one of them
// may be public.
func (s *Service) RouteForRequest(ctx context.Context, host, path string) (routeID int64, portalProtect bool, err error) {
	db := s.db()
	if db == nil {
		return 0, false, errors.New("portal: no db")
	}
	host = strings.ToLower(strings.TrimSpace(host))
	// Both halves of the identity come from the gate config the panel emits
	// (Host + X-Forwarded-Uri, both "set"). Missing either one means the call
	// did not come through a gate: refuse rather than guess a route.
	if host == "" || !strings.HasPrefix(path, "/") {
		return 0, false, ErrNoRoute
	}
	// Prefilter in SQL, decide in Go: alias lists and wildcard labels cannot be
	// matched portably in SQL, and the emitted-host rules live in one place.
	rows, err := db.QueryContext(ctx,
		`SELECT id, COALESCE(path_prefix,''), domain, COALESCE(aliases,''), COALESCE(aliases_verified,''),
		        COALESCE(portal_protect,0)
		   FROM routes
		  WHERE COALESCE(domain_verified,0) = 1
		    AND status IN ('dns_ok','active','pending_ssl')
		    AND (LOWER(domain) = ? OR domain LIKE '%*%'
		         OR LOWER(COALESCE(aliases,'')) LIKE ? OR COALESCE(aliases,'') LIKE '%*%')`,
		host, "%"+host+"%")
	if err != nil {
		return 0, false, fmt.Errorf("portal: route for request: %w", err)
	}
	defer rows.Close()

	lowPath := strings.ToLower(path)
	var (
		bestID      int64
		bestProtect bool
		bestLen     = -1
		ambiguous   bool
	)
	for rows.Next() {
		var (
			id                                  int64
			prefix, domain, aliases, aliasesVer string
			protect                             bool
		)
		if err := rows.Scan(&id, &prefix, &domain, &aliases, &aliasesVer, &protect); err != nil {
			return 0, false, err
		}
		if !hostServedBy(host, domain, aliases, aliasesVer) {
			continue
		}
		p := strings.TrimSpace(prefix)
		if p == "/" {
			p = "" // the host catch-all, same as no prefix
		}
		// Caddy matches "<prefix>*", so a plain prefix test is the exact rule.
		if p != "" && !strings.HasPrefix(lowPath, strings.ToLower(p)) {
			continue
		}
		switch {
		case len(p) > bestLen:
			bestID, bestProtect, bestLen, ambiguous = id, protect, len(p), false
		case len(p) == bestLen:
			ambiguous = true
		}
	}
	if err := rows.Err(); err != nil {
		return 0, false, err
	}
	if bestLen < 0 {
		return 0, false, ErrNoRoute
	}
	if ambiguous {
		return 0, false, ErrAmbiguousRoute
	}
	return bestID, bestProtect, nil
}

// hostServedBy mirrors buildRoutesForNode's host matchers: the primary domain
// always, plus only aliases whose ownership was proven.
func hostServedBy(host, domain, aliases, aliasesVerified string) bool {
	if caddyapi.HostsOverlap(domain, host) {
		return true
	}
	proven := map[string]bool{}
	for _, a := range splitHosts(aliasesVerified) {
		proven[a] = true
	}
	for _, a := range splitHosts(aliases) {
		if proven[a] && caddyapi.HostsOverlap(a, host) {
			return true
		}
	}
	return false
}

// splitHosts mirrors routes.splitHostList (unexported there).
func splitHosts(raw string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == ';'
	}) {
		if v := strings.ToLower(strings.TrimSpace(p)); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// IdentityStillValid re-checks the account behind a live portal session: the
// row must exist, be active, and still carry the epoch the session was minted
// with. (false, nil) is a definitive revocation - the caller may drop the
// session; a non-nil error is indeterminate - deny, but keep the session.
func (s *Service) IdentityStillValid(ctx context.Context, userID, epoch int64) (bool, error) {
	db := s.db()
	if db == nil {
		return false, errors.New("portal: no db")
	}
	var (
		active bool
		cur    int64
	)
	err := db.QueryRowContext(ctx,
		`SELECT is_active, auth_epoch FROM users WHERE id = ?`, userID).Scan(&active, &cur)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return active && cur == epoch, nil
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
