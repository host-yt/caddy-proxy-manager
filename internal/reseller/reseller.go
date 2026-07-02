// Package reseller stores and scopes the reseller ownership layer: a reseller
// owns a set of clients (and optionally its own plans + branding) and is managed
// by a reseller-admin user who sees only that reseller's tenants. reseller_id is
// NULL for platform-direct rows, so an all-NULL DB behaves exactly as before.
package reseller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrNotFound is returned when a reseller row does not exist.
var ErrNotFound = errors.New("reseller: not found")

// Status values for resellers.status.
const (
	StatusActive    = "active"
	StatusSuspended = "suspended"
)

// Reseller is one white-label tenant grouping. Branding fields are optional and
// fall back to the global settings branding when empty.
type Reseller struct {
	ID           int64
	Name         string
	Slug         string
	Status       string
	BrandName    string
	LogoURL      string
	SupportEmail string
	PrimaryColor string
}

// Store wraps a lazily-resolved *sql.DB (the DB may not exist pre-install).
type Store struct {
	db func() *sql.DB
}

// New returns a Store backed by the given DB accessor.
func New(db func() *sql.DB) *Store { return &Store{db: db} }

const resellerCols = "id, name, slug, status, " +
	"COALESCE(brand_name,''), COALESCE(logo_url,''), COALESCE(support_email,''), COALESCE(primary_color,'')"

func scanReseller(row interface{ Scan(...any) error }) (Reseller, error) {
	var r Reseller
	err := row.Scan(&r.ID, &r.Name, &r.Slug, &r.Status,
		&r.BrandName, &r.LogoURL, &r.SupportEmail, &r.PrimaryColor)
	return r, err
}

// Create inserts a reseller and returns its id. Slug must be unique; a duplicate
// surfaces the underlying DB error.
func (s *Store) Create(ctx context.Context, r Reseller) (int64, error) {
	db := s.db()
	if db == nil {
		return 0, errors.New("reseller: no db")
	}
	status := r.Status
	if status == "" {
		status = StatusActive
	}
	res, err := db.ExecContext(ctx,
		`INSERT INTO resellers (name, slug, status, brand_name, logo_url, support_email, primary_color)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		r.Name, r.Slug, status,
		nullIfEmpty(r.BrandName), nullIfEmpty(r.LogoURL), nullIfEmpty(r.SupportEmail), nullIfEmpty(r.PrimaryColor))
	if err != nil {
		return 0, fmt.Errorf("reseller: create: %w", err)
	}
	id, _ := res.LastInsertId()
	return id, nil
}

// Get returns one reseller by id, or ErrNotFound.
func (s *Store) Get(ctx context.Context, id int64) (Reseller, error) {
	db := s.db()
	if db == nil {
		return Reseller{}, errors.New("reseller: no db")
	}
	r, err := scanReseller(db.QueryRowContext(ctx,
		`SELECT `+resellerCols+` FROM resellers WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Reseller{}, ErrNotFound
	}
	if err != nil {
		return Reseller{}, fmt.Errorf("reseller: get: %w", err)
	}
	return r, nil
}

// List returns all resellers ordered by name.
func (s *Store) List(ctx context.Context) ([]Reseller, error) {
	db := s.db()
	if db == nil {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx,
		`SELECT `+resellerCols+` FROM resellers ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("reseller: list: %w", err)
	}
	defer rows.Close()
	var out []Reseller
	for rows.Next() {
		r, err := scanReseller(rows)
		if err != nil {
			return nil, fmt.Errorf("reseller: list scan: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Update writes name, status, and branding for an existing reseller.
func (s *Store) Update(ctx context.Context, r Reseller) error {
	db := s.db()
	if db == nil {
		return errors.New("reseller: no db")
	}
	res, err := db.ExecContext(ctx,
		`UPDATE resellers SET name=?, status=?, brand_name=?, logo_url=?, support_email=?, primary_color=?
		 WHERE id=?`,
		r.Name, r.Status,
		nullIfEmpty(r.BrandName), nullIfEmpty(r.LogoURL), nullIfEmpty(r.SupportEmail), nullIfEmpty(r.PrimaryColor),
		r.ID)
	if err != nil {
		return fmt.Errorf("reseller: update: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetStatus flips a reseller between active and suspended.
func (s *Store) SetStatus(ctx context.Context, id int64, status string) error {
	db := s.db()
	if db == nil {
		return errors.New("reseller: no db")
	}
	res, err := db.ExecContext(ctx, `UPDATE resellers SET status=? WHERE id=?`, status, id)
	if err != nil {
		return fmt.Errorf("reseller: set status: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Delete removes a reseller; owned clients/plans/users have their reseller_id
// reset to NULL by the ON DELETE SET NULL foreign keys (returns to platform-direct).
func (s *Store) Delete(ctx context.Context, id int64) error {
	db := s.db()
	if db == nil {
		return errors.New("reseller: no db")
	}
	res, err := db.ExecContext(ctx, `DELETE FROM resellers WHERE id=?`, id)
	if err != nil {
		return fmt.Errorf("reseller: delete: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ClientIDs returns the client ids owned by a reseller. This is the source of a
// reseller-admin's scope - never trust a model/request-supplied id.
func (s *Store) ClientIDs(ctx context.Context, resellerID int64) ([]int64, error) {
	db := s.db()
	if db == nil {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx,
		`SELECT id FROM clients WHERE reseller_id = ?`, resellerID)
	if err != nil {
		return nil, fmt.Errorf("reseller: client ids: %w", err)
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("reseller: client ids scan: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ResellerIDForUser returns the reseller a user belongs to. ok is false when the
// user is not tied to any reseller (platform admin / regular client).
func (s *Store) ResellerIDForUser(ctx context.Context, userID int64) (id int64, ok bool, err error) {
	db := s.db()
	if db == nil {
		return 0, false, nil
	}
	var rid sql.NullInt64
	e := db.QueryRowContext(ctx, `SELECT reseller_id FROM users WHERE id = ?`, userID).Scan(&rid)
	if errors.Is(e, sql.ErrNoRows) {
		return 0, false, nil
	}
	if e != nil {
		return 0, false, fmt.Errorf("reseller: user lookup: %w", e)
	}
	if !rid.Valid {
		return 0, false, nil
	}
	return rid.Int64, true, nil
}

// AssignClient sets (or clears, when resellerID is nil) the owning reseller of a
// client. Clearing returns the client to platform-direct ownership.
func (s *Store) AssignClient(ctx context.Context, clientID int64, resellerID *int64) error {
	db := s.db()
	if db == nil {
		return errors.New("reseller: no db")
	}
	res, err := db.ExecContext(ctx,
		`UPDATE clients SET reseller_id = ? WHERE id = ?`, resellerID, clientID)
	if err != nil {
		return fmt.Errorf("reseller: assign client: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// AssignAdmin sets (or clears, when resellerID is nil) a user's owning reseller,
// turning them into (or back from) a reseller-admin. Caller MUST revoke the
// user's live sessions after this - a cached Session.ResellerID bypasses the
// route boundary until it expires otherwise.
func (s *Store) AssignAdmin(ctx context.Context, userID int64, resellerID *int64) error {
	db := s.db()
	if db == nil {
		return errors.New("reseller: no db")
	}
	res, err := db.ExecContext(ctx,
		`UPDATE users SET reseller_id = ? WHERE id = ?`, resellerID, userID)
	if err != nil {
		return fmt.Errorf("reseller: assign admin: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
