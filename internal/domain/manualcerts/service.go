// Package manualcerts manages operator-imported TLS certificates.
// Private key material is stored encrypted via installstate.Manager (AES-256-GCM).
package manualcerts

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Record holds the parsed + stored representation of one imported cert.
type Record struct {
	ID         int64
	Name       string
	RouteID    sql.NullInt64
	CertPEM    string
	ChainPEM   string
	CommonName string
	SANs       []string
	NotBefore  time.Time
	NotAfter   time.Time
	CreatedAt  time.Time
}

// ExpiryStatus classifies a cert's proximity to expiry.
type ExpiryStatus string

const (
	StatusOK      ExpiryStatus = "ok"
	StatusWarn    ExpiryStatus = "warn"    // <30d
	StatusExpired ExpiryStatus = "expired" // past NotAfter
)

// DaysUntilExpiry returns days remaining (negative if expired).
func (r Record) DaysUntilExpiry() int {
	return int(time.Until(r.NotAfter).Hours() / 24)
}

// Expiry returns the expiry classification.
func (r Record) Expiry() ExpiryStatus {
	if time.Now().After(r.NotAfter) {
		return StatusExpired
	}
	if r.DaysUntilExpiry() < 30 {
		return StatusWarn
	}
	return StatusOK
}

// ImportInput carries raw PEM strings from the import form.
type ImportInput struct {
	Name     string
	RouteID  sql.NullInt64
	CertPEM  string
	KeyPEM   string
	ChainPEM string
}

// Service drives CRUD on manual_certs. Encrypt/Decrypt are injected from
// installstate.Manager so key derivation is centralised.
type Service struct {
	DB      func() *sql.DB
	Encrypt func(string) (string, error)
	Decrypt func(string) (string, error)
}

// Import validates, parses, and inserts a certificate. Returns the new record ID.
func (s *Service) Import(ctx context.Context, in ImportInput) (int64, error) {
	if in.CertPEM == "" || in.KeyPEM == "" {
		return 0, errors.New("cert PEM and key PEM are required")
	}

	// Validate cert+key pair and extract metadata.
	leaf, err := parseCertAndKey(in.CertPEM, in.KeyPEM)
	if err != nil {
		return 0, err
	}

	// Validate chain if provided (non-fatal warning becomes an error only if unparseable).
	if in.ChainPEM != "" {
		if err := validateChainPEM(in.ChainPEM); err != nil {
			return 0, fmt.Errorf("chain PEM: %w", err)
		}
	}

	// Encrypt the private key before storing.
	keyEnc, err := s.Encrypt(in.KeyPEM)
	if err != nil {
		return 0, fmt.Errorf("encrypt key: %w", err)
	}

	sans, err := json.Marshal(sanStrings(leaf))
	if err != nil {
		return 0, fmt.Errorf("marshal SANs: %w", err)
	}

	db := s.DB()
	if db == nil {
		return 0, errors.New("no database connection")
	}

	var routeID any
	if in.RouteID.Valid {
		routeID = in.RouteID.Int64
	}

	res, err := db.ExecContext(ctx,
		`INSERT INTO manual_certs
		   (name, route_id, cert_pem, key_pem_enc, chain_pem, common_name, sans, not_before, not_after)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		in.Name, routeID, in.CertPEM, keyEnc,
		in.ChainPEM, leaf.Subject.CommonName, string(sans),
		leaf.NotBefore.UTC(), leaf.NotAfter.UTC(),
	)
	if err != nil {
		return 0, fmt.Errorf("insert: %w", err)
	}
	return res.LastInsertId()
}

// List returns all manual certs ordered by expiry ascending.
func (s *Service) List(ctx context.Context) ([]Record, error) {
	db := s.DB()
	if db == nil {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx,
		`SELECT id, name, route_id, cert_pem, chain_pem, common_name, sans, not_before, not_after, created_at
		   FROM manual_certs
		  ORDER BY not_after ASC`)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	var out []Record
	for rows.Next() {
		var r Record
		var sansJSON string
		var routeID sql.NullInt64
		if err := rows.Scan(&r.ID, &r.Name, &routeID, &r.CertPEM, &r.ChainPEM,
			&r.CommonName, &sansJSON, &r.NotBefore, &r.NotAfter, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		r.RouteID = routeID
		_ = json.Unmarshal([]byte(sansJSON), &r.SANs)
		out = append(out, r)
	}
	return out, rows.Err()
}

// Delete removes a manual cert by ID.
func (s *Service) Delete(ctx context.Context, id int64) error {
	db := s.DB()
	if db == nil {
		return errors.New("no database connection")
	}
	_, err := db.ExecContext(ctx, "DELETE FROM manual_certs WHERE id = ?", id)
	return err
}

// ---- validation helpers ----

// parseCertAndKey verifies the PEM cert+key pair and returns the leaf cert.
func parseCertAndKey(certPEM, keyPEM string) (*x509.Certificate, error) {
	// tls.X509KeyPair checks that the key matches the cert's public key.
	tlsCert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("cert/key mismatch or invalid PEM: %w", err)
	}
	if len(tlsCert.Certificate) == 0 {
		return nil, errors.New("no certificate found in PEM")
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse leaf cert: %w", err)
	}
	return leaf, nil
}

// validateChainPEM ensures every PEM block in the chain is a valid certificate.
func validateChainPEM(chainPEM string) error {
	rest := []byte(strings.TrimSpace(chainPEM))
	if len(rest) == 0 {
		return nil
	}
	count := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("unexpected PEM block type %q in chain", block.Type)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("parse chain cert: %w", err)
		}
		count++
	}
	if count == 0 {
		return errors.New("no valid CERTIFICATE block in chain PEM")
	}
	return nil
}

// sanStrings collects SANs from a parsed cert as a string slice.
func sanStrings(c *x509.Certificate) []string {
	var out []string
	for _, d := range c.DNSNames {
		out = append(out, d)
	}
	for _, ip := range c.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}
