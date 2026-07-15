// Package mtls manages per-tenant/operator certificate authorities used for
// mutual-TLS client authentication. It generates CA keypairs, issues client
// certificates from them, and tracks revocation (CRL-style status list).
//
// CA private keys are stored encrypted at rest via installstate.Manager
// (AES-256-GCM). Client private keys are returned exactly once at issue time
// and never persisted. No key material is ever logged.
//
// Enforcement is wired end to end: hosts opt in via routes.require_client_cert
// + routes.mtls_ca_id, the routes builder emits a Caddy TLS connection policy
// (client_authentication require_and_verify against the CA's inline trust pool),
// and the CA cert PEM bundle / revocation list are exposed under /admin/mtls.
package mtls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/host-yt/caddy-proxy-manager/internal/store"
	"math/big"
	"strings"
	"time"
)

const (
	StatusActive  = "active"
	StatusRevoked = "revoked"

	defaultCAValidity     = 10 * 365 * 24 * time.Hour // 10 years
	defaultClientValidity = 365 * 24 * time.Hour      // 1 year
	maxClientValidity     = 5 * 365 * 24 * time.Hour
)

// CA is the stored representation of one certificate authority. KeyPEMEnc holds
// the encrypted private key and is never exposed to templates.
type CA struct {
	ID         int64
	Name       string
	ClientID   sql.NullInt64
	CommonName string
	CertPEM    string
	NotBefore  time.Time
	NotAfter   time.Time
	Status     string
	CreatedAt  time.Time
}

// IssuedCert is one client certificate minted from a CA. The private key is not
// part of this record - it is handed back only at issue time.
type IssuedCert struct {
	ID        int64
	CAID      int64
	Subject   string
	Serial    string
	CertPEM   string
	Status    string
	NotAfter  time.Time
	IssuedAt  time.Time
	RevokedAt sql.NullTime
}

// Revoked reports whether the cert has been revoked.
func (c IssuedCert) Revoked() bool { return c.Status == StatusRevoked }

// Expired reports whether the cert is past its NotAfter.
func (c IssuedCert) Expired() bool { return time.Now().After(c.NotAfter) }

// CreateCAInput carries the operator's request to mint a new CA.
type CreateCAInput struct {
	Name       string
	ClientID   sql.NullInt64
	CommonName string
	ValidFor   time.Duration // 0 -> defaultCAValidity
}

// IssueInput carries the operator's request to issue a client certificate.
type IssueInput struct {
	CAID     int64
	Subject  string        // CommonName placed on the client cert
	ValidFor time.Duration // 0 -> defaultClientValidity, capped at maxClientValidity
}

// IssueResult is returned once at issue time. KeyPEM is the client private key
// and MUST be delivered to the operator and then discarded - it is never stored.
type IssueResult struct {
	ID      int64
	Serial  string
	CertPEM string
	KeyPEM  string
}

// Service drives CA + issued-cert CRUD. Encrypt/Decrypt are injected from
// installstate.Manager so key derivation stays centralised.
type Service struct {
	DB      func() *sql.DB
	Encrypt func(string) (string, error)
	Decrypt func(string) (string, error)
}

func (s *Service) db() (*sql.DB, error) {
	if s == nil || s.DB == nil {
		return nil, errors.New("mtls: no database")
	}
	db := s.DB()
	if db == nil {
		return nil, errors.New("mtls: no database connection")
	}
	return db, nil
}

// CreateCA generates a self-signed CA keypair and stores it with the private
// key encrypted at rest. Returns the new CA's ID.
func (s *Service) CreateCA(ctx context.Context, in CreateCAInput) (int64, error) {
	if s.Encrypt == nil {
		return 0, errors.New("mtls: crypto not configured")
	}
	cn := strings.TrimSpace(in.CommonName)
	if cn == "" {
		cn = strings.TrimSpace(in.Name)
	}
	if cn == "" {
		return 0, errors.New("CA common name (or name) is required")
	}

	validity := in.ValidFor
	if validity <= 0 {
		validity = defaultCAValidity
	}

	certPEM, keyPEM, notBefore, notAfter, err := generateCA(cn, validity)
	if err != nil {
		return 0, err
	}

	keyEnc, err := s.Encrypt(keyPEM)
	if err != nil {
		return 0, fmt.Errorf("encrypt CA key: %w", err)
	}

	db, err := s.db()
	if err != nil {
		return 0, err
	}
	var clientID any
	if in.ClientID.Valid {
		clientID = in.ClientID.Int64
	}
	res, err := db.ExecContext(ctx,
		`INSERT INTO mtls_cas
		   (name, client_id, common_name, cert_pem, key_pem_enc, serial_seq, not_before, not_after, status)
		 VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)`,
		strings.TrimSpace(in.Name), clientID, cn, certPEM, keyEnc,
		notBefore.UTC(), notAfter.UTC(), StatusActive,
	)
	if err != nil {
		return 0, fmt.Errorf("insert CA: %w", err)
	}
	return res.LastInsertId()
}

// ListCAs returns all CAs ordered newest first.
func (s *Service) ListCAs(ctx context.Context) ([]CA, error) {
	db, err := s.db()
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx,
		`SELECT id, name, client_id, common_name, cert_pem, not_before, not_after, status, created_at
		   FROM mtls_cas ORDER BY id DESC`)
	if err != nil {
		return nil, fmt.Errorf("query CAs: %w", err)
	}
	defer rows.Close()
	var out []CA
	for rows.Next() {
		var c CA
		if err := rows.Scan(&c.ID, &c.Name, &c.ClientID, &c.CommonName,
			&c.CertPEM, &c.NotBefore, &c.NotAfter, &c.Status, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan CA: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteCA removes a CA and all of its issued-cert rows.
func (s *Service) DeleteCA(ctx context.Context, id int64) error {
	db, err := s.db()
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "DELETE FROM mtls_issued_certs WHERE ca_id = ?", id); err != nil {
		return fmt.Errorf("delete issued: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM mtls_cas WHERE id = ?", id); err != nil {
		return fmt.Errorf("delete CA: %w", err)
	}
	return tx.Commit()
}

// Issue mints a client certificate signed by the given CA. The returned KeyPEM
// is the only copy of the client private key and is never persisted.
func (s *Service) Issue(ctx context.Context, in IssueInput) (IssueResult, error) {
	if s.Decrypt == nil {
		return IssueResult{}, errors.New("mtls: crypto not configured")
	}
	subject := strings.TrimSpace(in.Subject)
	if subject == "" {
		return IssueResult{}, errors.New("client subject is required")
	}
	validity := in.ValidFor
	if validity <= 0 {
		validity = defaultClientValidity
	}
	if validity > maxClientValidity {
		validity = maxClientValidity
	}

	db, err := s.db()
	if err != nil {
		return IssueResult{}, err
	}

	// Atomically claim a serial and load CA material under one tx.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return IssueResult{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var caCertPEM, caKeyEnc, caStatus string
	var serialSeq uint64
	err = tx.QueryRowContext(ctx,
		`SELECT cert_pem, key_pem_enc, serial_seq, status
		   FROM mtls_cas WHERE id = ?`+store.ForUpdate(), in.CAID).
		Scan(&caCertPEM, &caKeyEnc, &serialSeq, &caStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return IssueResult{}, errors.New("CA not found")
	}
	if err != nil {
		return IssueResult{}, fmt.Errorf("load CA: %w", err)
	}
	if caStatus != StatusActive {
		return IssueResult{}, errors.New("CA is not active")
	}

	caKeyPEM, err := s.Decrypt(caKeyEnc)
	if err != nil {
		return IssueResult{}, fmt.Errorf("decrypt CA key: %w", err)
	}
	caCert, caKey, err := parseCA(caCertPEM, caKeyPEM)
	if err != nil {
		return IssueResult{}, err
	}

	serial := new(big.Int).SetUint64(serialSeq)
	certPEM, clientKeyPEM, notAfter, err := signClientCert(caCert, caKey, subject, serial, validity)
	if err != nil {
		return IssueResult{}, err
	}

	if _, err := tx.ExecContext(ctx,
		"UPDATE mtls_cas SET serial_seq = serial_seq + 1 WHERE id = ?", in.CAID); err != nil {
		return IssueResult{}, fmt.Errorf("bump serial: %w", err)
	}
	serialStr := serial.String()
	res, err := tx.ExecContext(ctx,
		`INSERT INTO mtls_issued_certs
		   (ca_id, subject, serial, cert_pem, status, not_after)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		in.CAID, subject, serialStr, certPEM, StatusActive, notAfter.UTC())
	if err != nil {
		return IssueResult{}, fmt.Errorf("insert issued: %w", err)
	}
	id, _ := res.LastInsertId()
	if err := tx.Commit(); err != nil {
		return IssueResult{}, err
	}
	return IssueResult{ID: id, Serial: serialStr, CertPEM: certPEM, KeyPEM: clientKeyPEM}, nil
}

// ListIssued returns issued certs for a CA, newest first.
func (s *Service) ListIssued(ctx context.Context, caID int64) ([]IssuedCert, error) {
	db, err := s.db()
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx,
		`SELECT id, ca_id, subject, serial, cert_pem, status, not_after, issued_at, revoked_at
		   FROM mtls_issued_certs WHERE ca_id = ? ORDER BY id DESC`, caID)
	if err != nil {
		return nil, fmt.Errorf("query issued: %w", err)
	}
	defer rows.Close()
	var out []IssuedCert
	for rows.Next() {
		var c IssuedCert
		if err := rows.Scan(&c.ID, &c.CAID, &c.Subject, &c.Serial, &c.CertPEM,
			&c.Status, &c.NotAfter, &c.IssuedAt, &c.RevokedAt); err != nil {
			return nil, fmt.Errorf("scan issued: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Revoke marks an issued cert revoked (CRL-style). Idempotent.
func (s *Service) Revoke(ctx context.Context, id int64) error {
	db, err := s.db()
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx,
		`UPDATE mtls_issued_certs
		    SET status = ?, revoked_at = UTC_TIMESTAMP()
		  WHERE id = ? AND status <> ?`,
		StatusRevoked, id, StatusRevoked)
	return err
}

// GetCA loads a single CA (without decrypting its key).
func (s *Service) GetCA(ctx context.Context, id int64) (CA, error) {
	db, err := s.db()
	if err != nil {
		return CA{}, err
	}
	var c CA
	err = db.QueryRowContext(ctx,
		`SELECT id, name, client_id, common_name, cert_pem, not_before, not_after, status, created_at
		   FROM mtls_cas WHERE id = ?`, id).
		Scan(&c.ID, &c.Name, &c.ClientID, &c.CommonName, &c.CertPEM,
			&c.NotBefore, &c.NotAfter, &c.Status, &c.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return CA{}, errors.New("CA not found")
	}
	return c, err
}

// ---- helpers (pure crypto, DB-free for testability) ----

// generateCA mints a self-signed ECDSA CA, returning cert+key PEM and validity
// window. The key PEM is the caller's responsibility to encrypt before storing.
func generateCA(commonName string, validity time.Duration) (certPEM, keyPEM string, notBefore, notAfter time.Time, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", time.Time{}, time.Time{}, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := randSerial()
	if err != nil {
		return "", "", time.Time{}, time.Time{}, err
	}
	now := time.Now()
	notBefore = now.Add(-5 * time.Minute) // small skew tolerance
	notAfter = now.Add(validity)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true, // issues leaf client certs only
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", time.Time{}, time.Time{}, fmt.Errorf("create CA cert: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", time.Time{}, time.Time{}, fmt.Errorf("marshal CA key: %w", err)
	}
	return pemEncode("CERTIFICATE", der), pemEncode("PRIVATE KEY", keyDER), notBefore, notAfter, nil
}

// signClientCert mints a client-auth leaf cert signed by the CA. The returned
// key PEM is the only copy of the client key and is never persisted by callers.
func signClientCert(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, subject string, serial *big.Int, validity time.Duration) (certPEM, keyPEM string, notAfter time.Time, err error) {
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("generate client key: %w", err)
	}
	now := time.Now()
	notAfter = now.Add(validity)
	// PKI invariant: a leaf must not outlive its issuer. Clamp to the CA's
	// NotAfter so a short-lived CA cannot mint longer-lived client certs.
	if notAfter.After(caCert.NotAfter) {
		notAfter = caCert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: subject},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("sign client cert: %w", err)
	}
	clientKeyDER, err := x509.MarshalPKCS8PrivateKey(clientKey)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("marshal client key: %w", err)
	}
	return pemEncode("CERTIFICATE", der), pemEncode("PRIVATE KEY", clientKeyDER), notAfter, nil
}

// randSerial returns a cryptographically random 128-bit positive serial, used
// for the CA's own certificate.
func randSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("rand serial: %w", err)
	}
	return n.Add(n, big.NewInt(1)), nil
}

func pemEncode(typ string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}))
}

// parseCA decodes a CA cert + PKCS8 private key PEM pair.
func parseCA(certPEM, keyPEM string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	cb, _ := pem.Decode([]byte(certPEM))
	if cb == nil || cb.Type != "CERTIFICATE" {
		return nil, nil, errors.New("invalid CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA cert: %w", err)
	}
	kb, _ := pem.Decode([]byte(keyPEM))
	if kb == nil {
		return nil, nil, errors.New("invalid CA key PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA key: %w", err)
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("CA key is not ECDSA")
	}
	return cert, ek, nil
}
