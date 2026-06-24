// Package-level passkey/WebAuthn helpers. Wraps go-webauthn so the handler
// layer stays free of library-specific imports.
package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthn wraps a configured webauthn.WebAuthn instance and the storage
// (MariaDB + Redis) needed by the handler layer.
type WebAuthn struct {
	wa *webauthn.WebAuthn
}

// NewWebAuthn builds a WebAuthn service. `appURL` must be the public origin
// the panel runs on (e.g. https://proxy.example.com). `displayName` is the
// brand name shown by the authenticator dialog. Returns nil + err if appURL
// is malformed; callers are expected to nil-check and degrade.
func NewWebAuthn(appURL, displayName string) (*WebAuthn, error) {
	u, err := url.Parse(strings.TrimSpace(appURL))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("webauthn: bad app URL %q", appURL)
	}
	cfg := &webauthn.Config{
		RPID:          u.Hostname(),
		RPDisplayName: displayName,
		RPOrigins:     []string{strings.TrimRight(u.Scheme+"://"+u.Host, "/")},
	}
	w, err := webauthn.New(cfg)
	if err != nil {
		return nil, err
	}
	return &WebAuthn{wa: w}, nil
}

// Lib exposes the underlying go-webauthn instance so handlers can drive
// the Begin/Finish flows directly. The wrapper exists for construction +
// per-user credential loading; the library itself is well-typed enough.
func (w *WebAuthn) Lib() *webauthn.WebAuthn { return w.wa }

// WAUser implements webauthn.User. WebAuthnID is a stable, opaque per-user
// handle - we use a 64-bit big-endian encoding of users.id so any user row
// can be reconstructed without a second lookup.
type WAUser struct {
	ID          int64
	Email       string
	DisplayName string
	Creds       []webauthn.Credential
}

// WebAuthnID returns a stable user handle (8 bytes, big-endian users.id).
func (u *WAUser) WebAuthnID() []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(u.ID))
	return b
}

// WebAuthnName is the login identifier shown to the authenticator.
func (u *WAUser) WebAuthnName() string { return u.Email }

// WebAuthnDisplayName is the human-readable label shown to the user.
func (u *WAUser) WebAuthnDisplayName() string {
	if strings.TrimSpace(u.DisplayName) != "" {
		return u.DisplayName
	}
	return u.Email
}

// WebAuthnCredentials returns the registered credentials for the user.
func (u *WAUser) WebAuthnCredentials() []webauthn.Credential { return u.Creds }

// WebAuthnIcon is optional and unused.
func (u *WAUser) WebAuthnIcon() string { return "" }

// LoadWAUser fetches a user + their credentials. clientID is set only for
// roles where we route to /app after login; pass 0 for admins.
func LoadWAUser(ctx context.Context, db *sql.DB, userID int64) (*WAUser, error) {
	u := &WAUser{ID: userID}
	var name sql.NullString
	if err := db.QueryRowContext(ctx,
		`SELECT email, full_name FROM users WHERE id = ?`, userID,
	).Scan(&u.Email, &name); err != nil {
		return nil, err
	}
	if name.Valid {
		u.DisplayName = name.String
	}
	creds, err := LoadCredentialsForUser(ctx, db, userID)
	if err != nil {
		return nil, err
	}
	u.Creds = creds
	return u, nil
}

// LoadCredentialsForUser hydrates webauthn.Credential structs from the DB.
// Returns an empty slice (no error) if the webauthn_credentials table does
// not exist yet - lets enrollment flows proceed even when migration 30
// hasn't landed; the subsequent SaveCredential will surface the real
// schema problem instead of failing earlier on a read.
func LoadCredentialsForUser(ctx context.Context, db *sql.DB, userID int64) ([]webauthn.Credential, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT credential_id, public_key, attestation_type, aaguid, sign_count,
		        transports, backup_eligible, backup_state, user_present, user_verified
		   FROM webauthn_credentials WHERE user_id = ?`, userID)
	if err != nil {
		if isMissingTableErr(err) {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()
	var out []webauthn.Credential
	for rows.Next() {
		var (
			credID, pub, aaguid []byte
			att, transports     string
			signCount           uint32
			bel, bst, up, uv    bool
		)
		if err := rows.Scan(&credID, &pub, &att, &aaguid, &signCount,
			&transports, &bel, &bst, &up, &uv); err != nil {
			return nil, err
		}
		ts := []protocol.AuthenticatorTransport{}
		for _, t := range strings.Split(transports, ",") {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}
			ts = append(ts, protocol.AuthenticatorTransport(t))
		}
		c := webauthn.Credential{
			ID:              credID,
			PublicKey:       pub,
			AttestationType: att,
			Authenticator: webauthn.Authenticator{
				AAGUID:    aaguid,
				SignCount: signCount,
			},
			Transport: ts,
			Flags: webauthn.CredentialFlags{
				UserPresent:    up,
				UserVerified:   uv,
				BackupEligible: bel,
				BackupState:    bst,
			},
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SaveCredential persists a freshly-registered credential and flips
// users.has_passkey on. Returns the credential ID (DB autoincrement row).
func SaveCredential(ctx context.Context, db *sql.DB, userID int64, cred *webauthn.Credential, name string) (int64, error) {
	transports := joinTransports(cred.Transport)
	res, err := db.ExecContext(ctx, `INSERT INTO webauthn_credentials
		(user_id, credential_id, public_key, attestation_type, aaguid, sign_count,
		 transports, backup_eligible, backup_state, user_present, user_verified, name)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		userID, cred.ID, cred.PublicKey, cred.AttestationType, cred.Authenticator.AAGUID,
		cred.Authenticator.SignCount, transports,
		cred.Flags.BackupEligible, cred.Flags.BackupState,
		cred.Flags.UserPresent, cred.Flags.UserVerified, strings.TrimSpace(name))
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	_, _ = db.ExecContext(ctx, `UPDATE users SET has_passkey = 1 WHERE id = ?`, userID)
	return id, nil
}

// BumpSignCount updates the stored signature counter + last_used_at after a
// successful assertion. Mismatch with cred.Authenticator.SignCount can mean
// the authenticator was cloned - we still accept the assertion but a future
// audit pass could surface this.
func BumpSignCount(ctx context.Context, db *sql.DB, credID []byte, newCount uint32) error {
	_, err := db.ExecContext(ctx,
		`UPDATE webauthn_credentials
		   SET sign_count = ?, last_used_at = NOW()
		 WHERE credential_id = ?`,
		newCount, credID)
	return err
}

// FindUserByCredentialID returns the owning user for a discoverable login
// (when the browser/authenticator picks the credential without us pre-
// listing candidates). Returns sql.ErrNoRows if unknown.
func FindUserByCredentialID(ctx context.Context, db *sql.DB, credID []byte) (*WAUser, error) {
	var uid int64
	if err := db.QueryRowContext(ctx,
		`SELECT user_id FROM webauthn_credentials WHERE credential_id = ? LIMIT 1`, credID,
	).Scan(&uid); err != nil {
		return nil, err
	}
	return LoadWAUser(ctx, db, uid)
}

// DeleteCredential removes a single credential (admin/self). Returns the
// users.has_passkey state after the delete so callers can audit accurately.
func DeleteCredential(ctx context.Context, db *sql.DB, userID, credPK int64) error {
	if _, err := db.ExecContext(ctx,
		`DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?`, credPK, userID,
	); err != nil {
		return err
	}
	// Re-derive has_passkey from row count (cheaper than per-delete subquery).
	var n int
	_ = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?`, userID,
	).Scan(&n)
	val := 0
	if n > 0 {
		val = 1
	}
	_, _ = db.ExecContext(ctx, `UPDATE users SET has_passkey = ? WHERE id = ?`, val, userID)
	return nil
}

// NewSessionTicket returns an opaque base64url token suitable for stashing
// transient WebAuthn session data in Redis (with a short TTL).
func NewSessionTicket() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// WebauthnTicketTTL is the TTL applied to Begin* session data.
const WebauthnTicketTTL = 5 * time.Minute

// isMissingTableErr matches MariaDB/MySQL error 1146 ("Table … doesn't exist").
// Used to tolerate a missing webauthn_credentials row pre-migration so the
// passkey flow can still log a meaningful save error instead of crashing
// during the initial load.
func isMissingTableErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "Error 1146") || strings.Contains(s, "doesn't exist")
}

func joinTransports(ts []protocol.AuthenticatorTransport) string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		s := strings.TrimSpace(string(t))
		if s != "" {
			out = append(out, s)
		}
	}
	return strings.Join(out, ",")
}
