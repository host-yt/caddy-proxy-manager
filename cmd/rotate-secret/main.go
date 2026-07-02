// hpg-rotate-secret re-encrypts every at-rest secret in the panel from an
// old APP_SECRET to a new one. Run while the panel is **stopped** — this
// rewrites rows the panel reads on boot.
//
// Touches:
//   - install_state.json: db.password_cipher, smtp.password_cipher
//   - users.totp_secret_enc (per-user)
//   - users.totp_pending_secret (transient enrollment; nulled, not re-encrypted)
//   - api_keys.key_hmac (recomputed from no plaintext — we cannot rotate
//     without re-issuing the keys, so we null these out and the operator
//     must distribute fresh tokens to integrators after rotation)
//   - settings.value WHERE is_encrypted = 1 (OIDC client_secret, Cloudflare
//     token, captcha secret, WG private key, …)
//   - every dedicated `_enc` column that stores installstate-encrypted
//     ciphertext: routes.proxy_secret_enc, backup_destinations.config_enc,
//     dns_providers.api_token_enc, webhook_endpoints.secret_enc,
//     oauth_providers.client_secret (is_encrypted=1), sync_slaves.token_enc,
//     customer_wg_peer.server_privkey_e2, mtls_cas.key_pem_enc,
//     manual_certs.key_pem_enc. Missing any of these silently orphans the
//     secret under the old key after rotation (security review CRYPTO-01).
//
// Usage:
//
//	hpg-rotate-secret \
//	  --state ./data/install_state.json \
//	  --old-secret $OLD --new-secret $NEW \
//	  --db-host 127.0.0.1 --db-port 3306 --db-name hpg --db-user hpg --db-pass …
//
// The tool refuses to run when --old equals --new and prints a dry-run
// summary unless --apply is passed.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/hkdf"
)

func main() {
	statePath := flag.String("state", "./data/install_state.json", "path to install_state.json")
	oldSecret := flag.String("old-secret", os.Getenv("APP_SECRET_OLD"), "old APP_SECRET (or env APP_SECRET_OLD)")
	newSecret := flag.String("new-secret", os.Getenv("APP_SECRET_NEW"), "new APP_SECRET (or env APP_SECRET_NEW)")
	host := flag.String("db-host", "127.0.0.1", "MariaDB host")
	port := flag.Int("db-port", 3306, "MariaDB port")
	name := flag.String("db-name", "hostyt_proxy", "MariaDB database name")
	user := flag.String("db-user", "", "MariaDB user")
	pass := flag.String("db-pass", "", "MariaDB password (or skip --apply for dry-run)")
	apply := flag.Bool("apply", false, "actually write (default: dry-run)")
	flag.Parse()

	if *oldSecret == "" || *newSecret == "" {
		fail("--old-secret and --new-secret are required")
	}
	if *oldSecret == *newSecret {
		fail("old and new secret are identical; nothing to rotate")
	}
	if len(*newSecret) < 32 {
		fail("--new-secret must be at least 32 chars")
	}

	oldKey := deriveStateKey(*oldSecret)
	newKey := deriveStateKey(*newSecret)

	// 1. install_state.json — re-encrypt DB + SMTP passwords.
	if err := rotateStateFile(*statePath, oldKey, newKey, *apply); err != nil {
		fail("state file: " + err.Error())
	}

	// 2. DB: re-encrypt every is_encrypted=1 setting row + every
	// totp_secret_enc + null out api_keys.key_hmac so the operator must
	// re-issue (we don't have the plain secret to recompute).
	if *user == "" {
		fmt.Println("[skip] DB rotation: no --db-user supplied; only state file rewritten.")
		return
	}
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&loc=UTC&charset=utf8mb4&multiStatements=true",
		*user, *pass, *host, *port, *name)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		fail("db open: " + err.Error())
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		fail("db ping: " + err.Error())
	}

	stats, err := rotateDB(db, oldKey, newKey, *apply)
	if err != nil {
		fail("db rotate: " + err.Error())
	}
	fmt.Printf("settings_rows: %d  totp_users: %d  enc_columns: %d  totp_pending_nulled: %d  api_keys_nulled: %d\n",
		stats.settings, stats.totp, stats.enc, stats.pending, stats.apikeys)
	if !*apply {
		fmt.Println("DRY RUN — pass --apply to commit.")
	} else {
		fmt.Println("DONE. Restart the panel with the NEW APP_SECRET.")
		fmt.Println("ACTION REQUIRED: re-issue every API key (their hmac was invalidated).")
	}
}

// deriveStateKey reproduces installstate.New: HKDF(secret, info=hpg/install-state/v1) → 32 bytes.
func deriveStateKey(secret string) []byte {
	r := hkdf.New(sha256.New, []byte(secret), nil, []byte("hpg/install-state/v1"))
	k := make([]byte, 32)
	_, _ = io.ReadFull(r, k)
	return k
}

// v2Prefix mirrors installstate: "v2:<purpose>:<b64>" per-purpose envelopes.
const v2Prefix = "v2:"

// derivePurposeKey reproduces installstate.Manager.purposeKey: the sub-key is
// HKDF(stateKey, info=hpg/secret/<purpose>/v1).
func derivePurposeKey(stateKey []byte, purpose string) []byte {
	r := hkdf.New(sha256.New, stateKey, nil, []byte("hpg/secret/"+purpose+"/v1"))
	k := make([]byte, 32)
	_, _ = io.ReadFull(r, k)
	return k
}

// decEnvelope decrypts a stored value under the state key, auto-detecting the
// v2 per-purpose envelope. Returns the purpose ("" for legacy) so the caller
// can re-emit the same form under the new key.
func decEnvelope(stored string, stateKey []byte) (purpose, pt string, err error) {
	if rest, ok := strings.CutPrefix(stored, v2Prefix); ok {
		p, payload, found := strings.Cut(rest, ":")
		if !found || p == "" {
			return "", "", errors.New("malformed v2 envelope")
		}
		s, e := decrypt(payload, derivePurposeKey(stateKey, p))
		return p, s, e
	}
	s, e := decrypt(stored, stateKey)
	return "", s, e
}

// encEnvelope re-seals under the new state key, preserving the envelope form
// (v2 per-purpose when purpose != "", else legacy shared-key).
func encEnvelope(purpose, pt string, stateKey []byte) (string, error) {
	if purpose == "" {
		return encrypt(pt, stateKey)
	}
	b64, err := encrypt(pt, derivePurposeKey(stateKey, purpose))
	if err != nil {
		return "", err
	}
	return v2Prefix + purpose + ":" + b64, nil
}

func decrypt(b64 string, key []byte) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return "", errors.New("ciphertext too short")
	}
	pt, err := gcm.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

func encrypt(pt string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(cryptoRand, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, []byte(pt), nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

// rotateStateFile reads install_state.json, decrypts each *_cipher field
// with oldKey, re-encrypts with newKey, writes back atomically.
func rotateStateFile(path string, oldKey, newKey []byte, apply bool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	changed := 0
	rotateField := func(parent map[string]any, key string) error {
		v, ok := parent[key].(string)
		if !ok || v == "" {
			return nil
		}
		pt, err := decrypt(v, oldKey)
		if err != nil {
			return fmt.Errorf("decrypt %s: %w", key, err)
		}
		ne, err := encrypt(pt, newKey)
		if err != nil {
			return err
		}
		parent[key] = ne
		changed++
		return nil
	}
	if db, ok := m["db"].(map[string]any); ok {
		if err := rotateField(db, "password_cipher"); err != nil {
			return err
		}
	}
	if smtp, ok := m["smtp"].(map[string]any); ok {
		if err := rotateField(smtp, "password_cipher"); err != nil {
			return err
		}
	}
	fmt.Printf("state file: %d field(s) re-encrypted\n", changed)
	if !apply {
		return nil
	}
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".rotated"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

type dbStats struct{ settings, totp, enc, pending, apikeys int }

// encColumn describes one id-keyed column holding installstate-encrypted
// ciphertext that rotate-secret must re-seal under the new key.
type encColumn struct {
	table    string // table name
	idCol    string // primary key column used to target the UPDATE
	col      string // encrypted column
	where    string // extra filter ANDed onto the non-empty guard, e.g. "is_encrypted = 1"
	prefix   string // storage prefix stripped before decrypt / re-added after, "" if none
	tolerant bool   // skip (not fail) rows that fail to decrypt (transitional plaintext)
}

// encColumns is every dedicated at-rest secret column outside settings/totp.
// Missing one here means an APP_SECRET rotation orphans it (CRYPTO-01).
var encColumns = []encColumn{
	{"routes", "id", "proxy_secret_enc", "", "", false},
	{"backup_destinations", "id", "config_enc", "", "enc:", false},
	{"dns_providers", "id", "api_token_enc", "", "", false},
	{"webhook_endpoints", "id", "secret_enc", "", "", false},
	{"oauth_providers", "provider", "client_secret", "is_encrypted = 1", "", false},
	{"sync_slaves", "id", "token_enc", "", "", false},
	{"customer_wg_peer", "id", "server_privkey_e2", "", "", false},
	{"mtls_cas", "id", "key_pem_enc", "", "", false},
	{"manual_certs", "id", "key_pem_enc", "", "", false},
	// lb_cookie_secret is encrypted at rest as of SECRET-02, but legacy rows
	// may still hold plaintext until re-saved - tolerate undecryptable rows.
	{"routes", "id", "lb_cookie_secret", "", "", true},
}

func rotateDB(db *sql.DB, oldKey, newKey []byte, apply bool) (dbStats, error) {
	var s dbStats

	// Open a single transaction so any failure mid-loop rolls everything
	// back. Previously each row was its own auto-commit Exec — SIGTERM in
	// the middle left a mix of OLD- and NEW-encrypted rows that no key
	// could decrypt cleanly (security review P1).
	var tx *sql.Tx
	var err error
	if apply {
		tx, err = db.Begin()
		if err != nil {
			return s, fmt.Errorf("tx begin: %w", err)
		}
		defer func() {
			if tx != nil {
				_ = tx.Rollback()
			}
		}()
	}
	execTX := func(q string, args ...any) (sql.Result, error) {
		if apply {
			return tx.Exec(q, args...)
		}
		return nil, nil
	}

	// Settings rows.
	rows, err := db.Query("SELECT `key`, value FROM settings WHERE is_encrypted = 1")
	if err != nil {
		return s, err
	}
	type kv struct{ k, v string }
	var todo []kv
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err == nil {
			todo = append(todo, kv{k, v})
		}
	}
	rows.Close()
	for _, e := range todo {
		purpose, pt, err := decEnvelope(e.v, oldKey)
		if err != nil {
			// Fail hard — silently skipping a setting we cannot decrypt
			// leaves a forever-broken row. The operator can re-run after
			// fixing the underlying issue (e.g., wrong --old-secret).
			return s, fmt.Errorf("setting %q decrypt: %w", e.k, err)
		}
		ne, err := encEnvelope(purpose, pt, newKey)
		if err != nil {
			return s, err
		}
		if _, err := execTX("UPDATE settings SET value = ? WHERE `key` = ?", ne, e.k); err != nil {
			return s, err
		}
		s.settings++
	}
	// TOTP secrets.
	urows, err := db.Query("SELECT id, totp_secret_enc FROM users WHERE totp_secret_enc IS NOT NULL AND totp_secret_enc <> ''")
	if err != nil {
		return s, err
	}
	type uent struct {
		id  int64
		enc string
	}
	var users []uent
	for urows.Next() {
		var u uent
		if err := urows.Scan(&u.id, &u.enc); err == nil {
			users = append(users, u)
		}
	}
	urows.Close()
	for _, u := range users {
		purpose, pt, err := decEnvelope(u.enc, oldKey)
		if err != nil {
			return s, fmt.Errorf("user %d totp decrypt: %w", u.id, err)
		}
		ne, err := encEnvelope(purpose, pt, newKey)
		if err != nil {
			return s, err
		}
		if _, err := execTX("UPDATE users SET totp_secret_enc = ? WHERE id = ?", ne, u.id); err != nil {
			return s, err
		}
		s.totp++
	}
	// Dedicated `_enc` columns: same installstate key, so they must be
	// re-sealed too. Fail hard on a row we cannot decrypt (a skip would
	// leave a forever-broken secret) — matches the settings/totp posture.
	for _, c := range encColumns {
		q := fmt.Sprintf("SELECT `%s`, `%s` FROM `%s` WHERE `%s` IS NOT NULL AND `%s` <> ''",
			c.idCol, c.col, c.table, c.col, c.col)
		if c.where != "" {
			q += " AND " + c.where
		}
		crows, qerr := db.Query(q)
		if qerr != nil {
			return s, fmt.Errorf("%s.%s select: %w", c.table, c.col, qerr)
		}
		type ent struct {
			id  string
			val string
		}
		var ents []ent
		for crows.Next() {
			var e ent
			if err := crows.Scan(&e.id, &e.val); err == nil {
				ents = append(ents, e)
			}
		}
		crows.Close()
		for _, e := range ents {
			b64 := e.val
			if c.prefix != "" {
				if !strings.HasPrefix(e.val, c.prefix) {
					// plain:/legacy blob — not encrypted under any key, leave as-is.
					continue
				}
				b64 = strings.TrimPrefix(e.val, c.prefix)
			}
			purpose, pt, derr := decEnvelope(b64, oldKey)
			if derr != nil {
				if c.tolerant {
					// Legacy plaintext / not-yet-encrypted row: leave as-is.
					continue
				}
				return s, fmt.Errorf("%s.%s id=%s decrypt: %w", c.table, c.col, e.id, derr)
			}
			ne, eerr := encEnvelope(purpose, pt, newKey)
			if eerr != nil {
				return s, eerr
			}
			upd := fmt.Sprintf("UPDATE `%s` SET `%s` = ? WHERE `%s` = ?", c.table, c.col, c.idCol)
			if _, err := execTX(upd, c.prefix+ne, e.id); err != nil {
				return s, err
			}
			s.enc++
		}
	}

	// Pending TOTP secrets are transient (10-min enrollment TTL) and may be
	// plaintext when the state manager was absent at write time. Rather than
	// risk a decrypt mismatch, null them — the user simply re-enrolls.
	if apply {
		res, perr := execTX("UPDATE users SET totp_pending_secret = NULL, totp_pending_exp = NULL WHERE totp_pending_secret IS NOT NULL")
		if perr != nil {
			return s, perr
		}
		n, _ := res.RowsAffected()
		s.pending = int(n)
	} else {
		var n int
		_ = db.QueryRow("SELECT COUNT(*) FROM users WHERE totp_pending_secret IS NOT NULL").Scan(&n)
		s.pending = n
	}

	// API keys: HMAC is keyed off APP_SECRET, so rotation invalidates the
	// fast path. Null out — but only rows that actually had a non-NULL
	// hmac, so we don't silently re-touch keys created without HMAC
	// (audit P1: blanket NULL was too aggressive).
	if apply {
		res, err := execTX("UPDATE api_keys SET key_hmac = NULL WHERE key_hmac IS NOT NULL")
		if err != nil {
			return s, err
		}
		n, _ := res.RowsAffected()
		s.apikeys = int(n)
	} else {
		var n int
		_ = db.QueryRow("SELECT COUNT(*) FROM api_keys WHERE key_hmac IS NOT NULL").Scan(&n)
		s.apikeys = n
	}
	// Commit only if every step above ran clean.
	if apply {
		if err := tx.Commit(); err != nil {
			return s, fmt.Errorf("tx commit: %w", err)
		}
		tx = nil // disable deferred rollback
	}
	return s, nil
}

var cryptoRand = &randReader{}

type randReader struct{}

func (r *randReader) Read(b []byte) (int, error) {
	// crypto/rand under the hood, kept indirect so test substitution is trivial.
	return readRand(b)
}

func readRand(b []byte) (int, error) {
	f, err := os.Open("/dev/urandom")
	if err != nil {
		return cryptoRandFallback(b)
	}
	defer f.Close()
	return io.ReadFull(f, b)
}

// cryptoRandFallback exists for environments without /dev/urandom (Windows
// in CI etc.). Not exercised in practice on the panel's Linux runtime.
func cryptoRandFallback(b []byte) (int, error) {
	// Minimal hkdf-of-time to keep the binary working on dev hosts that
	// somehow lack /dev/urandom. Production runs on distroless Linux.
	return 0, errors.New("no random source available")
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "error:", msg)
	os.Exit(1)
}

// _ ensures `strings` stays imported even if helper trimming evolves.
var _ = strings.TrimSpace
