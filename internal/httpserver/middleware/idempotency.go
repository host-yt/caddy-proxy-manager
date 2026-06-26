package middleware

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net/http"
	"strings"
	"time"
)

const idempotencyTTL = 24 * time.Hour

// captureWriter buffers the response so we can store it for replay.
type captureWriter struct {
	http.ResponseWriter
	buf    bytes.Buffer
	status int
}

func (cw *captureWriter) WriteHeader(status int) {
	cw.status = status
	cw.ResponseWriter.WriteHeader(status)
}

func (cw *captureWriter) Write(b []byte) (int, error) {
	cw.buf.Write(b)
	return cw.ResponseWriter.Write(b)
}

// Idempotency returns stored responses for repeated POST requests that carry
// an Idempotency-Key header. Keyed by (header_value, user_id) so one user
// cannot replay another user's key. TTL is 24 h.
func Idempotency(db func() *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				next.ServeHTTP(w, r)
				return
			}
			key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
			if key == "" {
				next.ServeHTTP(w, r)
				return
			}
			if len(key) > 128 {
				writeJSONErr(w, http.StatusBadRequest, "idempotency_key too long (max 128)")
				return
			}
			c := CallerFromContext(r.Context())
			if c == nil {
				next.ServeHTTP(w, r)
				return
			}
			d := db()
			if d == nil {
				next.ServeHTTP(w, r)
				return
			}
			// Hash the key to avoid storing raw user-provided strings.
			h := sha256.Sum256([]byte(key))
			keyHash := hex.EncodeToString(h[:])

			ctx, cancel := context.WithTimeout(r.Context(), 300*time.Millisecond)
			defer cancel()

			var status int
			var body string
			err := d.QueryRowContext(ctx,
				`SELECT response_status, response_body FROM idempotency_keys
				 WHERE idem_key=? AND user_id=? AND expires_at > NOW()`,
				keyHash, c.UserID,
			).Scan(&status, &body)
			if err == nil {
				// Replay stored response - identical to original.
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Idempotency-Replayed", "true")
				w.WriteHeader(status)
				_, _ = w.Write([]byte(body))
				return
			}

			cw := &captureWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(cw, r)

			// Only cache successful or conflict responses (2xx / 409).
			if cw.status < 200 || (cw.status >= 300 && cw.status != http.StatusConflict) {
				return
			}
			bodyStr := cw.buf.String()
			expires := time.Now().Add(idempotencyTTL)
			storeCtx, storeCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer storeCancel()
			_, _ = d.ExecContext(storeCtx,
				`INSERT INTO idempotency_keys (idem_key, user_id, method, path, response_status, response_body, expires_at)
				 VALUES (?, ?, ?, ?, ?, ?, ?)
				 ON DUPLICATE KEY UPDATE
				   response_status=VALUES(response_status),
				   response_body=VALUES(response_body),
				   expires_at=VALUES(expires_at)`,
				keyHash, c.UserID, r.Method, r.URL.Path, cw.status, bodyStr, expires,
			)
		})
	}
}

// ---- background cleaner ---------------------------------------------------

// IdempotencyPurgeExpired deletes rows past their expiry. Call from a
// maintenance goroutine; never in the request path.
func IdempotencyPurgeExpired(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, "DELETE FROM idempotency_keys WHERE expires_at < NOW()")
	return err
}
