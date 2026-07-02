package middleware

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

const idempotencyTTL = 24 * time.Hour

// idempotency row states.
const (
	idemStatePending = 0
	idemStateDone    = 1
)

// replayHeaders are the response headers worth preserving for a faithful replay.
var replayHeaders = []string{"Content-Type", "Location"}

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

// mutatingMethod reports whether a method changes state and is therefore worth
// deduping when an Idempotency-Key is supplied. Covers POST/PUT/PATCH/DELETE so
// entitlement-changing calls like PUT suspend / DELETE service are deduped, not
// just POST creates (security review BILL-02).
func mutatingMethod(m string) bool {
	switch m {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// Idempotency returns stored responses for repeated mutating requests that
// carry an Idempotency-Key header. Keyed by (header_value, user_id) so one user
// cannot replay another user's key. The cached entry is bound to the request
// method, path and body hash; reusing a key for a different request yields 409.
// The key is reserved before the handler runs so concurrent same-key requests
// do not both execute. TTL is 24 h.
func Idempotency(db func() *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !mutatingMethod(r.Method) {
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

			// Buffer the body so we can hash it and still pass it to the handler
			// (cap is enforced by an upstream 1 MiB MaxBytesReader).
			reqBody, err := io.ReadAll(r.Body)
			if err != nil {
				writeJSONErr(w, http.StatusBadRequest, "could not read request body")
				return
			}
			_ = r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(reqBody))

			// Hash the key to avoid storing raw user-provided strings.
			h := sha256.Sum256([]byte(key))
			keyHash := hex.EncodeToString(h[:])
			bh := sha256.Sum256(reqBody)
			bodyHash := hex.EncodeToString(bh[:])

			expires := time.Now().Add(idempotencyTTL)
			resCtx, resCancel := context.WithTimeout(r.Context(), 300*time.Millisecond)
			defer resCancel()

			// Reserve the key atomically before running the handler.
			_, err = d.ExecContext(resCtx,
				`INSERT INTO idempotency_keys (idem_key, user_id, method, path, body_hash, state, response_body, expires_at)
				 VALUES (?, ?, ?, ?, ?, ?, NULL, ?)`,
				keyHash, c.UserID, r.Method, r.URL.Path, bodyHash, idemStatePending, expires,
			)
			if err != nil {
				// Duplicate key: an entry already exists - inspect it.
				var (
					state   int
					method  string
					path    string
					oldHash string
					status  sql.NullInt64
					body    sql.NullString
					hdrs    sql.NullString
				)
				selErr := d.QueryRowContext(resCtx,
					`SELECT state, method, path, body_hash, response_status, response_body, response_headers
					 FROM idempotency_keys
					 WHERE idem_key=? AND user_id=? AND expires_at > NOW()`,
					keyHash, c.UserID,
				).Scan(&state, &method, &path, &oldHash, &status, &body, &hdrs)
				if selErr != nil {
					// Row expired between insert race and select, or other error:
					// fail open and run the handler without caching.
					next.ServeHTTP(w, r)
					return
				}
				// Same key reused for a different request - never replay it.
				if method != r.Method || path != r.URL.Path || oldHash != bodyHash {
					writeJSONErr(w, http.StatusConflict, "idempotency_key reused for a different request")
					return
				}
				if state == idemStatePending {
					writeJSONErr(w, http.StatusConflict, "request with this idempotency_key is already in progress")
					return
				}
				// Completed: replay the stored response verbatim.
				if hdrs.Valid {
					restoreHeaders(w, hdrs.String)
				}
				w.Header().Set("X-Idempotency-Replayed", "true")
				if status.Valid {
					w.WriteHeader(int(status.Int64))
				}
				if body.Valid {
					_, _ = w.Write([]byte(body.String))
				}
				return
			}

			cw := &captureWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(cw, r)

			storeCtx, storeCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer storeCancel()

			// Only cache successful or conflict responses (2xx / 409). For anything
			// else, drop the reservation so the caller can retry the same key.
			if cw.status < 200 || (cw.status >= 300 && cw.status != http.StatusConflict) {
				_, _ = d.ExecContext(storeCtx,
					`DELETE FROM idempotency_keys WHERE idem_key=? AND user_id=? AND state=?`,
					keyHash, c.UserID, idemStatePending,
				)
				return
			}

			_, _ = d.ExecContext(storeCtx,
				`UPDATE idempotency_keys
				 SET state=?, response_status=?, response_body=?, response_headers=?, expires_at=?
				 WHERE idem_key=? AND user_id=?`,
				idemStateDone, cw.status, cw.buf.String(), captureHeaders(cw.Header()), expires,
				keyHash, c.UserID,
			)
		})
	}
}

// captureHeaders serialises the replay-relevant response headers to JSON.
func captureHeaders(hdr http.Header) sql.NullString {
	out := map[string]string{}
	for _, k := range replayHeaders {
		if v := hdr.Get(k); v != "" {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return sql.NullString{}
	}
	b, err := json.Marshal(out)
	if err != nil {
		return sql.NullString{}
	}
	return sql.NullString{String: string(b), Valid: true}
}

// restoreHeaders re-applies stored response headers on replay.
func restoreHeaders(w http.ResponseWriter, raw string) {
	var m map[string]string
	if json.Unmarshal([]byte(raw), &m) != nil {
		return
	}
	for k, v := range m {
		w.Header().Set(k, v)
	}
}

// ---- background cleaner ---------------------------------------------------

// IdempotencyPurgeExpired deletes rows past their expiry. Call from a
// maintenance goroutine; never in the request path.
func IdempotencyPurgeExpired(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, "DELETE FROM idempotency_keys WHERE expires_at < NOW()")
	return err
}
