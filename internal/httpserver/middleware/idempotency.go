package middleware

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

const idempotencyTTL = 24 * time.Hour

// idempotency row states.
const (
	idemStatePending = 0
	idemStateDone    = 1
	// idemStateUnresolved: the handler ran and reported success, but the
	// outcome could not be recorded. A retry must not re-execute it and must
	// not be told "in progress" for the next 24 h.
	idemStateUnresolved = 2
)

// idemLease bounds how long a pending row counts as genuinely in flight. Past
// it, the owning request is gone and the outcome is unknown, not in progress.
const idemLease = 2 * time.Minute

// replayHeaders are the response headers worth preserving for a faithful replay.
var replayHeaders = []string{"Content-Type", "Location", "X-Operation-Id"}

// captureWriter holds the whole response back: nothing reaches the client
// until the outcome is recorded, so a caller can never see a 201 whose
// idempotency row stayed pending.
type captureWriter struct {
	hdr    http.Header
	buf    bytes.Buffer
	status int
	wrote  bool
}

func (cw *captureWriter) Header() http.Header { return cw.hdr }

func (cw *captureWriter) WriteHeader(status int) {
	if cw.wrote {
		return
	}
	cw.status = status
	cw.wrote = true
}

func (cw *captureWriter) Write(b []byte) (int, error) {
	cw.wrote = true
	return cw.buf.Write(b)
}

// flush replays the buffered response onto the real writer.
func (cw *captureWriter) flush(w http.ResponseWriter) {
	dst := w.Header()
	for k, v := range cw.hdr {
		dst[k] = v
	}
	w.WriteHeader(cw.status)
	_, _ = w.Write(cw.buf.Bytes())
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

			// 300ms was tight enough that a loaded DB (or a CI runner mid-fsync)
			// blew the deadline and turned a healthy write into a 503.
			resCtx, resCancel := context.WithTimeout(r.Context(), 2*time.Second)
			defer resCancel()

			// operation_id is the durable handle for this attempt: it goes to
			// the client and the logs, so an operation whose outcome could not
			// be recorded can still be traced to what actually happened.
			opID, oerr := newOperationID()
			if oerr != nil {
				writeJSONErr(w, http.StatusServiceUnavailable, "idempotency store unavailable; retry")
				return
			}
			// Expiry and lease are computed DB-side to share a clock with the
			// 'expires_at > NOW()' lookup below: the panel's timezone need not
			// match the DB server's.
			_, err = d.ExecContext(resCtx,
				`INSERT INTO idempotency_keys (idem_key, user_id, method, path, body_hash, state, operation_id, lease_until, response_body, expires_at)
				 VALUES (?, ?, ?, ?, ?, ?, ?, `+store.DateAddSecondsParam()+`, NULL, `+store.DateAddSecondsParam()+`)`,
				keyHash, c.UserID, r.Method, r.URL.Path, bodyHash, idemStatePending, opID,
				int(idemLease/time.Second), int(idempotencyTTL/time.Second),
			)
			if err != nil {
				// Only a unique-key collision means "an entry already exists".
				// Any other insert failure means the reservation did not land,
				// and running the handler anyway would execute a mutation the
				// caller explicitly asked to be deduped - twice, on retry. The
				// caller asked for idempotency, so refuse instead.
				if !isDuplicateKeyErr(err) {
					slog.Warn("idempotency reservation failed", "err", err, "path", r.URL.Path)
					writeJSONErr(w, http.StatusServiceUnavailable, "idempotency store unavailable; retry")
					return
				}
				// Duplicate key: an entry already exists - inspect it.
				var (
					state    int
					method   string
					path     string
					oldHash  string
					oldOpID  sql.NullString
					inFlight bool
					status   sql.NullInt64
					body     sql.NullString
					hdrs     sql.NullString
				)
				selErr := d.QueryRowContext(resCtx,
					`SELECT state, method, path, body_hash, operation_id,
					        CASE WHEN lease_until IS NOT NULL AND lease_until > NOW() THEN 1 ELSE 0 END,
					        response_status, response_body, response_headers
					 FROM idempotency_keys
					 WHERE idem_key=? AND user_id=? AND expires_at > NOW()`,
					keyHash, c.UserID,
				).Scan(&state, &method, &path, &oldHash, &oldOpID, &inFlight, &status, &body, &hdrs)
				switch {
				case errors.Is(selErr, sql.ErrNoRows):
					// The colliding row is expired. Reclaim it for this request
					// rather than running unprotected: the UPDATE is conditional
					// on it still being expired, so only one racing request wins.
					res, rerr := d.ExecContext(resCtx,
						`UPDATE idempotency_keys
						    SET method=?, path=?, body_hash=?, state=?, operation_id=?,
						        lease_until=`+store.DateAddSecondsParam()+`,
						        response_status=NULL, response_body=NULL, response_headers=NULL,
						        expires_at=`+store.DateAddSecondsParam()+`
						  WHERE idem_key=? AND user_id=? AND expires_at <= NOW()`,
						r.Method, r.URL.Path, bodyHash, idemStatePending, opID,
						int(idemLease/time.Second), int(idempotencyTTL/time.Second), keyHash, c.UserID)
					if rerr != nil {
						writeJSONErr(w, http.StatusServiceUnavailable, "idempotency store unavailable; retry")
						return
					}
					if n, _ := res.RowsAffected(); n == 0 {
						// Someone else reclaimed it first: their request owns
						// the key now.
						writeJSONErr(w, http.StatusConflict, "request with this idempotency_key is already in progress")
						return
					}
				case selErr != nil:
					writeJSONErr(w, http.StatusServiceUnavailable, "idempotency store unavailable; retry")
					return
				default:
					// Same key reused for a different request - never replay it.
					if method != r.Method || path != r.URL.Path || oldHash != bodyHash {
						writeJSONErr(w, http.StatusConflict, "idempotency_key reused for a different request")
						return
					}
					if state == idemStatePending && inFlight {
						writeJSONErr(w, http.StatusConflict, "request with this idempotency_key is already in progress")
						return
					}
					// Pending past its lease, or explicitly unresolved: the
					// operation may well have been applied, so replaying it
					// would duplicate and re-running it is not allowed. Hand
					// back the operation id so it can be reconciled.
					if state != idemStateDone {
						writeIdemUnresolved(w, oldOpID.String)
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
			}

			cw := &captureWriter{hdr: http.Header{}, status: http.StatusOK}
			cw.hdr.Set("X-Operation-Id", opID)
			next.ServeHTTP(cw, r)

			// Detached from the request: a client that hung up mid-write must
			// not leave the outcome unrecorded. Generous timeout - the whole
			// point is that this write, not the response, decides the state.
			storeCtx, storeCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer storeCancel()

			// Only cache successful or conflict responses (2xx / 409). For anything
			// else, drop the reservation so the caller can retry the same key.
			if cw.status < 200 || (cw.status >= 300 && cw.status != http.StatusConflict) {
				_, _ = d.ExecContext(storeCtx,
					`DELETE FROM idempotency_keys WHERE idem_key=? AND user_id=? AND state=?`,
					keyHash, c.UserID, idemStatePending,
				)
				cw.flush(w)
				return
			}

			if ferr := finalizeIdem(storeCtx, d, keyHash, c.UserID, cw); ferr != nil {
				// The handler already applied its change; only the record of it
				// is missing. Flag the row so the retry gets a definite answer
				// instead of a 24 h "in progress", and tell the caller that the
				// operation needs reconciliation rather than a blind retry.
				markIdemUnresolved(storeCtx, d, keyHash, c.UserID)
				slog.Error("idempotency finalize failed", "err", ferr, "path", r.URL.Path, "operation_id", opID)
				writeIdemUnresolved(w, opID)
				return
			}
			cw.flush(w)
		})
	}
}

// newOperationID returns a random durable handle for one attempt.
func newOperationID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// finalizeIdem records the response against the reservation. The result is
// checked - an ignored UPDATE here is exactly how a row stayed pending after a
// successful operation. One retry covers a momentary DB blip.
func finalizeIdem(ctx context.Context, d *sql.DB, keyHash string, userID int64, cw *captureWriter) error {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		res, err := d.ExecContext(ctx,
			`UPDATE idempotency_keys
			 SET state=?, lease_until=NULL, response_status=?, response_body=?, response_headers=?,
			     expires_at=`+store.DateAddSecondsParam()+`
			 WHERE idem_key=? AND user_id=? AND state=?`,
			idemStateDone, cw.status, cw.buf.String(), captureHeaders(cw.hdr),
			int(idempotencyTTL/time.Second), keyHash, userID, idemStatePending,
		)
		if err == nil {
			if n, rerr := res.RowsAffected(); rerr == nil && n == 0 {
				return errors.New("idempotency reservation vanished before finalize")
			}
			return nil
		}
		lastErr = err
	}
	return lastErr
}

// markIdemUnresolved is best effort: if it too fails, the lease expiry makes
// the row unresolved by time, which reads the same way to a retry.
func markIdemUnresolved(ctx context.Context, d *sql.DB, keyHash string, userID int64) {
	_, _ = d.ExecContext(ctx,
		`UPDATE idempotency_keys SET state=?, lease_until=NULL WHERE idem_key=? AND user_id=? AND state=?`,
		idemStateUnresolved, keyHash, userID, idemStatePending)
}

// writeIdemUnresolved answers a request whose operation may have been applied
// but whose result is not recorded. Machine-readable so a client can reconcile
// on the operation id instead of retrying with a fresh key and duplicating.
func writeIdemUnresolved(w http.ResponseWriter, opID string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	_ = json.NewEncoder(w).Encode(struct {
		Error       string `json:"error"`
		Code        string `json:"code"`
		OperationID string `json:"operation_id,omitempty"`
	}{
		Error:       "operation with this idempotency_key was executed but its result was not recorded; reconcile before retrying",
		Code:        "idempotent_operation_unresolved",
		OperationID: opID,
	})
}

// isDuplicateKeyErr reports whether err is a unique-key violation, in either
// MariaDB's or the SQLite transform's wording.
func isDuplicateKeyErr(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "Duplicate entry") || strings.Contains(err.Error(), "UNIQUE constraint")
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
