// Package webhook delivers structured event notifications to admin-
// configured HTTP endpoints (FOSSBilling integration, Slack incoming
// webhooks, generic ops monitors). Payloads are JSON. Each delivery is
// signed with an endpoint-specific HMAC-SHA256 secret over the raw body;
// receivers verify via `X-HPG-Signature: sha256=<hex>`.
//
// Persistence: every attempt lands in webhook_deliveries with status
// pending/success/failed. The dispatcher retries failed rows with
// exponential backoff via a leader-only ticker.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"net/url"

	"github.com/host-yt/caddy-proxy-manager/internal/installstate"
	"github.com/host-yt/caddy-proxy-manager/internal/security"
)

// Event types the panel emits.
const (
	EventRouteCreated  = "route.created"
	EventRouteActive   = "route.active"
	EventRouteFailed   = "route.failed"
	EventNodeJoined    = "node.joined"
	EventNodeApproved  = "node.approved"
	EventNodeDown      = "node.down"
	EventCertIssued    = "cert.issued"
	EventBackupSuccess = "backup.success"
	EventBackupFailed  = "backup.failed"
)

// Service dispatches events.
type Service struct {
	DB     func() *sql.DB
	State  *installstate.Manager
	Logger *slog.Logger

	hc *http.Client
}

// New returns a Service whose outbound HTTP client refuses to dial
// RFC1918 / loopback / link-local / CGNAT addresses and bounds redirects
// at 5 hops. This closes the SSRF primitive flagged by the security
// review (admin-set webhook URL could otherwise hit
// http://10.66.0.1:2019/load on the WireGuard mesh).
func New(db func() *sql.DB, state *installstate.Manager, logger *slog.Logger) *Service {
	return &Service{
		DB:     db,
		State:  state,
		Logger: logger,
		hc:     security.SafeHTTPClient(10 * time.Second),
	}
}

// Emit queues an event for every enabled endpoint whose events filter
// matches. Non-blocking: returns immediately after the DB insert; the
// background dispatcher does the actual HTTP call.
func (s *Service) Emit(ctx context.Context, eventType string, payload map[string]any) {
	db := s.DB()
	if db == nil {
		return
	}
	rows, err := db.QueryContext(ctx,
		"SELECT id, events FROM webhook_endpoints WHERE is_enabled = 1")
	if err != nil {
		return
	}
	type ep struct {
		id     int64
		events string
	}
	var eps []ep
	for rows.Next() {
		var e ep
		if err := rows.Scan(&e.id, &e.events); err == nil {
			eps = append(eps, e)
		}
	}
	rows.Close()
	body, err := json.Marshal(map[string]any{
		"event":     eventType,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"data":      payload,
	})
	if err != nil {
		return
	}
	for _, e := range eps {
		if !eventMatches(eventType, e.events) {
			continue
		}
		_, _ = db.ExecContext(ctx,
			`INSERT INTO webhook_deliveries (endpoint_id, event_type, payload, status, next_retry_at)
			 VALUES (?, ?, ?, 'pending', NOW())`,
			e.id, eventType, string(body))
	}
}

// Dispatch processes pending deliveries: pulls up to N rows whose
// next_retry_at <= NOW(), POSTs them, marks success/failure with
// exponential backoff. Called from a leader-only ticker.
func (s *Service) Dispatch(ctx context.Context) {
	db := s.DB()
	if db == nil {
		return
	}
	rows, err := db.QueryContext(ctx,
		`SELECT id, endpoint_id, event_type, payload, attempts
		 FROM webhook_deliveries
		 WHERE status = 'pending' AND (next_retry_at IS NULL OR next_retry_at <= NOW())
		 ORDER BY id ASC LIMIT 50`)
	if err != nil {
		return
	}
	type job struct {
		id, epID int64
		evt      string
		payload  string
		attempts int
	}
	var jobs []job
	for rows.Next() {
		var j job
		if err := rows.Scan(&j.id, &j.epID, &j.evt, &j.payload, &j.attempts); err == nil {
			jobs = append(jobs, j)
		}
	}
	rows.Close()
	for _, j := range jobs {
		s.attempt(ctx, j.id, j.epID, j.payload, j.attempts)
	}
}

func (s *Service) attempt(ctx context.Context, deliveryID, epID int64, body string, attempts int) {
	db := s.DB()
	if db == nil {
		return
	}
	var endpointURL string
	var secretEnc sql.NullString
	if err := db.QueryRowContext(ctx,
		"SELECT url, COALESCE(secret_enc,'') FROM webhook_endpoints WHERE id = ? AND is_enabled = 1",
		epID,
	).Scan(&endpointURL, &secretEnc); err != nil {
		_, _ = db.ExecContext(ctx,
			"UPDATE webhook_deliveries SET status='failed', last_error=? WHERE id = ?",
			"endpoint missing or disabled", deliveryID)
		return
	}
	// Re-validate at dispatch time (URL could have been saved before the
	// SSRF guard existed, or set via direct DB write). SafeHTTPClient also
	// re-validates each redirect hop.
	if parsed, perr := url.Parse(endpointURL); perr != nil {
		s.markFail(ctx, deliveryID, attempts, 0, "parse url: "+perr.Error())
		return
	} else if verr := security.ValidateOutboundURL(parsed); verr != nil {
		s.markFail(ctx, deliveryID, attempts, 0, verr.Error())
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL, bytes.NewReader([]byte(body)))
	if err != nil {
		s.markFail(ctx, deliveryID, attempts, 0, err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "hostyt-proxy-webhook/1")
	if secretEnc.String != "" && s.State != nil {
		if secret, derr := s.State.Decrypt(secretEnc.String); derr == nil {
			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write([]byte(body))
			req.Header.Set("X-HPG-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
		}
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		s.markFail(ctx, deliveryID, attempts, 0, err.Error())
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		_, _ = db.ExecContext(ctx,
			`UPDATE webhook_deliveries SET status='success', http_code=?, delivered_at=NOW(),
			 attempts=attempts+1, last_error=NULL WHERE id = ?`,
			resp.StatusCode, deliveryID)
		return
	}
	s.markFail(ctx, deliveryID, attempts, resp.StatusCode, fmt.Sprintf("HTTP %d", resp.StatusCode))
}

func (s *Service) markFail(ctx context.Context, deliveryID int64, attempts, httpCode int, msg string) {
	db := s.DB()
	if db == nil {
		return
	}
	nextAttempts := attempts + 1
	// Exponential backoff: 1m, 5m, 25m, 2h. After 4 attempts, give up.
	if nextAttempts >= 4 {
		_, _ = db.ExecContext(ctx,
			"UPDATE webhook_deliveries SET status='failed', attempts=?, http_code=?, last_error=? WHERE id = ?",
			nextAttempts, httpCode, truncateErr(msg), deliveryID)
		return
	}
	backoff := time.Duration(1<<uint(nextAttempts-1)) * time.Minute * 5
	if backoff < time.Minute {
		backoff = time.Minute
	}
	_, _ = db.ExecContext(ctx,
		`UPDATE webhook_deliveries
		 SET status='pending', attempts=?, http_code=?, last_error=?,
		     next_retry_at = NOW() + INTERVAL ? SECOND
		 WHERE id = ?`,
		nextAttempts, httpCode, truncateErr(msg), int(backoff.Seconds()), deliveryID)
}

// SaveEndpoint upserts an endpoint by name. The secret is encrypted at
// rest before write.
func (s *Service) SaveEndpoint(ctx context.Context, name, urlStr, secret, events string, enabled bool, createdBy int64) (int64, error) {
	if name == "" || urlStr == "" {
		return 0, errors.New("name + url required")
	}
	parsed, perr := url.Parse(urlStr)
	if perr != nil {
		return 0, fmt.Errorf("parse url: %w", perr)
	}
	if err := security.ValidateOutboundURL(parsed); err != nil {
		return 0, err
	}
	db := s.DB()
	if db == nil {
		return 0, errors.New("db not ready")
	}
	var secretEnc sql.NullString
	if secret != "" && s.State != nil {
		enc, err := s.State.Encrypt(secret)
		if err != nil {
			return 0, fmt.Errorf("encrypt: %w", err)
		}
		secretEnc = sql.NullString{String: enc, Valid: true}
	}
	var createdByVal sql.NullInt64
	if createdBy != 0 {
		createdByVal = sql.NullInt64{Int64: createdBy, Valid: true}
	}
	enabledInt := 0
	if enabled {
		enabledInt = 1
	}
	res, err := db.ExecContext(ctx,
		`INSERT INTO webhook_endpoints (name, url, secret_enc, events, is_enabled, created_by)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON DUPLICATE KEY UPDATE url=VALUES(url), secret_enc=VALUES(secret_enc),
		   events=VALUES(events), is_enabled=VALUES(is_enabled)`,
		name, urlStr, secretEnc, events, enabledInt, createdByVal)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	return id, nil
}

// eventMatches returns true if any of the comma-separated patterns in
// `filter` matches `evt`. "*" matches everything; "route.*" prefix-matches.
func eventMatches(evt, filter string) bool {
	for _, p := range strings.Split(filter, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if p == "*" || p == evt {
			return true
		}
		if strings.HasSuffix(p, ".*") {
			prefix := strings.TrimSuffix(p, "*")
			if strings.HasPrefix(evt, prefix) {
				return true
			}
		}
	}
	return false
}

func truncateErr(s string) string {
	if len(s) > 2000 {
		return s[:2000] + "..."
	}
	return s
}
