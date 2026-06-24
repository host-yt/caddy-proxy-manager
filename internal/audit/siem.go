package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/hostyt/proxy-gateway/internal/security"
)

// Forwarder posts audit events to an external SIEM endpoint.
// Zero value is a no-op. Build with NewForwarder.
type Forwarder struct {
	url    string
	client *http.Client
	sem    chan struct{} // bounds concurrent outbound calls
	logger *slog.Logger
}

// NewForwarder validates rawURL and returns a ready Forwarder.
// Returns (nil, nil) when rawURL is empty (feature disabled).
// Returns non-nil error when rawURL fails SSRF pre-check so startup fails fast.
func NewForwarder(rawURL string, logger *slog.Logger) (*Forwarder, error) {
	if rawURL == "" {
		return nil, nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if err := security.ValidateOutboundURL(u); err != nil {
		return nil, err
	}
	return &Forwarder{
		url:    rawURL,
		client: security.SafeHTTPClient(5 * time.Second),
		sem:    make(chan struct{}, 8), // max 8 in-flight
		logger: logger,
	}, nil
}

// siemPayload is the JSON body sent to the SIEM endpoint.
type siemPayload struct {
	Source    string         `json:"source"`
	ActorType string         `json:"actor_type"`
	Action    string         `json:"action"`
	Entity    string         `json:"entity"`
	EntityID  string         `json:"entity_id,omitempty"`
	UserID    *int64         `json:"user_id,omitempty"`
	IP        string         `json:"ip,omitempty"`
	UA        string         `json:"user_agent,omitempty"`
	Meta      map[string]any `json:"meta,omitempty"`
	Timestamp string         `json:"timestamp"` // RFC3339 UTC
}

// Send fires the event asynchronously; errors are logged only.
// If the semaphore is full the goroutine is not spawned
// (back-pressure shedding: audit gaps beat goroutine leaks).
func (f *Forwarder) Send(e Entry, ip, ua string) {
	if f == nil {
		return
	}
	select {
	case f.sem <- struct{}{}:
	default:
		// semaphore full: drop rather than block caller
		return
	}
	go func() {
		defer func() { <-f.sem }()
		p := siemPayload{
			Source:    "hostyt-proxy-gateway",
			ActorType: e.ActorType,
			Action:    e.Action,
			Entity:    e.Entity,
			EntityID:  e.EntityID,
			UserID:    e.UserID,
			IP:        ip,
			UA:        ua,
			Meta:      e.Meta,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		}
		body, err := json.Marshal(p)
		if err != nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.url, bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := f.client.Do(req)
		if err != nil {
			if f.logger != nil {
				f.logger.Warn("siem forward failed", "err", err)
			}
			return
		}
		resp.Body.Close()
		if resp.StatusCode >= 400 && f.logger != nil {
			f.logger.Warn("siem returned error", "status", resp.StatusCode)
		}
	}()
}
