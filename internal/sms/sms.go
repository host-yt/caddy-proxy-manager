// Package sms wraps a small set of SMS providers behind one Sender
// interface so the rest of the app can issue OTPs and operational alerts
// without caring which provider the operator wired up. Config is sourced
// from the settings table (settings_e2 for secrets) and reloaded on save.
package sms

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/hostyt/proxy-gateway/internal/installstate"
	"github.com/hostyt/proxy-gateway/internal/security"
)

// Provider identifies the upstream gateway.
type Provider string

const (
	ProviderTwilio   Provider = "twilio"   // https://www.twilio.com/
	ProviderSMSAPI   Provider = "smsapi"   // https://www.smsapi.pl/
	ProviderBulkGate Provider = "bulkgate" // https://www.bulkgate.com/ (Simple Transactional)
	ProviderWebhook  Provider = "webhook"  // generic JSON POST to operator URL
)

// Config is the runtime SMS config; loaded from settings table on demand.
//
// Twilio uses AccountSID + AuthToken; From is the verified sender phone or
// alphanumeric ID. SMSAPI uses a single API token (OAuth-style) and From as
// alphanumeric sender; BaseURL defaults to https://api.smsapi.pl. Webhook
// POSTs {"to","from","message"} JSON to URL with optional Bearer token.
type Config struct {
	Enabled  bool
	Provider Provider
	From     string

	TwilioAccountSID string
	TwilioAuthToken  string

	SMSAPIToken   string
	SMSAPIBaseURL string

	BulkGateAppID    string
	BulkGateAppToken string

	WebhookURL   string
	WebhookToken string
}

// IsZero reports whether SMS has been configured at all.
func (c Config) IsZero() bool {
	if !c.Enabled || c.From == "" {
		return true
	}
	switch c.Provider {
	case ProviderTwilio:
		return c.TwilioAccountSID == "" || c.TwilioAuthToken == ""
	case ProviderSMSAPI:
		return c.SMSAPIToken == ""
	case ProviderBulkGate:
		return c.BulkGateAppID == "" || c.BulkGateAppToken == ""
	case ProviderWebhook:
		return c.WebhookURL == ""
	}
	return true
}

// Sender is the operational seam used by handlers + 2FA challenges.
type Sender struct {
	DB     *sql.DB
	Logger *slog.Logger
	// State decrypts secrets stored with is_encrypted=1. Without it the
	// cached Config has empty tokens → IsZero true → "disabled or not
	// configured" on every Send after a fresh boot.
	State *installstate.Manager

	mu  sync.RWMutex
	cfg *Config
}

// New returns a Sender ready for use; config is lazy-loaded on first Send.
func New(db *sql.DB, logger *slog.Logger) *Sender {
	return &Sender{DB: db, Logger: logger}
}

// Invalidate drops the cached Config so the next Send re-reads settings.
// Call after the admin saves the SMS form.
func (s *Sender) Invalidate() {
	s.mu.Lock()
	s.cfg = nil
	s.mu.Unlock()
}

// Send delivers a text message to the E.164 phone number. Returns an error
// if SMS is disabled or unconfigured so the caller can fall back (e.g. to
// email). Body is provider-side limited; we don't pre-truncate so the
// caller can choose its own policy.
func (s *Sender) Send(ctx context.Context, toPhone, body string) error {
	toPhone = strings.TrimSpace(toPhone)
	if toPhone == "" {
		return errors.New("sms: empty recipient")
	}
	if strings.TrimSpace(body) == "" {
		return errors.New("sms: empty body")
	}
	cfg, err := s.loadConfig(ctx)
	if err != nil {
		return fmt.Errorf("sms: load config: %w", err)
	}
	if cfg.IsZero() {
		return errors.New("sms: disabled or not configured")
	}
	switch cfg.Provider {
	case ProviderTwilio:
		return sendTwilio(ctx, cfg, toPhone, body)
	case ProviderSMSAPI:
		return sendSMSAPI(ctx, cfg, toPhone, body)
	case ProviderBulkGate:
		return sendBulkGate(ctx, cfg, toPhone, body)
	case ProviderWebhook:
		return sendWebhook(ctx, cfg, toPhone, body)
	}
	return fmt.Errorf("sms: unknown provider %q", cfg.Provider)
}

// CurrentConfig returns a copy of the cached config (or loads it). Used by
// the settings page to render the form.
func (s *Sender) CurrentConfig(ctx context.Context) (Config, error) {
	cfg, err := s.loadConfig(ctx)
	if err != nil {
		return Config{}, err
	}
	return *cfg, nil
}

func (s *Sender) loadConfig(ctx context.Context) (*Config, error) {
	s.mu.RLock()
	c := s.cfg
	s.mu.RUnlock()
	if c != nil {
		return c, nil
	}
	loaded, err := loadFromDB(ctx, s.DB, s.State)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.cfg = loaded
	s.mu.Unlock()
	return loaded, nil
}

// loadFromDB pulls all sms.* settings (plain + encrypted) and returns a
// ready-to-use Config. Encrypted rows are decrypted in-place via the
// State manager; without State the secret fields stay empty (IsZero true).
func loadFromDB(ctx context.Context, db *sql.DB, st *installstate.Manager) (*Config, error) {
	if db == nil {
		return &Config{}, nil
	}
	c := &Config{}
	rows, err := db.QueryContext(ctx,
		"SELECT `key`, value, is_encrypted FROM settings WHERE `key` LIKE 'sms.%'")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		var enc bool
		if err := rows.Scan(&k, &v, &enc); err != nil {
			return nil, err
		}
		if enc && st != nil {
			if dec, derr := st.Decrypt(v); derr == nil {
				v = dec
			} else {
				v = ""
			}
		}
		switch k {
		case "sms.enabled":
			c.Enabled = v == "1"
		case "sms.provider":
			c.Provider = Provider(v)
		case "sms.from":
			c.From = v
		case "sms.twilio_account_sid":
			c.TwilioAccountSID = v
		case "sms.twilio_auth_token":
			c.TwilioAuthToken = v
		case "sms.smsapi_base_url":
			c.SMSAPIBaseURL = v
		case "sms.smsapi_token":
			c.SMSAPIToken = v
		case "sms.bulkgate_app_id":
			c.BulkGateAppID = v
		case "sms.bulkgate_app_token":
			c.BulkGateAppToken = v
		case "sms.webhook_url":
			c.WebhookURL = v
		case "sms.webhook_token":
			c.WebhookToken = v
		}
	}
	if c.SMSAPIBaseURL == "" {
		c.SMSAPIBaseURL = "https://api.smsapi.pl"
	}
	return c, nil
}

// SetSecrets is called by the handler after decrypting the AES-GCM
// ciphertexts from settings_e2. Keeps the sms package free of the cipher
// dependency that lives in handlers/admin.go.
func (s *Sender) SetSecrets(twilioAuth, smsapiToken, bulkGateAppToken, webhookToken string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg == nil {
		s.cfg = &Config{}
	}
	s.cfg.TwilioAuthToken = twilioAuth
	s.cfg.SMSAPIToken = smsapiToken
	s.cfg.BulkGateAppToken = bulkGateAppToken
	s.cfg.WebhookToken = webhookToken
}

// ---- providers --------------------------------------------------------

func sendTwilio(ctx context.Context, cfg *Config, to, body string) error {
	endpoint := "https://api.twilio.com/2010-04-01/Accounts/" + cfg.TwilioAccountSID + "/Messages.json"
	form := url.Values{}
	form.Set("To", to)
	form.Set("From", cfg.From)
	form.Set("Body", body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.SetBasicAuth(cfg.TwilioAccountSID, cfg.TwilioAuthToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return doSend(req, "twilio")
}

func sendSMSAPI(ctx context.Context, cfg *Config, to, body string) error {
	base := strings.TrimRight(cfg.SMSAPIBaseURL, "/")
	// SSRF guard: base URL is admin-configurable, so validate + dial through
	// SafeHTTPClient (same as webhook) - else http://10.66.0.1:2019 would reach
	// the WG-only Caddy admin API.
	u, err := url.Parse(base + "/sms.do")
	if err != nil {
		return fmt.Errorf("smsapi: bad url: %w", err)
	}
	if err := security.ValidateOutboundURL(u); err != nil {
		return fmt.Errorf("smsapi: %w", err)
	}
	form := url.Values{}
	form.Set("to", to)
	form.Set("from", cfg.From)
	form.Set("message", body)
	form.Set("format", "json")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.SMSAPIToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := security.SafeHTTPClient(15 * time.Second).Do(req)
	if err != nil {
		return fmt.Errorf("smsapi: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("smsapi: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(buf)))
	}
	return nil
}

// BulkGate Simple Transactional. Body fields carry the credentials (no header).
// Phone must be digits-only with country prefix (no leading "+").
// Docs: https://help.bulkgate.com/docs/en/http-simple-transactional.html
func sendBulkGate(ctx context.Context, cfg *Config, to, body string) error {
	num := strings.TrimPrefix(strings.TrimSpace(to), "+")
	payload := map[string]any{
		"application_id":    cfg.BulkGateAppID,
		"application_token": cfg.BulkGateAppToken,
		"number":            num,
		"text":              body,
		"duplicates_check":  "on",
	}
	if cfg.From != "" {
		payload["sender_id"] = "gText"
		payload["sender_id_value"] = cfg.From
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://portal.bulkgate.com/api/1.0/simple/transactional",
		bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return doSend(req, "bulkgate")
}

func sendWebhook(ctx context.Context, cfg *Config, to, body string) error {
	// SSRF guard: the webhook URL is admin-set but must still go through the
	// validating dialer - otherwise an admin-set (or DB-injected) host like
	// http://10.66.0.1:2019 would reach the WG-only Caddy admin API. Validate
	// the literal first, then dial through SafeHTTPClient which re-checks every
	// resolved IP and redirect hop.
	u, err := url.Parse(cfg.WebhookURL)
	if err != nil {
		return fmt.Errorf("webhook: bad url: %w", err)
	}
	if err := security.ValidateOutboundURL(u); err != nil {
		return fmt.Errorf("webhook: %w", err)
	}
	// Webhook payload is form-encoded so operators can wire it to any
	// HTTP-callable gateway without writing a JSON parser.
	form := url.Values{}
	form.Set("to", to)
	form.Set("from", cfg.From)
	form.Set("message", body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.WebhookURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	if cfg.WebhookToken != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.WebhookToken)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := security.SafeHTTPClient(15 * time.Second).Do(req)
	if err != nil {
		return fmt.Errorf("webhook: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("webhook: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(buf)))
	}
	return nil
}

var httpClient = &http.Client{Timeout: 15 * time.Second}

func doSend(req *http.Request, provider string) error {
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", provider, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("%s: HTTP %d: %s", provider, resp.StatusCode, strings.TrimSpace(string(buf)))
	}
	return nil
}
