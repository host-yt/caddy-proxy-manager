package handlers

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/audit"
	"github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
	"github.com/host-yt/caddy-proxy-manager/internal/sms"
)

// e164Re matches the E.164 phone format: a leading +, a non-zero leading
// digit, then up to 14 more digits. We enforce this before hitting any
// provider so an obvious typo doesn't get billed as an SMS attempt.
var e164Re = regexp.MustCompile(`^\+[1-9]\d{1,14}$`)

// SMSConfigView is the form-binding shape consumed by settings.html.tmpl.
type SMSConfigView struct {
	Enabled          bool
	Provider         string
	From             string
	TwilioAccountSID string
	HasTwilioToken   bool
	SMSAPIBaseURL    string
	HasSMSAPIToken   bool
	BulkGateAppID    string
	HasBulkGateToken bool
	WebhookURL       string
	HasWebhookToken  bool
}

// LoadSMSConfigView returns the (sanitized) current SMS settings for the
// admin form. Secrets are never returned, only a "has-value" flag.
func (h *AdminHandlers) LoadSMSConfigView(ctx context.Context) SMSConfigView {
	// BulkGate is the suggested default for new installs.
	v := SMSConfigView{Provider: string(sms.ProviderBulkGate), SMSAPIBaseURL: "https://api.smsapi.pl"}
	db := h.DB()
	if db == nil {
		return v
	}
	kv := h.loadSettings(ctx, db, []string{
		"sms.enabled", "sms.provider", "sms.from",
		"sms.twilio_account_sid", "sms.twilio_auth_token",
		"sms.smsapi_base_url", "sms.smsapi_token",
		"sms.bulkgate_app_id", "sms.bulkgate_app_token",
		"sms.webhook_url", "sms.webhook_token",
	})
	v.Enabled = kv["sms.enabled"] == "1"
	if s := kv["sms.provider"]; s != "" {
		v.Provider = s
	}
	v.From = kv["sms.from"]
	v.TwilioAccountSID = kv["sms.twilio_account_sid"]
	v.HasTwilioToken = kv["sms.twilio_auth_token"] != ""
	if u := kv["sms.smsapi_base_url"]; u != "" {
		v.SMSAPIBaseURL = u
	}
	v.HasSMSAPIToken = kv["sms.smsapi_token"] != ""
	v.BulkGateAppID = kv["sms.bulkgate_app_id"]
	v.HasBulkGateToken = kv["sms.bulkgate_app_token"] != ""
	v.WebhookURL = kv["sms.webhook_url"]
	v.HasWebhookToken = kv["sms.webhook_token"] != ""
	return v
}

// SettingsSMS handles POST /admin/settings/sms.
func (h *AdminHandlers) SettingsSMS(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	enabled := r.FormValue("enabled") == "1"
	// sms_provider comes from the card-picker hidden input; "provider" kept for
	// backward-compat (old form posts / direct API calls).
	provider := strings.TrimSpace(r.FormValue("sms_provider"))
	if provider == "" {
		provider = strings.TrimSpace(r.FormValue("provider"))
	}
	if provider == "" {
		provider = string(sms.ProviderBulkGate)
	}
	switch sms.Provider(provider) {
	case sms.ProviderTwilio, sms.ProviderSMSAPI, sms.ProviderBulkGate, sms.ProviderWebhook:
	default:
		redirectWithFlash(w, r, "/admin/settings", "", "SMS: unknown provider")
		return
	}
	from := strings.TrimSpace(r.FormValue("from"))
	twilioSID := strings.TrimSpace(r.FormValue("twilio_account_sid"))
	twilioTok := r.FormValue("twilio_auth_token")
	smsapiBase := strings.TrimSpace(r.FormValue("smsapi_base_url"))
	smsapiTok := r.FormValue("smsapi_token")
	bulkGateID := strings.TrimSpace(r.FormValue("bulkgate_app_id"))
	bulkGateTok := r.FormValue("bulkgate_app_token")
	webhookURL := strings.TrimSpace(r.FormValue("webhook_url"))
	webhookTok := r.FormValue("webhook_token")

	if enabled && from == "" {
		redirectWithFlash(w, r, "/admin/settings", "", "SMS: sender ID required when enabled")
		return
	}
	if webhookURL != "" && !isHTTPURL(webhookURL) {
		redirectWithFlash(w, r, "/admin/settings", "", "SMS: webhook URL must be http(s)")
		return
	}
	// Base URL is admin-set; reject non-http(s) early. SSRF is enforced
	// authoritatively at send time via security.SafeHTTPClient.
	if smsapiBase != "" && !isHTTPURL(smsapiBase) {
		redirectWithFlash(w, r, "/admin/settings", "", "SMS: SMSAPI base URL must be http(s)")
		return
	}

	enabledStr := "0"
	if enabled {
		enabledStr = "1"
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	if err := h.saveSettings(ctx, db, map[string]string{
		"sms.enabled":            enabledStr,
		"sms.provider":           provider,
		"sms.from":               from,
		"sms.twilio_account_sid": twilioSID,
		"sms.smsapi_base_url":    defaultStr(smsapiBase, "https://api.smsapi.pl"),
		"sms.bulkgate_app_id":    bulkGateID,
		"sms.webhook_url":        webhookURL,
	}, false); err != nil {
		redirectWithFlash(w, r, "/admin/settings", "", "save failed: "+sanitizeErr(err))
		return
	}

	// Persist secrets only when the operator supplied a new value; empty
	// field means "keep what is stored".
	saveSecret := func(key, val string) error {
		if val == "" {
			return nil
		}
		ct, err := h.encryptSetting(val)
		if err != nil {
			return err
		}
		return h.saveSettings(ctx, db, map[string]string{key: ct}, true)
	}
	if err := saveSecret("sms.twilio_auth_token", twilioTok); err != nil {
		redirectWithFlash(w, r, "/admin/settings", "", "twilio token save failed")
		return
	}
	if err := saveSecret("sms.smsapi_token", smsapiTok); err != nil {
		redirectWithFlash(w, r, "/admin/settings", "", "smsapi token save failed")
		return
	}
	if err := saveSecret("sms.bulkgate_app_token", bulkGateTok); err != nil {
		redirectWithFlash(w, r, "/admin/settings", "", "bulkgate token save failed")
		return
	}
	if err := saveSecret("sms.webhook_token", webhookTok); err != nil {
		redirectWithFlash(w, r, "/admin/settings", "", "webhook token save failed")
		return
	}

	// Force re-load on next Send; also push decrypted secrets into the
	// in-memory Sender so a "send test" right after save uses fresh values.
	if h.SMS != nil {
		h.SMS.Invalidate()
		_, _ = h.SMS.CurrentConfig(ctx)
		secrets := h.loadSettings(ctx, db, []string{
			"sms.twilio_auth_token", "sms.smsapi_token",
			"sms.bulkgate_app_token", "sms.webhook_token",
		})
		h.SMS.SetSecrets(secrets["sms.twilio_auth_token"],
			secrets["sms.smsapi_token"],
			secrets["sms.bulkgate_app_token"],
			secrets["sms.webhook_token"])
	}

	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID:   actorUserID(sess),
		Action:   "settings.sms.save",
		Entity:   "settings",
		EntityID: "sms",
		Meta:     map[string]any{"enabled": enabled, "provider": provider},
	})
	redirectWithFlash(w, r, "/admin/settings", "SMS settings saved.", "")
}

// SettingsSMSTest sends a one-off test SMS to the operator-supplied phone
// and reports the outcome via flash. Useful for verifying provider config
// without spinning up a real OTP flow.
func (h *AdminHandlers) SettingsSMSTest(w http.ResponseWriter, r *http.Request) {
	if h.SMS == nil {
		redirectWithFlash(w, r, "/admin/settings", "", "SMS not wired into this build")
		return
	}
	_ = r.ParseForm()
	to := strings.TrimSpace(r.FormValue("test_phone"))
	if to == "" {
		redirectWithFlash(w, r, "/admin/settings", "", "enter a test phone (E.164, e.g. +48555111222)")
		return
	}
	if !e164Re.MatchString(to) {
		redirectWithFlash(w, r, "/admin/settings", "", "test phone must be E.164: + then up to 15 digits (e.g. +48555111222)")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	// Ensure the in-memory Sender has fresh decrypted secrets before we
	// hit the wire.
	if db := h.DB(); db != nil {
		secrets := h.loadSettings(ctx, db, []string{
			"sms.twilio_auth_token", "sms.smsapi_token",
			"sms.bulkgate_app_token", "sms.webhook_token",
		})
		h.SMS.SetSecrets(secrets["sms.twilio_auth_token"],
			secrets["sms.smsapi_token"],
			secrets["sms.bulkgate_app_token"],
			secrets["sms.webhook_token"])
	}
	err := h.SMS.Send(ctx, to, "Hostyt Proxy Gateway: test message from admin panel.")
	sess := middleware.SessionFromContext(r.Context())
	if err != nil {
		audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
			UserID: actorUserID(sess), Action: "settings.sms.test", Entity: "settings",
			EntityID: "sms", Meta: map[string]any{"to": to, "ok": false, "err": err.Error()},
		})
		redirectWithFlash(w, r, "/admin/settings", "", "SMS test failed: "+sanitizeErr(err))
		return
	}
	audit.Write(ctx, h.DB(), h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "settings.sms.test", Entity: "settings",
		EntityID: "sms", Meta: map[string]any{"to": to, "ok": true},
	})
	redirectWithFlash(w, r, "/admin/settings", "Test SMS sent.", "")
}

// SettingsSMSOTPAvailable toggles whether customers can use SMS as 2FA.
// Admin must explicitly enable; default is OFF.
func (h *AdminHandlers) SettingsSMSOTPAvailable(w http.ResponseWriter, r *http.Request) {
	db := h.DB()
	if db == nil {
		http.Error(w, "no db", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	available := r.FormValue("sms_otp_available") == "1"
	val := "0"
	if available {
		val = "1"
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := h.saveSettings(ctx, db, map[string]string{"sms_otp_available": val}, false); err != nil {
		redirectWithFlash(w, r, "/admin/settings", "", "save failed: "+sanitizeErr(err))
		return
	}
	sess := middleware.SessionFromContext(r.Context())
	audit.Write(ctx, db, h.Logger, r, audit.Entry{
		UserID: actorUserID(sess), Action: "settings.sms_otp.save", Entity: "settings",
		EntityID: "sms_otp", Meta: map[string]any{"available": available},
	})
	redirectWithFlash(w, r, "/admin/settings", "SMS 2FA availability saved.", "")
}
