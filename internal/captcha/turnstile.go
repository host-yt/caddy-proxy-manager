// Package captcha verifies CAPTCHA responses from a configurable provider.
//
// Settings (DB-backed via Refresh; env fallback in main):
//
//	captcha.provider  = "turnstile" | "hcaptcha" | "recaptcha" | "" (disabled)
//	captcha.site_key  = public site key shown in HTML
//	captcha.secret    = server secret (encrypted at rest)
//
// All three providers share the same siteverify contract (POST secret+response,
// JSON {success, error-codes}); only the endpoint URL differs.
package captcha

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/installstate"
)

// verifyURLs maps each supported provider to its server-side siteverify endpoint.
var verifyURLs = map[string]string{
	"turnstile": "https://challenges.cloudflare.com/turnstile/v0/siteverify",
	"hcaptcha":  "https://api.hcaptcha.com/siteverify",
	"recaptcha": "https://www.google.com/recaptcha/api/siteverify",
}

// knownProvider reports whether p is a supported (non-empty) provider.
func knownProvider(p string) bool { _, ok := verifyURLs[p]; return ok }

// Verifier holds the secret + a shared client.
type Verifier struct {
	hc *http.Client

	mu       sync.RWMutex
	provider string
	siteKey  string
	secret   string

	// Optional dependencies for DB-backed Refresh.
	DB         func() *sql.DB
	State      *installstate.Manager
	lastReload time.Time
}

func New(provider, secret string) *Verifier {
	return &Verifier{
		provider: provider,
		secret:   secret,
		hc:       &http.Client{Timeout: 5 * time.Second},
	}
}

// SetSiteKey lets callers seed the public key without DB hit.
func (v *Verifier) SetSiteKey(key string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.siteKey = key
}

// SiteKey returns the public site key for HTML rendering.
func (v *Verifier) SiteKey() string {
	v.maybeReload()
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.siteKey
}

// Enabled returns true when a known provider and a secret are both set.
func (v *Verifier) Enabled() bool {
	v.maybeReload()
	v.mu.RLock()
	defer v.mu.RUnlock()
	return knownProvider(v.provider) && v.secret != ""
}

// Provider returns the active provider id ("turnstile"|"hcaptcha"|"recaptcha"|"")
// so the login template can render the matching widget.
func (v *Verifier) Provider() string {
	v.maybeReload()
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.provider
}

// Refresh forces a reload of captcha settings from DB (super_admin
// flipped them in the UI). Safe to call from any goroutine.
func (v *Verifier) Refresh(ctx context.Context) {
	if v.DB == nil {
		return
	}
	db := v.DB()
	if db == nil {
		return
	}
	rows, err := db.QueryContext(ctx,
		"SELECT `key`, value, is_encrypted FROM settings WHERE `key` LIKE 'captcha.%'")
	if err != nil {
		return
	}
	defer rows.Close()
	var provider, siteKey, secret string
	// Track which rows exist so an admin who blanks a value (e.g. disables
	// CAPTCHA -> provider="") actually clears the in-memory verifier, while a
	// missing row keeps any env-seeded value.
	var haveProvider, haveSite, haveSecret bool
	for rows.Next() {
		var k, val string
		var enc bool
		if err := rows.Scan(&k, &val, &enc); err != nil {
			continue
		}
		if enc && v.State != nil {
			if dec, derr := v.State.Decrypt(val); derr == nil {
				val = dec
			} else {
				val = ""
			}
		}
		switch k {
		case "captcha.provider":
			provider, haveProvider = val, true
		case "captcha.site_key":
			siteKey, haveSite = val, true
		case "captcha.secret":
			secret, haveSecret = val, true
		}
	}
	v.mu.Lock()
	if haveProvider {
		v.provider = provider
	}
	if haveSite {
		v.siteKey = siteKey
	}
	if haveSecret {
		v.secret = secret
	}
	v.lastReload = time.Now()
	v.mu.Unlock()
}

// maybeReload triggers a DB refresh at most every 30 s.
func (v *Verifier) maybeReload() {
	v.mu.RLock()
	stale := time.Since(v.lastReload) > 30*time.Second
	v.mu.RUnlock()
	if stale && v.DB != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		v.Refresh(ctx)
	}
}

// Verify hits Cloudflare with the user-submitted token + remote IP.
func (v *Verifier) Verify(ctx context.Context, token, ip string) error {
	if !v.Enabled() {
		return nil
	}
	if strings.TrimSpace(token) == "" {
		return errors.New("captcha token missing")
	}
	v.mu.RLock()
	secret := v.secret
	endpoint := verifyURLs[v.provider]
	v.mu.RUnlock()
	if endpoint == "" {
		return nil // unknown provider -> treat as disabled
	}
	form := url.Values{
		"secret":   {secret},
		"response": {token},
	}
	if ip != "" {
		form.Set("remoteip", ip)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := v.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var body struct {
		Success    bool     `json:"success"`
		ErrorCodes []string `json:"error-codes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return err
	}
	if !body.Success {
		return errors.New("captcha failed: " + strings.Join(body.ErrorCodes, ","))
	}
	return nil
}
