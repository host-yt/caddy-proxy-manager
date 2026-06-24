// Package captcha verifies Cloudflare Turnstile responses.
//
// Settings (DB-backed via Refresh; env fallback in main):
//
//	captcha.provider  = "turnstile" | "" (disabled)
//	captcha.site_key  = public site key shown in HTML
//	captcha.secret    = server secret (encrypted at rest)
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

	"github.com/hostyt/proxy-gateway/internal/installstate"
)

const turnstileVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

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

// Enabled returns true when both provider and secret are set.
func (v *Verifier) Enabled() bool {
	v.maybeReload()
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.provider == "turnstile" && v.secret != ""
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
			provider = val
		case "captcha.site_key":
			siteKey = val
		case "captcha.secret":
			secret = val
		}
	}
	v.mu.Lock()
	if provider != "" {
		v.provider = provider
	}
	if siteKey != "" {
		v.siteKey = siteKey
	}
	if secret != "" {
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
	v.mu.RUnlock()
	form := url.Values{
		"secret":   {secret},
		"response": {token},
	}
	if ip != "" {
		form.Set("remoteip", ip)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, turnstileVerifyURL, strings.NewReader(form.Encode()))
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
