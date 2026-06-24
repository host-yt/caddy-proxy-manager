// Package oidc wraps coreos/go-oidc with a settings-backed config that
// the admin can change at runtime. Designed for Authentik but works
// with any OIDC-compliant IdP.
package oidc

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	goOIDC "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/hostyt/proxy-gateway/internal/installstate"
	"github.com/hostyt/proxy-gateway/internal/security"
)

// Config is what we persist in the `settings` table.
type Config struct {
	Enabled       bool
	ProviderName  string // display label, e.g. "Authentik"
	Issuer        string // e.g. https://authentik.example.com/application/o/hostyt/
	ClientID      string
	ClientSecret  string // decrypted
	RedirectURL   string // e.g. https://panel.example.com/auth/oidc/callback
	DefaultRole   string // role assigned to auto-provisioned users
	AutoProvision bool   // create local user on first login
	Scopes        string // space-separated; empty => "openid email profile"
	// AllowUnverifiedEmail bypasses the email_verified ID-token claim
	// check. ONLY enable when the IdP guarantees email ownership some
	// other way (e.g. corporate Authentik tied to AD/LDAP — emails are
	// authoritative, IdP just doesn't bother emitting the claim).
	AllowUnverifiedEmail bool
}

// Service caches the parsed OIDC provider per (issuer, client_id) pair
// to avoid re-fetching the discovery document on every login.
type Service struct {
	DB    *sql.DB
	State *installstate.Manager

	mu        sync.Mutex
	cacheKey  string
	provider  *goOIDC.Provider
	oauthCfg  *oauth2.Config
	loadedCfg Config
	cacheTime time.Time
}

// CurrentConfig loads (or returns cached) settings + provider.
// Refreshes cache when issuer/client_id changes or after 5 minutes.
func (s *Service) currentConfig(ctx context.Context) (Config, *oauth2.Config, *goOIDC.Provider, error) {
	cfg, err := s.loadConfig(ctx)
	if err != nil {
		return cfg, nil, nil, err
	}
	if !cfg.Enabled || cfg.Issuer == "" || cfg.ClientID == "" {
		return cfg, nil, nil, errors.New("oidc not configured")
	}
	key := cfg.Issuer + "|" + cfg.ClientID
	// Fast path: serve a warm cache under the lock, then release it. We must
	// NOT hold s.mu across the discovery fetch below - a slow/hung IdP would
	// otherwise serialize every concurrent login behind one mutex for the full
	// SafeHTTPClient timeout.
	s.mu.Lock()
	if s.cacheKey == key && time.Since(s.cacheTime) < 5*time.Minute && s.provider != nil {
		oc, p := s.oauthCfg, s.provider
		s.mu.Unlock()
		return cfg, oc, p, nil
	}
	s.mu.Unlock()

	// SSRF guard: refuse to fetch discovery from RFC1918 / loopback /
	// link-local hosts. Admin-set free text would otherwise let a malicious
	// admin (or compromised account) point the discovery fetch at
	// http://10.66.0.1:2019/config/ to probe the WG-only Caddy admin API.
	if u, perr := url.Parse(cfg.Issuer); perr == nil {
		if verr := security.ValidateOutboundURL(u); verr != nil {
			return cfg, nil, nil, fmt.Errorf("oidc issuer rejected: %w", verr)
		}
	} else {
		return cfg, nil, nil, fmt.Errorf("oidc issuer not a URL: %w", perr)
	}
	// Use a safe HTTP client for discovery + JWKS fetch. Done WITHOUT the lock.
	discoCtx := goOIDC.ClientContext(ctx, security.SafeHTTPClient(10*time.Second))
	p, err := goOIDC.NewProvider(discoCtx, cfg.Issuer)
	if err != nil {
		return cfg, nil, nil, fmt.Errorf("oidc discover: %w", err)
	}
	oc := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     p.Endpoint(),
		Scopes:       resolveScopes(cfg.Scopes),
	}
	// Store under the lock. A concurrent caller may have populated the cache
	// while we fetched; that's fine - both computed an equivalent provider and
	// last writer wins.
	s.mu.Lock()
	s.cacheKey = key
	s.provider = p
	s.oauthCfg = oc
	s.loadedCfg = cfg
	s.cacheTime = time.Now()
	s.mu.Unlock()
	return cfg, oc, p, nil
}

// CurrentConfigForUI returns the loaded (or stored) config without
// triggering discovery — used by Settings page to render form values.
func (s *Service) CurrentConfigForUI(ctx context.Context) (Config, error) {
	return s.loadConfig(ctx)
}

// AuthURL returns the redirect URL for the IdP, plus state/nonce/verifier
// tokens that the caller stores in a short-lived cookie / Redis ticket.
// PKCE (S256) is always used — recommended by RFC 9700 even for
// confidential clients.
func (s *Service) AuthURL(ctx context.Context) (url, state, nonce, verifier string, cfg Config, err error) {
	cfg, oc, _, err := s.currentConfig(ctx)
	if err != nil {
		return "", "", "", "", cfg, err
	}
	state, err = randID(16)
	if err != nil {
		return "", "", "", "", cfg, err
	}
	nonce, err = randID(16)
	if err != nil {
		return "", "", "", "", cfg, err
	}
	verifier = oauth2.GenerateVerifier()
	url = oc.AuthCodeURL(state,
		oauth2.AccessTypeOnline,
		goOIDC.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
	)
	return url, state, nonce, verifier, cfg, nil
}

// UserInfo is the minimal claim set we consume.
type UserInfo struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	Issuer        string
}

// Exchange completes the OIDC flow: exchanges code for tokens (with PKCE
// verifier), verifies the ID token signature + nonce, returns user info.
func (s *Service) Exchange(ctx context.Context, code, expectedNonce, verifier string) (UserInfo, error) {
	_, oc, p, err := s.currentConfig(ctx)
	if err != nil {
		return UserInfo{}, err
	}
	// Use a SafeHTTPClient so the token endpoint POST also goes through the
	// SSRF guard (the discovered token_endpoint comes from the issuer's
	// .well-known; we already restrict the issuer host but the token URL
	// may differ).
	tokCtx := goOIDC.ClientContext(ctx, security.SafeHTTPClient(10*time.Second))
	var opts []oauth2.AuthCodeOption
	if verifier != "" {
		opts = append(opts, oauth2.VerifierOption(verifier))
	}
	tok, err := oc.Exchange(tokCtx, code, opts...)
	if err != nil {
		return UserInfo{}, fmt.Errorf("oauth exchange: %w", err)
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok {
		return UserInfo{}, errors.New("no id_token in response")
	}
	idv := p.Verifier(&goOIDC.Config{ClientID: oc.ClientID})
	idToken, err := idv.Verify(ctx, rawIDToken)
	if err != nil {
		return UserInfo{}, fmt.Errorf("id token verify: %w", err)
	}
	if expectedNonce != "" && idToken.Nonce != expectedNonce {
		return UserInfo{}, errors.New("nonce mismatch")
	}
	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		PreferredUser string `json:"preferred_username"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return UserInfo{}, err
	}
	if claims.Email == "" {
		return UserInfo{}, errors.New("email claim missing — request the email scope on your IdP")
	}
	name := claims.Name
	if name == "" {
		name = claims.PreferredUser
	}
	return UserInfo{
		Subject:       idToken.Subject,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		Name:          name,
		Issuer:        idToken.Issuer,
	}, nil
}

// loadConfig reads OIDC settings from the `settings` table.
func (s *Service) loadConfig(ctx context.Context) (Config, error) {
	c := Config{ProviderName: "OIDC", DefaultRole: "support", AutoProvision: false}
	if s.DB == nil {
		return c, nil
	}
	rows, err := s.DB.QueryContext(ctx,
		"SELECT `key`, value, is_encrypted FROM settings WHERE `key` LIKE 'oidc.%'")
	if err != nil {
		return c, err
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		var enc bool
		if err := rows.Scan(&k, &v, &enc); err != nil {
			continue
		}
		if enc && s.State != nil {
			if dec, derr := s.State.Decrypt(v); derr == nil {
				v = dec
			} else {
				v = ""
			}
		}
		switch k {
		case "oidc.enabled":
			c.Enabled = v == "1"
		case "oidc.provider_name":
			if v != "" {
				c.ProviderName = v
			}
		case "oidc.issuer":
			c.Issuer = v
		case "oidc.client_id":
			c.ClientID = v
		case "oidc.client_secret":
			c.ClientSecret = v
		case "oidc.redirect_url":
			c.RedirectURL = v
		case "oidc.default_role":
			if v != "" {
				c.DefaultRole = v
			}
		case "oidc.auto_provision":
			c.AutoProvision = v == "1"
		case "oidc.scopes":
			c.Scopes = v
		case "oidc.allow_unverified_email":
			c.AllowUnverifiedEmail = v == "1"
		}
	}
	// Normalize issuer: trim trailing slash variants so admin can paste
	// "https://idp/app/o/hostyt/" or without and discovery still works.
	c.Issuer = strings.TrimRight(c.Issuer, " \t\r\n")
	return c, nil
}

// resolveScopes returns the configured scope list or a sane default.
func resolveScopes(s string) []string {
	if strings.TrimSpace(s) == "" {
		return []string{goOIDC.ScopeOpenID, "email", "profile"}
	}
	fields := strings.Fields(s)
	hasOpenID := false
	for _, f := range fields {
		if strings.EqualFold(f, "openid") {
			hasOpenID = true
			break
		}
	}
	if !hasOpenID {
		fields = append([]string{goOIDC.ScopeOpenID}, fields...)
	}
	return fields
}

// TestDiscovery probes the issuer's discovery + JWKS endpoints without
// performing a login. Returns the discovered endpoint URLs on success so
// the admin can sanity-check what they configured.
type DiscoveryProbe struct {
	Issuer        string `json:"issuer"`
	AuthEndpoint  string `json:"authorization_endpoint"`
	TokenEndpoint string `json:"token_endpoint"`
	JWKSURI       string `json:"jwks_uri"`
	UserInfoURL   string `json:"userinfo_endpoint,omitempty"`
}

// TestDiscovery validates the issuer URL (SSRF guard) then runs OIDC
// discovery + JWKS fetch using SafeHTTPClient. Read-only; never mutates
// the cache. Intended for the Settings → OIDC "Test discovery" button.
func (s *Service) TestDiscovery(ctx context.Context, issuer string) (DiscoveryProbe, error) {
	var p DiscoveryProbe
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return p, errors.New("issuer is empty")
	}
	u, err := url.Parse(issuer)
	if err != nil {
		return p, fmt.Errorf("issuer not a URL: %w", err)
	}
	if err := security.ValidateOutboundURL(u); err != nil {
		return p, fmt.Errorf("issuer rejected: %w", err)
	}
	dctx := goOIDC.ClientContext(ctx, security.SafeHTTPClient(10*time.Second))
	prov, err := goOIDC.NewProvider(dctx, issuer)
	if err != nil {
		return p, fmt.Errorf("discovery failed: %w", err)
	}
	var claims struct {
		Issuer        string `json:"issuer"`
		AuthEndpoint  string `json:"authorization_endpoint"`
		TokenEndpoint string `json:"token_endpoint"`
		JWKSURI       string `json:"jwks_uri"`
		UserInfoURL   string `json:"userinfo_endpoint"`
	}
	if err := prov.Claims(&claims); err != nil {
		return p, fmt.Errorf("decode discovery claims: %w", err)
	}
	p = DiscoveryProbe{
		Issuer:        claims.Issuer,
		AuthEndpoint:  claims.AuthEndpoint,
		TokenEndpoint: claims.TokenEndpoint,
		JWKSURI:       claims.JWKSURI,
		UserInfoURL:   claims.UserInfoURL,
	}
	if p.AuthEndpoint == "" || p.TokenEndpoint == "" || p.JWKSURI == "" {
		return p, errors.New("discovery missing required endpoint(s)")
	}
	return p, nil
}

// InvalidateCache clears the in-memory provider cache so the next login
// re-runs discovery. Call after Settings → OIDC save.
func (s *Service) InvalidateCache() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cacheKey = ""
	s.provider = nil
	s.oauthCfg = nil
	s.cacheTime = time.Time{}
}

func randID(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
