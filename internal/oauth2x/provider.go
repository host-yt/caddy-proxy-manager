// Package oauth2x adds plain-OAuth2 social login (GitHub, Google) that runs
// ALONGSIDE the OIDC flow. Each provider resolves a stable subject + a
// verified email, which the auth handlers feed into the SAME hardened
// SaveIdentity / link path used by OIDC. This package does only the
// provider-specific bits: config load, auth URL, code exchange, userinfo.
package oauth2x

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"

	"github.com/host-yt/caddy-proxy-manager/internal/installstate"
	"github.com/host-yt/caddy-proxy-manager/internal/security"
)

// Supported provider slugs. Keep in sync with the UI + router param check.
const (
	ProviderGitHub = "github"
	ProviderGoogle = "google"
)

// IsSupported reports whether slug is a provider this package can drive.
func IsSupported(slug string) bool {
	return slug == ProviderGitHub || slug == ProviderGoogle
}

// Config is one row of oauth_providers with the secret already decrypted.
type Config struct {
	Provider      string
	Enabled       bool
	ClientID      string
	ClientSecret  string // decrypted; never logged
	Scopes        string // space-separated extra scopes
	AutoProvision bool
	DefaultRole   string
}

// UserInfo is the normalized identity we hand back to the auth layer. Subject
// is provider-stable (GitHub numeric id, Google `sub`), NOT the email, so a
// later email change does not orphan the linked identity.
type UserInfo struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
}

// Service loads per-provider config from the DB and runs the OAuth2 dance.
// Stateless beyond DB+crypto handles, so it is safe to share.
type Service struct {
	DB    func() *sql.DB
	State *installstate.Manager
}

// httpTimeout bounds each outbound call (token + userinfo). SafeHTTPClient
// also enforces the SSRF guard on every hop.
const httpTimeout = 10 * time.Second

// LoadConfig reads one provider's row and decrypts the client secret. Returns
// a zero-value (disabled) Config with no error when the row is absent so the
// login page can simply not render the button.
func (s *Service) LoadConfig(ctx context.Context, provider string) (Config, error) {
	c := Config{Provider: provider, DefaultRole: "support"}
	if !IsSupported(provider) {
		return c, fmt.Errorf("unsupported provider %q", provider)
	}
	db := s.dbOrNil()
	if db == nil {
		return c, errors.New("db not ready")
	}
	var (
		enabled    bool
		clientID   string
		secret     sql.NullString
		isEnc      bool
		scopes     string
		autoProv   bool
		defaultRol string
	)
	err := db.QueryRowContext(ctx,
		"SELECT enabled, client_id, client_secret, is_encrypted, scopes, auto_provision, default_role "+
			"FROM oauth_providers WHERE provider = ? LIMIT 1", provider,
	).Scan(&enabled, &clientID, &secret, &isEnc, &scopes, &autoProv, &defaultRol)
	if errors.Is(err, sql.ErrNoRows) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	c.Enabled = enabled
	c.ClientID = clientID
	c.Scopes = scopes
	c.AutoProvision = autoProv
	if defaultRol != "" {
		c.DefaultRole = defaultRol
	}
	if secret.Valid && secret.String != "" {
		if isEnc && s.State != nil {
			// Fail closed: a secret we cannot decrypt must NOT silently become
			// an empty secret that then sails through to a public-client token
			// exchange. Surface the error so the caller aborts.
			pt, derr := s.State.Decrypt(secret.String)
			if derr != nil {
				return c, fmt.Errorf("decrypt %s client_secret: %w", provider, derr)
			}
			c.ClientSecret = pt
		} else {
			c.ClientSecret = secret.String
		}
	}
	return c, nil
}

// Enabled is a cheap check used by the login page / account view to decide
// whether to render a provider button. Never returns an error.
func (s *Service) Enabled(ctx context.Context, provider string) bool {
	db := s.dbOrNil()
	if db == nil || !IsSupported(provider) {
		return false
	}
	var enabled bool
	var clientID string
	_ = db.QueryRowContext(ctx,
		"SELECT enabled, client_id FROM oauth_providers WHERE provider = ? LIMIT 1", provider,
	).Scan(&enabled, &clientID)
	return enabled && clientID != ""
}

// oauthConfig builds the *oauth2.Config for a ready provider. redirectURL is
// the panel callback the IdP will redirect back to.
func (c Config) oauthConfig(redirectURL string) (*oauth2.Config, error) {
	if !c.Enabled {
		return nil, fmt.Errorf("%s login is disabled", c.Provider)
	}
	if c.ClientID == "" || c.ClientSecret == "" {
		return nil, fmt.Errorf("%s login not configured", c.Provider)
	}
	oc := &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURL:  redirectURL,
		Scopes:       c.resolvedScopes(),
	}
	switch c.Provider {
	case ProviderGitHub:
		oc.Endpoint = github.Endpoint
	case ProviderGoogle:
		oc.Endpoint = google.Endpoint
	default:
		return nil, fmt.Errorf("unsupported provider %q", c.Provider)
	}
	return oc, nil
}

// resolvedScopes returns the request scopes: a per-provider default plus any
// admin-configured extras. We always ask for the email scope - the whole
// account-link model depends on a verified email.
func (c Config) resolvedScopes() []string {
	var base []string
	switch c.Provider {
	case ProviderGitHub:
		base = []string{"read:user", "user:email"}
	case ProviderGoogle:
		base = []string{"openid", "email", "profile"}
	}
	for _, f := range strings.Fields(c.Scopes) {
		dup := false
		for _, b := range base {
			if strings.EqualFold(b, f) {
				dup = true
				break
			}
		}
		if !dup {
			base = append(base, f)
		}
	}
	return base
}

// AuthURL returns the provider authorization URL for the given state. PKCE
// (S256) is always used per RFC 9700. verifier must be stored by the caller
// (Redis ticket) and passed back to Exchange.
func (s *Service) AuthURL(ctx context.Context, provider, redirectURL, state string) (authURL, verifier string, err error) {
	cfg, err := s.LoadConfig(ctx, provider)
	if err != nil {
		return "", "", err
	}
	oc, err := cfg.oauthConfig(redirectURL)
	if err != nil {
		return "", "", err
	}
	verifier = oauth2.GenerateVerifier()
	opts := []oauth2.AuthCodeOption{
		oauth2.AccessTypeOnline,
		oauth2.S256ChallengeOption(verifier),
	}
	return oc.AuthCodeURL(state, opts...), verifier, nil
}

// Exchange swaps the auth code for a token then fetches the provider's
// userinfo. All outbound calls go through SafeHTTPClient (SSRF guard).
func (s *Service) Exchange(ctx context.Context, provider, redirectURL, code, verifier string) (UserInfo, error) {
	cfg, err := s.LoadConfig(ctx, provider)
	if err != nil {
		return UserInfo{}, err
	}
	oc, err := cfg.oauthConfig(redirectURL)
	if err != nil {
		return UserInfo{}, err
	}
	httpCtx := context.WithValue(ctx, oauth2.HTTPClient, security.SafeHTTPClient(httpTimeout))
	var opts []oauth2.AuthCodeOption
	if verifier != "" {
		opts = append(opts, oauth2.VerifierOption(verifier))
	}
	tok, err := oc.Exchange(httpCtx, code, opts...)
	if err != nil {
		return UserInfo{}, fmt.Errorf("oauth exchange: %w", err)
	}
	if !tok.Valid() {
		return UserInfo{}, errors.New("oauth token invalid")
	}
	client := oc.Client(httpCtx, tok)
	switch provider {
	case ProviderGitHub:
		return fetchGitHub(httpCtx, client)
	case ProviderGoogle:
		return fetchGoogle(httpCtx, client)
	default:
		return UserInfo{}, fmt.Errorf("unsupported provider %q", provider)
	}
}

// userinfo response size cap: a userinfo body should be small; this stops a
// hostile/compromised endpoint from streaming gigabytes into memory.
const maxUserInfoBytes = 1 << 20 // 1 MiB

func fetchGoogle(ctx context.Context, client *http.Client) (UserInfo, error) {
	body, err := getJSON(ctx, client, "https://openidconnect.googleapis.com/v1/userinfo")
	if err != nil {
		return UserInfo{}, err
	}
	var u struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := json.Unmarshal(body, &u); err != nil {
		return UserInfo{}, fmt.Errorf("google userinfo decode: %w", err)
	}
	if u.Sub == "" {
		return UserInfo{}, errors.New("google userinfo missing sub")
	}
	return UserInfo{
		Subject:       u.Sub,
		Email:         strings.TrimSpace(u.Email),
		EmailVerified: u.EmailVerified,
		Name:          u.Name,
	}, nil
}

func fetchGitHub(ctx context.Context, client *http.Client) (UserInfo, error) {
	// Primary profile: stable numeric id is the subject.
	body, err := getJSON(ctx, client, "https://api.github.com/user")
	if err != nil {
		return UserInfo{}, err
	}
	var prof struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal(body, &prof); err != nil {
		return UserInfo{}, fmt.Errorf("github user decode: %w", err)
	}
	if prof.ID == 0 {
		return UserInfo{}, errors.New("github user missing id")
	}
	info := UserInfo{
		Subject: strconv.FormatInt(prof.ID, 10),
		Name:    prof.Name,
	}
	if info.Name == "" {
		info.Name = prof.Login
	}
	// GitHub only emits a verified primary email via /user/emails. The profile
	// `email` field is whatever the user set public and is NOT trustworthy for
	// account matching, so pick the verified primary explicitly.
	emailsBody, eerr := getJSON(ctx, client, "https://api.github.com/user/emails")
	if eerr == nil {
		var emails []struct {
			Email    string `json:"email"`
			Primary  bool   `json:"primary"`
			Verified bool   `json:"verified"`
		}
		if json.Unmarshal(emailsBody, &emails) == nil {
			for _, e := range emails {
				if e.Primary && e.Verified {
					info.Email = strings.TrimSpace(e.Email)
					info.EmailVerified = true
					break
				}
			}
			// Fall back to any verified email when no primary is flagged.
			if info.Email == "" {
				for _, e := range emails {
					if e.Verified {
						info.Email = strings.TrimSpace(e.Email)
						info.EmailVerified = true
						break
					}
				}
			}
		}
	}
	return info, nil
}

// getJSON performs a GET and returns the (size-capped) body. Sets a JSON
// Accept header; GitHub wants its v3 media type.
func getJSON(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json, application/json")
	req.Header.Set("User-Agent", "hostyt-proxy-gateway")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Drain a little so the message is useful but bounded; never include tokens.
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, fmt.Errorf("userinfo HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxUserInfoBytes))
}

func (s *Service) dbOrNil() *sql.DB {
	if s == nil || s.DB == nil {
		return nil
	}
	return s.DB()
}
