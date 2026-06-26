// Package cloudflare wraps Cloudflare-specific settings:
//   - API token (saved in `settings`, encrypted; future DNS automation)
//   - account_id
//   - whether to trust the CF-Connecting-IP header
//
// The package keeps a runtime cache that the admin Settings page
// invalidates via Refresh on save.
package cloudflare

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/installstate"
)

type Config struct {
	Enabled           bool
	APIToken          string // decrypted
	AccountID         string
	TrustConnectingIP bool
}

type Service struct {
	DB    func() *sql.DB
	State *installstate.Manager

	hc *http.Client

	mu  sync.RWMutex
	cfg Config
	at  time.Time
}

func New(db func() *sql.DB, state *installstate.Manager) *Service {
	return &Service{
		DB:    db,
		State: state,
		hc:    &http.Client{Timeout: 8 * time.Second},
	}
}

// Get returns a cached copy of the config (auto-refreshing every 30 s).
func (s *Service) Get() Config {
	s.maybeRefresh()
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

// TrustConnectingIP is a shortcut for middlewares.
func (s *Service) TrustConnectingIP() bool { return s.Get().TrustConnectingIP }

// Refresh forces a reload from the settings table.
func (s *Service) Refresh(ctx context.Context) {
	db := s.DB()
	if db == nil {
		return
	}
	rows, err := db.QueryContext(ctx,
		"SELECT `key`, value, is_encrypted FROM settings WHERE `key` LIKE 'cloudflare.%'")
	if err != nil {
		return
	}
	defer rows.Close()
	var c Config
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
		case "cloudflare.enabled":
			c.Enabled = v == "1"
		case "cloudflare.api_token":
			c.APIToken = v
		case "cloudflare.account_id":
			c.AccountID = v
		case "cloudflare.trust_connecting_ip":
			c.TrustConnectingIP = v == "1"
		}
	}
	s.mu.Lock()
	s.cfg = c
	s.at = time.Now()
	s.mu.Unlock()
}

func (s *Service) maybeRefresh() {
	s.mu.RLock()
	stale := time.Since(s.at) > 30*time.Second
	s.mu.RUnlock()
	if stale {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		s.Refresh(ctx)
	}
}

// VerifyToken pings /user/tokens/verify to confirm the saved API token
// is valid. Used by the Settings UI on save.
func (s *Service) VerifyToken(ctx context.Context, token string) error {
	if token == "" {
		return errors.New("empty token")
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.cloudflare.com/client/v4/user/tokens/verify", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := s.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var body struct {
		Success bool `json:"success"`
		Result  struct {
			Status string `json:"status"`
		} `json:"result"`
		Errors []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return err
	}
	if !body.Success {
		if len(body.Errors) > 0 {
			return errors.New(body.Errors[0].Message)
		}
		return errors.New("token verify failed")
	}
	if body.Result.Status != "active" {
		return errors.New("token status: " + body.Result.Status)
	}
	return nil
}
