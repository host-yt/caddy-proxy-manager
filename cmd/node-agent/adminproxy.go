package main

// Admin proxy: the node-agent fronting this node's Caddy Admin API.
//
// Caddy's admin API has no authentication of its own, so publishing it on the
// node's WireGuard address makes "can route to <wg-ip>:2019" equivalent to root
// on that node - anything on the control-plane mesh can POST /load and replace
// every tenant's routes. That is the topology documented in
// docs/SECURITY.md#caddy-admin-api---known-limitation.
//
// With this listener the panel talks to the agent instead: Caddy binds
// 127.0.0.1 and the only writer to it is this process, which authenticates the
// caller with a per-node key issued by the panel at join time and refuses any
// request outside a small method+path allow-list.
//
// Opt-in and dormant unless both HPG_ADMIN_PROXY_LISTEN and
// HPG_ADMIN_PROXY_KEY are set, so an existing node keeps its current topology
// until the operator migrates it.

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxAdminBody bounds a proxied request body. A full /load for a large fleet is
// a few MB of JSON; 32 MiB is far above that and stops a caller pinning memory
// on the node before the allow-list has even run.
const maxAdminBody = 32 << 20

// adminProxyConfig is the listener's configuration, all from env.
type adminProxyConfig struct {
	Listen   string // HPG_ADMIN_PROXY_LISTEN, e.g. "10.66.0.2:2021"
	Key      string // HPG_ADMIN_PROXY_KEY, issued by the panel at join
	AdminURL string // HPG_CADDY_ADMIN_URL, e.g. "http://127.0.0.1:2019"
}

// enabled reports whether the operator configured the proxy.
func (c adminProxyConfig) enabled() bool { return c.Listen != "" && c.Key != "" }

// validate rejects a configuration that would be unsafe rather than starting a
// listener that only looks protected.
func (c adminProxyConfig) validate() error {
	if len(c.Key) < 32 {
		return errors.New("HPG_ADMIN_PROXY_KEY must be at least 32 characters")
	}
	host, _, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return errors.New("HPG_ADMIN_PROXY_LISTEN must be host:port")
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		// The key is the gate, but binding the whole world is never what the
		// operator meant: this belongs on the WireGuard address.
		return errors.New("HPG_ADMIN_PROXY_LISTEN must name an address (bind the WireGuard IP, not 0.0.0.0)")
	}
	u, err := url.Parse(c.AdminURL)
	if err != nil || u.Scheme != "http" || u.Host == "" {
		return errors.New("HPG_CADDY_ADMIN_URL must be an http:// URL")
	}
	return nil
}

// adminProxyAllowed reports whether a method+path pair is one the panel
// legitimately uses. Everything the control plane does goes through these:
//
//	POST   /load                     full config replace
//	GET    /config/...               read config (drift probe, presence check)
//	POST   /config/.../routes        append one route
//	PATCH  /config/...               partial update (cache app re-provision)
//	PATCH  /id/route_<n>             replace one route in place
//	DELETE /id/route_<n>             remove one route
//	POST   /souin-api/souin/...      cache purge
//
// Anything else - /stop, /adapt, arbitrary PUTs - is refused here even with a
// valid key, so a leaked key cannot stop the node or rewrite its admin config.
func adminProxyAllowed(method, path string) bool {
	if strings.Contains(path, "..") {
		return false
	}
	switch method {
	case http.MethodGet:
		return path == "/config" || strings.HasPrefix(path, "/config/") || strings.HasPrefix(path, "/id/")
	case http.MethodPost:
		return path == "/load" ||
			strings.HasPrefix(path, "/config/") ||
			strings.HasPrefix(path, "/souin-api/")
	case http.MethodPatch:
		return strings.HasPrefix(path, "/config/") || strings.HasPrefix(path, "/id/")
	case http.MethodDelete:
		return strings.HasPrefix(path, "/config/") || strings.HasPrefix(path, "/id/")
	}
	return false
}

// adminProxyHandler authenticates the caller and forwards the request to the
// node-local Caddy admin API.
func adminProxyHandler(cfg adminProxyConfig, log *slog.Logger) http.Handler {
	client := &http.Client{Timeout: 30 * time.Second}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		// Constant-time: the key is a bearer secret, so a comparison whose
		// timing depends on the prefix leaks it byte by byte.
		if subtle.ConstantTimeCompare([]byte(token), []byte(cfg.Key)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !adminProxyAllowed(r.Method, r.URL.Path) {
			log.Warn("admin proxy refused a request outside the allow-list",
				"method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxAdminBody)
		target := strings.TrimSuffix(cfg.AdminURL, "/") + r.URL.Path
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, r.Method, target, r.Body)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if ct := r.Header.Get("Content-Type"); ct != "" {
			req.Header.Set("Content-Type", ct)
		}
		resp, err := client.Do(req)
		if err != nil {
			log.Warn("admin proxy upstream failed", "method", r.Method, "path", r.URL.Path, "err", err)
			http.Error(w, "caddy unreachable", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		if ct := resp.Header.Get("Content-Type"); ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, io.LimitReader(resp.Body, maxAdminBody))
	})
}

// startAdminProxy runs the listener until ctx is done. A no-op when the proxy
// is not configured; a configuration error is fatal, because a half-configured
// proxy would leave the operator believing the admin API is authenticated.
func startAdminProxy(ctx context.Context, log *slog.Logger, cfg adminProxyConfig) (*http.Server, error) {
	if !cfg.enabled() {
		if cfg.Listen != "" || cfg.Key != "" {
			return nil, errors.New("admin proxy needs both HPG_ADMIN_PROXY_LISTEN and HPG_ADMIN_PROXY_KEY")
		}
		return nil, nil
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           adminProxyHandler(cfg, log),
		ReadHeaderTimeout: 10 * time.Second,
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return nil, err
	}
	log.Info("admin proxy listening; Caddy admin API should now bind 127.0.0.1 only",
		"listen", cfg.Listen, "upstream", cfg.AdminURL)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("admin proxy stopped", "err", err)
		}
	}()
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	return srv, nil
}
