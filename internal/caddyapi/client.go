// Package caddyapi is a thin client for Caddy's Admin API (default :2019).
//
// We use Caddy's JSON config + Admin API (not Caddyfile) because:
//   - Adding/removing one route is a PATCH, no full reload.
//   - Atomic config swap; no template rendering on app side.
//   - Reference: https://caddyserver.com/docs/api
//
// Source of truth lives in MariaDB. This client only writes to a node.
// "Resync node" rebuilds the entire node config from DB and POSTs /load.
package caddyapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	base string
	hc   *http.Client
}

func New(adminURL string) *Client {
	return &Client{
		base: adminURL,
		hc:   &http.Client{Timeout: 10 * time.Second},
	}
}

// Load replaces the full Caddy config atomically.
// POST {base}/load with application/json body.
func (c *Client) Load(ctx context.Context, config any) error {
	body, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return c.do(ctx, http.MethodPost, "/load", bytes.NewReader(body), "application/json")
}

// PatchPath applies a partial update at a JSON config path.
// path example: "/config/apps/http/servers/srv0/routes/0"
func (c *Client) PatchPath(ctx context.Context, path string, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal patch: %w", err)
	}
	return c.do(ctx, http.MethodPatch, path, bytes.NewReader(raw), "application/json")
}

// Delete removes a node at a JSON config path.
func (c *Client) Delete(ctx context.Context, path string) error {
	return c.do(ctx, http.MethodDelete, path, nil, "")
}

// routesArrayPath is the Caddy config path to the per-node route array
// (single server "srv0", matching BuildNodeConfig).
const routesArrayPath = "/config/apps/http/servers/srv0/routes"

// idPath returns the @id alias path for a route object. caddyID must be the
// full "route_<id>" tag emitted by BuildRoute, not the bare numeric id.
func idPath(caddyID string) string { return "/id/" + caddyID }

// AddRoute appends one route object to the server's route array.
// POST /config/.../routes appends to the array (caddyserver.com/docs/api).
// Use only when the route is known absent; callers fall back to ReplaceRoute
// or a full Load.
func (c *Client) AddRoute(ctx context.Context, route any) error {
	body, err := json.Marshal(route)
	if err != nil {
		return fmt.Errorf("marshal route: %w", err)
	}
	return c.do(ctx, http.MethodPost, routesArrayPath, bytes.NewReader(body), "application/json")
}

// ReplaceRoute replaces the route tagged @id=caddyID in place.
// PATCH /id/<caddyID> replaces the existing array element, preserving its
// index (match order) - safe for subroute-wrapped handle shapes.
func (c *Client) ReplaceRoute(ctx context.Context, caddyID string, route any) error {
	body, err := json.Marshal(route)
	if err != nil {
		return fmt.Errorf("marshal route: %w", err)
	}
	return c.do(ctx, http.MethodPatch, idPath(caddyID), bytes.NewReader(body), "application/json")
}

// DeleteRoute removes the route tagged @id=caddyID. DELETE /id/<caddyID>.
// A 404 (already gone) is surfaced as an error; callers treat it as success.
func (c *Client) DeleteRoute(ctx context.Context, caddyID string) error {
	return c.do(ctx, http.MethodDelete, idPath(caddyID), nil, "")
}

// PurgeCache flushes the Souin cache on this node.
//
// Two-step strategy:
//  1. Try the Souin admin endpoint (only registers when souin.enable=true,
//     which we deliberately skip - cache-handler v0.16 panics on it).
//  2. Fall back to re-provisioning the cache app via PATCH with a unique
//     cache_name. Different config bytes → Caddy reloads cache-handler →
//     fresh in-memory store = cache effectively flushed.
//
// Returns ErrNotFound only when apps.cache isn't loaded at all.
func (c *Client) PurgeCache(ctx context.Context) error {
	for _, p := range []string{
		"/souin-api/souin/",
		"/souin-api/souin",
		"/souin-api/souin/flush",
		"/souin-api/flush",
	} {
		if err := c.do(ctx, "PURGE", p, nil, ""); err == nil {
			return nil
		} else if !strings.Contains(err.Error(), "404") {
			return err
		}
	}
	body, err := c.GetRaw(ctx, "/config/apps/cache")
	if err != nil {
		return err
	}
	if len(body) == 0 || strings.TrimSpace(string(body)) == "null" {
		return ErrNotFound
	}
	var cfg map[string]any
	if err := json.Unmarshal(body, &cfg); err != nil {
		return fmt.Errorf("cache purge fallback parse: %w", err)
	}
	// cache_name is a label header; toggling it differs the bytes and
	// forces Caddy to re-provision cache-handler (fresh store).
	cfg["cache_name"] = fmt.Sprintf("hpg-%d", time.Now().UnixNano())
	newBody, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodPatch, "/config/apps/cache", bytes.NewReader(newBody), "application/json")
}

// CacheAppLoaded reports whether the node's running config actually has
// apps.cache configured. Useful to disambiguate "cache module missing in
// Caddy build" from "config was pushed without apps.cache" - both surface
// as 404 from PurgeCache but require different operator action.
func (c *Client) CacheAppLoaded(ctx context.Context) (bool, error) {
	b, err := c.GetRaw(ctx, "/config/apps/cache")
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			return false, nil
		}
		return false, err
	}
	return len(b) > 0 && string(b) != "null\n" && string(b) != "null", nil
}

// maxAdminResponse caps the body we read back from a Caddy admin API. A
// compromised or malfunctioning node could otherwise force the panel to
// allocate arbitrary memory on every health probe or drift check
// (security review P1).
const maxAdminResponse = 32 << 20 // 32 MiB

// GetRaw fetches the JSON value at a config path.
func (c *Client) GetRaw(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("caddy GET %s: %s", path, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxAdminResponse))
}

func (c *Client) do(ctx context.Context, method, path string, body io.Reader, ct string) error {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("caddy %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		// Bound the error body too - a misbehaving node could otherwise
		// stream gigabytes of error text into every push error log.
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		return fmt.Errorf("caddy %s %s: %s: %s", method, path, resp.Status, string(msg))
	}
	return nil
}

// ErrNotFound is returned by higher-level helpers when a config node is absent.
var ErrNotFound = errors.New("caddy: config node not found")
