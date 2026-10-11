package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
	mw "github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

// Node tokens are header-only; documenting a query form leaks them into logs.
func TestAPIDocsNoQueryNodeToken(t *testing.T) {
	if strings.Contains(string(openapiSpec), "node_token") {
		t.Error("openapi.json still documents a node_token query parameter")
	}
}

// encoding/json keeps the last of duplicate keys, so a repeated path silently
// drops operations (POST /api/v1/services did). Walk the raw tokens instead.
func TestAPIDocsNoDuplicateKeys(t *testing.T) {
	dec := json.NewDecoder(bytes.NewReader(openapiSpec))
	var walk func(path string)
	walk = func(path string) {
		tok, err := dec.Token()
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		switch tok {
		case json.Delim('{'):
			seen := map[string]bool{}
			for dec.More() {
				k, _ := dec.Token()
				key := k.(string)
				if seen[key] {
					t.Errorf("duplicate key %s/%s", path, key)
				}
				seen[key] = true
				walk(path + "/" + key)
			}
			_, _ = dec.Token()
		case json.Delim('['):
			for dec.More() {
				walk(path + "[]")
			}
			_, _ = dec.Token()
		}
	}
	walk("")

	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(openapiSpec, &doc); err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{"get", "post"} {
		if _, ok := doc.Paths["/api/v1/services"][m]; !ok {
			t.Errorf("/api/v1/services lost %s", m)
		}
	}
}

// specPaths runs Spec for a given session and returns the path set + server URL.
func specPaths(t *testing.T, sess *auth.Session) (map[string]bool, string) {
	t.Helper()
	hh := &APIDocsHandler{DB: func() *sql.DB { return nil }} // nil DB -> public docs
	req := httptest.NewRequest("GET", "http://panel.test/api-docs/openapi.json", nil)
	if sess != nil {
		req = req.WithContext(mw.ContextWithSession(req.Context(), sess))
	}
	rec := httptest.NewRecorder()
	hh.Spec(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	var doc struct {
		Servers []struct {
			URL string `json:"url"`
		} `json:"servers"`
		Paths map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	set := map[string]bool{}
	for p := range doc.Paths {
		set[p] = true
	}
	url := ""
	if len(doc.Servers) > 0 {
		url = doc.Servers[0].URL
	}
	return set, url
}

func TestAPIDocsAudienceFilter(t *testing.T) {
	// Server URL follows the browsed host, not the hardcoded example.
	pub, url := specPaths(t, nil)
	if url != "http://panel.test" {
		t.Errorf("server url = %q, want http://panel.test", url)
	}
	// Unauth: only public paths.
	if !pub["/api/v1/health"] || !pub["/api/wg/bootstrap"] {
		t.Error("public docs must include health + wg bootstrap")
	}
	for _, p := range []string{"/api/v1/services", "/api/v1/clients", "/api/v1/resellers", "/api/node/waf/events"} {
		if pub[p] {
			t.Errorf("unauth must NOT see %s", p)
		}
	}

	// Client: public + services/routes, nothing admin.
	cli, _ := specPaths(t, &auth.Session{Role: "client"})
	if !cli["/api/v1/services"] || !cli["/api/v1/routes"] {
		t.Error("client must see services + routes")
	}
	for _, p := range []string{"/api/v1/clients", "/api/v1/nodes", "/api/v1/resellers", "/api/node/geoip/mmdb"} {
		if cli[p] {
			t.Errorf("client must NOT see %s", p)
		}
	}

	// Reseller-admin: admin scope but not platform / node.
	res, _ := specPaths(t, &auth.Session{Role: "admin", ResellerID: 9})
	if !res["/api/v1/clients"] || !res["/api/v1/nodes"] || !res["/api/v1/services"] {
		t.Error("reseller-admin must see clients + nodes + services")
	}
	for _, p := range []string{"/api/v1/resellers", "/api/v1/provisioning/client", "/api/node/waf/events"} {
		if res[p] {
			t.Errorf("reseller-admin must NOT see %s", p)
		}
	}

	// Platform admin: everything.
	plat, _ := specPaths(t, &auth.Session{Role: "super_admin", ResellerID: 0})
	for _, p := range []string{"/api/v1/resellers", "/api/v1/reseller-plans", "/api/v1/provisioning/client", "/api/node/waf/events", "/api/v1/clients", "/api/v1/services"} {
		if !plat[p] {
			t.Errorf("platform admin must see %s", p)
		}
	}
}
