package caddyapi

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

func consoleRoute() Route {
	return Route{ID: "1", Hosts: []string{"c.example"}, Kind: "proxy", External: true,
		UpstreamIP: "vps.example", UpstreamPort: 443, UpstreamScheme: "https",
		PathPrefix: "/console/tok", StripPathPrefix: true, UpstreamPathPrefix: "/kvm"}
}

// The strip must end on a segment boundary and always leave a "/" path.
func TestPathRewrite_SegmentBoundary(t *testing.T) {
	r := consoleRoute()
	m := BuildRoute(r)["match"].([]any)[0].(map[string]any)
	if got := strings.Join(m["path"].([]string), ","); got != "/console/tok,/console/tok/*" {
		t.Fatalf("matcher = %s", got)
	}
	rw := pathRewriteHandlers(r)[0].(map[string]any)["path_regexp"].([]any)[0].(map[string]any)
	re := regexp.MustCompile(rw["find"].(string))
	for in, want := range map[string]string{
		"/console/tok":     "/kvm/",
		"/console/tok/":    "/kvm/",
		"/console/tok/a/b": "/kvm/a/b",
		"/Console/TOK/a":   "/kvm/a",
		"/console/tokX/a":  "/console/tokX/a", // not stripped (and not matched)
	} {
		if got := re.ReplaceAllString(in, rw["replace"].(string)); got != want {
			t.Errorf("%s -> %s, want %s", in, got, want)
		}
	}
	r.UpstreamPathPrefix = ""
	rw = pathRewriteHandlers(r)[0].(map[string]any)["path_regexp"].([]any)[0].(map[string]any)
	if got := regexp.MustCompile(rw["find"].(string)).ReplaceAllString("/console/tok", rw["replace"].(string)); got != "/" {
		t.Errorf("bare prefix -> %q, want /", got)
	}
}

// Location rules see the client's path; only the fallback to the origin is
// rewritten. Non-external routes never carry the rewrite.
func TestPathRewrite_AfterLocationRulesExternalOnly(t *testing.T) {
	r := consoleRoute()
	r.LocationRules = []LocationRule{{Path: "/console/tok/admin", Action: "proxy", UpstreamHost: "203.0.113.9", UpstreamPort: 8443}}
	cfg := BuildRoute(r)
	var sub map[string]any
	for _, h := range cfg["handle"].([]any) {
		hm := h.(map[string]any)
		if hm["handler"] == "rewrite" {
			t.Fatal("rewrite runs before location matching")
		}
		if hm["handler"] == "subroute" {
			sub = hm
		}
	}
	if sub == nil {
		t.Fatal("no location subroute")
	}
	routes := sub["routes"].([]any)
	fb, _ := json.Marshal(routes[len(routes)-1])
	first, _ := json.Marshal(routes[0])
	if !strings.Contains(string(fb), "path_regexp") || strings.Contains(string(first), "path_regexp") {
		t.Fatalf("rewrite must sit on the fallback only:\nfirst=%s\nfallback=%s", first, fb)
	}

	r = consoleRoute()
	r.External = false
	out, _ := json.Marshal(BuildRoute(r))
	if strings.Contains(string(out), "path_regexp") || strings.Contains(string(out), "/kvm") {
		t.Fatalf("non-external route emitted the rewrite: %s", out)
	}
}
