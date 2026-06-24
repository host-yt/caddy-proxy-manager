package caddyapi

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// captures the method+path+body of the last request the client made.
type capture struct {
	method string
	path   string
	body   string
}

func newCapturingNode(t *testing.T, status int) (*Client, *capture) {
	t.Helper()
	cap := &capture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap.method = r.Method
		cap.path = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		cap.body = string(b)
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return New(srv.URL), cap
}

func TestAddRoutePostsToArray(t *testing.T) {
	c, cap := newCapturingNode(t, 200)
	if err := c.AddRoute(context.Background(), map[string]any{"@id": "route_7"}); err != nil {
		t.Fatalf("AddRoute: %v", err)
	}
	if cap.method != http.MethodPost {
		t.Errorf("method = %s, want POST", cap.method)
	}
	if cap.path != "/config/apps/http/servers/srv0/routes" {
		t.Errorf("path = %s, want routes array", cap.path)
	}
	if !strings.Contains(cap.body, `"@id":"route_7"`) {
		t.Errorf("body missing route object: %s", cap.body)
	}
}

func TestReplaceRoutePatchesById(t *testing.T) {
	c, cap := newCapturingNode(t, 200)
	if err := c.ReplaceRoute(context.Background(), "route_7", map[string]any{"@id": "route_7"}); err != nil {
		t.Fatalf("ReplaceRoute: %v", err)
	}
	if cap.method != http.MethodPatch {
		t.Errorf("method = %s, want PATCH", cap.method)
	}
	if cap.path != "/id/route_7" {
		t.Errorf("path = %s, want /id/route_7", cap.path)
	}
}

func TestDeleteRouteByeId(t *testing.T) {
	c, cap := newCapturingNode(t, 200)
	if err := c.DeleteRoute(context.Background(), "route_7"); err != nil {
		t.Fatalf("DeleteRoute: %v", err)
	}
	if cap.method != http.MethodDelete {
		t.Errorf("method = %s, want DELETE", cap.method)
	}
	if cap.path != "/id/route_7" {
		t.Errorf("path = %s, want /id/route_7", cap.path)
	}
}

func TestRouteOpsSurfaceErrors(t *testing.T) {
	c, _ := newCapturingNode(t, 500)
	if err := c.AddRoute(context.Background(), map[string]any{}); err == nil {
		t.Error("AddRoute: want error on 500")
	}
	if err := c.ReplaceRoute(context.Background(), "route_1", map[string]any{}); err == nil {
		t.Error("ReplaceRoute: want error on 500")
	}
}

func TestDeleteRoute404IsDetectable(t *testing.T) {
	c, _ := newCapturingNode(t, 404)
	err := c.DeleteRoute(context.Background(), "route_gone")
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("want a 404-containing error so callers treat it as success, got %v", err)
	}
}
