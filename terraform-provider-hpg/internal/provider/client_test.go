package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestClientCRUD exercises the REST client against a stub server: auth header,
// /api/v1 prefixing, JSON round-trip, and 404 -> IsNotFound mapping.
func TestClientCRUD(t *testing.T) {
	var gotAuth, gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotMethod = r.Method
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/plans":
			json.NewEncoder(w).Encode(map[string]any{"id": 42})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/plans/42":
			json.NewEncoder(w).Encode(map[string]any{"id": 42, "name": "pro"})
		case r.URL.Path == "/api/v1/plans/999":
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"not found"}`))
		default:
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"bad"}`))
		}
	}))
	defer srv.Close()

	c := NewClient(srv.URL+"/", "hpg_test_key") // trailing slash must be trimmed
	ctx := context.Background()

	var created struct {
		ID int64 `json:"id"`
	}
	if err := c.Post(ctx, "/plans", map[string]any{"name": "pro"}, &created); err != nil {
		t.Fatalf("post: %v", err)
	}
	if created.ID != 42 {
		t.Fatalf("post id = %d, want 42", created.ID)
	}
	if gotAuth != "Bearer hpg_test_key" {
		t.Fatalf("auth header = %q", gotAuth)
	}
	if gotMethod != http.MethodPost || gotPath != "/api/v1/plans" {
		t.Fatalf("post routed to %s %s", gotMethod, gotPath)
	}

	var got struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
	}
	if err := c.Get(ctx, "/plans/42", &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "pro" {
		t.Fatalf("get name = %q", got.Name)
	}

	// 404 must map to IsNotFound.
	err := c.Get(ctx, "/plans/999", &got)
	if err == nil || !IsNotFound(err) {
		t.Fatalf("expected IsNotFound, got %v", err)
	}
	// Non-404 error surfaces the status + body.
	if err := c.Delete(ctx, "/plans/1"); err == nil || IsNotFound(err) {
		t.Fatalf("expected non-404 error, got %v", err)
	}
}
