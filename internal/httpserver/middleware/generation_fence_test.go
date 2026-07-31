package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"sync/atomic"
	"testing"
)

// TestGenerationFenceCutsOffKeepAliveConnections is the point of enforcing the
// fence in the request path: readiness alone leaves an already-open connection
// authenticating against this more permissive binary until an external
// controller finishes draining it.
func TestGenerationFenceCutsOffKeepAliveConnections(t *testing.T) {
	var fenced atomic.Bool
	srv := httptest.NewServer(GenerationFence(fenced.Load)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "served")
	})))
	defer srv.Close()

	client := &http.Client{}
	do := func(path string) (*http.Response, bool) {
		t.Helper()
		var reused bool
		req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
			GotConn: func(i httptrace.GotConnInfo) { reused = i.Reused },
		}))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %s: %v", path, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp, reused
	}

	resp, _ := do("/admin/hosts")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pre-rollout status = %d, want 200", resp.StatusCode)
	}

	// A newer generation appears mid-connection.
	fenced.Store(true)
	resp, reused := do("/admin/hosts")
	if !reused {
		t.Fatal("precondition: second request should ride the pre-existing connection")
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("fenced status = %d, want 503", resp.StatusCode)
	}
	if !resp.Close {
		t.Fatal("fenced response must close the keep-alive connection")
	}

	// A fresh connection is fenced too.
	if resp, _ := do("/admin/hosts"); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("new-connection status = %d, want 503", resp.StatusCode)
	}
	// Probes stay reachable so the orchestrator can still see the drain.
	if resp, _ := do("/readyz"); resp.StatusCode != http.StatusOK {
		t.Fatalf("/readyz status = %d, want 200 (exempt)", resp.StatusCode)
	}
}

func TestGenerationFenceNoopWhenUnset(t *testing.T) {
	rr := httptest.NewRecorder()
	GenerationFence(nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin", nil))
	if rr.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want 418", rr.Code)
	}
}
