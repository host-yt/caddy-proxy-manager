package httpserver

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// SSE endpoints must not inherit the request deadline: clearing the write
// deadline is not enough when r.Context() itself expires (#51).
func TestRequestTimeoutSkipsStreams(t *testing.T) {
	cases := map[string]bool{
		"/admin/hosts/7/logs/stream":        false,
		"/admin/ai/chat/sessions/3/message": false,
		"/app/ai/chat/sessions/3/message":   false,
		"/admin/hosts/7/logs":               true,
		"/app/routes":                       true,
		"/admin/hosts/7/x/logs/stream":      true,
	}
	for p, wantDeadline := range cases {
		var got bool
		h := requestTimeout(time.Minute)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			_, got = r.Context().Deadline()
		}))
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, p, nil))
		if got != wantDeadline {
			t.Errorf("%s: deadline=%v, want %v", p, got, wantDeadline)
		}
	}
}
