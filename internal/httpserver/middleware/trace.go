package middleware

import (
	"net/http"

	chimw "github.com/go-chi/chi/v5/middleware"
)

// TraceID echoes the chi-generated request id into the X-Request-Id response
// header so an operator can correlate a panel action with the server logs
// (slogRequestLogger already logs the same id). Must run after chi RequestID.
func TraceID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id := chimw.GetReqID(r.Context()); id != "" {
			w.Header().Set("X-Request-Id", id)
		}
		next.ServeHTTP(w, r)
	})
}
