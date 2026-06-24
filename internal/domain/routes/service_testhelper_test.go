package routes

import (
	"fmt"

	"github.com/hostyt/proxy-gateway/internal/caddyapi"
)

// hashRoutesViaCaddy is a test-only bridge that lets the table-driven hash
// stability test exercise hashRoutes without importing caddyapi from the
// test file (keeps that file lean).
func hashRoutesViaCaddy(fs []routeFixture) string {
	out := make([]caddyapi.Route, 0, len(fs))
	for _, f := range fs {
		out = append(out, caddyapi.Route{
			ID:           fmt.Sprintf("%d", f.ID),
			Hosts:        []string{f.Host},
			PathPrefix:   f.Path,
			UpstreamIP:   "10.0.0.1",
			UpstreamPort: f.Port,
		})
	}
	return hashRoutes(out)
}
