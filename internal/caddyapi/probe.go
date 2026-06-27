package caddyapi

import (
	"context"
	"strings"
)

// Capabilities holds the detected Caddy module feature flags for a node.
type Capabilities struct {
	HasWAF      bool
	HasL4       bool
	HasDNS      bool
	HasRateLimit bool
	HasGeoIP    bool
}

// ProbeCapabilities fetches the module list and maps it to Capabilities.
func ProbeCapabilities(ctx context.Context, c *Client) (Capabilities, error) {
	modules, err := c.ListModules(ctx)
	if err != nil {
		return Capabilities{}, err
	}
	var caps Capabilities
	for _, m := range modules {
		switch {
		case strings.Contains(m, "waf") || strings.Contains(m, "coraza"):
			caps.HasWAF = true
		case strings.Contains(m, "layer4"):
			caps.HasL4 = true
		case strings.Contains(m, "dns.") || strings.Contains(m, "caddy.dns"):
			caps.HasDNS = true
		case strings.Contains(m, "rate_limit"):
			caps.HasRateLimit = true
		case strings.Contains(m, "geoip") || strings.Contains(m, "maxmind"):
			caps.HasGeoIP = true
		}
	}
	return caps, nil
}
