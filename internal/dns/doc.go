// Package dns validates customer domains before SSL issuance.
//
// Pre-flight check: customer domain MUST resolve to the configured Caddy node
// hostname or public IP. Performed before flipping a route to "active". Avoids
// burning ACME quota on misconfigured DNS.
package dns
