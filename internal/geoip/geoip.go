// Package geoip holds helpers for per-route GeoIP country matching + blocking.
//
// The MaxMind GeoLite2-Country DB is expected at /data/geoip/GeoLite2-Country.mmdb
// on every Caddy node, provisioned out of band (mounted/refreshed by the deploy
// path), exactly like the WAF/CRS ruleset. The panel only emits the geo matcher
// when GEOIP_AVAILABLE=1, i.e. once every node runs the custom Caddy image with
// the caddy-maxmind-geolocation module AND has that DB file present.
package geoip

import (
	"sort"
	"strings"
)

// DBPath is where the GeoLite2-Country mmdb lives on each node (provisioned out
// of band). Kept here so the builder and deploy path agree on one location.
const DBPath = "/data/geoip/GeoLite2-Country.mmdb"

// ASNDBPath is where the GeoLite2-ASN mmdb lives on each node.
const ASNDBPath = "/data/geoip/GeoLite2-ASN.mmdb"

// NormalizeCountries sanitizes a raw user list of country codes into a canonical
// "PL,DE,US" form: uppercased, trimmed, de-duped, sorted, keeping only valid
// ISO 3166-1 alpha-2 tokens (exactly two A-Z letters). Junk tokens are dropped.
func NormalizeCountries(raw string) string {
	seen := make(map[string]struct{})
	var out []string
	for _, tok := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';' || r == '\t' || r == '\n'
	}) {
		code := strings.ToUpper(strings.TrimSpace(tok))
		if !isAlpha2(code) {
			continue
		}
		if _, dup := seen[code]; dup {
			continue
		}
		seen[code] = struct{}{}
		out = append(out, code)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// isAlpha2 reports whether s is exactly two ASCII A-Z letters.
func isAlpha2(s string) bool {
	if len(s) != 2 {
		return false
	}
	for i := 0; i < 2; i++ {
		if s[i] < 'A' || s[i] > 'Z' {
			return false
		}
	}
	return true
}
