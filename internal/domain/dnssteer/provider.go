// Package dnssteer keeps public DNS A/AAAA records for active_active route
// groups in sync with live node health, so a dead node's IP stops being
// served without waiting on a manual DNS edit.
package dnssteer

import (
	"context"
	"errors"
	"time"
)

// Record is a minimal DNS record. Unlike libdns.Record, Name is the full
// FQDN rather than zone-relative - this package doesn't depend on libdns
// (see NewProvider), so there's no zone-relative convention to match.
type Record struct {
	ID    string // provider-assigned ID; empty until returned by GetRecords/AppendRecords
	Type  string // "A" or "AAAA"
	Name  string // full FQDN, e.g. "app.customer.com"
	Value string // IPv4/IPv6 literal
	TTL   time.Duration
}

// Provider manages A/AAAA records for one DNS zone. Method shapes mirror
// libdns's RecordGetter/RecordAppender/RecordDeleter split so a real vendored
// libdns provider could be adapted in later behind a thin wrapper.
type Provider interface {
	GetRecords(ctx context.Context, zone string) ([]Record, error)
	AppendRecords(ctx context.Context, zone string, recs []Record) ([]Record, error)
	DeleteRecords(ctx context.Context, zone string, recs []Record) ([]Record, error)
}

// ErrUnsupportedProvider is returned by NewProvider for a registry slug with
// no direct-API implementation here. Every other slug's credentials are only
// ever fed into Caddy's own DNS-01 JSON (see internal/caddyapi/dnsproviders.go);
// no libdns/<provider> package is vendored in go.mod for this module to call
// directly, and adding one per provider is out of scope for this change.
var ErrUnsupportedProvider = errors.New("dnssteer: provider not wired for direct API calls")

// NewProvider builds a Provider for a registry slug (see caddyapi.DNSProvider)
// plus its decrypted credential fields (same map shape caddyapi.DecodeDNSFields
// returns). Only Cloudflare talks to a real API today.
func NewProvider(slug string, fields map[string]string) (Provider, error) {
	switch slug {
	case "cloudflare":
		return newCloudflareProvider(fields)
	default:
		return nil, ErrUnsupportedProvider
	}
}
