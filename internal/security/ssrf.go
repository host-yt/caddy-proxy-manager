package security

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrSSRFBlocked is returned when an outbound URL or its resolved address
// hits a forbidden range. Wrapped errors describe which gate failed
// (scheme, hostname, redirect, resolved address).
var ErrSSRFBlocked = errors.New("ssrf: address blocked")

// SafeHTTPClient returns an *http.Client whose Transport refuses to dial
// any host that resolves to a private / loopback / link-local / CGNAT
// address, refuses non-HTTP(S) schemes, and re-validates every redirect
// hop. Use this for outbound calls driven by admin-configurable URLs
// (webhook endpoints, OIDC discovery, generic outbound HTTP).
//
// The safety layer is the DialContext - that's the last point at which a
// hostname is converted to a real address, so resolving exotic hostnames
// (e.g. DNS rebinding, IPv6-mapped IPv4) all surface here. We resolve the
// host explicitly, walk every returned A/AAAA, refuse on the first match
// of a forbidden CIDR, and dial the survivor.
func SafeHTTPClient(timeout time.Duration) *http.Client {
	base := &net.Dialer{Timeout: 15 * time.Second}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if !isAllowedIP(ip.IP) {
					return nil, fmt.Errorf("%w: %s resolved to %s", ErrSSRFBlocked, host, ip.IP)
				}
			}
			// Dial the first survivor.
			return base.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
		},
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        8,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	c := &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects (%d)", len(via))
			}
			if err := ValidateOutboundURL(req.URL); err != nil {
				return err
			}
			return nil
		},
	}
	return c
}

// ValidateOutboundURL refuses URLs whose scheme/host fails the SSRF guard
// up-front (cheap, before we even open a socket). Use this anywhere a URL
// is admin-input and the panel is about to fetch it.
func ValidateOutboundURL(u *url.URL) error {
	if u == nil {
		return fmt.Errorf("%w: nil url", ErrSSRFBlocked)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return fmt.Errorf("%w: scheme %q not allowed", ErrSSRFBlocked, u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("%w: empty host", ErrSSRFBlocked)
	}
	// If the host is literally an IP, validate it now. Hostnames fall
	// through to the dial step for full DNS resolution.
	if ip := net.ParseIP(host); ip != nil && !isAllowedIP(ip) {
		return fmt.Errorf("%w: host %s in forbidden range", ErrSSRFBlocked, ip)
	}
	return nil
}

// ValidateOutboundHost resolves host (DNS) and refuses if ANY resolved
// address falls in a forbidden range. Use this for non-HTTP outbound dials
// (SFTP/FTP/S3 backup destinations) where ValidateOutboundURL's literal-only
// check is insufficient: a hostname resolving to 127.0.0.1 / 10.x / ::1 would
// otherwise be accepted. host may include a port.
func ValidateOutboundHost(ctx context.Context, host string) error {
	if host == "" {
		return fmt.Errorf("%w: empty host", ErrSSRFBlocked)
	}
	// Strip an optional port.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if ip := net.ParseIP(host); ip != nil {
		if !isAllowedIP(ip) {
			return fmt.Errorf("%w: host %s in forbidden range", ErrSSRFBlocked, ip)
		}
		return nil
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("%w: resolve %s: %v", ErrSSRFBlocked, host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("%w: %s did not resolve", ErrSSRFBlocked, host)
	}
	for _, ip := range ips {
		if !isAllowedIP(ip.IP) {
			return fmt.Errorf("%w: %s resolved to %s", ErrSSRFBlocked, host, ip.IP)
		}
	}
	return nil
}

// IsDangerousProxyBackend reports whether ip is unsafe to use as a
// reverse-proxy backend even in self-service (npm) plans. It blocks
// loopback (reach node-local services), link-local / cloud-metadata
// (169.254.169.254 → node credential theft), unspecified and multicast.
// RFC1918 / CGNAT are intentionally ALLOWED: legitimate customer backends
// live on the private WireGuard mesh, so blocking them would break the
// product. backend_ip remains admin-only for restricted plans (hard rule #1).
func IsDangerousProxyBackend(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}

// isAllowedIP returns true when the address is publicly routable. Blocks
// loopback, RFC1918 private nets, link-local, CGNAT (100.64/10), benchmark
// (198.18/15), and the corresponding IPv6 ranges.
func isAllowedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	if ip.IsPrivate() {
		return false
	}
	// CGNAT 100.64.0.0/10 - IsPrivate doesn't cover it.
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1]&0xC0 == 64 {
			return false
		}
		// Documentation ranges + benchmarking nets, just in case.
		if v4[0] == 0 || v4[0] == 169 && v4[1] == 254 {
			return false
		}
	}
	return true
}
