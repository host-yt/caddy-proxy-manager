package backup

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/security"
)

// insecureTransportAllowed reports whether insecure backup transport opt-outs
// (plaintext FTP, skip_verify, insecure_host_key) may be honoured. Unset/empty
// APP_ENV must deny, same as internal/config's envOr("APP_ENV","production").
func insecureTransportAllowed() bool {
	env := os.Getenv("APP_ENV")
	if env == "" {
		env = "production"
	}
	return env != "production"
}

// validateDestHost rejects backup destination hostnames that resolve into
// SSRF-sensitive ranges (loopback, RFC1918, link-local, CGNAT). Admin is
// trusted but the Test/Save flow gives any admin-controlled string a
// straight path into outbound connect — block by default, force them to
// add an explicit allowlist if they really need a private destination.
//
// Unlike the HTTP path, SFTP/FTP/S3 dial with a plain net.Dialer (no
// SafeHTTPClient), so we must resolve the name HERE and check every resolved
// IP - a hostname pointing at 127.0.0.1 / 10.x would otherwise slip through.
func validateDestHost(host string) error {
	if host == "" {
		return fmt.Errorf("empty host")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return security.ValidateOutboundHost(ctx, host)
}

// pinnedDialContext resolves host once, validates the resolved address with
// the same check validateDestHost used at config-save time, then dials that
// exact address. Closes the DNS-rebinding gap between the SSRF check and the
// actual connect (a re-resolve mid-flight could otherwise land on a private
// IP). Shared by S3 (http.Transport.DialContext) and, via closures, SFTP/FTP.
func pinnedDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	pinned, err := pinnedAddr(ctx, addr)
	if err != nil {
		return nil, err
	}
	d := &net.Dialer{Timeout: 15 * time.Second}
	return d.DialContext(ctx, network, pinned)
}

// pinnedAddr resolves addr once and returns host:port with the literal IP, so
// the caller dials exactly what was validated. Use this instead of overriding a
// library's dialer when that library wraps the connection (e.g. FTPS TLS).
func pinnedAddr(ctx context.Context, addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return "", err
		}
		if len(ips) == 0 {
			return "", fmt.Errorf("pinned dial: %s did not resolve", host)
		}
		ip = ips[0].IP
	}
	if err := validateDestHost(ip.String()); err != nil {
		return "", fmt.Errorf("pinned dial: %w", err)
	}
	return net.JoinHostPort(ip.String(), port), nil
}

// Uploader is the destination-side write interface backups speak.
// Implementations must:
//   - Upload(): create or overwrite `key` with the given body. Total body
//     length is `size` bytes (may be -1 if unknown). `body` is seekable if
//     the implementation needs to retry.
//   - Delete(): remove `key` if present; nil if absent.
type Uploader interface {
	Upload(ctx context.Context, key string, body io.Reader, size int64) error
	Delete(ctx context.Context, key string) error
}

// newDestination returns an Uploader for a configured Destination. Each
// implementation reads its own subset of d.Config (documented per kind).
func newDestination(d Destination) (Uploader, error) {
	switch d.Kind {
	case KindSFTP:
		return newSFTPDest(d.Config)
	case KindFTP:
		return newFTPDest(d.Config)
	case KindS3:
		return newS3Dest(d.Config)
	case KindLocal:
		return newLocalDest(d.Config)
	}
	return nil, fmt.Errorf("unknown destination kind: %s", d.Kind)
}
