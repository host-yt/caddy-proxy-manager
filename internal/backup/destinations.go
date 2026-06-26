package backup

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/security"
)

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
