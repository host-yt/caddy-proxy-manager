package backup

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/jlaffaye/ftp"
)

// FTP / FTPS destination.
//
// Config keys:
//
//	host           hostname (required)
//	port           default 21
//	user           username (required)
//	password       password (required)
//	tls            "explicit" | "implicit" | "" (plain — discouraged)
//	skip_verify    "1" to skip cert verification (NOT for prod)
//	path           remote base path, e.g. "/backups"
type ftpDest struct {
	addr       string
	user       string
	password   string
	tlsMode    string
	skipVerify bool
	basePath   string
}

func newFTPDest(cfg map[string]string) (*ftpDest, error) {
	host := strings.TrimSpace(cfg["host"])
	if host == "" {
		return nil, errors.New("ftp: host required")
	}
	if err := validateDestHost(host); err != nil {
		return nil, fmt.Errorf("ftp: %w", err)
	}
	port := strings.TrimSpace(cfg["port"])
	if port == "" {
		port = "21"
	}
	if _, err := strconv.Atoi(port); err != nil {
		return nil, fmt.Errorf("ftp: invalid port %q", port)
	}
	user := strings.TrimSpace(cfg["user"])
	pw := cfg["password"]
	if user == "" || pw == "" {
		return nil, errors.New("ftp: user + password required")
	}
	d := &ftpDest{
		addr:       net.JoinHostPort(host, port),
		user:       user,
		password:   pw,
		tlsMode:    strings.ToLower(strings.TrimSpace(cfg["tls"])),
		skipVerify: cfg["skip_verify"] == "1",
		basePath:   strings.TrimSpace(cfg["path"]),
	}
	if d.basePath == "" {
		d.basePath = "."
	}
	switch d.tlsMode {
	case "explicit", "implicit":
	case "":
		// Plaintext FTP puts credentials + the full backup on the wire (DB-02).
		// Require FTPS unless an explicit opt-out is set, and never in prod.
		if !(cfg["insecure_ftp"] == "1" && insecureTransportAllowed()) {
			return nil, errors.New("ftp: plaintext transport refused; use tls=explicit|implicit (or set insecure_ftp=1 outside production)")
		}
	default:
		return nil, fmt.Errorf("ftp: invalid tls=%q", d.tlsMode)
	}
	// skip_verify defeats TLS cert validation - only outside production (DB-03).
	if d.skipVerify && !insecureTransportAllowed() {
		return nil, errors.New("ftp: skip_verify not allowed in production")
	}
	return d, nil
}

func (d *ftpDest) dial(ctx context.Context) (*ftp.ServerConn, error) {
	host := strings.SplitN(d.addr, ":", 2)[0]
	var opts []ftp.DialOption
	opts = append(opts, ftp.DialWithContext(ctx))
	opts = append(opts, ftp.DialWithTimeout(20*time.Second))
	if d.tlsMode == "implicit" {
		opts = append(opts, ftp.DialWithTLS(&tls.Config{
			ServerName:         host,
			InsecureSkipVerify: d.skipVerify, // #nosec G402 — gated by explicit config
		}))
	} else if d.tlsMode == "explicit" {
		opts = append(opts, ftp.DialWithExplicitTLS(&tls.Config{
			ServerName:         host,
			InsecureSkipVerify: d.skipVerify, // #nosec G402 — gated by explicit config
		}))
	}
	c, err := ftp.Dial(d.addr, opts...)
	if err != nil {
		return nil, fmt.Errorf("ftp: dial: %w", err)
	}
	if err := c.Login(d.user, d.password); err != nil {
		_ = c.Quit()
		return nil, fmt.Errorf("ftp: login: %w", err)
	}
	return c, nil
}

func (d *ftpDest) Upload(ctx context.Context, key string, body io.Reader, _ int64) error {
	if strings.Contains(key, "..") {
		return errors.New("ftp: key contains traversal")
	}
	c, err := d.dial(ctx)
	if err != nil {
		return err
	}
	defer c.Quit()
	if err := mkdirAllFTP(c, d.basePath); err != nil {
		return fmt.Errorf("ftp: mkdir base: %w", err)
	}
	full := path.Join(d.basePath, key)
	tmp := full + ".tmp"
	if err := c.Stor(tmp, body); err != nil {
		return fmt.Errorf("ftp: stor: %w", err)
	}
	// Best-effort: server may not support overwrite-rename.
	_ = c.Delete(full)
	if err := c.Rename(tmp, full); err != nil {
		return fmt.Errorf("ftp: rename: %w", err)
	}
	return nil
}

func (d *ftpDest) Delete(ctx context.Context, key string) error {
	if strings.Contains(key, "..") {
		return errors.New("ftp: key contains traversal")
	}
	c, err := d.dial(ctx)
	if err != nil {
		return err
	}
	defer c.Quit()
	full := path.Join(d.basePath, key)
	if err := c.Delete(full); err != nil {
		// FTP error codes: 550 = file not found.
		if strings.Contains(err.Error(), "550") {
			return nil
		}
		return err
	}
	return nil
}

func mkdirAllFTP(c *ftp.ServerConn, p string) error {
	if p == "" || p == "." || p == "/" {
		return nil
	}
	parts := strings.Split(strings.Trim(p, "/"), "/")
	cur := ""
	if strings.HasPrefix(p, "/") {
		cur = "/"
	}
	for _, part := range parts {
		if part == "" {
			continue
		}
		if cur == "" || cur == "/" {
			cur += part
		} else {
			cur = cur + "/" + part
		}
		// MakeDir returns an error if already present; ignore.
		_ = c.MakeDir(cur)
	}
	return nil
}
