package backup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// keysEqual compares two ssh.PublicKey values byte-for-byte (Marshal
// produces a canonical wire form). Older golang.org/x/crypto versions
// don't ship ssh.KeysEqual.
func keysEqual(a, b ssh.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	return bytes.Equal(a.Marshal(), b.Marshal())
}

// SFTP destination — Hetzner Storage Box, generic SSH/SFTP servers.
//
// Config keys:
//
//	host                hostname (required)
//	port                default 22
//	user                SSH user (required)
//	password            password (optional if private_key set)
//	private_key         OpenSSH private key PEM (optional if password set)
//	private_key_pass    passphrase for private_key (optional)
//	host_key            ssh-pubkey line for host pinning ("ssh-rsa AAAA…")
//	                    — REQUIRED for production; if empty we refuse to
//	                    connect unless `insecure_host_key`="1"
//	insecure_host_key   "1" to skip host-key verification (NOT for prod)
//	path                remote base directory, e.g. "./backups" or "/home/u/backups"
type sftpDest struct {
	addr           string
	user           string
	password       string
	privateKey     []byte
	privateKeyPass string
	hostKey        ssh.PublicKey
	insecure       bool
	basePath       string
}

func newSFTPDest(cfg map[string]string) (*sftpDest, error) {
	host := strings.TrimSpace(cfg["host"])
	if host == "" {
		return nil, errors.New("sftp: host required")
	}
	if err := validateDestHost(host); err != nil {
		return nil, fmt.Errorf("sftp: %w", err)
	}
	port := strings.TrimSpace(cfg["port"])
	if port == "" {
		port = "22"
	}
	if _, err := strconv.Atoi(port); err != nil {
		return nil, fmt.Errorf("sftp: invalid port %q", port)
	}
	user := strings.TrimSpace(cfg["user"])
	if user == "" {
		return nil, errors.New("sftp: user required")
	}
	password := cfg["password"]
	pk := strings.TrimSpace(cfg["private_key"])
	if password == "" && pk == "" {
		return nil, errors.New("sftp: password or private_key required")
	}
	d := &sftpDest{
		addr:           net.JoinHostPort(host, port),
		user:           user,
		password:       password,
		privateKey:     []byte(pk),
		privateKeyPass: cfg["private_key_pass"],
		basePath:       strings.TrimSpace(cfg["path"]),
		insecure:       cfg["insecure_host_key"] == "1",
	}
	if d.basePath == "" {
		d.basePath = "."
	}
	if hk := strings.TrimSpace(cfg["host_key"]); hk != "" {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hk))
		if err != nil {
			return nil, fmt.Errorf("sftp: parse host_key: %w", err)
		}
		d.hostKey = pub
	} else if !d.insecure {
		return nil, errors.New("sftp: host_key required (or set insecure_host_key=1 explicitly)")
	}
	return d, nil
}

func (d *sftpDest) dial(ctx context.Context) (*ssh.Client, *sftp.Client, error) {
	cfg := &ssh.ClientConfig{
		User:            d.user,
		HostKeyCallback: d.hostKeyCallback(),
		Timeout:         15 * time.Second,
	}
	if d.password != "" {
		cfg.Auth = append(cfg.Auth, ssh.Password(d.password))
	}
	if len(d.privateKey) > 0 {
		var signer ssh.Signer
		var err error
		if d.privateKeyPass != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(d.privateKey, []byte(d.privateKeyPass))
		} else {
			signer, err = ssh.ParsePrivateKey(d.privateKey)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("sftp: parse private_key: %w", err)
		}
		cfg.Auth = append(cfg.Auth, ssh.PublicKeys(signer))
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", d.addr)
	if err != nil {
		return nil, nil, fmt.Errorf("sftp: dial: %w", err)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, d.addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("sftp: handshake: %w", err)
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	sc, err := sftp.NewClient(client)
	if err != nil {
		_ = client.Close()
		return nil, nil, fmt.Errorf("sftp: new client: %w", err)
	}
	return client, sc, nil
}

func (d *sftpDest) hostKeyCallback() ssh.HostKeyCallback {
	if d.insecure {
		return ssh.InsecureIgnoreHostKey() // gated by explicit config flag
	}
	expected := d.hostKey
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if !keysEqual(expected, key) {
			return errors.New("sftp: host key mismatch")
		}
		return nil
	}
}

func (d *sftpDest) Upload(ctx context.Context, key string, body io.Reader, _ int64) error {
	if strings.Contains(key, "..") {
		return errors.New("sftp: key contains traversal")
	}
	ssh, sc, err := d.dial(ctx)
	if err != nil {
		return err
	}
	defer ssh.Close()
	defer sc.Close()

	if err := mkdirAllSFTP(sc, d.basePath); err != nil {
		return fmt.Errorf("sftp: mkdir base: %w", err)
	}
	full := path.Join(d.basePath, key)
	tmp := full + ".tmp"

	f, err := sc.OpenFile(tmp, sftpWrite)
	if err != nil {
		return fmt.Errorf("sftp: open: %w", err)
	}
	if _, err := io.Copy(f, body); err != nil {
		_ = f.Close()
		_ = sc.Remove(tmp)
		return fmt.Errorf("sftp: copy: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = sc.Remove(tmp)
		return fmt.Errorf("sftp: close: %w", err)
	}
	// Atomic-ish: try Rename, fall back to delete+rename for picky servers.
	if err := sc.PosixRename(tmp, full); err != nil {
		_ = sc.Remove(full)
		if err2 := sc.Rename(tmp, full); err2 != nil {
			_ = sc.Remove(tmp)
			return fmt.Errorf("sftp: rename: %w", err2)
		}
	}
	return nil
}

func (d *sftpDest) Download(ctx context.Context, key string) (io.ReadCloser, error) {
	if strings.Contains(key, "..") {
		return nil, errors.New("sftp: key contains traversal")
	}
	sshc, sc, err := d.dial(ctx)
	if err != nil {
		return nil, err
	}
	f, err := sc.Open(path.Join(d.basePath, key))
	if err != nil {
		_ = sc.Close()
		_ = sshc.Close()
		return nil, err
	}
	return &sftpReadCloser{f: f, sc: sc, ssh: sshc}, nil
}

// sftpReadCloser wraps a remote file + its parent connection so Close()
// tears the whole stack down.
type sftpReadCloser struct {
	f   io.ReadCloser
	sc  io.Closer
	ssh io.Closer
}

func (s *sftpReadCloser) Read(p []byte) (int, error) { return s.f.Read(p) }
func (s *sftpReadCloser) Close() error {
	_ = s.f.Close()
	_ = s.sc.Close()
	return s.ssh.Close()
}

func (d *sftpDest) Delete(ctx context.Context, key string) error {
	if strings.Contains(key, "..") {
		return errors.New("sftp: key contains traversal")
	}
	ssh, sc, err := d.dial(ctx)
	if err != nil {
		return err
	}
	defer ssh.Close()
	defer sc.Close()
	full := path.Join(d.basePath, key)
	if err := sc.Remove(full); err != nil {
		if strings.Contains(err.Error(), "does not exist") || strings.Contains(err.Error(), "not exist") {
			return nil
		}
		return err
	}
	return nil
}

// Open flags for create+truncate+write. pkg/sftp doesn't expose os flags
// in the helper; spell them out.
const sftpWrite = 0x0001 | 0x0040 | 0x0200 // O_WRONLY | O_CREAT | O_TRUNC

// mkdirAllSFTP creates dir + parents on the remote.
func mkdirAllSFTP(c *sftp.Client, p string) error {
	if p == "" || p == "." || p == "/" {
		return nil
	}
	if _, err := c.Stat(p); err == nil {
		return nil
	}
	return c.MkdirAll(p)
}
