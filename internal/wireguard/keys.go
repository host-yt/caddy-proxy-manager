// Package wireguard implements WireGuard key generation and manages the
// control-plane WG identity stored in the settings table.
//
// Key generation follows the WireGuard spec:
//
//	private key = 32 random bytes, clamped per Curve25519 rules
//	public key  = Curve25519(private, basepoint)
//
// We never shell out to `wg` — pure Go.
package wireguard

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"sync"

	"golang.org/x/crypto/curve25519"

	"github.com/hostyt/proxy-gateway/internal/installstate"
)

// Keypair is a base64-encoded WireGuard keypair.
type Keypair struct {
	PrivateKey string
	PublicKey  string
}

// GenerateKeypair produces a fresh WG-compatible keypair.
func GenerateKeypair() (Keypair, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return Keypair{}, err
	}
	// Curve25519 clamping (per RFC 7748).
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return Keypair{}, err
	}
	return Keypair{
		PrivateKey: base64.StdEncoding.EncodeToString(priv[:]),
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
	}, nil
}

// ControlPlane is the WG identity of this control plane. Lazily created
// from the settings table on first call; refreshed when admin edits.
type ControlPlane struct {
	Enabled    bool
	Endpoint   string // host:port (public reachable, e.g. manager.example.com:51820)
	ListenPort int
	Subnet     string // e.g. 10.66.0.0/24
	ControlIP  string // e.g. 10.66.0.1 (this manager's WG IP)
	PrivateKey string // decrypted
	PublicKey  string
}

// Service exposes the control-plane WG identity + IP allocator for nodes.
type Service struct {
	DB    func() *sql.DB
	State *installstate.Manager

	mu  sync.RWMutex
	cfg ControlPlane
}

// Get returns the cached control-plane config (loaded from DB on first call).
func (s *Service) Get(ctx context.Context) (ControlPlane, error) {
	s.mu.RLock()
	if s.cfg.PublicKey != "" {
		c := s.cfg
		s.mu.RUnlock()
		return c, nil
	}
	s.mu.RUnlock()
	return s.load(ctx)
}

// Reload forces re-read from settings table.
func (s *Service) Reload(ctx context.Context) (ControlPlane, error) { return s.load(ctx) }

func (s *Service) load(ctx context.Context) (ControlPlane, error) {
	db := s.DB()
	if db == nil {
		return ControlPlane{}, errors.New("db not ready")
	}
	rows, err := db.QueryContext(ctx,
		"SELECT `key`, value, is_encrypted FROM settings WHERE `key` LIKE 'wireguard.%'")
	if err != nil {
		return ControlPlane{}, err
	}
	defer rows.Close()
	c := ControlPlane{Subnet: "10.66.0.0/24", ControlIP: "10.66.0.1", ListenPort: 51820}
	for rows.Next() {
		var k, v string
		var enc bool
		if err := rows.Scan(&k, &v, &enc); err != nil {
			continue
		}
		if enc && s.State != nil {
			if dec, derr := s.State.Decrypt(v); derr == nil {
				v = dec
			} else {
				v = ""
			}
		}
		switch k {
		case "wireguard.enabled":
			c.Enabled = v == "1"
		case "wireguard.endpoint":
			c.Endpoint = v
		case "wireguard.listen_port":
			if n, err := atoi(v); err == nil && n > 0 {
				c.ListenPort = n
			}
		case "wireguard.subnet":
			if v != "" {
				c.Subnet = v
			}
		case "wireguard.control_ip":
			if v != "" {
				c.ControlIP = v
			}
		case "wireguard.private_key":
			c.PrivateKey = v
		case "wireguard.public_key":
			c.PublicKey = v
		}
	}
	s.mu.Lock()
	s.cfg = c
	s.mu.Unlock()
	return c, nil
}

// EnsureKeypair generates + persists a fresh control-plane keypair if
// none is stored yet. Idempotent; safe to call from any caller path.
func (s *Service) EnsureKeypair(ctx context.Context) (ControlPlane, error) {
	c, err := s.load(ctx)
	if err != nil {
		return c, err
	}
	if c.PrivateKey != "" && c.PublicKey != "" {
		return c, nil
	}
	kp, err := GenerateKeypair()
	if err != nil {
		return c, err
	}
	encPriv, err := s.State.Encrypt(kp.PrivateKey)
	if err != nil {
		return c, err
	}
	db := s.DB()
	if db == nil {
		return c, errors.New("db not ready")
	}
	upserts := map[string]struct {
		v   string
		enc int
	}{
		"wireguard.public_key":  {kp.PublicKey, 0},
		"wireguard.private_key": {encPriv, 1},
	}
	for k, val := range upserts {
		if _, err := db.ExecContext(ctx,
			"INSERT INTO settings (`key`, value, is_encrypted) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE value=VALUES(value), is_encrypted=VALUES(is_encrypted)",
			k, val.v, val.enc); err != nil {
			return c, err
		}
	}
	return s.load(ctx)
}

// AllocateNodeIP returns the next unused /32 inside subnet, skipping
// control_ip + already-assigned `caddy_nodes.wg_ip`. Simple linear scan
// — fine for the few-hundred-nodes scale we target.
func (s *Service) AllocateNodeIP(ctx context.Context) (string, error) {
	c, err := s.Get(ctx)
	if err != nil {
		return "", err
	}
	prefix, err := subnetPrefix(c.Subnet)
	if err != nil {
		return "", err
	}
	db := s.DB()
	if db == nil {
		return "", errors.New("db not ready")
	}
	used := map[string]struct{}{c.ControlIP: {}}
	rows, err := db.QueryContext(ctx, "SELECT wg_ip FROM caddy_nodes WHERE wg_ip IS NOT NULL")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var ip sql.NullString
			if rows.Scan(&ip) == nil && ip.Valid {
				used[ip.String] = struct{}{}
			}
		}
	}
	// Try .2 .. .254
	for i := 2; i < 255; i++ {
		ip := prefix + "." + itoa(i)
		if _, taken := used[ip]; taken {
			continue
		}
		return ip, nil
	}
	return "", errors.New("wg subnet exhausted")
}

// subnetPrefix accepts "10.66.0.0/24" → returns "10.66.0".
func subnetPrefix(cidr string) (string, error) {
	slash := strings.IndexByte(cidr, '/')
	if slash < 0 {
		return "", errors.New("invalid CIDR")
	}
	ip := cidr[:slash]
	last := strings.LastIndexByte(ip, '.')
	if last < 0 {
		return "", errors.New("invalid CIDR ip")
	}
	return ip[:last], nil
}

// atoi/itoa duplicates avoid an strconv import in hot paths.
func atoi(s string) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("nan")
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [4]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
