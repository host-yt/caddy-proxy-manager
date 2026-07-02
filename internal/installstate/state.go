// Package installstate manages the install wizard's persisted state.
//
// The wizard writes step-by-step progress to data/install_state.json. The
// app reads it at boot. When .Installed == true, the wizard is locked
// and /install routes 404.
//
// DB credentials in this file are encrypted (AES-256-GCM) with a key
// derived from APP_SECRET (HKDF-SHA256). APP_SECRET MUST be stable across
// restarts - losing it means re-running the wizard.
package installstate

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"crypto/sha256"

	"golang.org/x/crypto/hkdf"
)

type State struct {
	Installed   bool   `json:"installed"`
	CurrentStep string `json:"current_step"`
	// Profile is the deployment shape (homelab|smallteam|advanced|provider).
	// Empty on legacy installs - readers treat empty as the full-menu default.
	Profile string `json:"profile,omitempty"`
	// DBDriver is the chosen database driver ("mysql"; "sqlite" reserved).
	DBDriver string `json:"db_driver,omitempty"`
	// SetupVersion/SetupCompletedAt are stamped on completion so later schema
	// changes to the profile model can detect and upgrade older installs.
	SetupVersion     string      `json:"setup_version,omitempty"`
	SetupCompletedAt string      `json:"setup_completed_at,omitempty"` // RFC3339
	DB               *DBState    `json:"db,omitempty"`
	Admin            *AdminState `json:"admin,omitempty"`
	App              *AppState   `json:"app,omitempty"`
	SMTP             *SMTPState  `json:"smtp,omitempty"`
	CaddyNode        *NodeState  `json:"caddy_node,omitempty"`
}

type DBState struct {
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Name           string `json:"name"`
	User           string `json:"user"`
	PasswordCipher string `json:"password_cipher"` // AES-GCM encrypted
	TLS            bool   `json:"tls"`
	SQLitePath     string `json:"sqlite_path,omitempty"`
}

type AdminState struct {
	UserID   int64  `json:"user_id"`
	Email    string `json:"email"`
	FullName string `json:"full_name"`
}

type AppState struct {
	URL string `json:"url"`
}

type SMTPState struct {
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Encryption     string `json:"encryption"`
	Username       string `json:"username"`
	PasswordCipher string `json:"password_cipher,omitempty"`
	FromEmail      string `json:"from_email"`
	FromName       string `json:"from_name"`
}

type NodeState struct {
	Name           string `json:"name"`
	APIURL         string `json:"api_url"`
	PublicHostname string `json:"public_hostname"`
	PublicIP       string `json:"public_ip"`
}

// Steps in order. UI advances linearly.
const (
	StepWelcome = "welcome"
	StepProfile = "profile"
	StepDB      = "db"
	StepAdmin   = "admin"
	StepApp     = "app"
	StepSMTP    = "smtp"
	StepCaddy   = "caddy"
	StepDone    = "done"
)

var StepOrder = []string{StepWelcome, StepProfile, StepDB, StepAdmin, StepApp, StepSMTP, StepCaddy, StepDone}

// Manager persists state and provides encryption helpers.
type Manager struct {
	path string
	key  []byte
	// purpose, when non-empty, makes Encrypt emit a per-purpose envelope
	// (see Scoped / CRYPTO-02). Empty = the legacy shared-key format.
	purpose string
	mu      sync.RWMutex
	cache   *State
}

// New returns a Manager whose state file lives at <dir>/install_state.json.
// appSecret must be at least 32 bytes (raw or hex).
func New(dir, appSecret string) (*Manager, error) {
	if appSecret == "" {
		return nil, errors.New("APP_SECRET required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dir, err)
	}
	// Derive 32-byte AES key via HKDF(secret).
	r := hkdf.New(sha256.New, []byte(appSecret), nil, []byte("hpg/install-state/v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	m := &Manager{
		path: filepath.Join(dir, "install_state.json"),
		key:  key,
	}
	if _, err := m.Load(); err != nil {
		return nil, err
	}
	return m, nil
}

// Load reads state from disk. Returns a zero-value State if file is absent.
func (m *Manager) Load() (*State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, err := os.ReadFile(m.path)
	if errors.Is(err, os.ErrNotExist) {
		m.cache = &State{CurrentStep: StepWelcome}
		return m.cache, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read state: %w", err)
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("unmarshal state: %w", err)
	}
	m.cache = &s
	return &s, nil
}

// Get returns a copy of the current state.
func (m *Manager) Get() State {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cache == nil {
		return State{CurrentStep: StepWelcome}
	}
	return *m.cache
}

// Save writes the state atomically (write+rename).
func (m *Manager) Save(s *State) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Rename(tmp, m.path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	m.cache = s
	return nil
}

// v2Prefix marks a per-purpose envelope: "v2:<purpose>:<base64(nonce||ct)>".
// Ciphertext without it is the legacy shared-key format (decrypted with m.key).
const v2Prefix = "v2:"

// Scoped returns a Manager whose Encrypt emits a per-purpose envelope sealed
// under a sub-key HKDF(stateKey, "hpg/secret/<purpose>/v1"), so a single leaked
// sub-key or a per-domain rotation is scoped to that purpose (CRYPTO-02). The
// returned Manager shares the base key, so its Decrypt still reads legacy and
// any-purpose v2 values. Use it only for at-rest secret crypto (not state I/O).
func (m *Manager) Scoped(purpose string) *Manager {
	return &Manager{path: m.path, key: m.key, purpose: purpose}
}

// purposeKey derives the per-purpose AES key from the state key.
func (m *Manager) purposeKey(purpose string) ([]byte, error) {
	r := hkdf.New(sha256.New, m.key, nil, []byte("hpg/secret/"+purpose+"/v1"))
	k := make([]byte, 32)
	if _, err := io.ReadFull(r, k); err != nil {
		return nil, fmt.Errorf("hkdf purpose %q: %w", purpose, err)
	}
	return k, nil
}

func seal(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

func open(key []byte, b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return "", errors.New("ciphertext too short")
	}
	pt, err := gcm.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return "", fmt.Errorf("gcm open: %w", err)
	}
	return string(pt), nil
}

// EncryptFor seals plaintext under the named purpose's sub-key and returns the
// self-describing v2 envelope.
func (m *Manager) EncryptFor(purpose, plaintext string) (string, error) {
	key, err := m.purposeKey(purpose)
	if err != nil {
		return "", err
	}
	b64, err := seal(key, plaintext)
	if err != nil {
		return "", err
	}
	return v2Prefix + purpose + ":" + b64, nil
}

// Encrypt seals plaintext. A purpose-scoped Manager (see Scoped) emits a v2
// per-purpose envelope; otherwise it uses the legacy shared-key format so
// unmigrated callers keep producing back-compatible ciphertext.
func (m *Manager) Encrypt(plaintext string) (string, error) {
	if m.purpose != "" {
		return m.EncryptFor(m.purpose, plaintext)
	}
	return seal(m.key, plaintext)
}

// Decrypt reverses Encrypt/EncryptFor. It auto-detects the format: a v2
// envelope is opened with its embedded purpose's sub-key; anything else is
// treated as legacy shared-key ciphertext.
func (m *Manager) Decrypt(b64 string) (string, error) {
	if rest, ok := strings.CutPrefix(b64, v2Prefix); ok {
		purpose, payload, found := strings.Cut(rest, ":")
		if !found || purpose == "" {
			return "", errors.New("malformed v2 envelope")
		}
		key, err := m.purposeKey(purpose)
		if err != nil {
			return "", err
		}
		return open(key, payload)
	}
	return open(m.key, b64)
}

// DeriveBackupKey returns a 32-byte key derived from APP_SECRET via HKDF
// under a backup-specific info label. Used by the backup module to encrypt
// artifacts at rest before upload.
func (m *Manager) DeriveBackupKey() ([]byte, error) {
	r := hkdf.New(sha256.New, m.key, nil, []byte("hpg/backup/v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("hkdf backup: %w", err)
	}
	return key, nil
}

// IsInstalled returns whether the wizard completed.
func (m *Manager) IsInstalled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cache != nil && m.cache.Installed
}
