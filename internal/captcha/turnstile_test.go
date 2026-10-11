package captcha

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/installstate"
	_ "modernc.org/sqlite"
)

// A secret that no longer decrypts must keep the last-known-good secret, or,
// with none, fail Verify closed instead of silently disabling CAPTCHA.
func TestRefreshDecryptFailureFailsClosed(t *testing.T) {
	good, _ := installstate.New(t.TempDir(), strings.Repeat("a", 32))
	bad, _ := installstate.New(t.TempDir(), strings.Repeat("b", 32))
	enc, err := bad.Encrypt("other-key-secret")
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE settings (`key` TEXT, value TEXT, is_encrypted BOOL)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO settings VALUES ('captcha.provider','turnstile',0), ('captcha.secret',?,1)", enc); err != nil {
		t.Fatal(err)
	}

	v := New("", "")
	v.DB, v.State = func() *sql.DB { return db }, good
	v.Refresh(context.Background())
	if !v.Enabled() {
		t.Fatal("Enabled() = false with an undecryptable secret; CAPTCHA silently off")
	}
	if err := v.Verify(context.Background(), "tok", ""); err == nil {
		t.Fatal("Verify passed with no usable secret")
	}

	v = New("turnstile", "last-good")
	v.DB, v.State = func() *sql.DB { return db }, good
	v.Refresh(context.Background())
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.secret != "last-good" {
		t.Fatalf("secret = %q, want last-known-good kept", v.secret)
	}
}

// Enabled must accept every known provider (when a secret is set) and reject
// unknown/empty providers - the latter is the safety net that keeps a stale or
// misconfigured provider string from enforcing CAPTCHA with no working verify.
func TestEnabledByProvider(t *testing.T) {
	cases := []struct {
		provider string
		secret   string
		want     bool
	}{
		{"turnstile", "s", true},
		{"hcaptcha", "s", true},
		{"recaptcha", "s", true},
		{"turnstile", "", false},  // no secret
		{"", "s", false},          // disabled
		{"bogus", "s", false},     // unknown provider
		{"Turnstile", "s", false}, // case-sensitive: not a known id
	}
	for _, c := range cases {
		v := New(c.provider, c.secret) // DB nil -> maybeReload is a no-op
		if got := v.Enabled(); got != c.want {
			t.Errorf("provider=%q secret=%q: Enabled()=%v want %v", c.provider, c.secret, got, c.want)
		}
	}
}

func TestProviderGetter(t *testing.T) {
	if p := New("hcaptcha", "s").Provider(); p != "hcaptcha" {
		t.Fatalf("Provider() = %q, want hcaptcha", p)
	}
}

// Every known provider must have a distinct, https siteverify endpoint, or
// Verify would silently treat it as disabled.
func TestVerifyURLsComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range []string{"turnstile", "hcaptcha", "recaptcha"} {
		u := verifyURLs[p]
		if u == "" {
			t.Errorf("provider %q has no verify URL", p)
		}
		if seen[u] {
			t.Errorf("provider %q reuses verify URL %q", p, u)
		}
		seen[u] = true
		if !knownProvider(p) {
			t.Errorf("knownProvider(%q) = false", p)
		}
	}
	if knownProvider("") || knownProvider("nope") {
		t.Error("knownProvider accepted an unknown provider")
	}
}
