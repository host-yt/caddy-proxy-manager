package backup

import (
	"context"
	"os"
	"testing"
)

// insecureTransportAllowed must deny (return false) unless APP_ENV is
// explicitly set to something other than "production" - unset/empty must
// behave exactly like the production default (DB-02/DB-03).
func TestInsecureTransportAllowed(t *testing.T) {
	orig, had := os.LookupEnv("APP_ENV")
	t.Cleanup(func() {
		if had {
			os.Setenv("APP_ENV", orig)
		} else {
			os.Unsetenv("APP_ENV")
		}
	})

	cases := []struct {
		name  string
		env   string
		unset bool
		want  bool
	}{
		{name: "unset", unset: true, want: false},
		{name: "empty", env: "", want: false},
		{name: "production", env: "production", want: false},
		{name: "development", env: "development", want: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.unset {
				os.Unsetenv("APP_ENV")
			} else {
				os.Setenv("APP_ENV", c.env)
			}
			if got := insecureTransportAllowed(); got != c.want {
				t.Errorf("APP_ENV=%q (unset=%v): got %v, want %v", c.env, c.unset, got, c.want)
			}
		})
	}
}

// newS3Dest must refuse use_ssl=0 in production, same as the FTP/SFTP
// plaintext and cert-verification opt-outs (DB-02).
func TestS3UseSSLGate(t *testing.T) {
	orig, had := os.LookupEnv("APP_ENV")
	t.Cleanup(func() {
		if had {
			os.Setenv("APP_ENV", orig)
		} else {
			os.Unsetenv("APP_ENV")
		}
	})
	cfg := map[string]string{
		"endpoint":   "8.8.8.8", // public IP literal, skips DNS in validateDestHost
		"bucket":     "b",
		"access_key": "ak",
		"secret_key": "sk",
		"use_ssl":    "0",
	}

	os.Unsetenv("APP_ENV")
	if _, err := newS3Dest(cfg); err == nil {
		t.Error("use_ssl=0 with unset APP_ENV: want error, got nil")
	}

	os.Setenv("APP_ENV", "production")
	if _, err := newS3Dest(cfg); err == nil {
		t.Error("use_ssl=0 in production: want error, got nil")
	}

	os.Setenv("APP_ENV", "development")
	if _, err := newS3Dest(cfg); err != nil {
		t.Errorf("use_ssl=0 outside production: want nil, got %v", err)
	}
}

// The FTP dial hook must validate every address it is handed, not just the
// control one: a malicious server can fail EPSV and advertise a private PASV
// host to steer the panel at internal services.
func TestPinnedAddrRejectsPrivateTargets(t *testing.T) {
	ctx := context.Background()
	for _, addr := range []string{
		"127.0.0.1:21", "10.0.0.5:2121", "169.254.169.254:80", "192.168.1.1:21",
	} {
		if _, err := pinnedAddr(ctx, addr); err == nil {
			t.Errorf("pinnedAddr(%q) must be refused", addr)
		}
	}
	if _, err := pinnedAddr(ctx, "8.8.8.8:21"); err != nil {
		t.Errorf("public address must be allowed, got %v", err)
	}
}
