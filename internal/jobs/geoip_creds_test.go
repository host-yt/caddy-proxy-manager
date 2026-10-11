package jobs

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/installstate"
	_ "modernc.org/sqlite"
)

func TestLoadGeoIPCredsDecryptFailure(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("CREATE TABLE settings (`key` TEXT PRIMARY KEY, value TEXT, is_encrypted INTEGER)"); err != nil {
		t.Fatal(err)
	}
	st, err := installstate.New(t.TempDir(), strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// No rows: unconfigured, not an error.
	if a, k, err := loadGeoIPCreds(ctx, db, st); err != nil || a != "" || k != "" {
		t.Fatalf("absent: got %q %q %v", a, k, err)
	}

	encKey, _ := st.Encrypt("lic")
	_, _ = db.Exec("INSERT INTO settings VALUES ('geoip.account_id','42',0),('geoip.license_key',?,1)", encKey)
	if a, k, err := loadGeoIPCreds(ctx, db, st); err != nil || a != "42" || k != "lic" {
		t.Fatalf("valid: got %q %q %v", a, k, err)
	}

	// Ciphertext under a different APP_SECRET must surface as an error.
	other, _ := installstate.New(t.TempDir(), strings.Repeat("b", 32))
	if _, _, err := loadGeoIPCreds(ctx, db, other); err == nil || !strings.Contains(err.Error(), "geoip.license_key") {
		t.Fatalf("decrypt failure: want error naming key, got %v", err)
	}
}
