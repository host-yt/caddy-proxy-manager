package wireguard

import (
	"context"
	"database/sql"
	"encoding/base64"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/curve25519"

	"github.com/host-yt/caddy-proxy-manager/internal/installstate"
)

// Concurrent first-time EnsureKeypair calls must persist one matching pair.
func TestEnsureKeypairConcurrentPersistsMatchingPair(t *testing.T) {
	db := openPSKTestDB(t)
	ctx := context.Background()
	enc, err := installstate.New(t.TempDir(), strings.Repeat("z", 32))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := db.ExecContext(ctx, "DELETE FROM settings WHERE `key` IN ('wireguard.public_key','wireguard.private_key')"); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for j := 0; j < 8; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				s := &Service{DB: func() *sql.DB { return db }, State: enc}
				if _, err := s.EnsureKeypair(ctx); err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		c, err := (&Service{DB: func() *sql.DB { return db }, State: enc}).Reload(ctx)
		if err != nil {
			t.Fatal(err)
		}
		priv, err := base64.StdEncoding.DecodeString(c.PrivateKey)
		if err != nil || len(priv) != 32 {
			t.Fatalf("stored private key unusable: %v", err)
		}
		pub, _ := curve25519.X25519(priv, curve25519.Basepoint)
		if base64.StdEncoding.EncodeToString(pub) != c.PublicKey {
			t.Fatalf("round %d: stored public key does not match private key", i)
		}
	}
}
