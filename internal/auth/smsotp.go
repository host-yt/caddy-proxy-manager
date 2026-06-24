package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/redis/go-redis/v9"
)

const SMSOTPTTLSeconds = 300 // 5 min

// GenerateSMSOTP returns a zero-padded 6-digit code.
func GenerateSMSOTP() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// SMSOTPHash returns the hex-encoded SHA-256 of a code. Exported for handlers.
func SMSOTPHash(code string) string {
	h := sha256.Sum256([]byte(code))
	return hex.EncodeToString(h[:])
}

// StoreSMSOTP stashes a SHA-256 hash of the code in Redis for 5 min.
// Returns an opaque ticket stored in a browser cookie.
func StoreSMSOTP(ctx context.Context, rdb *redis.Client, userID int64, code string) (string, error) {
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	ticket := base64.RawURLEncoding.EncodeToString(raw)
	key := fmt.Sprintf("hpg:smsotp:%s", ticket)
	val := fmt.Sprintf("%d:%s", userID, SMSOTPHash(code))
	return ticket, rdb.Set(ctx, key, val, SMSOTPTTLSeconds*time.Second).Err()
}

// VerifySMSOTP verifies the code, deletes the ticket on success, returns userID.
func VerifySMSOTP(ctx context.Context, rdb *redis.Client, ticket, code string) (int64, error) {
	key := fmt.Sprintf("hpg:smsotp:%s", ticket)
	stored, err := rdb.Get(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("smsotp: ticket not found or expired")
	}
	var userID int64
	var storedHash string
	if n, _ := fmt.Sscanf(stored, "%d:", &userID); n != 1 {
		return 0, fmt.Errorf("smsotp: bad store format")
	}
	for i, c := range stored {
		if c == ':' && i > 0 {
			storedHash = stored[i+1:]
			break
		}
	}
	if subtle.ConstantTimeCompare([]byte(SMSOTPHash(code)), []byte(storedHash)) != 1 {
		return 0, fmt.Errorf("smsotp: invalid code")
	}
	_ = rdb.Del(ctx, key).Err()
	return userID, nil
}
