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
	return verifyOTP(ctx, rdb, "smsotp", ticket, code)
}

// compareAndDel deletes KEYS[1] only if it still holds ARGV[1]; returns 1 for
// exactly one caller, so concurrent requests cannot both consume one code.
var compareAndDel = redis.NewScript(`if redis.call("GET", KEYS[1]) == ARGV[1] then return redis.call("DEL", KEYS[1]) end return 0`)

// verifyOTP checks code against the hpg:<kind>:<ticket> entry and consumes it
// atomically; any Redis error fails closed.
func verifyOTP(ctx context.Context, rdb *redis.Client, kind, ticket, code string) (int64, error) {
	key := fmt.Sprintf("hpg:%s:%s", kind, ticket)
	stored, err := rdb.Get(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("%s: ticket not found or expired", kind)
	}
	var userID int64
	var storedHash string
	if n, _ := fmt.Sscanf(stored, "%d:", &userID); n != 1 {
		return 0, fmt.Errorf("%s: bad store format", kind)
	}
	for i, c := range stored {
		if c == ':' && i > 0 {
			storedHash = stored[i+1:]
			break
		}
	}
	if subtle.ConstantTimeCompare([]byte(SMSOTPHash(code)), []byte(storedHash)) != 1 {
		return 0, fmt.Errorf("%s: invalid code", kind)
	}
	if n, err := compareAndDel.Run(ctx, rdb, []string{key}, stored).Int(); err != nil || n != 1 {
		return 0, fmt.Errorf("%s: code already used", kind)
	}
	return userID, nil
}
