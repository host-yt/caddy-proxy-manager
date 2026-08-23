package middleware

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// incrWithTTLScript increments a counter and, only when it just came into
// existence, gives it a TTL - in one atomic server-side step.
//
// Doing INCR and EXPIRE as two commands has a failure mode with no recovery:
// if the EXPIRE never lands (Redis blip, client timeout between the two, panel
// restart), the counter keeps its value forever and that key's caller is rate
// limited permanently. The script makes the pair indivisible.
var incrWithTTLScript = redis.NewScript(`
local n = redis.call('INCR', KEYS[1])
if n == 1 then
	redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return n
`)

// incrWithTTL returns the counter's new value for key, creating it with ttl on
// first use. A returned error means the count is unknown - callers decide
// whether that fails open or closed.
func incrWithTTL(ctx context.Context, rdb *redis.Client, key string, ttl time.Duration) (int64, error) {
	secs := int64(ttl / time.Second)
	if secs < 1 {
		secs = 1
	}
	return incrWithTTLScript.Run(ctx, rdb, []string{key}, secs).Int64()
}
