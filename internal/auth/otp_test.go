package auth

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/redis/go-redis/v9"
)

// One correct code verified concurrently must succeed exactly once.
func TestVerifyOTPSingleUseUnderConcurrency(t *testing.T) {
	addr := os.Getenv("HPG_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("HPG_TEST_REDIS_ADDR not set")
	}
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	defer rdb.Close()
	ctx := context.Background()
	for _, kind := range []string{"sms", "email"} {
		store, verify := StoreSMSOTP, VerifySMSOTP
		if kind == "email" {
			store, verify = StoreEmailOTP, VerifyEmailOTP
		}
		ticket, err := store(ctx, rdb, 42, "123456")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := verify(ctx, rdb, ticket, "000000"); err == nil {
			t.Fatalf("%s: wrong code accepted", kind)
		}
		var ok atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if uid, err := verify(ctx, rdb, ticket, "123456"); err == nil && uid == 42 {
					ok.Add(1)
				}
			}()
		}
		wg.Wait()
		if ok.Load() != 1 {
			t.Fatalf("%s: %d successes, want 1", kind, ok.Load())
		}
	}
}
