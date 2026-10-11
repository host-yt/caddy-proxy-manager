package cloudflare

import (
	"database/sql"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Concurrent requests on a stale cache must trigger one reload, not one each.
func TestStaleCacheRefreshesOnce(t *testing.T) {
	var loads atomic.Int32
	s := New(func() *sql.DB {
		loads.Add(1)
		time.Sleep(50 * time.Millisecond) // slow DB
		return nil
	}, nil)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			s.TrustConnectingIP()
		}()
	}
	close(start)
	wg.Wait()
	if n := loads.Load(); n != 1 {
		t.Fatalf("reloads = %d, want 1", n)
	}
}
