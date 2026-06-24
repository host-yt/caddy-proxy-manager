//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestAskLoad hammers the panel's /internal/ask endpoint (the Caddy
// On-Demand TLS gate — hot path for every new HTTPS handshake) with N
// concurrent requests for M seconds and reports throughput + p50/p95/p99
// latency. Used as a smoke load test before claiming "prod-ready at
// 1000 RPS".
//
// Run against a live panel:
//
//	HPG_PANEL_URL=http://127.0.0.1:38080 \
//	HPG_LOAD_CONCURRENCY=64 \
//	HPG_LOAD_DURATION=20s \
//	go test -tags=integration -run TestAskLoad ./internal/integration/...
//
// Skipped when HPG_PANEL_URL is unset.
func TestAskLoad(t *testing.T) {
	base := os.Getenv("HPG_PANEL_URL")
	if base == "" {
		t.Skip("set HPG_PANEL_URL to run the load probe")
	}
	concurrency := envInt("HPG_LOAD_CONCURRENCY", 32)
	duration := envDur("HPG_LOAD_DURATION", 10*time.Second)
	target := strings.TrimRight(base, "/") + "/internal/ask?domain=load-test.invalid"

	hc := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			MaxIdleConnsPerHost: concurrency,
			IdleConnTimeout:     30 * time.Second,
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	var wg sync.WaitGroup
	var ok, fail atomic.Uint64
	latencies := make(chan time.Duration, 1<<20)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				start := time.Now()
				resp, err := hc.Get(target)
				lat := time.Since(start)
				if err != nil {
					fail.Add(1)
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				// 403 is the expected default-deny answer; we count it as OK
				// because that means the handler ran end-to-end and the
				// rate-limit/redis path is exercised.
				if resp.StatusCode == 200 || resp.StatusCode == 403 || resp.StatusCode == 429 {
					ok.Add(1)
					select {
					case latencies <- lat:
					default:
					}
				} else {
					fail.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	close(latencies)

	var lats []time.Duration
	for l := range latencies {
		lats = append(lats, l)
	}
	if len(lats) == 0 {
		t.Fatal("zero successful requests")
	}
	for i := 1; i < len(lats); i++ {
		// insertion sort — fine for the bounded sample.
		j := i
		for j > 0 && lats[j-1] > lats[j] {
			lats[j-1], lats[j] = lats[j], lats[j-1]
			j--
		}
	}
	p := func(q float64) time.Duration { return lats[int(float64(len(lats))*q)] }
	t.Logf("requests ok=%d fail=%d duration=%s rps=%.1f p50=%v p95=%v p99=%v",
		ok.Load(), fail.Load(), duration, float64(ok.Load())/duration.Seconds(),
		p(0.5), p(0.95), p(0.99))
	if fail.Load() > ok.Load()/100 {
		t.Errorf("error rate > 1%%: ok=%d fail=%d", ok.Load(), fail.Load())
	}
}

func envInt(k string, def int) int {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	n := 0
	for _, c := range v {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func envDur(k string, def time.Duration) time.Duration {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

// _ keep deps stable.
var _ = sha256.New
var _ = hex.EncodeToString
var _ = fmt.Sprintf
