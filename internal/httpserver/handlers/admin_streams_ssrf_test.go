package handlers

import (
	"context"
	"io"
	"log/slog"
	"testing"
)

// TestScreenStreamUpstreamsBlocksInternalAddresses covers the shared SSRF
// screen used by both StreamsCreate and StreamsUpdate, so the update path
// can't regress into accepting internal-network upstreams.
func TestScreenStreamUpstreamsBlocksInternalAddresses(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()

	blocked := []string{
		"127.0.0.1:2019",     // loopback - Caddy admin API
		"169.254.169.254:80", // link-local - cloud metadata
		"224.0.0.1:53",       // multicast
	}
	for _, addr := range blocked {
		err := screenStreamUpstreams(ctx, logger, []upstreamEntry{{Address: addr, Weight: 1}})
		if err == nil {
			t.Errorf("expected %s to be blocked", addr)
		}
	}
}

func TestScreenStreamUpstreamsAllowsPrivateNet(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()

	// RFC1918 stays allowed - the WG mesh backend network.
	if err := screenStreamUpstreams(ctx, logger, []upstreamEntry{{Address: "10.0.0.5:8080", Weight: 1}}); err != nil {
		t.Errorf("expected 10.0.0.5 to be allowed, got %v", err)
	}
}
