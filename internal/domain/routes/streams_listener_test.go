package routes

import (
	"context"
	"strings"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
)

// A "both" row and a tcp row on one port bind the same tcp listener: the older
// row keeps it and the clash is rejected visibly, never silently overwritten.
func TestScreenStreamSetRejectsOverlappingListeners(t *testing.T) {
	in := []caddyapi.StreamRoute{
		{ID: 1, Protocol: "both", ListenPort: 5000, UpstreamIP: "10.0.0.5", UpstreamPort: 8080},
		{ID: 2, Protocol: "tcp", ListenPort: 5000, UpstreamIP: "10.0.0.6", UpstreamPort: 8080},
		{ID: 3, Protocol: "udp", ListenPort: 5001, UpstreamIP: "10.0.0.6", UpstreamPort: 8080},
		{ID: 4, Protocol: "tcp", ListenPort: 5001, UpstreamIP: "10.0.0.7", UpstreamPort: 8080},
	}
	kept, rejected := screenStreamSet(context.Background(), screenTestInfra(t), in)
	if len(kept) != 3 || len(rejected) != 1 || rejected[0].route.ID != 2 {
		t.Fatalf("want stream #2 rejected, got kept=%+v rejected=%+v", kept, rejected)
	}
	if !strings.Contains(rejected[0].cause.Error(), "stream #1") {
		t.Errorf("cause must name the owner: %v", rejected[0].cause)
	}
}
