package routes

import (
	"strings"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/streamguard"
)

// A socket or file-descriptor upstream names no address, so the deny set
// cannot reason about it. Emission must refuse the shape outright.
func TestScreenEmittedRejectsNonAddressDialTargets(t *testing.T) {
	infra := &streamguard.InfraTargets{}
	for _, host := range []string{
		"unix//run/caddy/admin.sock",
		"unix+h2c//run/caddy/admin.sock",
		"unixgram//run/caddy/admin.sock",
		"fd/3",
	} {
		if err := screenEmitted(infra, host, 0); err == nil {
			t.Errorf("screenEmitted(%q) allowed a non-address upstream", host)
		}
	}
	// Ordinary targets, including IPv6, must still pass this gate.
	for _, host := range []string{"10.1.2.3", "backend.internal", "::1", "2001:db8::1"} {
		if err := screenEmitted(infra, host, 8080); err != nil && strings.Contains(err.Error(), "host:port") {
			t.Errorf("screenEmitted(%q) wrongly rejected a normal upstream: %v", host, err)
		}
	}
}
