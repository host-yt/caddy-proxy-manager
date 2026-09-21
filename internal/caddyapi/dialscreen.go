package caddyapi

import (
	"fmt"
	"strings"
)

// ScreenDialTarget rejects an upstream `dial` value that is not a plain
// host:port. Caddy also accepts filesystem-socket and file-descriptor
// networks ("unix/...", "unix+h2c/...", "fd/...") which name no address at
// all, so no address-based screen can cover them; every legitimate proxy
// target the panel emits is host:port and carries no slash.
//
// Callers: the emission-time backend screen (internal/domain/routes) and any
// code path that puts an operator- or tenant-supplied string into a dial.
func ScreenDialTarget(dial string) error {
	if strings.Contains(strings.TrimSpace(dial), "/") {
		return fmt.Errorf("upstream %q is not a host:port target", dial)
	}
	return nil
}
