package streamguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/host-yt/caddy-proxy-manager/internal/security"
)

// ErrUnresolved marks a hostname the panel could not resolve. It is a hard
// failure on the write path, but callers whose target is resolved node-side
// (tunnel backends, config emission during a DNS blip) may tolerate exactly
// this one case without losing the deny-set checks that ran before it.
var ErrUnresolved = errors.New("host did not resolve")

// ScreenHTTPBackend is the single fail-closed screen for every tenant-controlled
// HTTP reverse-proxy target: the primary backend, extra upstreams and path-rule
// upstreams all end up as a Caddy `dial`, so they all come through here.
// Customer RFC1918/CGNAT origins stay allowed on purpose; what is refused is
// the control plane itself - the admin API port, managed node and panel
// addresses, and the control-plane mesh. port 0 means "not dialed yet"
// (caller validates it separately) and skips only the port check.
func (t *InfraTargets) ScreenHTTPBackend(ctx context.Context, host string, port int) error {
	_, err := t.screenHTTP(ctx, host, port, true)
	return err
}

// PinHTTPBackend screens like ScreenHTTPBackend and returns the address to
// dial: an IP literal unchanged, a hostname replaced by the address it
// screened to. Dialing the pinned address is what stops a later DNS answer
// from moving an already-approved destination. Several addresses collapse to
// the lowest one so repeated pushes stay byte-identical.
func (t *InfraTargets) PinHTTPBackend(ctx context.Context, host string, port int) (string, error) {
	return t.screenHTTP(ctx, host, port, true)
}

// ScreenHTTPTargetLiteral is ScreenHTTPBackend without the DNS step: the deny
// set, the admin API port and IP literals are still enforced. Used at config
// emission for targets that must stay names (resolved on the node) and for
// re-checking an address that was already resolved and pinned.
func (t *InfraTargets) ScreenHTTPTargetLiteral(host string, port int) error {
	_, err := t.screenHTTP(context.Background(), host, port, false)
	return err
}

// screenHTTP returns the screened dial address alongside the verdict: the
// host itself for a literal or an unresolved screen, the chosen address for a
// resolved name.
func (t *InfraTargets) screenHTTP(ctx context.Context, host string, port int, resolve bool) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", nil
	}
	if port != 0 {
		if port < 0 || port > 65535 {
			return "", fmt.Errorf("invalid port %d", port)
		}
		if _, bad := streamDeniedPorts[port]; bad {
			return "", fmt.Errorf("port %d is reserved for the node admin API", port)
		}
	}
	if t.Blocked(host) {
		return "", fmt.Errorf("%s is a managed node or control-plane address", host)
	}
	if ip := net.ParseIP(host); ip != nil {
		if security.IsDangerousProxyBackend(ip) {
			return "", fmt.Errorf("address %s is not allowed", host)
		}
		return host, nil
	}
	if !resolve {
		return host, nil
	}
	addrs, err := lookupAddrs(ctx, host)
	if err != nil || len(addrs) == 0 {
		return "", fmt.Errorf("%w: %s", ErrUnresolved, host)
	}
	pin := ""
	for _, a := range addrs {
		lit := a.Unmap().String()
		if security.IsDangerousProxyBackend(net.IP(a.Unmap().AsSlice())) {
			return "", fmt.Errorf("host %s resolves to a blocked address", host)
		}
		if t.Blocked(lit) {
			return "", fmt.Errorf("host %s resolves to %s, a managed node or control-plane address", host, lit)
		}
		if pin == "" || lit < pin {
			pin = lit
		}
	}
	return pin, nil
}

// addEnvInfra denies the control-plane services this process itself talks to.
// They sit on the same bridge as the data plane, so a tenant route pointed at
// them would turn Caddy into a proxy for the panel's own dependencies.
func (t *InfraTargets) addEnvInfra() {
	t.AddURLHost(os.Getenv("CADDY_ADMIN_URL"))
	t.Add(os.Getenv("APP_INTERNAL_HOST"))
	// DB/Redis only by service name: on a single-box install their address can
	// be a LAN IP that also hosts legitimate customer backends, and denying a
	// whole host over a database port would break them.
	addNamed(t, os.Getenv("DB_HOST"))
	addNamed(t, hostOnly(os.Getenv("REDIS_ADDR")))
}

func addNamed(t *InfraTargets, v string) {
	v = strings.TrimSpace(v)
	if v == "" || net.ParseIP(v) != nil {
		return
	}
	t.Add(v)
}

// hostOnly strips an optional :port.
func hostOnly(addr string) string {
	addr = strings.TrimSpace(addr)
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}
