// hpg-node-agent runs on each Caddy node as a privileged sidecar. Its
// sole job is to keep wg-tun0 (customer-tunnel WireGuard interface) in
// sync with the peer list the control panel exposes at
// /api/node/wg/peers, plus a static nftables rule that drops cross-peer
// forwarding (defense-in-depth against AllowedIPs misconfig).
//
// Configuration is env-based:
//
//	HPG_PANEL_URL        e.g. https://proxy.example.com
//	HPG_NODE_TOKEN       per-node bearer token (matches caddy_nodes.agent_token_hash)
//	HPG_WG_INTERFACE     defaults to wg-tun0
//	HPG_WG_LISTEN_PORT   defaults to 51821
//	HPG_WG_PRIVATE_KEY   base64 server-side private key (matches caddy_nodes.tunnel_privkey)
//	HPG_WG_GATEWAY_IP    e.g. 100.96.1.1/16 (this node's tunnel gateway IP + subnet)
//	HPG_POLL_INTERVAL    defaults to 30s
//
// The agent assumes wireguard-tools and nftables are installed and that
// it runs as root (NET_ADMIN cap is enough; in Docker mount /dev/net/tun
// and add cap_add: NET_ADMIN). It is deliberately tiny: ~250 LoC, no
// third-party deps beyond Go's stdlib.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type config struct {
	PanelURL        string
	NodeToken       string
	Interface       string
	ListenPort      string
	PrivateKey      string
	GatewayCIDR     string
	PollInterval    time.Duration
	TunnelTransport string // "udp"|"wss"|"auto"; default "udp"
	WstunnelPort    int    // loopback port for wstunnel server; default 0 (disabled)
}

// agentHTTP is a client-level backstop timeout: requests already set a
// per-call context deadline, but http.DefaultClient has none, so a future
// caller that forgets the ctx deadline would hang forever.
var agentHTTP = &http.Client{Timeout: 30 * time.Second}

// forwardHealth is the node-level forwarding diagnostic captured each
// firewall reconcile and shipped with stats so the panel can show WHY a
// peer is provisioned-but-dead (the silent blackhole modes).
type forwardHealth struct {
	IPForwardEnabled          bool   `json:"ip_forward_enabled"`
	ForwardPolicyDropDetected bool   `json:"forward_policy_drop_detected"`
	DockerRulesInstalled      bool   `json:"docker_rules_installed"`
	FirewallBackend           string `json:"firewall_backend"` // nft|iptables-legacy|firewalld|ufw|none
	MTU                       int    `json:"mtu"`
	ListenPort                string `json:"listen_port"`
	LastSetupError            string `json:"last_setup_error,omitempty"`
	WstunnelHealthy           *bool  `json:"wstunnel_healthy,omitempty"` // nil on UDP nodes; gates WSS advertising
}

// healthState holds the latest forwarding diagnostic + setup error string.
// Written on the (single-goroutine) reconcile path, read by the stats
// reporter; a plain mutex keeps it race-free without restructuring.
type healthState struct {
	mu sync.Mutex
	h  forwardHealth
}

func (s *healthState) set(h forwardHealth) {
	s.mu.Lock()
	// Preserve a previously recorded setup error if this pass had none.
	if h.LastSetupError == "" {
		h.LastSetupError = s.h.LastSetupError
	}
	s.h = h
	s.mu.Unlock()
}

func (s *healthState) get() forwardHealth {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.h
}

// health is the process-wide forwarding diagnostic shared between reconcile
// (writer) and reportStats (reader).
var health healthState

// wstunnelRunning is true while the wstunnel server is actually supervised. The
// panel reads this (via the node diag) to gate WSS route/installer rendering -
// it must never advertise WSS for a node that is not serving it.
var wstunnelRunning atomic.Bool

// wstunnelIngressOK is true when the host firewall actually lets Caddy's
// bridge->host hop reach the wstunnel port. WSS health = process up AND ingress
// reachable, so we never advertise WSS that Caddy can't reach (Oracle INPUT).
var wstunnelIngressOK atomic.Bool

func loadConfig() (config, error) {
	c := config{
		PanelURL:     os.Getenv("HPG_PANEL_URL"),
		NodeToken:    os.Getenv("HPG_NODE_TOKEN"),
		Interface:    envOr("HPG_WG_INTERFACE", "wg-tun0"),
		ListenPort:   envOr("HPG_WG_LISTEN_PORT", "51821"),
		PrivateKey:   os.Getenv("HPG_WG_PRIVATE_KEY"),
		GatewayCIDR:  os.Getenv("HPG_WG_GATEWAY_IP"),
		PollInterval: 30 * time.Second,
	}
	if d := os.Getenv("HPG_POLL_INTERVAL"); d != "" {
		if v, err := time.ParseDuration(d); err == nil {
			c.PollInterval = v
		}
	}
	c.TunnelTransport = envOr("HPG_TUNNEL_TRANSPORT", "udp")
	switch c.TunnelTransport {
	case "udp", "wss", "auto":
	default:
		return c, fmt.Errorf("invalid HPG_TUNNEL_TRANSPORT %q (want udp|wss|auto)", c.TunnelTransport)
	}
	c.WstunnelPort = 0
	if p := os.Getenv("HPG_WSTUNNEL_PORT"); p != "" {
		if n, err := strconv.Atoi(p); err == nil && n > 0 && n < 65536 {
			c.WstunnelPort = n
		}
	}
	if c.PanelURL == "" || c.NodeToken == "" || c.PrivateKey == "" || c.GatewayCIDR == "" {
		return c, fmt.Errorf("missing required env: HPG_PANEL_URL, HPG_NODE_TOKEN, HPG_WG_PRIVATE_KEY, HPG_WG_GATEWAY_IP")
	}
	// Interface + port are interpolated raw into the nft script; a malformed
	// value would break the ruleset (or inject rules). Linux ifname is <=15
	// chars, [A-Za-z0-9._-]; port is 1..65535.
	if !validIfname(c.Interface) {
		return c, fmt.Errorf("invalid HPG_WG_INTERFACE %q", c.Interface)
	}
	if n, err := strconv.Atoi(c.ListenPort); err != nil || n < 1 || n > 65535 {
		return c, fmt.Errorf("invalid HPG_WG_LISTEN_PORT %q", c.ListenPort)
	}
	return c, nil
}

// sanitizeCIDRList validates a comma-separated CIDR list before it is
// interpolated into the nft script. IPv4 only (the rule uses `ip saddr`), so an
// IPv6 CIDR is rejected as a config footgun. Returns def if anything is
// malformed, so a hostile env value can never inject nft rules.
func sanitizeCIDRList(in, def string) string {
	parts := strings.Split(in, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		ip, _, err := net.ParseCIDR(p)
		if err != nil || ip.To4() == nil {
			return def
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return def
	}
	return strings.Join(out, ", ")
}

// dockerBridgeCIDRs returns the IPv4 networks of docker bridge interfaces
// (docker0, br-*) so the wstunnel allowlist is exactly the Caddy-reachable
// bridges, not the whole 172.16/12. node-agent runs with host networking so it
// sees these interfaces. Empty when none are present.
func dockerBridgeCIDRs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, ifc := range ifaces {
		if ifc.Name != "docker0" && !strings.HasPrefix(ifc.Name, "br-") {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil {
				continue
			}
			network := &net.IPNet{IP: ipnet.IP.Mask(ipnet.Mask), Mask: ipnet.Mask}
			out = append(out, network.String())
		}
	}
	return out
}

// validIfname matches the Linux interface-name constraints.
func validIfname(s string) bool {
	if s == "" || len(s) > 15 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

// validPubkey checks a WireGuard base64 public key (32 bytes → 44 chars, '='
// terminated). validAllowedIP checks a CIDR. Both guard against a malformed
// panel response breaking the WHOLE syncconf (one bad peer = all peers lost).
func validPubkey(s string) bool {
	if len(s) != 44 || !strings.HasSuffix(s, "=") {
		return false
	}
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}

func validAllowedIP(s string) bool {
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	dry := flag.Bool("dry-run", false, "print actions, do not execute")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := loadConfig()
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := ensureInterface(ctx, log, cfg, *dry); err != nil {
		log.Error("interface setup failed", "err", err)
		os.Exit(1)
	}
	// Firewall is its own step now: nft (defense-in-depth) and the Docker
	// FORWARD-drop fix are independent. nft failure must not skip the
	// Docker rule (legacy-iptables hosts have no nft but still blackhole).
	nftErr := reconcileFirewall(ctx, log, cfg, *dry)
	if nftErr != nil {
		// Kernel cryptokey routing with AllowedIPs=/32 is still the
		// primary cross-tenant block; nftables is defense in depth. We
		// warn loudly and continue UNLESS the operator opts into
		// hard-fail via HPG_REQUIRE_NFTABLES=1 (paranoid deploys).
		log.Warn("nftables setup failed - kernel /32 routing still protects, but defense-in-depth disabled", "err", nftErr)
		if os.Getenv("HPG_REQUIRE_NFTABLES") == "1" {
			log.Error("HPG_REQUIRE_NFTABLES=1 set, aborting")
			os.Exit(3)
		}
	}

	// wstunnel lifecycle is tied to firewall health: the listener binds 0.0.0.0
	// and is only safe behind the nft input-drop rule, so a failed reconcile
	// must take it down (forced wss aborts; auto degrades to UDP).
	var wssCancel context.CancelFunc
	wssStart := func() {
		if wssCancel != nil {
			return // already running
		}
		if _, err := exec.LookPath("wstunnel"); err != nil {
			if cfg.TunnelTransport == "wss" {
				log.Error("transport=wss but wstunnel binary not found - cannot serve WSS, aborting", "err", err)
				os.Exit(4)
			}
			log.Warn("transport=auto but wstunnel binary not found - WSS fallback disabled, UDP only", "err", err)
			return
		}
		var wctx context.Context
		wctx, wssCancel = context.WithCancel(ctx)
		go superviseWstunnel(wctx, log, cfg)
	}
	wssStop := func(reason string, err error) {
		if wssCancel == nil {
			return
		}
		log.Warn("stopping wstunnel: "+reason, "err", err)
		wssCancel()
		wssCancel = nil
		wstunnelRunning.Store(false)
	}
	// wssReconcile (re)decides wstunnel state from the latest firewall result.
	wssReconcile := func(nftErr error) {
		if cfg.TunnelTransport == "udp" || cfg.WstunnelPort <= 0 {
			return
		}
		if nftErr != nil {
			if cfg.TunnelTransport == "wss" {
				log.Error("transport=wss but firewall isolation failed - refusing to expose wstunnel, aborting", "err", nftErr)
				os.Exit(5)
			}
			wssStop("firewall isolation failed (auto -> UDP only)", nftErr)
			return
		}
		wssStart()
	}
	wssReconcile(nftErr)

	log.Info("agent up", "iface", cfg.Interface, "panel", cfg.PanelURL, "poll", cfg.PollInterval.String())

	t := time.NewTicker(cfg.PollInterval)
	defer t.Stop()
	// First reconcile immediately.
	reconcile(ctx, log, cfg, *dry)
	for {
		select {
		case <-ctx.Done():
			log.Info("shutting down")
			return
		case <-t.C:
			// Re-run firewall each tick: a Docker restart/daemon reload
			// flushes DOCKER-USER and re-breaks tunnel forwarding, so the
			// fix must be reasserted (idempotent via iptables -C). Re-evaluate
			// wstunnel exposure against the fresh result.
			nftErr := reconcileFirewall(ctx, log, cfg, *dry)
			wssReconcile(nftErr)
			reconcile(ctx, log, cfg, *dry)
		}
	}
}

// reconcileFirewall runs the full node forwarding setup as independent steps
// and records a forwardHealth snapshot for telemetry. Steps:
//  1. ensure net.ipv4.ip_forward=1 (best-effort)
//  2. detect the firewall backend present (report-only)
//  3. install nft defense-in-depth rules (may fail -> error returned)
//  4. install Docker DOCKER-USER accept ALWAYS (decoupled from nft)
//  5. detect forward policy-drop (nft + iptables-legacy) -> report
//
// Returns the nft error (if any) so the caller keeps the existing
// require-nftables hard-fail semantics; all other steps are best-effort.
func reconcileFirewall(ctx context.Context, log *slog.Logger, c config, dry bool) error {
	hh := forwardHealth{ListenPort: c.ListenPort}
	hh.IPForwardEnabled = ensureIPForward(ctx, log, dry)
	hh.FirewallBackend = detectFirewallBackend(ctx)
	nftErr := ensureFirewall(ctx, log, c, dry)
	hh.DockerRulesInstalled = ensureDockerUserRules(ctx, log, c.Interface, dry)
	ensureWstunnelHostInputRule(ctx, log, c, dry)
	hh.ForwardPolicyDropDetected = forwardPolicyDropDetected(ctx, log)
	hh.MTU = currentTunnelMTU(c.Interface)
	if nftErr != nil {
		hh.LastSetupError = nftErr.Error()
	}
	health.set(hh)
	return nftErr
}

// ensureIPForward makes sure net.ipv4.ip_forward=1; without it the kernel
// will not route tunnel->backend at all (silent blackhole). Best-effort:
// read /proc, and if 0 try `sysctl -w`. Returns the effective state.
func ensureIPForward(ctx context.Context, log *slog.Logger, dry bool) bool {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return false // /proc absent (non-Linux/dry container); unknown -> false
	}
	if strings.TrimSpace(string(b)) == "1" {
		return true
	}
	if dry {
		log.Info("(dry) would enable net.ipv4.ip_forward")
		return false
	}
	log.Warn("net.ipv4.ip_forward=0 - tunnel->backend forwarding is disabled; enabling")
	if _, err := run(ctx, false, "sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		log.Warn("sysctl ip_forward enable failed", "err", err)
		// Fall back to writing /proc directly (sysctl may be absent).
		_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o644)
	}
	nb, _ := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	return strings.TrimSpace(string(nb)) == "1"
}

// detectFirewallBackend reports which firewall stack the host runs so the
// panel can flag risky setups. Report-only: we never reconfigure firewalld
// or ufw zones (too easy to lock the operator out). Order matters - a host
// may have multiple installed; we report the one most likely to govern
// forwarding.
func detectFirewallBackend(ctx context.Context) string {
	// firewalld/ufw sit ON TOP of nft/iptables and own the FORWARD policy,
	// so detect them first via a quick active-state probe.
	if _, err := exec.LookPath("firewall-cmd"); err == nil {
		c, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		if exec.CommandContext(c, "firewall-cmd", "--state").Run() == nil {
			return "firewalld"
		}
	}
	if _, err := exec.LookPath("ufw"); err == nil {
		c, cancel := context.WithTimeout(ctx, 2*time.Second)
		out, _ := exec.CommandContext(c, "ufw", "status").CombinedOutput()
		cancel()
		if strings.Contains(strings.ToLower(string(out)), "status: active") {
			return "ufw"
		}
	}
	if _, err := exec.LookPath("nft"); err == nil {
		return "nft"
	}
	if _, err := exec.LookPath("iptables"); err == nil {
		return "iptables-legacy"
	}
	return "none"
}

// currentTunnelMTU reads the live MTU of iface (post-setup) for telemetry.
func currentTunnelMTU(iface string) int {
	b, err := os.ReadFile("/sys/class/net/" + iface + "/mtu")
	if err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
			return n
		}
	}
	return 0
}

// ensureInterface brings wg-tun0 up (idempotent). Creates the iface,
// loads the private key, binds the listen port, and assigns the
// gateway IP/CIDR.
func ensureInterface(ctx context.Context, log *slog.Logger, c config, dry bool) error {
	// `ip link show wg-tun0` returns non-zero when the iface is absent;
	// only then do we create it. After create the rest is idempotent.
	if _, err := run(ctx, dry, "ip", "link", "show", c.Interface); err != nil {
		log.Info("creating interface", "iface", c.Interface)
		if _, err := run(ctx, dry, "ip", "link", "add", c.Interface, "type", "wireguard"); err != nil {
			return fmt.Errorf("ip link add: %w", err)
		}
	}
	// Address (idempotent: ip addr add is fine, dup returns error we ignore).
	_, _ = run(ctx, dry, "ip", "address", "add", c.GatewayCIDR, "dev", c.Interface)
	// MTU: probe the underlay path MTU to a public anchor and derive the WG
	// MTU (underlay - 80B WireGuard overhead). Falls back to 1420 (1500-80)
	// whenever the probe can't run, so a missing `ping` or filtered ICMP keeps
	// today's safe behaviour. 1420 still avoids the PMTU blackhole over WG/IPv4.
	mtu := deriveTunnelMTU(ctx, log, dry)
	_, _ = run(ctx, dry, "ip", "link", "set", c.Interface, "mtu", strconv.Itoa(mtu))
	// Bring up.
	if _, err := run(ctx, dry, "ip", "link", "set", c.Interface, "up"); err != nil {
		return fmt.Errorf("ip link set up: %w", err)
	}
	// Key file fed via stdin (avoid leaking on argv).
	if dry {
		log.Info("(dry) would set private key + listen port", "port", c.ListenPort)
		return nil
	}
	keyFile, err := writeTemp(c.PrivateKey)
	if err != nil {
		return err
	}
	defer os.Remove(keyFile)
	if _, err := run(ctx, dry, "wg", "set", c.Interface, "private-key", keyFile, "listen-port", c.ListenPort); err != nil {
		return fmt.Errorf("wg set key/port: %w", err)
	}
	return nil
}

const (
	wgOverhead = 80   // WireGuard encapsulation overhead (IPv4/UDP)
	mtuDefault = 1420 // 1500 underlay - wgOverhead; safe fallback
	mtuFloor   = 1280 // IPv6 minimum; never go below this
)

// deriveTunnelMTU probes the underlay path MTU to a public anchor and returns
// pathMTU - wgOverhead, clamped to [mtuFloor, 1420]. Any failure (no ping,
// filtered ICMP, dry-run) returns mtuDefault, preserving today's behaviour.
func deriveTunnelMTU(ctx context.Context, log *slog.Logger, dry bool) int {
	if dry {
		return mtuDefault
	}
	pmtu := probePathMTU(ctx, "1.1.1.1")
	if pmtu <= 0 {
		log.Info("mtu probe unavailable, using default", "mtu", mtuDefault)
		return mtuDefault
	}
	mtu := pmtu - wgOverhead
	if mtu > mtuDefault {
		mtu = mtuDefault // never exceed the conservative default
	}
	if mtu < mtuFloor {
		mtu = mtuFloor
	}
	log.Info("derived tunnel mtu from path probe", "path_mtu", pmtu, "wg_mtu", mtu)
	return mtu
}

// probePathMTU binary-searches the largest DF-bit ICMP packet that reaches host,
// returning the underlay path MTU in bytes, or 0 if ping is unavailable / all
// probes fail. ping -M do sets the don't-fragment bit (Linux only; node-agent
// runs in a Linux container). -s is the ICMP payload, so total = payload + 28.
func probePathMTU(ctx context.Context, host string) int {
	const icmpHdr = 28
	if _, err := exec.LookPath("ping"); err != nil {
		return 0
	}
	lo, hi, best := mtuFloor, 1500, 0
	for lo <= hi {
		mid := (lo + hi) / 2
		pctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := exec.CommandContext(pctx, "ping", "-M", "do", "-c", "1", "-W", "1",
			"-s", strconv.Itoa(mid-icmpHdr), host).Run()
		cancel()
		if err == nil {
			best = mid
			lo = mid + 1 // packet fit; try larger
		} else {
			hi = mid - 1 // too big (or dropped); try smaller
		}
	}
	return best
}

// ensureFirewall installs the nftables drop rules:
//  1. cross-peer forwarding block (cross-tenant defense in depth)
//  2. per-source HANDSHAKE rate limit on the listen port (ct state new only);
//     established WG data is never limited
//
// Idempotent: re-runs replace the chain content atomically. We use a
// dedicated table so we don't clash with operator rules.
//
// The Docker DOCKER-USER fix is NOT done here - reconcileFirewall runs it as
// an independent step so an nft failure (or absent nft) never skips it.
func ensureFirewall(ctx context.Context, log *slog.Logger, c config, dry bool) error {
	tableName := "hpg_tunnel"
	// `meter` is nftables' rate-limit primitive keyed on source IP. We limit
	// only NEW flows (ct state new = the handshake's first packet) to 10/s
	// burst 30 per source - enough for legit reconnects, tight enough to slow
	// handshake floods. Established WG data is NEVER limited: a blanket per-
	// packet cap throttled the whole tunnel to ~0.5 Mbit (removed in d08551f),
	// and WG's kernel cryptokey routing already drops invalid packets cheaply,
	// so the data plane needs no nft limiter. Volumetric floods are an upstream
	// (provider/Cloudflare) concern, not a node-local pps cap.
	// Two-step: first nuke the table (ignore "no such table" on first run),
	// then build it fresh in a single transactional script. A single nft -f
	// with `flush table` inline did NOT actually clear named meters in
	// practice (atomic tx semantics: the meter created by a later `add
	// rule` clashed with the meter that existed BEFORE the flush in the
	// same tx, because flush is also tx-deferred). Splitting makes the
	// delete fully commit before the add starts.
	if !dry {
		delCmd := exec.CommandContext(ctx, "nft", "delete", "table", "inet", tableName)
		_ = delCmd.Run() // ok to fail on first start when table doesn't exist
	}
	// Rule order in our forward chain: explicitly ACCEPT legit
	// tunnel->backend forwarding first (iif wg-tun0, oif NOT wg-tun0), then
	// DROP cross-tenant (iif==oif==wg-tun0). Makes intent explicit and ensures
	// our own chain never drops customer traffic.
	script := fmt.Sprintf(`
add table inet %s
add chain inet %s forward { type filter hook forward priority -10; policy accept; }
add rule inet %s forward ct state established,related accept comment "hpg: return traffic fast-path"
add rule inet %s forward iifname "%s" oifname != "%s" ct state new,established,related accept comment "allow tunnel->backend"
add rule inet %s forward iifname "%s" oifname "%s" drop comment "cross-tenant block"
add chain inet %s input { type filter hook input priority 0; policy accept; }
add rule inet %s input udp dport %s ct state new meter hpg_tun_new { ip saddr limit rate over 10/second burst 30 packets } drop comment "wg handshake rate limit"
add chain inet %s mangle_fwd { type filter hook forward priority -150; policy accept; }
add rule inet %s mangle_fwd oifname "%s" tcp flags syn tcp option maxseg size set rt mtu comment "MSS clamp out"
add rule inet %s mangle_fwd iifname "%s" tcp flags syn tcp option maxseg size set rt mtu comment "MSS clamp in"
`,
		tableName,
		tableName,
		tableName,                           // ct established,related accept
		tableName, c.Interface, c.Interface, // accept tunnel->backend
		tableName, c.Interface, c.Interface, // drop cross-tenant
		tableName,
		tableName, c.ListenPort, // handshake rate limit (ct state new only)
		tableName,
		tableName, c.Interface,
		tableName, c.Interface)
	// wstunnel server binds 0.0.0.0 (Caddy reaches it via the docker bridge
	// gateway). Drop everything except loopback + the Docker bridge range so a
	// LAN/VPC neighbour can't reach the raw WebSocket->WG path outside Caddy/TLS.
	// Docker default + user-defined bridges live in 172.16/12; operators on a
	// custom subnet (e.g. 10.x) widen it via HPG_WSTUNNEL_ALLOW_CIDR.
	if c.TunnelTransport != "udp" && c.WstunnelPort > 0 {
		// Allowlist precedence: explicit env override (sanitized, interpolated
		// into `nft -f` so it must be validated) > auto-detected docker bridges.
		// If neither yields a subnet we FAIL CLOSED (loopback only): Caddy can't
		// reach it either so WSS won't work, but the raw ws:// port is never
		// exposed. Operator must pin HPG_WSTUNNEL_ALLOW_CIDR to Caddy's subnet.
		allowSet := "127.0.0.0/8"
		if env := os.Getenv("HPG_WSTUNNEL_ALLOW_CIDR"); env != "" {
			allowSet = "127.0.0.0/8, " + sanitizeCIDRList(env, "127.0.0.0/8")
		} else if br := dockerBridgeCIDRs(); len(br) > 0 {
			allowSet = "127.0.0.0/8, " + strings.Join(br, ", ")
		} else {
			log.Warn("wstunnel ingress: no docker bridge detected and HPG_WSTUNNEL_ALLOW_CIDR unset - failing closed (loopback only); set the env to Caddy's subnet")
		}
		script += fmt.Sprintf(
			"add rule inet %s input tcp dport %d ip saddr != { %s } drop comment \"wstunnel: allowlist only\"\n",
			tableName, c.WstunnelPort, allowSet)
		log.Info("wstunnel ingress restricted", "allow", allowSet)
	}
	if dry {
		log.Info("(dry) nftables script", "script", script)
		return nil
	}
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft -f: %s: %w", strings.TrimSpace(string(out)), err)
	}
	log.Info("nftables drop rule installed", "table", tableName, "iface", c.Interface)
	return nil
}

// forwardPolicyDropDetected inspects the live ruleset for a forward base chain
// whose policy is drop. Such a chain (from an operator/host firewall) drops
// forwarded tunnel traffic regardless of our accept rules, because in nftables
// a drop in any base chain at a hook is terminal; on legacy iptables a FORWARD
// `policy DROP` does the same. We can't safely fix it from here (operator zones)
// so we surface it loudly AND report it. Best-effort: any probe error is
// ignored. Returns true if a drop policy was found in either backend.
func forwardPolicyDropDetected(ctx context.Context, log *slog.Logger) bool {
	detected := false
	// nftables path.
	if out, err := exec.CommandContext(ctx, "nft", "list", "ruleset").CombinedOutput(); err == nil {
		inForward := false
		for _, line := range strings.Split(string(out), "\n") {
			l := strings.TrimSpace(line)
			if strings.Contains(l, "hook forward") {
				inForward = true
				if strings.Contains(l, "policy drop") { // header may carry policy inline
					detected = true
					inForward = false
				}
				continue
			}
			if inForward {
				if strings.HasPrefix(l, "policy drop") {
					detected = true
				}
				if l == "}" {
					inForward = false
				}
			}
		}
	}
	// Legacy iptables path: `iptables -L FORWARD` header shows the policy.
	if out, err := exec.CommandContext(ctx, "iptables", "-L", "FORWARD", "-n").CombinedOutput(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			l := strings.TrimSpace(line)
			if strings.HasPrefix(l, "Chain FORWARD") && strings.Contains(l, "policy DROP") {
				detected = true
				break
			}
		}
	}
	if detected {
		log.Warn("host firewall has a 'forward' chain/policy DROP - it will drop tunnel->backend traffic; our DOCKER-USER accept covers Docker, but a host firewalld/ufw/base ruleset may still need accept for wg-tun0 forwarding")
	}
	return detected
}

// ensureDockerUserRules adds iptables ACCEPT rules in DOCKER-USER for iface.
// Docker sets FORWARD policy drop and routes all traffic through DOCKER-USER;
// without explicit accept here, tunnel->backend forwarding is silently dropped
// on hosts where Docker and the node-agent share the same network namespace.
// Re-run every poll: a Docker restart/daemon reload flushes DOCKER-USER.
// Returns true when DOCKER-USER is present AND both directions are accepted
// (so telemetry can distinguish "no Docker" from "Docker but insert failed").
func ensureDockerUserRules(ctx context.Context, log *slog.Logger, iface string, dry bool) bool {
	// Missing DOCKER-USER chain = Docker absent. Normal on bare-metal/VM
	// hosts; skip silently (not an error).
	if exec.CommandContext(ctx, "iptables", "-L", "DOCKER-USER", "-n").Run() != nil {
		return false
	}
	ok := true
	for _, dir := range []string{"-i", "-o"} {
		ruleArgs := []string{"DOCKER-USER", dir, iface, "-j", "ACCEPT"}
		if exec.CommandContext(ctx, "iptables", append([]string{"-C"}, ruleArgs...)...).Run() == nil {
			continue // already present
		}
		if dry {
			log.Info("(dry) would insert iptables DOCKER-USER rule", "dir", dir, "iface", iface)
			continue
		}
		// Docker present but insert failed = permission/backend error, not the
		// benign "no Docker" case. Surface it loudly so the operator gets a signal.
		if out, err := exec.CommandContext(ctx, "iptables", append([]string{"-I"}, ruleArgs...)...).CombinedOutput(); err != nil {
			ok = false
			log.Warn("iptables DOCKER-USER insert failed", "dir", dir, "iface", iface, "err", err, "out", strings.TrimSpace(string(out)))
		} else {
			log.Info("iptables DOCKER-USER accept added", "dir", dir, "iface", iface)
		}
	}
	return ok
}

// ensureWstunnelHostInputRule lets Caddy's bridge->host hop reach the wstunnel
// server on hosts with a default-REJECT INPUT (Oracle Cloud:
// `-A INPUT -j REJECT --reject-with icmp-host-prohibited`). Inserted at the top
// so it precedes that REJECT; idempotent, re-run every poll (reloads flush it).
// Stores the outcome in wstunnelIngressOK so WSS health reflects reachability:
// if the punch fails, Caddy can't reach wstunnel and we must NOT advertise WSS.
func ensureWstunnelHostInputRule(ctx context.Context, log *slog.Logger, c config, dry bool) {
	if c.TunnelTransport == "udp" || c.WstunnelPort <= 0 {
		wstunnelIngressOK.Store(true) // n/a on UDP nodes
		return
	}
	// Resolve the allowed source CIDRs first. With NONE (bridge detection
	// failed or env sanitized empty) BOTH the nft allowlist and this rule fall
	// closed to loopback-only, so Caddy's bridge cannot reach wstunnel - report
	// ingress UNHEALTHY rather than advertise a WSS path Caddy can't proxy.
	var cidrs []string
	if env := os.Getenv("HPG_WSTUNNEL_ALLOW_CIDR"); env != "" {
		if s := sanitizeCIDRList(env, ""); s != "" {
			cidrs = strings.Split(s, ", ")
		}
	} else {
		cidrs = dockerBridgeCIDRs()
	}
	usable := 0
	for _, cc := range cidrs {
		if strings.TrimSpace(cc) != "" {
			usable++
		}
	}
	if usable == 0 {
		log.Warn("wstunnel ingress: no usable allow CIDR (no docker bridge / empty HPG_WSTUNNEL_ALLOW_CIDR) - Caddy can't reach wstunnel; reporting WSS unhealthy")
		wstunnelIngressOK.Store(false)
		return
	}
	// iptables-legacy absent (pure-nft host) = nothing to punch; our nft input
	// chain already accepts the resolved CIDRs, so ingress is fine.
	if exec.CommandContext(ctx, "iptables", "-L", "INPUT", "-n").Run() != nil {
		wstunnelIngressOK.Store(true)
		return
	}
	port := strconv.Itoa(c.WstunnelPort)
	ok := true
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		body := []string{"-s", cidr, "-p", "tcp", "--dport", port, "-j", "ACCEPT"}
		if exec.CommandContext(ctx, "iptables", append([]string{"-C", "INPUT"}, body...)...).Run() == nil {
			continue // already present
		}
		if dry {
			log.Info("(dry) would insert iptables INPUT accept for wstunnel", "cidr", cidr, "port", port)
			continue
		}
		if out, err := exec.CommandContext(ctx, "iptables", append([]string{"-I", "INPUT", "1"}, body...)...).CombinedOutput(); err != nil {
			ok = false
			log.Warn("iptables INPUT wstunnel accept failed", "cidr", cidr, "port", port, "err", err, "out", strings.TrimSpace(string(out)))
		} else {
			log.Info("iptables INPUT wstunnel accept added", "cidr", cidr, "port", port)
		}
	}
	wstunnelIngressOK.Store(ok)
}

type peerListReply struct {
	Peers []struct {
		Pubkey    string `json:"pubkey"`
		AllowedIP string `json:"allowed_ip"`
		Status    string `json:"status"`
	} `json:"peers"`
}

// reconcile fetches the desired peer set from the panel and applies it
// to wg-tun0 via `wg syncconf`. Revoked peers are removed. Handshake
// timestamps are reported back as a best-effort observability signal.
func reconcile(ctx context.Context, log *slog.Logger, c config, dry bool) {
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	url := c.PanelURL + "/api/node/wg/peers"
	req, _ := http.NewRequestWithContext(pctx, http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+c.NodeToken)
	resp, err := agentHTTP.Do(req)
	if err != nil {
		log.Warn("pull failed", "err", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		log.Warn("pull non-200", "code", resp.StatusCode, "body", strings.TrimSpace(string(body)))
		return
	}
	var reply peerListReply
	if err := json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		log.Warn("pull decode", "err", err)
		return
	}

	// Build a `wg syncconf` config snippet. syncconf replaces the whole
	// peer set atomically - exactly the semantics we want (revoked peers
	// disappear without an explicit `peer remove`).
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nListenPort = %s\nPrivateKey = %s\n\n", c.ListenPort, c.PrivateKey)
	active := 0
	for _, p := range reply.Peers {
		if p.Status != "active" && p.Status != "pending" {
			continue
		}
		if p.Pubkey == "" || p.AllowedIP == "" {
			continue
		}
		// Reject malformed entries: one bad line would make `wg syncconf`
		// reject the entire config, dropping every peer at once.
		if !validPubkey(p.Pubkey) || !validAllowedIP(p.AllowedIP) {
			log.Warn("skipping malformed peer", "pubkey", p.Pubkey, "allowed_ip", p.AllowedIP)
			continue
		}
		// PersistentKeepalive keeps the NAT mapping warm in both directions so
		// idle reverse-proxy tunnels don't blackhole (node→customer) until the
		// customer re-punches. 25s is the WireGuard-recommended value.
		fmt.Fprintf(&b, "[Peer]\nPublicKey = %s\nAllowedIPs = %s\nPersistentKeepalive = 25\n\n", p.Pubkey, p.AllowedIP)
		active++
	}
	if dry {
		log.Info("(dry) syncconf would apply", "peers", active)
		return
	}
	confPath, err := writeTemp(b.String())
	if err != nil {
		log.Warn("temp conf", "err", err)
		return
	}
	defer os.Remove(confPath)
	if _, err := run(pctx, false, "wg", "syncconf", c.Interface, confPath); err != nil {
		log.Warn("wg syncconf", "err", err)
		return
	}
	log.Info("reconciled", "peers", active)

	// Best-effort handshake report (form-encoded so the panel handler
	// stays trivial).
	go reportStats(ctx, log, c)
}

// peerStat is one peer's WireGuard counters as parsed from `wg show <iface> dump`.
type peerStat struct {
	Pubkey        string `json:"pubkey"`
	LastHandshake int64  `json:"last_handshake"` // unix epoch (0 = never)
	RxBytes       int64  `json:"rx_bytes"`
	TxBytes       int64  `json:"tx_bytes"`
	Endpoint      string `json:"endpoint"` // "(none)" mapped to ""
}

// reportStats parses `wg show <iface> dump` and POSTs per-peer stats
// (handshake epoch, rx/tx bytes, observed endpoint) plus node-level
// forwarding diagnostics as JSON to /api/node/wg/stats so the panel can show a
// health badge, traffic, AND "provisioned but never connected" peers.
func reportStats(ctx context.Context, log *slog.Logger, c config) {
	out, err := run(ctx, false, "wg", "show", c.Interface, "dump")
	if err != nil {
		return
	}
	var stats []peerStat
	for i, line := range strings.Split(strings.TrimSpace(out), "\n") {
		// First line is the interface itself; peers follow.
		if i == 0 {
			continue
		}
		// dump columns: 0 pubkey, 1 psk, 2 endpoint, 3 allowed_ips,
		// 4 latest_handshake_epoch, 5 rx_bytes, 6 tx_bytes, 7 keepalive.
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		pubkey := fields[0]
		if len(pubkey) != 44 || !strings.HasSuffix(pubkey, "=") {
			continue
		}
		// Report EVERY configured peer, including hs==0 (never handshook), so
		// the panel can flag "provisioned but never connected". The server
		// guards against clobbering a good timestamp with 0.
		hs, _ := strconv.ParseInt(fields[4], 10, 64)
		rx, _ := strconv.ParseInt(fields[5], 10, 64)
		tx, _ := strconv.ParseInt(fields[6], 10, 64)
		ep := fields[2]
		if ep == "(none)" {
			ep = ""
		}
		stats = append(stats, peerStat{Pubkey: pubkey, LastHandshake: hs, RxBytes: rx, TxBytes: tx, Endpoint: ep})
	}
	// Always POST node diagnostics even when no peers are configured, so a
	// blackholed node (ip_forward=0, FORWARD drop) is visible in the panel.
	hh := health.get()
	// Report wstunnel liveness so the panel only advertises WSS when the node
	// is actually serving it (nil on UDP nodes - not applicable).
	if c.TunnelTransport != "udp" {
		// Healthy only when the server is up AND Caddy's ingress to it works;
		// a running process behind a rejecting host firewall is not serviceable.
		v := wstunnelRunning.Load() && wstunnelIngressOK.Load()
		hh.WstunnelHealthy = &v
	}
	body, err := json.Marshal(map[string]any{"stats": stats, "node": hh})
	if err != nil {
		return
	}
	pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(pctx, http.MethodPost,
		c.PanelURL+"/api/node/wg/stats", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+c.NodeToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := agentHTTP.Do(req)
	if err != nil {
		log.Debug("stats report", "err", err)
		return
	}
	resp.Body.Close()
}

// superviseWstunnel keeps wstunnel server alive; restarts on crash (5s backoff).
// Forwards all incoming WebSocket connections to WG's local UDP port.
func superviseWstunnel(ctx context.Context, log *slog.Logger, c config) {
	bind := "ws://0.0.0.0:" + strconv.Itoa(c.WstunnelPort)
	target := "127.0.0.1:" + c.ListenPort
	defer wstunnelRunning.Store(false)
	for {
		log.Info("starting wstunnel server", "bind", bind, "wg_target", target)
		// Server accepts any upgrade path; the WSS port is already locked to the
		// docker bridge (nft + iptables), so a path restriction adds no real guard.
		cmd := exec.CommandContext(ctx, "wstunnel", "server",
			"--restrict-to", target, bind)
		wstunnelRunning.Store(true)
		out, err := cmd.CombinedOutput()
		wstunnelRunning.Store(false)
		if ctx.Err() != nil {
			return
		}
		log.Warn("wstunnel exited", "err", err, "output", strings.TrimSpace(string(out)))
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

// run executes a shell command and returns combined output.
func run(ctx context.Context, dry bool, name string, args ...string) (string, error) {
	if dry {
		return fmt.Sprintf("(dry) %s %s", name, strings.Join(args, " ")), nil
	}
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// writeTemp writes content to a 0600 tempfile and returns the path.
func writeTemp(content string) (string, error) {
	f, err := os.CreateTemp("", "hpg-agent-*.conf")
	if err != nil {
		return "", err
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return "", err
	}
	f.Close()
	return f.Name(), nil
}
