// Preflight doctor for the node-agent: read-only checks a fresh Caddy node
// needs before it can serve traffic or join the panel's tunnel mesh.
//
// Deliberately stdlib-only (no internal/caddyapi import) to keep the agent's
// dependency-free build intact - see the package doc on main.go.
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"text/tabwriter"
	"time"
)

type checkStatus string

const (
	statusPass checkStatus = "PASS"
	statusWarn checkStatus = "WARN"
	statusFail checkStatus = "FAIL"
)

type check struct {
	name   string
	status checkStatus
	detail string
}

// runDoctor runs the node-agent's preflight checks and prints a PASS/WARN/FAIL
// table. Returns the process exit code (1 if any check FAILed).
func runDoctor() int {
	fmt.Println("Hostyt Proxy Gateway - node-agent preflight doctor")
	fmt.Println()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	adminURL := envOr("HPG_CADDY_ADMIN_URL", "http://localhost:2019")
	caddyUp, adminCheck := doctorCaddyAdminLocal(ctx, adminURL)

	var checks []check
	checks = append(checks, adminCheck)
	checks = append(checks, doctorPort("80", caddyUp), doctorPort("443", caddyUp))
	checks = append(checks, doctorWstunnelBinary())
	checks = append(checks, doctorPanelReachable(ctx)...)

	printDoctorChecks(checks)
	return summarizeDoctor(checks)
}

// doctorCaddyAdminLocal checks the local Caddy admin API. Plain net/http GET
// (not internal/caddyapi) - importing that package would pull in every
// DNS-provider module it registers, bloating this otherwise stdlib-only binary.
func doctorCaddyAdminLocal(ctx context.Context, adminURL string) (bool, check) {
	reqCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, strings.TrimRight(adminURL, "/")+"/config/", nil)
	if err != nil {
		return false, check{"caddy: admin API (local)", statusFail, err.Error()}
	}
	resp, err := agentHTTP.Do(req)
	if err != nil {
		return false, check{"caddy: admin API (local)", statusFail,
			err.Error() + " - verify the local Caddy container is up; override with HPG_CADDY_ADMIN_URL"}
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return false, check{"caddy: admin API (local)", statusFail,
			fmt.Sprintf("HTTP %d from %s", resp.StatusCode, adminURL)}
	}
	return true, check{"caddy: admin API (local)", statusPass, adminURL + " reachable"}
}

// doctorPort reports whether a listen port is free, or - if occupied - whether
// the local Caddy admin API confirms Caddy is the one holding it. We can't
// enumerate the socket owner without extra host tooling, so admin-API
// reachability is the best-effort proxy for "occupied by Caddy".
func doctorPort(port string, caddyUp bool) check {
	ln, err := net.Listen("tcp", ":"+port)
	if err == nil {
		ln.Close()
		return check{"port " + port, statusPass, "free and bindable"}
	}
	if caddyUp {
		return check{"port " + port, statusPass, "in use, but local Caddy admin API confirms Caddy owns it"}
	}
	return check{"port " + port, statusFail,
		err.Error() + " - held by an unknown process; Caddy admin API is not reachable to confirm ownership"}
}

// doctorWstunnelBinary mirrors the runtime posture in wssStart(): "wss" hard-
// requires the binary (agent would os.Exit(4)), "auto" degrades to UDP-only,
// "udp" never needs it.
func doctorWstunnelBinary() check {
	transport := envOr("HPG_TUNNEL_TRANSPORT", "udp")
	_, err := exec.LookPath("wstunnel")
	switch {
	case transport == "udp":
		return check{"tunnel: wstunnel binary", statusPass, "transport=udp, wstunnel not required"}
	case err == nil:
		return check{"tunnel: wstunnel binary", statusPass, "found (transport=" + transport + ")"}
	case transport == "wss":
		return check{"tunnel: wstunnel binary", statusFail,
			"transport=wss requires wstunnel but it is not on PATH - install it (see deploy/node-agent/Dockerfile)"}
	default: // "auto"
		return check{"tunnel: wstunnel binary", statusWarn,
			"transport=auto but wstunnel not found - WSS fallback disabled, UDP-only"}
	}
}

// doctorPanelReachable is a soft outbound check: only runs when HPG_PANEL_URL
// is set, since a node isn't necessarily joined to a panel yet at doctor time.
func doctorPanelReachable(ctx context.Context) []check {
	panelURL := os.Getenv("HPG_PANEL_URL")
	if panelURL == "" {
		return nil
	}
	url := strings.TrimRight(panelURL, "/") + "/healthz"
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return []check{{"panel: outbound reachability", statusFail, err.Error()}}
	}
	resp, err := agentHTTP.Do(req)
	if err != nil {
		return []check{{"panel: outbound reachability", statusFail,
			err.Error() + " - verify HPG_PANEL_URL and outbound network/firewall/DNS"}}
	}
	resp.Body.Close()
	return []check{{"panel: outbound reachability", statusPass, fmt.Sprintf("%s -> HTTP %d", url, resp.StatusCode)}}
}

func printDoctorChecks(checks []check) {
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "STATUS\tCHECK\tDETAIL")
	for _, c := range checks {
		fmt.Fprintf(w, "%s\t%s\t%s\n", c.status, c.name, c.detail)
	}
	w.Flush()
}

// summarizeDoctor prints pass/warn/fail totals and returns the process exit code.
func summarizeDoctor(checks []check) int {
	var pass, warn, fail int
	for _, c := range checks {
		switch c.status {
		case statusPass:
			pass++
		case statusWarn:
			warn++
		case statusFail:
			fail++
		}
	}
	fmt.Printf("\n%d passed, %d warned, %d failed\n", pass, warn, fail)
	if fail > 0 {
		return 1
	}
	return 0
}
