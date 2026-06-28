package main

import "testing"

// A VERBATIM coraza-caddy v2 JSON audit line captured from prod: rule details
// are in messages[].error_message (data is null, message is empty), host is
// transaction.server_id, unix_timestamp is nanoseconds, and the timestamp is
// "2006/01/02 15:04:05". This locks the parser to the real emitted schema.
const corazaSampleLine = `{"transaction":{"timestamp":"2026/06/28 14:23:55","unix_timestamp":1782656635784730907,"id":"FtOIiOOzqTxjyCIl","client_ip":"85.222.65.102","client_port":0,"server_id":"sso.example.com","request":{"method":"GET","uri":"/?q=<script>alert(1)</script>","headers":{"host":["sso.example.com"],"user-agent":["curl/8.7.1"]}},"is_interrupted":false},"messages":[{"actionset":"","message":"","error_message":"[client \"85.222.65.102\"] Coraza: Warning. XSS Attack Detected via libinjection [file \"@owasp_crs/REQUEST-941-APPLICATION-ATTACK-XSS.conf\"] [line \"5178\"] [id \"941100\"] [msg \"XSS Attack Detected via libinjection\"] [data \"Matched Data: XSS data\"] [severity \"critical\"] [tag \"attack-xss\"] [unique_id \"FtOIiOOzqTxjyCIl\"]","data":null}]}`

func TestParseCorazaLines_RealSchema(t *testing.T) {
	evs := parseCorazaLines([]byte(corazaSampleLine + "\n"))
	if len(evs) != 1 {
		t.Fatalf("expected 1 event, got %d", len(evs))
	}
	e := evs[0]
	if e.RuleID != "941100" {
		t.Errorf("rule_id: got %q want 941100 (from error_message blob)", e.RuleID)
	}
	if e.Severity != "critical" {
		t.Errorf("severity: got %q want critical", e.Severity)
	}
	if e.Action != "detected" { // is_interrupted false
		t.Errorf("action: got %q want detected", e.Action)
	}
	if e.RemoteIP != "85.222.65.102" {
		t.Errorf("remote_ip: got %q", e.RemoteIP)
	}
	if e.Host != "sso.example.com" { // from server_id
		t.Errorf("host: got %q want sso.example.com", e.Host)
	}
	if e.TS != "2026-06-28T14:23:55Z" { // "2006/01/02 15:04:05" -> RFC3339 UTC
		t.Errorf("ts: got %q want 2026-06-28T14:23:55Z", e.TS)
	}
	if e.Message != "XSS Attack Detected via libinjection" {
		t.Errorf("message: got %q (want the [msg ...] field)", e.Message)
	}
	if e.URI == "" {
		t.Errorf("uri must be populated: %+v", e)
	}
}

// A blocked request: is_interrupted=true -> action "blocked". Also proves the
// nanosecond unix_timestamp fallback when no timestamp string is present.
func TestParseCorazaLines_BlockedAndNanoUnix(t *testing.T) {
	line := `{"transaction":{"unix_timestamp":1782656635784730907,"client_ip":"1.2.3.4","server_id":"x.example","is_interrupted":true,"request":{"uri":"/x","headers":{}}},"messages":[{"error_message":"[id \"942100\"] [severity \"CRITICAL\"] [msg \"SQLi\"]"}]}`
	evs := parseCorazaLines([]byte(line))
	if len(evs) != 1 {
		t.Fatalf("expected 1 event, got %d", len(evs))
	}
	if evs[0].Action != "blocked" {
		t.Errorf("action: got %q want blocked", evs[0].Action)
	}
	if evs[0].RuleID != "942100" || evs[0].Severity != "critical" {
		t.Errorf("id/severity from blob: %+v", evs[0])
	}
	if evs[0].TS != "2026-06-28T14:23:55Z" {
		t.Errorf("nano unix ts: got %q", evs[0].TS)
	}
}

// wafBatchBounds must process complete lines, wait on a partial trailing line,
// and skip (not loop on) a single oversized record that fills the read window.
func TestWAFBatchBounds(t *testing.T) {
	// complete lines: process up to last newline
	if n, skip := wafBatchBounds([]byte("a\nb\n"), false); n != 4 || skip {
		t.Errorf("complete lines: got n=%d skip=%v want 4,false", n, skip)
	}
	// trailing partial line (not at cap): wait, don't advance
	if n, skip := wafBatchBounds([]byte("a\npartial"), false); n != 2 || skip {
		t.Errorf("partial line: got n=%d skip=%v want 2,false", n, skip)
	}
	// no newline at all, not at cap: wait
	if n, skip := wafBatchBounds([]byte("stillwriting"), false); n != 0 || skip {
		t.Errorf("no newline, not cap: got n=%d skip=%v want 0,false", n, skip)
	}
	// no newline AND window full: oversized record -> skip (the deadlock fix)
	if n, skip := wafBatchBounds([]byte("giantrecordnotnewline"), true); n != 0 || !skip {
		t.Errorf("oversized: got n=%d skip=%v want 0,true", n, skip)
	}
}

// Lines without a rule id or without messages are skipped (panel rejects them).
func TestParseCorazaLines_SkipsEmpty(t *testing.T) {
	in := `{"transaction":{"client_ip":"1.2.3.4"},"messages":[]}` + "\n" +
		`not json` + "\n" +
		`{"transaction":{"client_ip":"1.2.3.4"},"messages":[{"message":"m","data":{"severity":2}}]}`
	if evs := parseCorazaLines([]byte(in)); len(evs) != 0 {
		t.Errorf("expected 0 events, got %d: %+v", len(evs), evs)
	}
}
