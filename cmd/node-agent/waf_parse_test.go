package main

import "testing"

// A realistic Coraza v3 JSON audit line (SecAuditLogFormat JSON): rule id and
// severity are NUMBERS, the message data object key is "data", the client IP is
// "client_ip", and the timestamp is Apache-style. This locks the parser to the
// real schema - the previous struct used "details"/"ruleId"/"remote_address"
// and would have silently produced zero events.
const corazaSampleLine = `{"transaction":{"timestamp":"28/Jun/2026:13:54:06 +0000","unix_timestamp":1782654846,"client_ip":"85.222.65.102","client_port":60198,"request":{"uri":"/?id=1' UNION SELECT NULL,NULL--","headers":{"Host":["sso.example.com"],"User-Agent":["curl/8"]}}},"messages":[{"message":"SQL Injection Attack Detected via libinjection","data":{"id":942100,"severity":2,"msg":"SQL Injection Attack Detected via libinjection"}}],"interruption":{"action":"deny"}}`

func TestParseCorazaLines_RealSchema(t *testing.T) {
	evs := parseCorazaLines([]byte(corazaSampleLine + "\n"))
	if len(evs) != 1 {
		t.Fatalf("expected 1 event, got %d", len(evs))
	}
	e := evs[0]
	if e.RuleID != "942100" {
		t.Errorf("rule_id: got %q want 942100", e.RuleID)
	}
	if e.Severity != "critical" { // numeric 2 -> critical
		t.Errorf("severity: got %q want critical", e.Severity)
	}
	if e.Action != "blocked" { // interruption present
		t.Errorf("action: got %q want blocked", e.Action)
	}
	if e.RemoteIP != "85.222.65.102" {
		t.Errorf("remote_ip: got %q", e.RemoteIP)
	}
	if e.Host != "sso.example.com" { // case-insensitive header lookup
		t.Errorf("host: got %q want sso.example.com", e.Host)
	}
	if e.TS != "2026-06-28T13:54:06Z" { // apache ts -> RFC3339 UTC
		t.Errorf("ts: got %q want 2026-06-28T13:54:06Z", e.TS)
	}
	if e.URI == "" || e.Message == "" {
		t.Errorf("uri/message must be populated: %+v", e)
	}
}

// Detection-only entries have no interruption -> action "detected".
func TestParseCorazaLines_DetectionAndStringSeverity(t *testing.T) {
	line := `{"transaction":{"unix_timestamp":1782654846,"client_ip":"1.2.3.4","request":{"uri":"/x","headers":{}}},"messages":[{"message":"XSS","data":{"id":"941100","severity":"critical"}}]}`
	evs := parseCorazaLines([]byte(line))
	if len(evs) != 1 {
		t.Fatalf("expected 1 event, got %d", len(evs))
	}
	if evs[0].Action != "detected" {
		t.Errorf("action: got %q want detected", evs[0].Action)
	}
	if evs[0].RuleID != "941100" || evs[0].Severity != "critical" {
		t.Errorf("string-form id/severity not handled: %+v", evs[0])
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
