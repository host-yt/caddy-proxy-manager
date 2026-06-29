package main

import (
	"os"
	"path/filepath"
	"testing"
)

// initForwardOffset must never silently skip an existing backlog on a fresh
// start: with no (or a corrupt) sidecar it returns 0 so the backlog is
// forwarded once, unless tail-only is explicitly requested.
func TestInitForwardOffset(t *testing.T) {
	dir := t.TempDir()
	pos := filepath.Join(dir, "log.hpgpos")

	// No sidecar, default: forward the whole existing file once.
	if got := initForwardOffset(pos, 500, false); got != 0 {
		t.Errorf("missing sidecar default: want 0, got %d", got)
	}
	// No sidecar, tail-only opt-in: skip the backlog (start at EOF).
	if got := initForwardOffset(pos, 500, true); got != 500 {
		t.Errorf("missing sidecar tail-only: want 500, got %d", got)
	}

	// Valid saved offset within the file: resume there.
	if err := os.WriteFile(pos, []byte("123\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := initForwardOffset(pos, 500, false); got != 123 {
		t.Errorf("resume: want 123, got %d", got)
	}
	// tail-only must NOT override a real saved offset.
	if got := initForwardOffset(pos, 500, true); got != 123 {
		t.Errorf("resume with tail-only: want 123, got %d", got)
	}

	// Saved offset past EOF (rotation/truncation): re-read from 0.
	if err := os.WriteFile(pos, []byte("999"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := initForwardOffset(pos, 500, false); got != 0 {
		t.Errorf("rotation: want 0, got %d", got)
	}

	// Corrupt sidecar, default: treat as first run -> 0, never silent EOF loss.
	if err := os.WriteFile(pos, []byte("not-a-number"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := initForwardOffset(pos, 500, false); got != 0 {
		t.Errorf("corrupt sidecar default: want 0, got %d", got)
	}
}

// writeForwardPos/readForwardPos must round-trip so restarts resume instead of
// replaying the whole log.
func TestForwardPosRoundTrip(t *testing.T) {
	pos := filepath.Join(t.TempDir(), "rt.hpgpos")
	if got := readForwardPos(pos); got != -1 {
		t.Errorf("absent sidecar: want -1, got %d", got)
	}
	writeForwardPos(pos, 4096)
	if got := readForwardPos(pos); got != 4096 {
		t.Errorf("round-trip: want 4096, got %d", got)
	}
}
