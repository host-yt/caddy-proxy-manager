package auth

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// TestLegacyMintingDetectedDecodeError guards against a corrupt legacy key
// being silently treated as "no legacy sessions" - a decode failure must
// surface as an error so the operator isn't told the fleet is clean.
func TestLegacyMintingDetectedDecodeError(t *testing.T) {
	f := newFakeRedis()
	f.vals[legacySessionKeyPrefix+"bad"] = "{not json"
	m := testManager(f)

	found, err := m.LegacyMintingDetected(context.Background(), time.Now().Add(-time.Hour))
	if err == nil {
		t.Fatal("expected an error for an undecodable legacy session, got nil")
	}
	if found {
		t.Fatal("a decode failure must not also report a positive detection")
	}
}

// TestLegacyMintingDetectedFindsRecentSession is the happy-path control: a
// legacy key created after `since` is a live old replica minting sessions.
func TestLegacyMintingDetectedFindsRecentSession(t *testing.T) {
	f := newFakeRedis()
	since := time.Now().Add(-time.Hour)
	b, err := json.Marshal(Session{CreatedAt: time.Now()})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	f.vals[legacySessionKeyPrefix+"fresh"] = string(b)
	m := testManager(f)

	found, err := m.LegacyMintingDetected(context.Background(), since)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found {
		t.Fatal("expected a recent legacy session to be detected")
	}
}

// TestLegacyMintingDetectedClean confirms no false positives when nothing
// legacy is present.
func TestLegacyMintingDetectedClean(t *testing.T) {
	f := newFakeRedis()
	m := testManager(f)

	found, err := m.LegacyMintingDetected(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Fatal("expected no legacy session detected on an empty namespace")
	}
}
