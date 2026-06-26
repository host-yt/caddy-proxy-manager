package chatstore_test

import (
	"testing"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/chatstore"
)

// Verify struct fields are accessible and zero-valued correctly (no live DB needed).
func TestStructFields(t *testing.T) {
	var sess chatstore.Session
	if sess.ID != 0 || sess.UserID != 0 {
		t.Fatal("unexpected non-zero Session defaults")
	}
	if sess.Title != "" || sess.Provider != "" {
		t.Fatal("unexpected non-empty Session string defaults")
	}
	var z time.Time
	if sess.CreatedAt != z || sess.UpdatedAt != z {
		t.Fatal("unexpected non-zero Session time defaults")
	}

	var msg chatstore.Message
	if msg.ID != 0 || msg.SessionID != 0 {
		t.Fatal("unexpected non-zero Message defaults")
	}
	if msg.Role != "" || msg.Content != "" {
		t.Fatal("unexpected non-empty Message string defaults")
	}
}

// ErrNotFound must be a non-nil sentinel so callers can errors.Is check it.
func TestErrNotFoundSentinel(t *testing.T) {
	if chatstore.ErrNotFound == nil {
		t.Fatal("ErrNotFound must not be nil")
	}
	if chatstore.ErrNotFound.Error() == "" {
		t.Fatal("ErrNotFound must have a non-empty message")
	}
}

// New must return a non-nil Store even when given a nil DB; the nil DB will
// only panic when a method is actually called - construction itself is safe.
func TestNewNotNil(t *testing.T) {
	s := chatstore.New(nil)
	if s == nil {
		t.Fatal("New(nil) returned nil Store")
	}
}
