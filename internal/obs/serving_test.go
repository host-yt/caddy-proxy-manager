package obs

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// TestServingGateStartsClosed: nothing may advertise before the listener is
// proven, which is the whole point of the gate.
func TestServingGateStartsClosed(t *testing.T) {
	g := NewServingGate(0)
	if err := g.Check(context.Background()); !errors.Is(err, ErrNotServing) {
		t.Fatalf("want ErrNotServing, got %v", err)
	}
	g.MarkServing()
	if err := g.Check(context.Background()); err != nil {
		t.Fatalf("gate must open once serving, got %v", err)
	}
	bindErr := errors.New("address already in use")
	g.MarkStopped(bindErr)
	if err := g.Check(context.Background()); !errors.Is(err, bindErr) {
		t.Fatalf("want the bind error back, got %v", err)
	}
}

// TestServingGateSettleWindow: a listener that only just came up is not yet
// trusted, so a flapping bind cannot produce a moment of advertisement.
func TestServingGateSettleWindow(t *testing.T) {
	g := NewServingGate(time.Hour)
	g.MarkServing()
	if err := g.Check(context.Background()); !errors.Is(err, ErrNotServing) {
		t.Fatalf("gate must stay closed during the settle window, got %v", err)
	}
}

// TestHealthLocalServingReadyIncludesListener: the beacon's local readiness
// must fail while the listener is not serving.
func TestHealthLocalServingReadyIncludesListener(t *testing.T) {
	g := NewServingGate(0)
	h := &Health{Serving: g.Check}
	if err := h.LocalServingReady(context.Background()); err == nil {
		t.Fatal("local readiness must fail without a serving listener")
	}
	g.MarkServing()
	if err := h.LocalServingReady(context.Background()); err != nil {
		t.Fatalf("local readiness must pass once serving, got %v", err)
	}
}

func TestLoopbackTarget(t *testing.T) {
	cases := map[string]string{
		"0.0.0.0:8080":   "127.0.0.1:8080",
		"[::]:8080":      "[::1]:8080",
		"127.0.0.1:9000": "127.0.0.1:9000",
		"10.0.0.5:80":    "10.0.0.5:80",
	}
	for in, want := range cases {
		if got := LoopbackTarget(fakeAddr(in)); got != want {
			t.Fatalf("LoopbackTarget(%s) = %s, want %s", in, got, want)
		}
	}
}

type fakeAddr string

func (fakeAddr) Network() string  { return "tcp" }
func (a fakeAddr) String() string { return string(a) }

var _ net.Addr = fakeAddr("")
