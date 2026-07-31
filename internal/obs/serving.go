package obs

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// ErrNotServing means this process has not (yet) proven it owns its HTTP
// listener, so it must not claim the fleet's newest generation.
var ErrNotServing = errors.New("http listener is not serving")

// ServingGate tracks whether this replica's listener is bound and answered a
// real request on it. The generation beacon gates advertising on this: a
// process whose bind fails must never fence the healthy older fleet out.
type ServingGate struct {
	mu     sync.Mutex
	since  time.Time
	err    error
	settle time.Duration
}

// NewServingGate starts closed; settle is how long the listener must keep
// serving before we trust it enough to advertise.
func NewServingGate(settle time.Duration) *ServingGate {
	return &ServingGate{err: ErrNotServing, settle: settle}
}

// MarkServing records that the listener is bound and answered a self-probe.
func (g *ServingGate) MarkServing() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.err == nil {
		return
	}
	g.err = nil
	g.since = time.Now()
}

// MarkStopped closes the gate again: the listener died or never came up.
func (g *ServingGate) MarkStopped(err error) {
	if err == nil {
		err = ErrNotServing
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.err = err
	g.since = time.Time{}
}

// Check reports nil only once the listener has been serving for the settle
// window - a bind that flaps must not produce a moment of advertisement.
func (g *ServingGate) Check(context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.err != nil {
		return g.err
	}
	if d := time.Since(g.since); d < g.settle {
		return ErrNotServing
	}
	return nil
}

// LoopbackTarget turns a listener address into something dialable: a wildcard
// bind (0.0.0.0/::) cannot be connected to portably on every platform.
func LoopbackTarget(addr net.Addr) string {
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	if ip := net.ParseIP(host); ip == nil || ip.IsUnspecified() {
		if ip != nil && ip.To4() == nil {
			return net.JoinHostPort("::1", port)
		}
		return net.JoinHostPort("127.0.0.1", port)
	}
	return net.JoinHostPort(host, port)
}
