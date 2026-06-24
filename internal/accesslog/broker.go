package accesslog

import (
	"sync"
)

// Broker distributes new log entries to SSE subscribers keyed by route ID.
type Broker struct {
	mu   sync.Mutex
	subs map[int64][]chan Entry
}

// NewBroker returns an initialised Broker.
func NewBroker() *Broker {
	return &Broker{subs: make(map[int64][]chan Entry)}
}

// Subscribe returns a channel that receives entries for routeID.
// The caller must call Unsubscribe when done.
func (b *Broker) Subscribe(routeID int64) chan Entry {
	ch := make(chan Entry, 32)
	b.mu.Lock()
	b.subs[routeID] = append(b.subs[routeID], ch)
	b.mu.Unlock()
	return ch
}

// Unsubscribe removes ch from the route's subscriber list.
func (b *Broker) Unsubscribe(routeID int64, ch chan Entry) {
	b.mu.Lock()
	defer b.mu.Unlock()
	list := b.subs[routeID]
	for i, c := range list {
		if c == ch {
			b.subs[routeID] = append(list[:i], list[i+1:]...)
			break
		}
	}
	if len(b.subs[routeID]) == 0 {
		delete(b.subs, routeID)
	}
}

// Publish sends e to all subscribers for e.RouteID. Non-blocking: slow
// subscribers are skipped (their buffer full = they can't keep up).
func (b *Broker) Publish(e Entry) {
	b.mu.Lock()
	list := b.subs[e.RouteID]
	b.mu.Unlock()
	for _, ch := range list {
		select {
		case ch <- e:
		default:
		}
	}
}
