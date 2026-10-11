package accesslog

import (
	"sync"
	"testing"
)

// Run with -race: Publish must not read the slice Unsubscribe mutates.
func TestBrokerPublishUnsubscribeRace(t *testing.T) {
	b := NewBroker()
	keep := b.Subscribe(1)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			b.Unsubscribe(1, b.Subscribe(1))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			b.Publish(Entry{RouteID: 1})
			select {
			case <-keep:
			default:
			}
		}
	}()
	wg.Wait()
}
