// Package events is a non-blocking fan-out hub for live dashboard updates.
// Slow subscribers lose their oldest queued events; ingestion never waits for
// a browser.
package events

import (
	"sync"
	"sync/atomic"
)

// Event is one live update. Data must be treated as immutable by subscribers.
type Event struct {
	Type string
	Data any
}

// Subscriber is one SSE connection's queue.
type Subscriber struct {
	C      chan Event
	hub    *Hub
	closed atomic.Bool
}

// Hub fans out events to subscribers.
type Hub struct {
	mu      sync.Mutex
	clients map[*Subscriber]struct{}
	drops   atomic.Uint64
}

// New creates an empty hub.
func New() *Hub {
	return &Hub{clients: make(map[*Subscriber]struct{})}
}

// Subscribe registers a subscriber with a bounded queue.
func (h *Hub) Subscribe(buffer int) *Subscriber {
	if buffer < 1 {
		buffer = 64
	}
	sub := &Subscriber{C: make(chan Event, buffer), hub: h}
	h.mu.Lock()
	h.clients[sub] = struct{}{}
	h.mu.Unlock()
	return sub
}

// Unsubscribe removes a subscriber and closes its channel.
func (h *Hub) Unsubscribe(sub *Subscriber) {
	if sub == nil || !sub.closed.CompareAndSwap(false, true) {
		return
	}
	h.mu.Lock()
	if _, ok := h.clients[sub]; ok {
		delete(h.clients, sub)
		close(sub.C)
	}
	h.mu.Unlock()
}

// Publish sends an event to every subscriber without blocking. When a
// subscriber's queue is full, its oldest event is discarded to make room.
func (h *Hub) Publish(event Event) {
	// Sending while holding the hub lock keeps Unsubscribe from closing channels
	// underneath us. Every send is non-blocking, so the lock is not held for I/O.
	h.mu.Lock()
	defer h.mu.Unlock()
	for sub := range h.clients {
		if sub.closed.Load() {
			continue
		}
		for {
			select {
			case sub.C <- event:
				goto delivered
			default:
				select {
				case <-sub.C:
					h.drops.Add(1)
				default:
				}
				// Retry once after making room.
				select {
				case sub.C <- event:
					goto delivered
				default:
					h.drops.Add(1)
					goto delivered
				}
			}
		}
	delivered:
	}
}

// Clients returns the number of live subscribers.
func (h *Hub) Clients() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.clients)
}

// Dropped returns the number of events dropped for slow consumers.
func (h *Hub) Dropped() uint64 { return h.drops.Load() }

// Close unsubscribes everyone.
func (h *Hub) Close() {
	h.mu.Lock()
	clients := make([]*Subscriber, 0, len(h.clients))
	for sub := range h.clients {
		clients = append(clients, sub)
	}
	h.mu.Unlock()
	for _, sub := range clients {
		h.Unsubscribe(sub)
	}
}
