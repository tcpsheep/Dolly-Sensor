// Package buffer provides a bounded ring of recent packet observations.
package buffer

import (
	"sync"

	"dollysensor/internal/model"
)

// Ring is a fixed-size circular buffer. When full, the oldest observation is
// overwritten. It is safe for concurrent producers and readers.
type Ring struct {
	mu    sync.RWMutex
	items []model.Observation
	next  int
	count int
	total uint64
}

// New creates a ring holding at most size observations.
func New(size int) *Ring {
	if size < 1 {
		size = 1
	}
	return &Ring{items: make([]model.Observation, size)}
}

// Add inserts a deep copy of obs.
func (r *Ring) Add(obs model.Observation) {
	r.mu.Lock()
	r.items[r.next] = obs.Clone()
	r.next = (r.next + 1) % len(r.items)
	if r.count < len(r.items) {
		r.count++
	}
	r.total++
	r.mu.Unlock()
}

// Len returns the number of stored observations.
func (r *Ring) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.count
}

// Total returns the number of observations ever added.
func (r *Ring) Total() uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.total
}

// Latest returns up to limit observations, newest first.
func (r *Ring) Latest(limit int) []model.Observation {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if limit <= 0 || limit > r.count {
		limit = r.count
	}
	out := make([]model.Observation, 0, limit)
	for i := 1; i <= limit; i++ {
		index := (r.next - i + len(r.items)) % len(r.items)
		out = append(out, r.items[index].Clone())
	}
	return out
}

// All returns every stored observation in chronological order. Mostly useful
// in tests and for export-style tooling.
func (r *Ring) All() []model.Observation {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]model.Observation, 0, r.count)
	start := (r.next - r.count + len(r.items)) % len(r.items)
	for i := 0; i < r.count; i++ {
		index := (start + i) % len(r.items)
		out = append(out, r.items[index].Clone())
	}
	return out
}
