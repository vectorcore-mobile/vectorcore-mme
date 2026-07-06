// Package peertracker provides a thread-safe map of live connected peers.
// It is used to track connected eNodeBs (S1AP), S-GWs, and peer MMEs.
package peertracker

import (
	"sync"
	"time"
)

// Peer represents a single connected peer.
type Peer struct {
	Name       string
	RemoteAddr string
	Transport  string
	ConnectedAt time.Time
}

// Tracker is a concurrent-safe live-peer map with optional TTL expiry.
type Tracker struct {
	mu     sync.RWMutex
	peers  map[string]Peer // keyed by RemoteAddr
	maxAge time.Duration   // 0 = no TTL
}

// New returns a Tracker with no TTL (for direct TCP/SCTP connections).
func New() *Tracker {
	return &Tracker{peers: make(map[string]Peer)}
}

// NewWithMaxAge returns a Tracker that expires entries older than maxAge.
// Used for SCP-forwarded peers where there is no explicit disconnect event.
func NewWithMaxAge(maxAge time.Duration) *Tracker {
	return &Tracker{peers: make(map[string]Peer), maxAge: maxAge}
}

// Add inserts or replaces a peer entry.
func (t *Tracker) Add(p Peer) {
	if p.ConnectedAt.IsZero() {
		p.ConnectedAt = time.Now()
	}
	t.mu.Lock()
	t.peers[p.RemoteAddr] = p
	t.mu.Unlock()
}

// Remove deletes the peer with the given remote address.
func (t *Tracker) Remove(remoteAddr string) {
	t.mu.Lock()
	delete(t.peers, remoteAddr)
	t.mu.Unlock()
}

// Rename updates the display name for a peer.
func (t *Tracker) Rename(remoteAddr, name string) {
	t.mu.Lock()
	if p, ok := t.peers[remoteAddr]; ok {
		p.Name = name
		t.peers[remoteAddr] = p
	}
	t.mu.Unlock()
}

// List returns a snapshot of all live peers, applying TTL expiry if configured.
func (t *Tracker) List() []Peer {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]Peer, 0, len(t.peers))
	now := time.Now()
	for _, p := range t.peers {
		if t.maxAge > 0 && now.Sub(p.ConnectedAt) > t.maxAge {
			continue
		}
		out = append(out, p)
	}
	return out
}

// Count returns the number of live peers.
func (t *Tracker) Count() int {
	return len(t.List())
}
