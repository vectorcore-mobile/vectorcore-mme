package s11

import "sync/atomic"

var localCounter atomic.Uint32

// AllocateTEID returns a new, unique local GTPv2-C C-plane TEID. TEIDs are
// handed out in ascending order from the value set by SeedTEID (1 if never
// seeded), wrapping past 0xFFFFFFFF; 0 is reserved and never returned.
func AllocateTEID() uint32 {
	for {
		if v := localCounter.Add(1); v != 0 {
			return v
		}
	}
}

// SeedTEID makes next the first TEID AllocateTEID returns. Call once at
// startup, before any allocation, so TEIDs of the previous run that the
// S-GW or recovered UE contexts still hold are not handed out again.
func SeedTEID(next uint32) {
	localCounter.Store(next - 1)
}
