package s11

import "sync/atomic"

var localCounter atomic.Uint32

// AllocateTEID returns a new, unique local GTPv2-C C-plane TEID.
// TEIDs are handed out in ascending order starting at 1; 0 is reserved.
func AllocateTEID() uint32 {
	return localCounter.Add(1)
}
