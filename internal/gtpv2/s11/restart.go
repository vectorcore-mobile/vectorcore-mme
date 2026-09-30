package s11

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// CounterStore keeps the Restart Counter between runs (the SQLite database
// in persistent mode).
type CounterStore interface {
	// LoadCounter returns the saved value; ok is false if none is saved.
	LoadCounter() (value uint8, ok bool, err error)
	SaveCounter(value uint8) error
}

// LoadRestartCounter returns the GTPv2-C Restart Counter for this run
// (Recovery IE, TS 29.274 §8.17; TS 23.007 §18) in persistent mode. The
// saved value is kept, not incremented: UE contexts and their S-GW
// sessions are recovered after a restart, and a changed counter would make
// the S-GW delete them (TS 23.007 §17). initial is saved and used when no
// counter has been saved yet (first start).
func LoadRestartCounter(store CounterStore, initial uint8) (uint8, error) {
	saved, ok, err := store.LoadCounter()
	if err != nil {
		return initial, fmt.Errorf("s11: load restart counter: %w", err)
	}
	if ok {
		return saved, nil
	}
	if err := store.SaveCounter(initial); err != nil {
		return initial, fmt.Errorf("s11: save restart counter: %w", err)
	}
	return initial, nil
}

// ParseCounter parses a saved Restart Counter value.
func ParseCounter(s string) (uint8, bool, error) {
	v, err := strconv.ParseUint(strings.TrimSpace(s), 10, 8)
	if err != nil {
		return 0, false, fmt.Errorf("invalid restart counter %q: %w", strings.TrimSpace(s), err)
	}
	return uint8(v), true, nil
}

// teidSeedGap separates a new run's TEIDs from the highest TEID recorded by
// the previous run. Sessions that were being set up when the MME stopped
// (Create Session sent, not yet persisted) used TEIDs above that record.
const teidSeedGap = 1 << 16

// InitialTEID picks the first S11 TEID for this run. maxRecorded is the
// highest MME S11 TEID in the recovery store (0 if none): allocation
// resumes above it so recovered UEs keep unique TEIDs. With no record, a
// random start in the lower half of the space makes reuse of TEIDs the
// S-GW may still hold from an earlier run unlikely.
func InitialTEID(maxRecorded uint32) uint32 {
	if maxRecorded != 0 {
		next := maxRecorded + teidSeedGap
		if next < maxRecorded { // wrapped past 0xFFFFFFFF
			next = teidSeedGap
		}
		return next
	}
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 1
	}
	return binary.BigEndian.Uint32(b[:])&0x7FFFFFFF | 1
}
