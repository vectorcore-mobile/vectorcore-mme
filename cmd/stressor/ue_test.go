package main

import (
	"sync/atomic"
	"testing"
)

func TestUniqueStressorTEIDs(t *testing.T) {
	// Reset counter so test is deterministic regardless of run order.
	atomic.StoreUint32(&nextS1UTEID, 0)

	cfg := &Config{
		IMSIBase:    "204950000000001",
		K:           make([]byte, 16),
		OPC:         make([]byte, 16),
		Credentials: nil,
		ENBIP:       []byte{127, 0, 0, 1},
	}

	const n = 20
	seen := make(map[uint32]bool, n)
	for i := 0; i < n; i++ {
		ue := NewUE(cfg, nil, i)
		if ue.s1uTEID == 0 {
			t.Errorf("UE %d has TEID=0 (should start from 1)", i)
		}
		if seen[ue.s1uTEID] {
			t.Errorf("duplicate TEID %d at UE index %d", ue.s1uTEID, i)
		}
		seen[ue.s1uTEID] = true
	}
}

func TestERABSetupListEncoding(t *testing.T) {
	// Verify the ERAB list encodes a non-zero TEID correctly.
	data := encodeStressorERABSetupList([]byte{10, 0, 0, 1}, 0x00ABCDEF)
	if len(data) == 0 {
		t.Fatal("encodeStressorERABSetupList returned empty bytes")
	}
	// The TEID bytes should appear somewhere in the encoded output.
	teidBytes := []byte{0x00, 0xAB, 0xCD, 0xEF}
	found := false
	for i := 0; i+4 <= len(data); i++ {
		if data[i] == teidBytes[0] && data[i+1] == teidBytes[1] &&
			data[i+2] == teidBytes[2] && data[i+3] == teidBytes[3] {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("TEID bytes %v not found in encoded output: %v", teidBytes, data)
	}
}
