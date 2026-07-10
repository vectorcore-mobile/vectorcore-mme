package ies

import (
	"encoding/hex"
	"testing"
)

func TestDecodeSTMSIInitialUEVector(t *testing.T) {
	raw, err := hex.DecodeString("004000000002")
	if err != nil {
		t.Fatal(err)
	}
	mmec, mtmsi, err := DecodeSTMSI(raw)
	if err != nil {
		t.Fatalf("DecodeSTMSI: %v", err)
	}
	if mmec != 1 {
		t.Fatalf("MMEC got %d, want 1", mmec)
	}
	if mtmsi != 2 {
		t.Fatalf("M-TMSI got %#x, want 0x00000002", mtmsi)
	}
}

func TestDecodeSTMSILegacyFiveByteValue(t *testing.T) {
	mmec, mtmsi, err := DecodeSTMSI([]byte{0x01, 0x00, 0x00, 0x00, 0x02})
	if err != nil {
		t.Fatalf("DecodeSTMSI: %v", err)
	}
	if mmec != 1 || mtmsi != 2 {
		t.Fatalf("S-TMSI got MMEC=%d M-TMSI=%#x, want 1/0x00000002", mmec, mtmsi)
	}
}
