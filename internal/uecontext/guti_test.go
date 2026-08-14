package uecontext

import (
	"testing"

	"github.com/vectorcore/mme/internal/nas/emm"
)

func TestSerialiseDeserialiseGUTIRoundTrip(t *testing.T) {
	original := &emm.GUTI{
		PLMN:  [3]byte{0x02, 0xF8, 0x10},
		MMEGI: 0x1234,
		MMEC:  0xAB,
		MTMSI: 0xDEADBEEF,
	}

	s := SerialiseGUTI(original)
	got, err := DeserialiseGUTI(s)
	if err != nil {
		t.Fatalf("DeserialiseGUTI returned error: %v", err)
	}
	if got.PLMN != original.PLMN {
		t.Errorf("PLMN: got %x, want %x", got.PLMN, original.PLMN)
	}
	if got.MMEGI != original.MMEGI {
		t.Errorf("MMEGI: got %#x, want %#x", got.MMEGI, original.MMEGI)
	}
	if got.MMEC != original.MMEC {
		t.Errorf("MMEC: got %#x, want %#x", got.MMEC, original.MMEC)
	}
	if got.MTMSI != original.MTMSI {
		t.Errorf("MTMSI: got %#x, want %#x", got.MTMSI, original.MTMSI)
	}
}

func TestDeserialiseGUTIRejectsBadInput(t *testing.T) {
	if _, err := DeserialiseGUTI("not-hex"); err == nil {
		t.Error("expected error for non-hex input")
	}
	if _, err := DeserialiseGUTI("AABB"); err == nil {
		t.Error("expected error for short input")
	}
}
