package esm

import "testing"

func TestDecodeESMStatus(t *testing.T) {
	status, err := DecodeESMStatus([]byte{0x72, 0x03, MsgESMStatus, 0x62})
	if err != nil {
		t.Fatalf("DecodeESMStatus: %v", err)
	}
	if got, want := status.Cause, uint8(0x62); got != want {
		t.Fatalf("cause got %#x, want %#x", got, want)
	}
	if got, want := CauseName(status.Cause), "Message type not compatible with protocol state"; got != want {
		t.Fatalf("cause name got %q, want %q", got, want)
	}
}

func TestDecodeESMStatusRejectsShortData(t *testing.T) {
	if _, err := DecodeESMStatus([]byte{0x72, 0x03, MsgESMStatus}); err == nil {
		t.Fatal("DecodeESMStatus(short) expected error")
	}
}
