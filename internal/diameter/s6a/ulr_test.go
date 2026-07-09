package s6a

import "testing"

func TestDecodeMSISDNPureTBCD(t *testing.T) {
	// 16752012880 encoded as TBCD: 61 57 02 21 88 F0.
	got := decodeMSISDN([]byte{0x61, 0x57, 0x02, 0x21, 0x88, 0xF0})
	if got != "16752012880" {
		t.Fatalf("decodeMSISDN() = %q, want %q", got, "16752012880")
	}
}

func TestDecodeMSISDNEvenDigits(t *testing.T) {
	got := decodeMSISDN([]byte{0x21, 0x43, 0x65, 0x87})
	if got != "12345678" {
		t.Fatalf("decodeMSISDN() = %q, want %q", got, "12345678")
	}
}
