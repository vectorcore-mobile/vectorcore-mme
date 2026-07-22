package config

import (
	"bytes"
	"testing"
)

func TestSMSAddressNormalizationAndTBCD(t *testing.T) {
	got, err := NormalizeE164(" +15551230001 ")
	if err != nil || got != "15551230001" {
		t.Fatalf("NormalizeE164() = %q, %v", got, err)
	}
	b, err := EncodeTBCD(got)
	if err != nil || !bytes.Equal(b, []byte{0x51, 0x55, 0x21, 0x03, 0x00, 0xf1}) {
		t.Fatalf("EncodeTBCD() = %x, %v", b, err)
	}
}

func TestSMSAddressRejectsInvalidValues(t *testing.T) {
	for _, value := range []string{"", "+1-555", "1234567890123456"} {
		if _, err := NormalizeE164(value); err == nil {
			t.Fatalf("NormalizeE164(%q) succeeded", value)
		}
	}
}

func TestEncodeSGdSCAddressCompatibilityEncoding(t *testing.T) {
	got, err := EncodeSGdSCAddress("+15551230000", "ascii_digits")
	if err != nil || string(got) != "15551230000" {
		t.Fatalf("ascii_digits = %q, %v", got, err)
	}
	if _, err := EncodeSGdSCAddress("1555", "unsupported"); err == nil {
		t.Fatal("unsupported encoding accepted")
	}
}
