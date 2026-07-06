package emm

import (
	"testing"
	"time"
)

// ── IE-level tests ─────────────────────────────────────────────────────────────

func TestEncodeFullNetworkName(t *testing.T) {
	b := EncodeFullNetworkName("Test Net")
	if b == nil {
		t.Fatal("expected non-nil result")
	}
	if b[0] != 0x43 {
		t.Errorf("IEI: got 0x%02X, want 0x43", b[0])
	}
	wantLen := byte(1 + len("Test Net")) // coding byte + name bytes
	if b[1] != wantLen {
		t.Errorf("length byte: got %d, want %d", b[1], wantLen)
	}
	if b[2] != 0x80 {
		t.Errorf("coding byte: got 0x%02X, want 0x80", b[2])
	}
	if string(b[3:]) != "Test Net" {
		t.Errorf("name bytes: got %q, want %q", string(b[3:]), "Test Net")
	}
}

func TestEncodeShortNetworkName_Empty(t *testing.T) {
	b := EncodeShortNetworkName("")
	if b != nil {
		t.Errorf("expected nil for empty name, got %v", b)
	}
}

func TestEncodeShortNetworkName(t *testing.T) {
	b := EncodeShortNetworkName("TN")
	if b == nil {
		t.Fatal("expected non-nil result")
	}
	if b[0] != 0x45 {
		t.Errorf("IEI: got 0x%02X, want 0x45", b[0])
	}
	if string(b[3:]) != "TN" {
		t.Errorf("name: got %q, want TN", string(b[3:]))
	}
}

func TestEncodeLocalTimeZone_UTC2(t *testing.T) {
	// UTC+2 = 120 min = 8 quarter-hours
	// BCD swapped-nibbles of 8: hi=0, lo=8 → byte = (8<<4)|0 = 0x80. No sign bit.
	b := EncodeLocalTimeZone(120)
	if len(b) != 2 {
		t.Fatalf("expected 2 bytes, got %d", len(b))
	}
	if b[0] != 0x46 {
		t.Errorf("IEI: got 0x%02X, want 0x46", b[0])
	}
	want := byte(0x80) // lo=8 hi=0, sign=0
	if b[1] != want {
		t.Errorf("TZ byte: got 0x%02X, want 0x%02X", b[1], want)
	}
}

func TestEncodeLocalTimeZone_Negative(t *testing.T) {
	// UTC-5 = -300 min → 20 quarter-hours
	// 20 in BCD swapped: hi=2, lo=0 → byte = (0<<4)|2 = 0x02; sign bit → 0x0A
	b := EncodeLocalTimeZone(-300)
	if b[1]&0x08 == 0 {
		t.Errorf("sign bit not set for negative offset: byte 0x%02X", b[1])
	}
	// magnitude: 20 quarter-hours → BCD digits are 2,0 → swapped = lo=2, hi=0
	mag := b[1] &^ 0x08 // strip sign bit
	hi := mag & 0x07
	lo := (mag >> 4) & 0x0F
	units := hi*10 + lo
	if units != 20 {
		t.Errorf("magnitude: got %d quarter-hours, want 20", units)
	}
}

func TestEncodeDaylightSavingTime(t *testing.T) {
	b := EncodeDaylightSavingTime(1)
	if len(b) != 3 {
		t.Fatalf("expected 3 bytes, got %d", len(b))
	}
	if b[0] != 0x49 {
		t.Errorf("IEI: got 0x%02X, want 0x49", b[0])
	}
	if b[1] != 0x01 {
		t.Errorf("length byte: got %d, want 1", b[1])
	}
	if b[2] != 0x01 {
		t.Errorf("DST value: got %d, want 1", b[2])
	}
}

func TestEncodeUniversalTimeAndLocalTimeZone(t *testing.T) {
	// 2026-07-06 15:30:45 UTC, UTC+2 (120 min)
	loc := time.UTC
	ts := time.Date(2026, 7, 6, 15, 30, 45, 0, loc)
	b := EncodeUniversalTimeAndLocalTimeZone(ts, 120)
	if len(b) != 8 {
		t.Fatalf("expected 8 bytes, got %d", len(b))
	}
	if b[0] != 0x47 {
		t.Errorf("IEI: got 0x%02X, want 0x47", b[0])
	}
	// Year 2026 → 26 → BCD swapped: (6<<4)|2 = 0x62
	if b[1] != 0x62 {
		t.Errorf("year: got 0x%02X, want 0x62", b[1])
	}
	// Month 7 → BCD swapped: (7<<4)|0 = 0x70
	if b[2] != 0x70 {
		t.Errorf("month: got 0x%02X, want 0x70", b[2])
	}
	// Day 6 → (6<<4)|0 = 0x60
	if b[3] != 0x60 {
		t.Errorf("day: got 0x%02X, want 0x60", b[3])
	}
	// Hour 15 → (5<<4)|1 = 0x51
	if b[4] != 0x51 {
		t.Errorf("hour: got 0x%02X, want 0x51", b[4])
	}
	// Minute 30 → (0<<4)|3 = 0x03
	if b[5] != 0x03 {
		t.Errorf("minute: got 0x%02X, want 0x03", b[5])
	}
	// Second 45 → (5<<4)|4 = 0x54
	if b[6] != 0x54 {
		t.Errorf("second: got 0x%02X, want 0x54", b[6])
	}
	// TZ UTC+2 = 0x80 (verified in TestEncodeLocalTimeZone_UTC2)
	if b[7] != 0x80 {
		t.Errorf("tz: got 0x%02X, want 0x80", b[7])
	}
}

// ── EncodeEMMInformation tests ────────────────────────────────────────────────

func TestEncodeEMMInformation_AllEnabled(t *testing.T) {
	pdu := EncodeEMMInformation("Test Net", true, "TN", true, true, 120, 1)
	if pdu == nil {
		t.Fatal("expected non-nil PDU")
	}
	// Byte 0: PD=EMM (0x07), security header plain (0x0) → 0x07
	if pdu[0] != (PDEPSMobilityMgmt | (SecurityHeaderPlain << 4)) {
		t.Errorf("byte 0: got 0x%02X", pdu[0])
	}
	if pdu[2] != MsgEMMInformation {
		t.Errorf("MsgType: got 0x%02X, want 0x%02X", pdu[2], MsgEMMInformation)
	}
	// Verify IEI sequence: 0x43 (full), 0x45 (short), 0x46 (LTZ), 0x47 (UTLTZ), 0x49 (DST)
	body := pdu[3:]
	for _, wantIEI := range []byte{0x43, 0x45, 0x46, 0x47, 0x49} {
		found := false
		for _, b := range body {
			if b == wantIEI {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing IEI 0x%02X in PDU body", wantIEI)
		}
	}
}

func TestEncodeEMMInformation_NothingEnabled(t *testing.T) {
	pdu := EncodeEMMInformation("", false, "", false, false, 0, 0)
	if pdu != nil {
		t.Errorf("expected nil PDU when nothing enabled, got %d bytes", len(pdu))
	}
}

func TestEncodeEMMInformation_OnlyFullName(t *testing.T) {
	pdu := EncodeEMMInformation("Joran Mobile", true, "", false, false, 0, 0)
	if pdu == nil {
		t.Fatal("expected non-nil PDU")
	}
	if pdu[2] != MsgEMMInformation {
		t.Errorf("MsgType: got 0x%02X", pdu[2])
	}
	body := pdu[3:]
	if body[0] != 0x43 {
		t.Errorf("first IE should be Full Network Name (0x43), got 0x%02X", body[0])
	}
	// Short Network Name should be absent
	for _, b := range body {
		if b == 0x45 {
			t.Error("Short Network Name IEI 0x45 should not be present")
		}
	}
}

func TestEncodeEMMInformation_NITZNoDST(t *testing.T) {
	// DST=0 → Daylight Saving Time IE (0x49) should be absent
	pdu := EncodeEMMInformation("", false, "", false, true, 60, 0)
	if pdu == nil {
		t.Fatal("expected non-nil PDU (nitz enabled)")
	}
	for _, b := range pdu[3:] {
		if b == 0x49 {
			t.Error("DST IE 0x49 should not be present when dst=0")
		}
	}
}
