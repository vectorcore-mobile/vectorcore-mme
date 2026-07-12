package emm

import (
	"encoding/hex"
	"testing"
	"time"
)

// ── IE-level tests ─────────────────────────────────────────────────────────────

func TestEncodeFullNetworkName(t *testing.T) {
	b := EncodeFullNetworkName("TN")
	if b == nil {
		t.Fatal("expected non-nil result")
	}
	if b[0] != 0x43 {
		t.Errorf("IEI: got 0x%02X, want 0x43", b[0])
	}
	wantLen := byte(3) // coding byte + two packed GSM7 bytes
	if b[1] != wantLen {
		t.Errorf("length byte: got %d, want %d", b[1], wantLen)
	}
	if b[2] != 0x82 {
		t.Errorf("coding byte: got 0x%02X, want 0x82", b[2])
	}
	if got, want := b[3:], []byte{0x54, 0x27}; string(got) != string(want) {
		t.Errorf("packed GSM7 name bytes: got %x, want %x", got, want)
	}
}

func TestEncodeFullNetworkNameUCS2(t *testing.T) {
	b := EncodeFullNetworkNameWithEncoding("例", "ucs2", false)
	if b == nil {
		t.Fatal("expected non-nil result")
	}
	if got, want := b[0], byte(0x43); got != want {
		t.Fatalf("IEI got 0x%02x, want 0x%02x", got, want)
	}
	if got, want := b[1], byte(3); got != want {
		t.Fatalf("length got %d, want %d", got, want)
	}
	if got, want := b[2], byte(0x90); got != want {
		t.Fatalf("coding got 0x%02x, want 0x%02x", got, want)
	}
	if got, want := b[3:], []byte{0x4f, 0x8b}; string(got) != string(want) {
		t.Fatalf("UCS2 bytes got %x, want %x", got, want)
	}
}

func TestEncodeNetworkNameGSM7Vectors(t *testing.T) {
	tests := []struct {
		name    string
		ie      []byte
		payload []byte
	}{
		{name: "A", ie: []byte{0x43, 0x02, 0x81, 0x41}, payload: []byte{0x41}},
		{name: "VectorCore", ie: []byte{0x43, 0x0a, 0x82, 0xd6, 0xf2, 0x98, 0xfe, 0x96, 0x0f, 0xdf, 0xf2, 0x32}, payload: []byte{0xd6, 0xf2, 0x98, 0xfe, 0x96, 0x0f, 0xdf, 0xf2, 0x32}},
		{name: "VectorCore Mobile", ie: []byte{0x43, 0x10, 0x81, 0xd6, 0xf2, 0x98, 0xfe, 0x96, 0x0f, 0xdf, 0xf2, 0x32, 0xa8, 0xf9, 0x16, 0xa7, 0xd9, 0x65}, payload: []byte{0xd6, 0xf2, 0x98, 0xfe, 0x96, 0x0f, 0xdf, 0xf2, 0x32, 0xa8, 0xf9, 0x16, 0xa7, 0xd9, 0x65}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EncodeFullNetworkName(tt.name)
			if string(got) != string(tt.ie) {
				t.Fatalf("IE got %x, want %x", got, tt.ie)
			}
			if string(got[3:]) != string(tt.payload) {
				t.Fatalf("payload got %x, want %x", got[3:], tt.payload)
			}
		})
	}
}

func TestEncodeNetworkNameAddCountryInitials(t *testing.T) {
	b := EncodeFullNetworkNameWithEncoding("A", "gsm7", true)
	if got, want := b[2], byte(0x89); got != want {
		t.Fatalf("coding byte got 0x%02x, want 0x%02x", got, want)
	}
}

func TestEncodeNetworkNameUnsupportedGSM7Character(t *testing.T) {
	b := EncodeFullNetworkName("😀")
	if got, want := b, []byte{0x43, 0x02, 0x81, 0x3f}; string(got) != string(want) {
		t.Fatalf("unsupported GSM7 character got %x, want %x", got, want)
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
	if b[2] != 0x82 {
		t.Errorf("coding byte: got 0x%02X, want 0x82", b[2])
	}
	if got, want := b[3:], []byte{0x54, 0x27}; string(got) != string(want) {
		t.Errorf("packed GSM7 name: got %x, want %x", got, want)
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

func TestEncodeUniversalTimeAndLocalTimeZoneChicagoSummer(t *testing.T) {
	ts := time.Date(2026, 7, 11, 16, 3, 22, 0, time.UTC)
	b := EncodeUniversalTimeAndLocalTimeZone(ts, -300)
	want := []byte{0x47, 0x62, 0x70, 0x11, 0x61, 0x30, 0x22, 0x0a}
	if string(b) != string(want) {
		t.Fatalf("Chicago summer UTLTZ got %x, want %x", b, want)
	}
	if got := EncodeLocalTimeZone(-300); string(got) != string([]byte{0x46, 0x0a}) {
		t.Fatalf("Chicago summer local TZ got %x, want 460a", got)
	}
	if got := EncodeDaylightSavingTime(1); string(got) != string([]byte{0x49, 0x01, 0x01}) {
		t.Fatalf("Chicago summer DST got %x, want 490101", got)
	}
}

func TestCapturedEMMInformationNITZFieldMismatch(t *testing.T) {
	raw, err := hex.DecodeString("070061430887d6e65b9c669701450483d6e61546404762701161302240490101")
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 3 || raw[1] != 0x00 || raw[2] != MsgEMMInformation {
		t.Fatalf("malformed fixture should contain extra zero before EMM Information: %x", raw)
	}
	body := raw[3:]
	full := body[:10]
	short := body[10:16]
	localTZ := body[16:18]
	utltz := body[18:26]
	dst := body[26:29]
	if got, want := full, []byte{0x43, 0x08, 0x87, 0xd6, 0xe6, 0x5b, 0x9c, 0x66, 0x97, 0x01}; string(got) != string(want) {
		t.Fatalf("full name IE got %x, want %x", got, want)
	}
	if got, want := short, []byte{0x45, 0x04, 0x83, 0xd6, 0xe6, 0x15}; string(got) != string(want) {
		t.Fatalf("short name IE got %x, want %x", got, want)
	}
	if got, want := localTZ, []byte{0x46, 0x40}; string(got) != string(want) {
		t.Fatalf("local TZ IE got %x, want %x", got, want)
	}
	if got, want := utltz, []byte{0x47, 0x62, 0x70, 0x11, 0x61, 0x30, 0x22, 0x40}; string(got) != string(want) {
		t.Fatalf("UTLTZ IE got %x, want %x", got, want)
	}
	if got, want := dst, []byte{0x49, 0x01, 0x01}; string(got) != string(want) {
		t.Fatalf("DST IE got %x, want %x", got, want)
	}
	if minutes := decodeTZOffsetMinutes(localTZ[1]); minutes != 60 {
		t.Fatalf("captured local TZ decodes to %+d minutes, want +60", minutes)
	}
	if minutes := decodeTZOffsetMinutes(utltz[7]); minutes != 60 {
		t.Fatalf("captured UTLTZ timezone decodes to %+d minutes, want +60", minutes)
	}
}

func TestMalformedEMMInformationExtraZeroFixture(t *testing.T) {
	raw, err := hex.DecodeString("070061430887d6e65b9c669701450483d6e615460a476270116151550a490101")
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 3 {
		t.Fatalf("fixture too short: %x", raw)
	}
	if raw[0] != 0x07 || raw[1] != 0x00 || raw[2] != MsgEMMInformation {
		t.Fatalf("fixture does not show malformed 07 00 61 header: %x", raw[:3])
	}
	msgType, _, err := ParsePlainNASMessage(raw)
	if err != nil {
		t.Fatalf("ParsePlainNASMessage: %v", err)
	}
	if msgType != 0x00 {
		t.Fatalf("malformed fixture message type got 0x%02x, want 0x00", msgType)
	}
}

func TestEncodeEMMInformationHeaderIsTwoOctets(t *testing.T) {
	pdu := EncodeEMMInformation("VectorCore", true, "", false, "gsm7", false, false, 0, 0)
	if len(pdu) < 2 {
		t.Fatalf("EMM Information too short: %x", pdu)
	}
	if got, want := pdu[0], byte(PDEPSMobilityMgmt|(SecurityHeaderPlain<<4)); got != want {
		t.Fatalf("byte 0 got 0x%02x, want 0x%02x", got, want)
	}
	if got, want := pdu[1], MsgEMMInformation; got != want {
		t.Fatalf("message type got 0x%02x, want 0x%02x; payload=%x", got, want, pdu)
	}
	if len(pdu) > 2 && pdu[2] == 0x00 {
		t.Fatalf("unexpected extra zero octet after EMM Information header: %x", pdu[:4])
	}
}

// ── EncodeEMMInformation tests ────────────────────────────────────────────────

func TestEncodeEMMInformation_AllEnabled(t *testing.T) {
	pdu := EncodeEMMInformation("Test Net", true, "TN", true, "gsm7", false, true, 120, 1)
	if pdu == nil {
		t.Fatal("expected non-nil PDU")
	}
	// Byte 0: PD=EMM (0x07), security header plain (0x0) → 0x07
	if pdu[0] != (PDEPSMobilityMgmt | (SecurityHeaderPlain << 4)) {
		t.Errorf("byte 0: got 0x%02X", pdu[0])
	}
	if pdu[1] != MsgEMMInformation {
		t.Errorf("MsgType: got 0x%02X, want 0x%02X", pdu[1], MsgEMMInformation)
	}
	// Verify IEI sequence: 0x43 (full), 0x45 (short), 0x46 (LTZ), 0x47 (UTLTZ), 0x49 (DST)
	body := pdu[2:]
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
	pdu := EncodeEMMInformation("", false, "", false, "gsm7", false, false, 0, 0)
	if pdu != nil {
		t.Errorf("expected nil PDU when nothing enabled, got %d bytes", len(pdu))
	}
}

func TestEncodeEMMInformation_OnlyFullName(t *testing.T) {
	pdu := EncodeEMMInformation("Joran Mobile", true, "", false, "gsm7", false, false, 0, 0)
	if pdu == nil {
		t.Fatal("expected non-nil PDU")
	}
	if pdu[1] != MsgEMMInformation {
		t.Errorf("MsgType: got 0x%02X", pdu[1])
	}
	body := pdu[2:]
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

func TestEncodeEMMInformation_OnlyShortName(t *testing.T) {
	pdu := EncodeEMMInformation("", false, "VC", true, "gsm7", false, false, 0, 0)
	if pdu == nil {
		t.Fatal("expected non-nil PDU")
	}
	body := pdu[2:]
	if body[0] != 0x45 {
		t.Errorf("first IE should be Short Network Name (0x45), got 0x%02X", body[0])
	}
	for _, b := range body {
		if b == 0x43 {
			t.Error("Full Network Name IEI 0x43 should not be present")
		}
	}
}

func TestEncodeEMMInformation_NITZNoDST(t *testing.T) {
	// DST=0 → Daylight Saving Time IE (0x49) should be absent
	pdu := EncodeEMMInformation("", false, "", false, "gsm7", false, true, 60, 0)
	if pdu == nil {
		t.Fatal("expected non-nil PDU (nitz enabled)")
	}
	for _, b := range pdu[2:] {
		if b == 0x49 {
			t.Error("DST IE 0x49 should not be present when dst=0")
		}
	}
}

func decodeTZOffsetMinutes(b byte) int {
	negative := b&0x08 != 0
	mag := b &^ 0x08
	units := int(mag&0x07)*10 + int((mag>>4)&0x0f)
	minutes := units * 15
	if negative {
		return -minutes
	}
	return minutes
}
