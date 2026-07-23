package esm

import (
	"bytes"
	"fmt"
	"testing"
)

func TestEncodeActivateDedicatedEPSBearerContextRequestBuildsParsedEPSQoS(t *testing.T) {
	qos := []byte{
		0x10, 0x02,
		0x00, 0x00, 0x00, 0x04, 0x00,
		0x00, 0x00, 0x00, 0x08, 0x00,
		0x00, 0x00, 0x00, 0x0c, 0x00,
		0x00, 0x00, 0x00, 0x10, 0x00,
	}
	tft := []byte{0x21, 0x30, 0x30, 0x0b}

	got := EncodeActivateDedicatedEPSBearerContextRequest(7, 6, 3, qos, 2, tft, nil)

	if got[0] != 0x72 {
		t.Fatalf("header got %#x, want 0x72", got[0])
	}
	if got[1] != 3 {
		t.Fatalf("PTI got %d, want 3", got[1])
	}
	if got[2] != MsgActivateDedicatedEPSBearerContextRequest {
		t.Fatalf("message type got %#x, want %#x", got[2], MsgActivateDedicatedEPSBearerContextRequest)
	}
	if got[3] != 6 {
		t.Fatalf("linked EBI got %d, want 6", got[3])
	}
	if got[4] != 0x05 {
		t.Fatalf("EPS QoS length got %d, want 5", got[4])
	}
	if got[5] != 0x02 {
		t.Fatalf("EPS QoS QCI got %#x, want 0x02", got[5])
	}
	if !bytes.Equal(got[6:10], []byte{0x87, 0x97, 0xa7, 0xb7}) {
		t.Fatalf("EPS QoS rates got %x, want 8797a7b7", got[6:10])
	}
	tftOffset := 10
	if got[tftOffset] != byte(len(tft)) {
		t.Fatalf("TFT length got %d, want %d", got[tftOffset], len(tft))
	}
	if !bytes.Equal(got[tftOffset+1:tftOffset+1+len(tft)], tft) {
		t.Fatalf("TFT got %x, want %x", got[tftOffset+1:tftOffset+1+len(tft)], tft)
	}
}

func TestEncodeActivateDedicatedEPSBearerContextRequestFallsBackToQCIOnly(t *testing.T) {
	got := EncodeActivateDedicatedEPSBearerContextRequest(7, 6, 3, []byte{0x10, 0x02}, 2, nil, nil)

	if !bytes.Equal(got[4:6], []byte{0x01, 0x02}) {
		t.Fatalf("EPS QoS fallback got %x, want 0102", got[4:6])
	}
}

func TestEncodeModifyEPSBearerContextRequestBuildsParsedEPSQoS(t *testing.T) {
	qos := []byte{
		0x08, 0x01,
		0x00, 0x00, 0x00, 0x04, 0x00,
		0x00, 0x00, 0x00, 0x08, 0x00,
		0x00, 0x00, 0x00, 0x0c, 0x00,
		0x00, 0x00, 0x00, 0x10, 0x00,
	}

	got := EncodeModifyEPSBearerContextRequest(9, 5, 1, qos, nil, nil)

	if got[0] != 0x92 {
		t.Fatalf("header got %#x, want 0x92", got[0])
	}
	if got[1] != 5 {
		t.Fatalf("PTI got %d, want 5", got[1])
	}
	if got[2] != MsgModifyEPSBearerContextRequest {
		t.Fatalf("message type got %#x, want %#x", got[2], MsgModifyEPSBearerContextRequest)
	}
	if got[3] != 0x5b {
		t.Fatalf("EPS QoS IEI got %#x, want 0x5b", got[3])
	}
	if got[4] != 0x05 {
		t.Fatalf("EPS QoS length got %d, want 5", got[4])
	}
	if got[5] != 0x01 {
		t.Fatalf("EPS QoS QCI got %#x, want 0x01", got[5])
	}
	if !bytes.Equal(got[6:10], []byte{0x87, 0x97, 0xa7, 0xb7}) {
		t.Fatalf("EPS QoS rates got %x, want 8797a7b7", got[6:10])
	}
}

func TestEncodeNASQoSFromBpsUsesTS24008DecimalRates(t *testing.T) {
	tests := []struct {
		name      string
		bps       uint64
		base, ext uint8
		length    uint8
	}{
		{"unspecified", 0, 0xff, 0x00, 1},
		{"below-first-range", 1, 0x01, 0x00, 1},
		{"64-kbps-boundary", 64_000, 0x40, 0x00, 1},
		{"72-kbps", 72_000, 0x41, 0x00, 1},
		{"120-kbps", 120_000, 0x47, 0x00, 1},
		{"128-kbps", 128_000, 0x48, 0x00, 1},
		{"136-kbps", 136_000, 0x49, 0x00, 1},
		{"upper-first-range", 568_000, 0x7f, 0x00, 1},
		{"above-first-range", 569_000, 0x80, 0x00, 1},
		{"extended-rate", 128_000_000, 0xfe, 0xba, 2},
		{"saturation", 10_000_000_001, 0xfe, 0xfa, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got nasEPSQoSBitRate
			if length := encodeNASQoSFromBps(&got, tt.bps); length != tt.length || got.base != tt.base || got.extended != tt.ext {
				t.Fatalf("%d bps encoded length=%d base=%#02x ext=%#02x, want length=%d base=%#02x ext=%#02x", tt.bps, length, got.base, got.extended, tt.length, tt.base, tt.ext)
			}
		})
	}
}

func TestEncodeActivateDedicatedEPSBearerContextRequestWithIMSCompatibilityIEs(t *testing.T) {
	qosQCI2 := []byte{0x10, 0x02, 0, 0, 0, 0, 0x80, 0, 0, 0, 0, 0x80, 0, 0, 0, 0, 0x80, 0, 0, 0, 0, 0x80}
	qosQCI1 := append([]byte(nil), qosQCI2...)
	qosQCI1[1] = 0x01
	tftQCI2 := []byte{0x21, 0x30, 0x30, 0x0b, 0x10, 0x0a, 0x96, 0x03, 0x9c, 0xff, 0xff, 0xff, 0xff, 0x30, 0x11}
	tftQCI1 := []byte{0x21, 0x30, 0x35, 0x0b, 0x10, 0x0a, 0x96, 0x03, 0x9c, 0xff, 0xff, 0xff, 0xff, 0x30, 0x11}

	tests := []struct {
		name string
		ebi  uint8
		qci  uint8
		ti   uint8
		qos  []byte
		tft  []byte
		want string
	}{
		{"qci2", 7, 2, 2, qosQCI2, tftQCI2, "7200c5060502484848480f2130300b100a96039cffffffff30115d0120300c0c511f33964848733f484800320384"},
		{"qci1", 8, 1, 3, qosQCI1, tftQCI1, "8200c5060501484848480f2130350b100a96039cffffffff30115d0130300c0c511f33964848712b484801320384"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EncodeActivateDedicatedEPSBearerContextRequestWithOptionalIEs(tt.ebi, 6, 0, tt.qos, tt.qci, tt.tft, IMSDedicatedBearerInterworkingOptions(tt.ti, tt.qos, tt.qci), nil)
			if actual := fmt.Sprintf("%x", got); actual != tt.want {
				t.Fatalf("plain NAS got %s, want %s", actual, tt.want)
			}
		})
	}
}

func TestEncodeModifyEPSBearerContextRequestWithAPNAMBR(t *testing.T) {
	got := EncodeModifyEPSBearerContextRequestWithAPNAMBR(9, 0, 5, []byte{0x44, 0x05}, []byte{0xa4, 0x04, 0x05, 0x06, 0x07}, 3_850_000, 1_530_000, nil)

	want := []byte{0x5e, 0x02, 0x8f, 0xb4}
	if !bytes.Contains(got, want) {
		t.Fatalf("APN-AMBR IE got %x, want containing %x", got, want)
	}
}
