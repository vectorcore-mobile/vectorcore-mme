package esm

import (
	"bytes"
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
	if !bytes.Equal(got[6:10], []byte{0x86, 0x96, 0xa5, 0xb5}) {
		t.Fatalf("EPS QoS rates got %x, want 8696a5b5", got[6:10])
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
	if !bytes.Equal(got[6:10], []byte{0x86, 0x96, 0xa5, 0xb5}) {
		t.Fatalf("EPS QoS rates got %x, want 8696a5b5", got[6:10])
	}
}
