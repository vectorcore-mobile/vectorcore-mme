package emm_test

import (
	"testing"

	"github.com/vectorcore/mme/internal/nas/emm"
)

func TestDecodeServiceRequest_Valid(t *testing.T) {
	// byte[0] = 0xC7: security header 0x0C, PD 0x07
	// byte[1] = 0xA3: KSI=5 (bits[7:5]), SN=3 (bits[4:0])
	// bytes[2:4] = ShortMAC = 0x1234
	pdu := []byte{0xC7, 0xA3, 0x12, 0x34}
	sr, err := emm.DecodeServiceRequest(pdu)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sr.KSI != 5 {
		t.Errorf("KSI: got %d, want 5", sr.KSI)
	}
	if sr.SN != 3 {
		t.Errorf("SN: got %d, want 3", sr.SN)
	}
	if sr.ShortMAC != 0x1234 {
		t.Errorf("ShortMAC: got %#x, want 0x1234", sr.ShortMAC)
	}
}

func TestDecodeServiceRequest_TooShort(t *testing.T) {
	_, err := emm.DecodeServiceRequest([]byte{0xC7, 0x03})
	if err == nil {
		t.Error("expected error for 2-byte PDU, got nil")
	}
}

func TestDecodeServiceRequest_WrongSecHeader(t *testing.T) {
	// byte[0] = 0x07: plain EMM (security header 0x00), not Service Request
	pdu := []byte{0x07, 0x01, 0x00, 0x00}
	_, err := emm.DecodeServiceRequest(pdu)
	if err == nil {
		t.Error("expected error for wrong security header, got nil")
	}
}

func TestVerifyShortMAC_EIA0_Valid(t *testing.T) {
	// EIA0 null algorithm: MAC is always {0,0,0,0} → ShortMAC = {0,0}
	// ULNASCount=0, SN=1 → count = 1 > 0, no overflow wrap
	pdu := []byte{0xC7, 0x01, 0x00, 0x00}
	ok, count := emm.VerifyShortMAC(pdu, 0, make([]byte, 16), 0)
	if !ok {
		t.Error("VerifyShortMAC: expected true for EIA0 with zero MAC")
	}
	if count != 1 {
		t.Errorf("count: got %d, want 1", count)
	}
}

func TestVerifyShortMAC_EIA0_WrapAround(t *testing.T) {
	// ULNASCount=0, SN=0 → raw count=0 ≤ stored(0) → add 0x20
	pdu := []byte{0xC7, 0x00, 0x00, 0x00}
	ok, count := emm.VerifyShortMAC(pdu, 0, make([]byte, 16), 0)
	if !ok {
		t.Error("VerifyShortMAC: expected true for EIA0 wrap-around case")
	}
	if count != 0x20 {
		t.Errorf("count: got %#x, want 0x20", count)
	}
}

func TestVerifyShortMAC_EIA0_Invalid(t *testing.T) {
	// EIA0 computes {0,0,0,0} → ShortMAC expected {0,0}, but PDU has {0x01,0x02}
	pdu := []byte{0xC7, 0x01, 0x01, 0x02}
	ok, _ := emm.VerifyShortMAC(pdu, 0, make([]byte, 16), 0)
	if ok {
		t.Error("VerifyShortMAC: expected false for mismatched MAC")
	}
}

func TestEncodeServiceReject(t *testing.T) {
	const cause = emm.CauseImplicitlyDetached
	b := emm.EncodeServiceReject(cause)
	if len(b) != 3 {
		t.Fatalf("length: got %d, want 3", len(b))
	}
	if b[0] != emm.PDEPSMobilityMgmt {
		t.Errorf("byte[0] PD: got %#x, want %#x", b[0], emm.PDEPSMobilityMgmt)
	}
	if b[1] != emm.MsgServiceReject {
		t.Errorf("byte[1] msg type: got %#x, want %#x", b[1], emm.MsgServiceReject)
	}
	if b[2] != cause {
		t.Errorf("byte[2] cause: got %#x, want %#x", b[2], cause)
	}
}
