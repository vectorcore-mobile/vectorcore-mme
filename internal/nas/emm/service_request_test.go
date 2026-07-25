package emm_test

import (
	"encoding/hex"
	"testing"

	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/security"
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

func TestVerifyShortMAC_EIA2UsesFirstTwoOctetsAndLastTwoMACBytes(t *testing.T) {
	key, err := hex.DecodeString("00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	pdu := []byte{0xC7, 0x02, 0x00, 0x00}
	mac, err := security.ComputeNASMAC(security.AlgIDEIA2, key, 2, 0, 0, pdu[:2])
	if err != nil {
		t.Fatalf("ComputeNASMAC: %v", err)
	}
	copy(pdu[2:], mac[2:4])

	ok, details := emm.VerifyShortMACDetailed(pdu, security.AlgIDEIA2, key, 1)
	if !ok {
		t.Fatalf("VerifyShortMACDetailed failed: computed=%x expected=%x input=%x count=%d",
			details.ComputedShortMAC, details.ExpectedShortMAC, details.MessageForMAC, details.ReconstructedCount)
	}
	if details.ReconstructedCount != 2 {
		t.Fatalf("reconstructed count got %d, want 2", details.ReconstructedCount)
	}
	if got, want := hex.EncodeToString(details.MessageForMAC), "c702"; got != want {
		t.Fatalf("MAC input got %s, want %s", got, want)
	}
	if got, want := hex.EncodeToString(details.ComputedShortMAC), hex.EncodeToString(mac[2:4]); got != want {
		t.Fatalf("short MAC got %s, want %s", got, want)
	}
}

func TestEncodeServiceReject(t *testing.T) {
	const cause = emm.CauseCSDomainNotAvailable
	b := emm.EncodeServiceReject(cause)
	if len(b) != 3 {
		t.Fatalf("length: got %d, want 3", len(b))
	}
	if b[0] != emm.PDEPSMobilityMgmt {
		t.Errorf("byte[0] PD: got %#x, want %#x", b[0], emm.PDEPSMobilityMgmt)
	}
	if b[1] != 0x4e {
		t.Errorf("byte[1] msg type: got %#x, want Cisco golden 0x4e", b[1])
	}
	if b[2] != cause {
		t.Errorf("byte[2] cause: got %#x, want %#x", b[2], cause)
	}
	if got, want := hex.EncodeToString(b), "074e12"; got != want {
		t.Errorf("Service Reject got %s, want Cisco golden %s", got, want)
	}
}
