package esm

import (
	"bytes"
	"net"
	"testing"
)

func TestDecodePDNConnectivityRequestPCO(t *testing.T) {
	raw := []byte{
		0x02, 0x01, MsgPDNConnectivityRequest,
		0x11,
		0xd1,
		0x27, 0x06, 0x80, 0x80, 0x21, 0x10, 0x01, 0x00,
	}

	req := DecodePDNConnectivityRequest(raw)
	if req == nil {
		t.Fatal("DecodePDNConnectivityRequest returned nil")
	}
	if req.ProcedureTransactionID != 1 {
		t.Fatalf("PTI got %d, want 1", req.ProcedureTransactionID)
	}
	if req.RequestType != 1 {
		t.Fatalf("request type got %d, want 1", req.RequestType)
	}
	if req.PDNType != PDNTypeIPv4 {
		t.Fatalf("PDN type got %d, want IPv4", req.PDNType)
	}
	wantPCO := []byte{0x80, 0x80, 0x21, 0x10, 0x01, 0x00}
	if !bytes.Equal(req.PCO, wantPCO) {
		t.Fatalf("PCO got %x, want %x", req.PCO, wantPCO)
	}
}

func TestEncodeActivateDefaultEPSBearerContextRequestVector(t *testing.T) {
	got := EncodePDNConnectivityAccept(1, "internet", 5, net.IP{100, 64, 0, 241})
	want := []byte{
		0x52, 0x01, MsgActivateDefaultEPSBearerContextRequest,
		0x01, 0x09,
		0x09, 0x08, 'i', 'n', 't', 'e', 'r', 'n', 'e', 't',
		0x05, PDNTypeIPv4, 0x64, 0x40, 0x00, 0xf1,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Activate Default EPS Bearer Context Request got %x, want %x", got, want)
	}
}

func TestDecodeActivateDefaultEPSBearerContextAccept(t *testing.T) {
	raw := []byte{0x52, 0x01, MsgActivateDefaultEPSBearerContextAccept}
	got, err := DecodeActivateDefaultEPSBearerContextAccept(raw)
	if err != nil {
		t.Fatalf("DecodeActivateDefaultEPSBearerContextAccept: %v", err)
	}
	if got.EPSBearerID != 5 {
		t.Fatalf("EBI got %d, want 5", got.EPSBearerID)
	}
	if got.ProcedureTransactionID != 1 {
		t.Fatalf("PTI got %d, want 1", got.ProcedureTransactionID)
	}
	if len(got.PCO) != 0 {
		t.Fatalf("PCO got %x, want empty", got.PCO)
	}
}
