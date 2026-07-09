package esm

import (
	"bytes"
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
