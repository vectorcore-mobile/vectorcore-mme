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

func TestDecodePDNConnectivityRequestIMSFixture(t *testing.T) {
	raw := []byte{
		0x02, 0x01, MsgPDNConnectivityRequest, 0x31,
		0x28, 0x04, 0x03, 'i', 'm', 's',
		0x27, 0x23,
		0x80, 0x80, 0x21, 0x10, 0x01, 0x01, 0x00, 0x10,
		0x81, 0x06, 0x00, 0x00, 0x00, 0x00, 0x83, 0x06,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x03, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x0d, 0x00,
		0x00, 0x10, 0x00,
	}
	req := DecodePDNConnectivityRequest(raw)
	if req == nil {
		t.Fatal("DecodePDNConnectivityRequest returned nil")
	}
	if req.EPSBearerID != 0 {
		t.Fatalf("EBI got %d, want 0", req.EPSBearerID)
	}
	if req.ProcedureTransactionID != 1 {
		t.Fatalf("PTI got %d, want 1", req.ProcedureTransactionID)
	}
	if req.PDNType != PDNTypeIPv4 {
		t.Fatalf("PDN type got %d, want IPv4", req.PDNType)
	}
	if req.RequestType != 3 {
		t.Fatalf("request type got %d, want 3", req.RequestType)
	}
	if req.APN != "ims" {
		t.Fatalf("APN got %q, want ims", req.APN)
	}
	wantPCO := raw[12:]
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

func TestEncodeActivateDefaultEPSBearerContextRequestIncludesPCO(t *testing.T) {
	pco := []byte{0x80, 0x00, 0x0d, 0x04, 0x01, 0x01, 0x01, 0x01}
	got := EncodePDNConnectivityAcceptWithPCO(1, "internet", 5, net.IP{100, 64, 0, 241}, pco)
	wantSuffix := append([]byte{0x27, byte(len(pco))}, pco...)
	if !bytes.HasSuffix(got, wantSuffix) {
		t.Fatalf("Activate Default EPS Bearer Context Request suffix got %x, want suffix %x", got, wantSuffix)
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

func TestDecodePDNConnectivityRequestESMInformationFlag(t *testing.T) {
	raw := []byte{
		0x02, 0x01, MsgPDNConnectivityRequest,
		0x31,
		0xd1,
		0x27, 0x03, 0x80, 0x00, 0x0d,
	}
	req := DecodePDNConnectivityRequest(raw)
	if req == nil {
		t.Fatal("DecodePDNConnectivityRequest returned nil")
	}
	if !req.ESMInformationRequired {
		t.Fatal("ESMInformationRequired=false, want true")
	}
	if req.ProcedureTransactionID != 1 || req.PDNType != PDNTypeIPv4 || req.RequestType != 3 {
		t.Fatalf("unexpected request: %+v", req)
	}
}

func TestESMInformationRequestResponse(t *testing.T) {
	req := EncodeESMInformationRequest(7)
	if want := []byte{0x02, 0x07, MsgESMInformationRequest}; !bytes.Equal(req, want) {
		t.Fatalf("ESM Information Request got %x, want %x", req, want)
	}

	resp, err := DecodeESMInformationResponse([]byte{
		0x02, 0x07, MsgESMInformationResponse,
		0x28, 0x09, 0x08, 'i', 'n', 't', 'e', 'r', 'n', 'e', 't',
		0x27, 0x03, 0x80, 0x00, 0x0d,
	})
	if err != nil {
		t.Fatalf("DecodeESMInformationResponse: %v", err)
	}
	if resp.ProcedureTransactionID != 7 || resp.APN != "internet" || !bytes.Equal(resp.PCO, []byte{0x80, 0x00, 0x0d}) {
		t.Fatalf("unexpected response: %+v", resp)
	}
}
