package s10

import (
	"bytes"
	"net"
	"testing"

	"github.com/vectorcore/mme/internal/gtpv2"
)

func TestContextRequest_RoundTrip(t *testing.T) {
	rawPDU := []byte{0x07, 0x48, 0x01, 0x02, 0x03}
	orig := &ContextRequest{
		SenderFTEID: gtpv2.FTEID{
			InterfaceType: gtpv2.IFTypeS10MME,
			TEID:          0x0000CAFE,
			IP:            net.ParseIP("10.0.0.1").To4(),
		},
		RawTAURequest: rawPDU,
	}

	wire := EncodeContextRequest(orig, 42, 0)
	msg, err := gtpv2.Decode(wire)
	if err != nil {
		t.Fatalf("Decode wire: %v", err)
	}
	if msg.Type != gtpv2.MsgContextRequest {
		t.Errorf("type: got %d, want %d", msg.Type, gtpv2.MsgContextRequest)
	}
	if msg.SeqNum != 42 {
		t.Errorf("seqNum: got %d, want 42", msg.SeqNum)
	}

	decoded, err := DecodeContextRequest(msg)
	if err != nil {
		t.Fatalf("DecodeContextRequest: %v", err)
	}

	if decoded.SenderFTEID.TEID != orig.SenderFTEID.TEID {
		t.Errorf("SenderFTEID.TEID: got %d, want %d", decoded.SenderFTEID.TEID, orig.SenderFTEID.TEID)
	}
	if !decoded.SenderFTEID.IP.Equal(orig.SenderFTEID.IP) {
		t.Errorf("SenderFTEID.IP: got %v, want %v", decoded.SenderFTEID.IP, orig.SenderFTEID.IP)
	}
	if !bytes.Equal(decoded.RawTAURequest, rawPDU) {
		t.Errorf("RawTAURequest: got %v, want %v", decoded.RawTAURequest, rawPDU)
	}
}

func TestContextRequest_EmptyRawPDU(t *testing.T) {
	orig := &ContextRequest{
		SenderFTEID: gtpv2.FTEID{
			InterfaceType: gtpv2.IFTypeS10MME,
			TEID:          1,
			IP:            net.ParseIP("192.168.1.1").To4(),
		},
		RawTAURequest: nil,
	}
	wire := EncodeContextRequest(orig, 1, 0)
	msg, err := gtpv2.Decode(wire)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	decoded, err := DecodeContextRequest(msg)
	if err != nil {
		t.Fatalf("DecodeContextRequest: %v", err)
	}
	if len(decoded.RawTAURequest) != 0 {
		t.Errorf("RawTAURequest: expected empty, got %d bytes", len(decoded.RawTAURequest))
	}
}

func TestContextResponse_RoundTrip(t *testing.T) {
	kasme := bytes.Repeat([]byte{0xAB}, 32)
	nh := bytes.Repeat([]byte{0xCD}, 32)

	orig := &ContextResponse{
		Cause: gtpv2.CauseRequestAccepted,
		IMSI:  "001010123456789",
		SenderFTEID: gtpv2.FTEID{
			InterfaceType: gtpv2.IFTypeS10MME,
			TEID:          0xDEADBEEF,
			IP:            net.ParseIP("10.10.10.1").To4(),
		},
		MMContext: gtpv2.MMContextParams{
			IntAlg:     2,
			EncAlg:     2,
			NCC:        3,
			ULNASCount: 17,
			DLNASCount: 31,
			KASME:      kasme,
			NH:         nh,
			MSISDN:     "4915123456789",
			APN:        "internet.mnc001.mcc001.gprs",
		},
		PDNConnection: gtpv2.PDNParams{
			EBI: 5,
			SGWC_FTEID: gtpv2.FTEID{
				InterfaceType: gtpv2.IFTypeS11S4SGW,
				TEID:          0x1000,
				IP:            net.ParseIP("10.0.0.2").To4(),
			},
			SGWU_FTEID: gtpv2.FTEID{
				InterfaceType: gtpv2.IFTypeS1USGW,
				TEID:          0x2000,
				IP:            net.ParseIP("10.0.0.3").To4(),
			},
			ENBU_FTEID: gtpv2.FTEID{
				InterfaceType: gtpv2.IFTypeS1UENB,
				TEID:          0x3000,
				IP:            net.ParseIP("10.0.1.5").To4(),
			},
			UEIPv4: net.ParseIP("172.16.0.100").To4(),
			APN:    "internet.mnc001.mcc001.gprs",
		},
	}

	wire := EncodeContextResponse(orig, 99, 0x00001234)
	msg, err := gtpv2.Decode(wire)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if msg.Type != gtpv2.MsgContextResponse {
		t.Errorf("type: got %d, want %d", msg.Type, gtpv2.MsgContextResponse)
	}
	if msg.SeqNum != 99 {
		t.Errorf("seqNum: got %d, want 99", msg.SeqNum)
	}
	if msg.TEID != 0x00001234 {
		t.Errorf("header TEID: got 0x%X, want 0x1234", msg.TEID)
	}

	decoded, err := DecodeContextResponse(msg)
	if err != nil {
		t.Fatalf("DecodeContextResponse: %v", err)
	}

	if decoded.Cause != orig.Cause {
		t.Errorf("Cause: got %d, want %d", decoded.Cause, orig.Cause)
	}
	if decoded.IMSI != orig.IMSI {
		t.Errorf("IMSI: got %q, want %q", decoded.IMSI, orig.IMSI)
	}
	if decoded.SenderFTEID.TEID != orig.SenderFTEID.TEID {
		t.Errorf("SenderFTEID.TEID: got 0x%X, want 0x%X",
			decoded.SenderFTEID.TEID, orig.SenderFTEID.TEID)
	}
	if !decoded.SenderFTEID.IP.Equal(orig.SenderFTEID.IP) {
		t.Errorf("SenderFTEID.IP: got %v, want %v",
			decoded.SenderFTEID.IP, orig.SenderFTEID.IP)
	}

	mm := decoded.MMContext
	if mm.IntAlg != 2 || mm.EncAlg != 2 || mm.NCC != 3 {
		t.Errorf("MMContext alg/NCC: got IntAlg=%d EncAlg=%d NCC=%d", mm.IntAlg, mm.EncAlg, mm.NCC)
	}
	if mm.ULNASCount != 17 || mm.DLNASCount != 31 {
		t.Errorf("NAS counts: got UL=%d DL=%d, want 17/31", mm.ULNASCount, mm.DLNASCount)
	}
	if !bytes.Equal(mm.KASME, kasme) {
		t.Errorf("KASME mismatch")
	}
	if !bytes.Equal(mm.NH, nh) {
		t.Errorf("NH mismatch")
	}
	if mm.MSISDN != "4915123456789" {
		t.Errorf("MSISDN: got %q", mm.MSISDN)
	}
	if mm.APN != "internet.mnc001.mcc001.gprs" {
		t.Errorf("APN: got %q", mm.APN)
	}

	pdn := decoded.PDNConnection
	if pdn.EBI != 5 {
		t.Errorf("PDN EBI: got %d, want 5", pdn.EBI)
	}
	if pdn.SGWC_FTEID.TEID != 0x1000 {
		t.Errorf("SGWC TEID: got 0x%X, want 0x1000", pdn.SGWC_FTEID.TEID)
	}
	if !pdn.UEIPv4.Equal(net.ParseIP("172.16.0.100").To4()) {
		t.Errorf("UEIPv4: got %v", pdn.UEIPv4)
	}
}

func TestContextResponse_NotFound(t *testing.T) {
	orig := &ContextResponse{
		Cause: gtpv2.CauseContextNotFound,
	}
	wire := EncodeContextResponse(orig, 1, 0)
	msg, err := gtpv2.Decode(wire)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	decoded, err := DecodeContextResponse(msg)
	if err != nil {
		t.Fatalf("DecodeContextResponse: %v", err)
	}
	if decoded.Cause != gtpv2.CauseContextNotFound {
		t.Errorf("Cause: got %d, want %d", decoded.Cause, gtpv2.CauseContextNotFound)
	}
	if decoded.IMSI != "" {
		t.Errorf("IMSI: expected empty, got %q", decoded.IMSI)
	}
}

func TestContextAcknowledge_RoundTrip(t *testing.T) {
	wire := EncodeContextAcknowledge(gtpv2.CauseRequestAccepted, 77, 0xBEEF0001)
	msg, err := gtpv2.Decode(wire)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if msg.Type != gtpv2.MsgContextAcknowledge {
		t.Errorf("type: got %d, want %d", msg.Type, gtpv2.MsgContextAcknowledge)
	}
	if msg.TEID != 0xBEEF0001 {
		t.Errorf("header TEID: got 0x%X, want 0xBEEF0001", msg.TEID)
	}
	if msg.SeqNum != 77 {
		t.Errorf("seqNum: got %d, want 77", msg.SeqNum)
	}
	ack, err := DecodeContextAcknowledge(msg)
	if err != nil {
		t.Fatalf("DecodeContextAcknowledge: %v", err)
	}
	if ack.Cause != gtpv2.CauseRequestAccepted {
		t.Errorf("Cause: got %d, want %d", ack.Cause, gtpv2.CauseRequestAccepted)
	}
}

func TestContextAcknowledge_Denied(t *testing.T) {
	wire := EncodeContextAcknowledge(gtpv2.CauseRequestDenied, 1, 0)
	msg, err := gtpv2.Decode(wire)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	ack, err := DecodeContextAcknowledge(msg)
	if err != nil {
		t.Fatalf("DecodeContextAcknowledge: %v", err)
	}
	if ack.Cause != gtpv2.CauseRequestDenied {
		t.Errorf("Cause: got %d, want %d", ack.Cause, gtpv2.CauseRequestDenied)
	}
}

func TestBuildSenderFTEID(t *testing.T) {
	f, err := BuildSenderFTEID("10.0.0.5:2124", 42)
	if err != nil {
		t.Fatalf("BuildSenderFTEID: %v", err)
	}
	if f.TEID != 42 {
		t.Errorf("TEID: got %d, want 42", f.TEID)
	}
	if !f.IP.Equal(net.ParseIP("10.0.0.5").To4()) {
		t.Errorf("IP: got %v, want 10.0.0.5", f.IP)
	}
	if f.InterfaceType != gtpv2.IFTypeS10MME {
		t.Errorf("InterfaceType: got %d, want %d", f.InterfaceType, gtpv2.IFTypeS10MME)
	}
}

func TestBuildSenderFTEID_BareIP(t *testing.T) {
	// No port suffix
	f, err := BuildSenderFTEID("192.168.1.1", 7)
	if err != nil {
		t.Fatalf("BuildSenderFTEID bare IP: %v", err)
	}
	if !f.IP.Equal(net.ParseIP("192.168.1.1").To4()) {
		t.Errorf("IP: got %v, want 192.168.1.1", f.IP)
	}
}

func TestMMContext_NilNH(t *testing.T) {
	// NH is nil — should encode as 32 zero bytes, decode back to non-nil slice.
	p := gtpv2.MMContextParams{
		IntAlg:     1,
		EncAlg:     0,
		KASME:      bytes.Repeat([]byte{0xFF}, 32),
		NH:         nil,
		ULNASCount: 5,
		DLNASCount: 10,
	}
	ie := gtpv2.EncodeMMContext(p)
	decoded, err := gtpv2.DecodeMMContext(&ie)
	if err != nil {
		t.Fatalf("DecodeMMContext: %v", err)
	}
	if len(decoded.NH) != 32 {
		t.Errorf("NH len: got %d, want 32", len(decoded.NH))
	}
	// All NH bytes should be zero.
	for i, b := range decoded.NH {
		if b != 0 {
			t.Errorf("NH[%d] = %d, want 0", i, b)
			break
		}
	}
}

func TestMMContext_NoMSISDN(t *testing.T) {
	p := gtpv2.MMContextParams{
		KASME: bytes.Repeat([]byte{0x01}, 32),
		APN:   "internet",
	}
	ie := gtpv2.EncodeMMContext(p)
	decoded, err := gtpv2.DecodeMMContext(&ie)
	if err != nil {
		t.Fatalf("DecodeMMContext: %v", err)
	}
	if decoded.MSISDN != "" {
		t.Errorf("MSISDN: got %q, want empty", decoded.MSISDN)
	}
	if decoded.APN != "internet" {
		t.Errorf("APN: got %q, want \"internet\"", decoded.APN)
	}
}

func TestDecodeContextRequest_WrongType(t *testing.T) {
	// Encode a ContextResponse but try to decode as ContextRequest.
	wire := EncodeContextResponse(&ContextResponse{Cause: gtpv2.CauseContextNotFound}, 1, 0)
	msg, err := gtpv2.Decode(wire)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	_, err = DecodeContextRequest(msg)
	if err == nil {
		t.Error("expected error for wrong message type, got nil")
	}
}

func TestDecodeContextResponse_WrongType(t *testing.T) {
	wire := EncodeContextAcknowledge(gtpv2.CauseRequestAccepted, 1, 0)
	msg, err := gtpv2.Decode(wire)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	_, err = DecodeContextResponse(msg)
	if err == nil {
		t.Error("expected error for wrong message type, got nil")
	}
}

// ── Fix 3: pendingAck leak ────────────────────────────────────────────────────

// mockHandlerNotFound is a ContextRequestHandler that always returns not-found.
type mockHandlerNotFound struct{}

func (mockHandlerNotFound) HandleContextRequest(_ string, _ *ContextRequest) (*ContextResponse, uint32, bool) {
	return &ContextResponse{Cause: gtpv2.CauseContextNotFound}, 0, false
}
func (mockHandlerNotFound) HandleContextAcknowledge(_ uint32, _ uint8) {}

// TestPendingAck_NoLeakOnNotFound verifies that handleIncomingContextRequest does NOT
// store a pendingAck entry when the UE is not found (found=false). Previously mmeUEID=0
// was always stored, accumulating dead entries that were never cleaned up.
func TestPendingAck_NoLeakOnNotFound(t *testing.T) {
	srv := &Server{}
	srv.SetHandler(mockHandlerNotFound{})

	// Craft a minimal Context Request message.
	req := &ContextRequest{
		SenderFTEID: gtpv2.FTEID{
			InterfaceType: gtpv2.IFTypeS10MME,
			TEID:          0x0000ABCD,
			IP:            net.ParseIP("10.0.0.1").To4(),
		},
		RawTAURequest: []byte{0x07, 0x48},
	}
	wire := EncodeContextRequest(req, 1, 0)
	msg, err := gtpv2.Decode(wire)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	// Override conn to a stub that swallows the write so handleIncomingContextRequest
	// can proceed past the WriteToUDP call. We do this by leaving conn nil and verifying
	// the pendingAck map BEFORE the function reaches the WriteToUDP step — which would
	// panic on a nil conn. Instead, confirm pendingAck is NOT populated after the handler
	// sets found=false (the early-out path does not call pendingAck.Store at all).
	//
	// Since HandleContextRequest returns found=false the function clears pendingAck before
	// the response write (the Store is guarded by `if found`). We can verify by storing
	// a sentinel first and checking it is unchanged.
	const sentinel = uint32(0xDEADBEEF)
	const sentinelTEID = uint32(99999)
	srv.pendingAck.Store(sentinelTEID, sentinel)

	// Count entries before.
	countBefore := 0
	srv.pendingAck.Range(func(_, _ any) bool { countBefore++; return true })

	// Call the function — it will panic at WriteToUDP since conn is nil, so wrap in a
	// recover to capture only the "not-found → no store" portion of the logic.
	func() {
		defer func() { recover() }() //nolint:errcheck
		srv.handleIncomingContextRequest(msg, "10.0.0.1:2124")
	}()

	// Count entries after. The sentinel should still be the only entry.
	countAfter := 0
	srv.pendingAck.Range(func(_, _ any) bool { countAfter++; return true })

	if countAfter != countBefore {
		t.Errorf("pendingAck grew from %d to %d entries on not-found response",
			countBefore, countAfter)
	}

	// Verify the sentinel is intact.
	v, ok := srv.pendingAck.Load(sentinelTEID)
	if !ok || v.(uint32) != sentinel {
		t.Error("sentinel pendingAck entry was altered")
	}
}
