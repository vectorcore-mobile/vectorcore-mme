package emm

import (
	"bytes"
	"testing"
)

func TestGenericNASTransportLPP(t *testing.T) {
	payload := []byte{1, 2, 3}
	w, e := EncodeDownlinkGenericNASTransport(GenericMessageContainerTypeLPP, nil, payload)
	if e != nil {
		t.Fatal(e)
	}
	if w[1] != MsgDownlinkGenericNASTransport || w[2] != GenericMessageContainerTypeLPP {
		t.Fatalf("header %x", w[:3])
	}
	typ, got, e := DecodeUplinkGenericNASTransport(w[2:])
	if e != nil || typ != GenericMessageContainerTypeLPP || !bytes.Equal(got, payload) {
		t.Fatalf("typ=%d got=%x err=%v", typ, got, e)
	}
}

// TestGenericNASTransportLPPRoutingID guards the TS 24.171 §5.3.2.1.1 fix:
// an LPP-container Downlink Generic NAS Transport message must carry its
// SLs Correlation ID as a Routing Identifier in the Additional Information
// IE, or a real UE rejects the message with EMM cause #96 (Invalid
// mandatory information) — confirmed against a real Nokia eNB/UE.
func TestGenericNASTransportLPPRoutingID(t *testing.T) {
	payload := []byte{1, 2, 3}
	routing := []byte{0xde, 0xad, 0xbe, 0xef}
	w, e := EncodeDownlinkGenericNASTransport(GenericMessageContainerTypeLPP, routing, payload)
	if e != nil {
		t.Fatal(e)
	}
	wantTail := append([]byte{additionalInformationIEI, byte(len(routing))}, routing...)
	if !bytes.Equal(w[len(w)-len(wantTail):], wantTail) {
		t.Fatalf("additional information tail = %x, want %x", w[len(w)-len(wantTail):], wantTail)
	}
	// The UE echoing the Additional Information IE back in its Uplink
	// Generic NAS Transport response must still decode cleanly.
	typ, got, e := DecodeUplinkGenericNASTransport(w[2:])
	if e != nil || typ != GenericMessageContainerTypeLPP || !bytes.Equal(got, payload) {
		t.Fatalf("typ=%d got=%x err=%v", typ, got, e)
	}
}

// TestGenericNASTransportLCSOmitsRoutingID guards TS 24.171 §5.2.1.1.0's
// NOTE: the Additional Information IE must NOT be present for the
// LCS-notification container type.
func TestGenericNASTransportLCSOmitsRoutingID(t *testing.T) {
	payload := []byte{9}
	w, e := EncodeDownlinkGenericNASTransport(GenericMessageContainerTypeLCS, nil, payload)
	if e != nil {
		t.Fatal(e)
	}
	if len(w) != 6 {
		t.Fatalf("len(w) = %d, want 6 (no additional information)", len(w))
	}
}
func TestGenericNASTransportRejectsMalformed(t *testing.T) {
	for _, b := range [][]byte{{}, {1, 0}, {2, 0, 0}, {1, 0, 2, 1}} {
		if _, _, e := DecodeUplinkGenericNASTransport(b); e == nil {
			t.Fatalf("accepted %x", b)
		}
	}
}
