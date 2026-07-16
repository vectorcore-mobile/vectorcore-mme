package s1ap

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"github.com/vectorcore/mme/internal/uecontext"
)

// ── Shared helpers ────────────────────────────────────────────────────────────

const (
	srcAddr  = "10.10.1.1:36412"
	tgtAddr  = "10.10.2.1:36412"
	srcENBID = uint32(100)
	tgtENBID = uint32(200)
)

var (
	srcGlobalID = ies.GlobalENBID{MCC: "001", MNC: "01", ENB: ies.ENBID{Type: ies.ENBIDTypeMacro, Value: 0x00100}}
	tgtGlobalID = ies.GlobalENBID{MCC: "001", MNC: "01", ENB: ies.ENBID{Type: ies.ENBIDTypeMacro, Value: 0x00200}}
)

// roundTripGlobalENBID encodes then decodes a GlobalENBID to get the form
// the MME sees after it processes the S1 Setup or TargetID IE.
func roundTripGlobalENBID(g ies.GlobalENBID) ies.GlobalENBID {
	encoded, err := ies.EncodeGlobalENBID(g)
	if err != nil {
		return g
	}
	decoded, err := ies.DecodeGlobalENBID(encoded)
	if err != nil {
		return g
	}
	return decoded
}

// setupTwoENBServer creates a server with two eNBs registered and returns send capture channels.
// ENBContexts are registered with the round-tripped GlobalENBID (what the MME decodes from APER).
func setupTwoENBServer(s11 S11Client) (*Server, chan []byte, chan []byte) {
	srv := newTestServer(s11)
	srcCh := make(chan []byte, 16)
	tgtCh := make(chan []byte, 16)

	srcEnb := &ENBContext{RemoteAddr: srcAddr, GlobalENBID: roundTripGlobalENBID(srcGlobalID)}
	tgtEnb := &ENBContext{RemoteAddr: tgtAddr, GlobalENBID: roundTripGlobalENBID(tgtGlobalID)}
	srv.enbs.Store(srcAddr, srcEnb)
	srv.enbs.Store(tgtAddr, tgtEnb)
	srv.sends.Store(srcAddr, (chan<- []byte)(srcCh))
	srv.sends.Store(tgtAddr, (chan<- []byte)(tgtCh))
	return srv, srcCh, tgtCh
}

// makeHOUE creates a connected UE with NH/NCC set, attached to srcAddr.
func makeHOUE(srv *Server) *uecontext.Context {
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.ENBGlobalID = srcAddr
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMConnected
	ue.ENBS1APID = srcENBID
	ue.IMSI = "001010099900001"
	ue.DefaultEBI = 5
	ue.SGWC_TEID = 0xAABB0001
	ue.SGWC_IP = net.ParseIP("10.99.1.1").To4()
	ue.SGWU_TEID = 0xCCDD0001
	ue.SGWU_IP = net.ParseIP("10.99.1.2").To4()
	ue.ENBU_TEID = 0xDEAD0001
	ue.ENBU_IP = net.ParseIP("10.0.0.1").To4()
	ue.UEIPv4 = net.ParseIP("10.1.2.100").To4()
	ue.KASME = bytes.Repeat([]byte{0x11}, 32)
	ue.KNASint = make([]byte, 16)
	ue.KNASenc = make([]byte, 16)
	ue.NH = bytes.Repeat([]byte{0xAB}, 32)
	ue.NCC = 1
	ue.Unlock()
	return ue
}

// buildTargetIDBytes encodes a TargetID IE value for an intra-LTE TargeteNB-ID.
func buildTargetIDBytes(g ies.GlobalENBID) []byte {
	encoded, _ := ies.EncodeGlobalENBID(g)
	result := make([]byte, 2+len(encoded))
	result[0] = 0x00 // CHOICE ext=0, index=0 (targetENB-ID)
	result[1] = 0x00 // SEQUENCE ext=0, iE-Extensions absent
	copy(result[2:], encoded)
	return result
}

// buildERABAdmittedListBytes encodes a one-item E-RABAdmittedList IE value.
func buildERABAdmittedListBytes(ebi uint8, teid uint32, ip net.IP) []byte {
	iw := aper.NewBitWriter()
	// 6 preamble bits (ext + 5 optionals)
	for i := 0; i < 6; i++ {
		iw.WriteBit(0)
	}
	// E-RAB-ID (0..15, 4 bits)
	_ = aper.EncodeConstrainedWholeNumber(iw, int64(ebi), 0, 15)
	// transportLayerAddress BIT STRING (1..160): ext=0, len=32, align, 4 bytes
	iw.WriteBit(0)
	_ = aper.EncodeConstrainedWholeNumber(iw, 32, 1, 160)
	iw.AlignToByte()
	ipv4 := ip.To4()
	if ipv4 == nil {
		ipv4 = []byte{0, 0, 0, 0}
	}
	iw.WriteOctets(ipv4)
	// GTP-TEID (4 bytes, no length prefix)
	iw.AlignToByte()
	iw.WriteOctet(byte(teid >> 24))
	iw.WriteOctet(byte(teid >> 16))
	iw.WriteOctet(byte(teid >> 8))
	iw.WriteOctet(byte(teid))
	itemBody := iw.Bytes()

	// Wrap in IE container (IE 20, criticality=ignore), strip count prefix.
	innerIE := pdu.EncodeIEContainer([]pdu.ProtocolIE{
		{ID: pdu.IEERABAdmittedItem, Criticality: aper.CriticalityIgnore, Value: itemBody},
	})
	if len(innerIE) >= 2 {
		innerIE = innerIE[2:]
	}

	// Outer SEQUENCE OF count=1.
	ow := aper.NewBitWriter()
	_ = aper.EncodeConstrainedWholeNumber(ow, 1, 1, 256)
	ow.AlignToByte()
	ow.WriteOctets(innerIE)
	return ow.Bytes()
}

// buildHORequiredIEs builds the IE list for a Handover Required message.
func buildHORequiredIEs(mmeUEID, srcENBUEID uint32, targetID []byte) []pdu.ProtocolIE {
	cause := ies.EncodeCause(ies.CauseGroupRadioNetwork, ies.CauseRadioNetworkUnspecified)
	return []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeMMEUEApID(mmeUEID)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(srcENBUEID)},
		{ID: pdu.IEHandoverType, Criticality: aper.CriticalityReject, Value: ies.EncodeHandoverType(0)},
		{ID: pdu.IECause, Criticality: aper.CriticalityIgnore, Value: cause},
		{ID: pdu.IETargetID, Criticality: aper.CriticalityReject, Value: targetID},
		{ID: pdu.IESourceToTargetTransparentContainer, Criticality: aper.CriticalityReject, Value: []byte{0xAA, 0xBB}},
	}
}

// buildHORequestAckIEs builds the IE list for a Handover Request Acknowledge.
func buildHORequestAckIEs(mmeUEID, tgtENBUEID uint32, ebi uint8, teid uint32, ip net.IP) []pdu.ProtocolIE {
	admittedList := buildERABAdmittedListBytes(ebi, teid, ip)
	return []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeMMEUEApID(mmeUEID)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(tgtENBUEID)},
		{ID: pdu.IEERABAdmittedList, Criticality: aper.CriticalityReject, Value: admittedList},
		{ID: pdu.IETargetToSourceTransparentContainer, Criticality: aper.CriticalityReject, Value: []byte{0xCC, 0xDD}},
	}
}

// buildHONotifyIEs builds the IE list for a Handover Notify.
func buildHONotifyIEs(mmeUEID, tgtENBUEID uint32) []pdu.ProtocolIE {
	return []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeMMEUEApID(mmeUEID)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(tgtENBUEID)},
	}
}

// decodePDUType returns the PDU type byte from a raw encoded PDU (0=init, 1=succ, 2=unsucc).
func decodePDUType(raw []byte) pdu.PDUType {
	if len(raw) == 0 {
		return 255
	}
	p, err := pdu.Decode(raw)
	if err != nil {
		return 255
	}
	return p.Type
}

// decodeProcCode returns the procedure code from a raw encoded PDU.
func decodeProcCode(raw []byte) uint8 {
	p, err := pdu.Decode(raw)
	if err != nil {
		return 255
	}
	return p.ProcedureCode
}

func waitMsg(ch chan []byte, timeout time.Duration) ([]byte, bool) {
	select {
	case b := <-ch:
		return b, true
	case <-time.After(timeout):
		return nil, false
	}
}

// ── Unit tests: decode helpers ────────────────────────────────────────────────

func TestHandover_DecodeTargetID(t *testing.T) {
	original := ies.GlobalENBID{
		MCC: "001",
		MNC: "01",
		ENB: ies.ENBID{Type: ies.ENBIDTypeMacro, Value: 0x12345},
	}
	// The PLMN BCD codec swaps MNC digits on encode→decode; use the round-tripped form as ground truth.
	want := roundTripGlobalENBID(original)
	encoded := buildTargetIDBytes(original)
	got, err := decodeTargetID(encoded)
	if err != nil {
		t.Fatalf("decodeTargetID error: %v", err)
	}
	if got.Serialise() != want.Serialise() {
		t.Errorf("GlobalENBID mismatch: got %q, want %q", got.Serialise(), want.Serialise())
	}
	if got.ENB.Value != original.ENB.Value {
		t.Errorf("ENB value mismatch: got %d, want %d", got.ENB.Value, original.ENB.Value)
	}
}

func TestHandover_ERABAdmittedList(t *testing.T) {
	wantEBI := uint8(5)
	wantTEID := uint32(0xDEADBEEF)
	wantIP := net.ParseIP("10.20.30.40").To4()

	data := buildERABAdmittedListBytes(wantEBI, wantTEID, wantIP)
	gotEBI, gotTEID, gotIP, err := decodeERABAdmittedList(data)
	if err != nil {
		t.Fatalf("decodeERABAdmittedList error: %v", err)
	}
	if gotEBI != wantEBI {
		t.Errorf("EBI: got %d, want %d", gotEBI, wantEBI)
	}
	if gotTEID != wantTEID {
		t.Errorf("TEID: got %08X, want %08X", gotTEID, wantTEID)
	}
	if !gotIP.Equal(wantIP) {
		t.Errorf("IP: got %v, want %v", gotIP, wantIP)
	}
}

// ── Negative path: handleHandoverRequired ────────────────────────────────────

func TestHandover_UENotFound(t *testing.T) {
	srv, srcCh, _ := setupTwoENBServer(newMBRMock(nil))
	targetID := buildTargetIDBytes(tgtGlobalID)
	ieList := buildHORequiredIEs(0xDEAD, srcENBID, targetID)
	srv.handleHandoverRequired(srcAddr, &pdu.PDU{}, ieList)

	raw, ok := waitMsg(srcCh, 200*time.Millisecond)
	if !ok {
		t.Fatal("expected Prep Failure PDU, got nothing")
	}
	if decodePDUType(raw) != pdu.PDUTypeUnsuccessfulOutcome {
		t.Errorf("expected UnsuccessfulOutcome, got type %d", decodePDUType(raw))
	}
}

func TestHandover_NotRegistered(t *testing.T) {
	srv, srcCh, _ := setupTwoENBServer(newMBRMock(nil))
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.ENBGlobalID = srcAddr
	ue.EMMState = emm.StateDeregistered
	ue.ECMState = emm.ECMIdle
	mmeID := ue.MMEUES1APID
	ue.Unlock()

	targetID := buildTargetIDBytes(tgtGlobalID)
	ieList := buildHORequiredIEs(mmeID, srcENBID, targetID)
	srv.handleHandoverRequired(srcAddr, &pdu.PDU{}, ieList)

	raw, ok := waitMsg(srcCh, 200*time.Millisecond)
	if !ok {
		t.Fatal("expected Prep Failure PDU, got nothing")
	}
	if decodePDUType(raw) != pdu.PDUTypeUnsuccessfulOutcome {
		t.Error("expected UnsuccessfulOutcome")
	}
}

func TestHandover_NoBearer(t *testing.T) {
	srv, srcCh, _ := setupTwoENBServer(newMBRMock(nil))
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.ENBGlobalID = srcAddr
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMConnected
	ue.SGWC_TEID = 0 // no bearer
	ue.DefaultEBI = 0
	mmeID := ue.MMEUES1APID
	ue.Unlock()

	targetID := buildTargetIDBytes(tgtGlobalID)
	ieList := buildHORequiredIEs(mmeID, srcENBID, targetID)
	srv.handleHandoverRequired(srcAddr, &pdu.PDU{}, ieList)

	raw, ok := waitMsg(srcCh, 200*time.Millisecond)
	if !ok {
		t.Fatal("expected Prep Failure PDU, got nothing")
	}
	if decodePDUType(raw) != pdu.PDUTypeUnsuccessfulOutcome {
		t.Error("expected UnsuccessfulOutcome")
	}
}

func TestHandover_TargetNotFound(t *testing.T) {
	srv, srcCh, _ := setupTwoENBServer(newMBRMock(nil))
	ue := makeHOUE(srv)

	unknownGlobalID := ies.GlobalENBID{MCC: "001", MNC: "01", ENB: ies.ENBID{Type: ies.ENBIDTypeMacro, Value: 0x99999}}
	targetID := buildTargetIDBytes(unknownGlobalID)
	ieList := buildHORequiredIEs(ue.MMEUES1APID, srcENBID, targetID)
	srv.handleHandoverRequired(srcAddr, &pdu.PDU{}, ieList)

	raw, ok := waitMsg(srcCh, 200*time.Millisecond)
	if !ok {
		t.Fatal("expected Prep Failure PDU, got nothing")
	}
	if decodePDUType(raw) != pdu.PDUTypeUnsuccessfulOutcome {
		t.Error("expected UnsuccessfulOutcome")
	}
	// HOState must remain None
	ue.Lock()
	hoState := ue.HOState
	ue.Unlock()
	if hoState != uecontext.HOStateNone {
		t.Errorf("HOState should be None after failed HO, got %d", hoState)
	}
}

// ── Negative path: handleHandoverRequestAck wrong state ──────────────────────

func TestHandover_RequestAck_WrongState(t *testing.T) {
	srv, _, tgtCh := setupTwoENBServer(newMBRMock(nil))
	ue := makeHOUE(srv)
	// Do NOT send HO Required first — HOState stays None.

	ackIEs := buildHORequestAckIEs(ue.MMEUES1APID, tgtENBID, 5, 0x12340001, net.ParseIP("10.20.30.1"))
	srv.handleHandoverRequestAck(tgtAddr, &pdu.PDU{}, ackIEs)

	// No message should be sent anywhere.
	select {
	case <-tgtCh:
		t.Error("unexpected message sent for stale Ack")
	case <-time.After(100 * time.Millisecond):
	}
}

// ── handleHandoverRequestFailure ─────────────────────────────────────────────

func TestHandover_RequestFailure(t *testing.T) {
	srv, srcCh, tgtCh := setupTwoENBServer(newMBRMock(nil))
	ue := makeHOUE(srv)

	// Trigger HO Required to put UE in HOStatePreparing.
	targetID := buildTargetIDBytes(tgtGlobalID)
	reqIEs := buildHORequiredIEs(ue.MMEUES1APID, srcENBID, targetID)
	srv.handleHandoverRequired(srcAddr, &pdu.PDU{}, reqIEs)

	// Drain the HO Request sent to target.
	if _, ok := waitMsg(tgtCh, 200*time.Millisecond); !ok {
		t.Fatal("expected HO Request to target, got nothing")
	}

	// Target sends Failure.
	failIEs := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeMMEUEApID(ue.MMEUES1APID)},
		{ID: pdu.IECause, Criticality: aper.CriticalityIgnore, Value: ies.EncodeCause(ies.CauseGroupRadioNetwork, ies.CauseRadioNetworkUnspecified)},
	}
	srv.handleHandoverRequestFailure(tgtAddr, &pdu.PDU{}, failIEs)

	// Source should receive Prep Failure.
	raw, ok := waitMsg(srcCh, 200*time.Millisecond)
	if !ok {
		t.Fatal("expected Prep Failure to source, got nothing")
	}
	if decodePDUType(raw) != pdu.PDUTypeUnsuccessfulOutcome {
		t.Errorf("expected UnsuccessfulOutcome, got type %d", decodePDUType(raw))
	}

	// HOState must be cleared.
	ue.Lock()
	hoState := ue.HOState
	ue.Unlock()
	if hoState != uecontext.HOStateNone {
		t.Errorf("HOState should be None after Failure, got %d", hoState)
	}
}

// ── Timer expiry tests ────────────────────────────────────────────────────────

func TestHandover_PrepTimerExpiry(t *testing.T) {
	srv, srcCh, tgtCh := setupTwoENBServer(newMBRMock(nil))
	ue := makeHOUE(srv)

	// Set a very short prep timer by manipulating the UE context after sending HO Required.
	targetID := buildTargetIDBytes(tgtGlobalID)
	reqIEs := buildHORequiredIEs(ue.MMEUES1APID, srcENBID, targetID)
	srv.handleHandoverRequired(srcAddr, &pdu.PDU{}, reqIEs)

	// Drain the HO Request to target.
	if _, ok := waitMsg(tgtCh, 200*time.Millisecond); !ok {
		t.Fatal("expected HO Request to target")
	}

	// Fire the timer manually (simulates expiry without waiting 2s).
	srv.handoverPrepTimeout(ue.MMEUES1APID, srcENBID)

	// Source should receive Prep Failure.
	raw, ok := waitMsg(srcCh, 200*time.Millisecond)
	if !ok {
		t.Fatal("expected Prep Failure to source on timer expiry")
	}
	if decodePDUType(raw) != pdu.PDUTypeUnsuccessfulOutcome {
		t.Error("expected UnsuccessfulOutcome")
	}
	ue.Lock()
	hoState := ue.HOState
	ue.Unlock()
	if hoState != uecontext.HOStateNone {
		t.Errorf("HOState should be None after prep timeout, got %d", hoState)
	}
}

func TestHandover_ExecTimerExpiry(t *testing.T) {
	srv, srcCh, tgtCh := setupTwoENBServer(newMBRMock(nil))
	ue := makeHOUE(srv)

	// Drive through preparation phase.
	targetID := buildTargetIDBytes(tgtGlobalID)
	reqIEs := buildHORequiredIEs(ue.MMEUES1APID, srcENBID, targetID)
	srv.handleHandoverRequired(srcAddr, &pdu.PDU{}, reqIEs)
	if _, ok := waitMsg(tgtCh, 200*time.Millisecond); !ok {
		t.Fatal("expected HO Request")
	}

	ackIEs := buildHORequestAckIEs(ue.MMEUES1APID, tgtENBID, 5, 0xBBCC0001, net.ParseIP("10.20.30.2"))
	srv.handleHandoverRequestAck(tgtAddr, &pdu.PDU{}, ackIEs)
	if _, ok := waitMsg(srcCh, 200*time.Millisecond); !ok {
		t.Fatal("expected HO Command to source")
	}

	// Fire exec timeout manually.
	srv.handoverExecTimeout(ue.MMEUES1APID, tgtAddr, tgtENBID)

	// Target should receive UE Context Release.
	raw, ok := waitMsg(tgtCh, 200*time.Millisecond)
	if !ok {
		t.Fatal("expected UE Context Release to target on exec timeout")
	}
	p, err := pdu.Decode(raw)
	if err != nil {
		t.Fatalf("PDU decode error: %v", err)
	}
	if p.Type != pdu.PDUTypeInitiatingMessage || p.ProcedureCode != pdu.ProcUEContextRelease {
		t.Errorf("expected UE Context Release (proc 23), got type=%d proc=%d", p.Type, p.ProcedureCode)
	}
}

// ── Full success flow ─────────────────────────────────────────────────────────

func TestHandover_SuccessfulFlow(t *testing.T) {
	mock := newMBRMock(nil)
	srv, srcCh, tgtCh := setupTwoENBServer(mock)
	ue := makeHOUE(srv)
	mmeID := ue.MMEUES1APID

	// Step 1: HO Required from source.
	targetID := buildTargetIDBytes(tgtGlobalID)
	reqIEs := buildHORequiredIEs(mmeID, srcENBID, targetID)
	srv.handleHandoverRequired(srcAddr, &pdu.PDU{}, reqIEs)

	// Target should receive HO Request.
	raw, ok := waitMsg(tgtCh, 300*time.Millisecond)
	if !ok {
		t.Fatal("expected HO Request to target")
	}
	p, err := pdu.Decode(raw)
	if err != nil {
		t.Fatalf("PDU decode error: %v", err)
	}
	if p.Type != pdu.PDUTypeInitiatingMessage || p.ProcedureCode != pdu.ProcHandoverResourceAllocation {
		t.Errorf("expected HO Request (proc 1), got type=%d proc=%d", p.Type, p.ProcedureCode)
	}

	// Verify SecurityContext IE is present.
	ieList, _ := pdu.DecodeIEContainer(p.Value)
	hasSecCtx := false
	for _, ie := range ieList {
		if ie.ID == pdu.IESecurityContext {
			hasSecCtx = true
		}
	}
	if !hasSecCtx {
		t.Error("HO Request missing SecurityContext IE")
	}

	// Verify UE is in HOStatePreparing.
	ue.Lock()
	if ue.HOState != uecontext.HOStatePreparing {
		t.Errorf("expected HOStatePreparing, got %d", ue.HOState)
	}
	ue.Unlock()

	// Step 2: HO Request Ack from target.
	newTEID := uint32(0xBEEF0001)
	newIP := net.ParseIP("10.20.30.50").To4()
	ackIEs := buildHORequestAckIEs(mmeID, tgtENBID, 5, newTEID, newIP)
	srv.handleHandoverRequestAck(tgtAddr, &pdu.PDU{}, ackIEs)

	// Source should receive HO Command.
	raw, ok = waitMsg(srcCh, 300*time.Millisecond)
	if !ok {
		t.Fatal("expected HO Command to source")
	}
	p, err = pdu.Decode(raw)
	if err != nil {
		t.Fatalf("PDU decode error: %v", err)
	}
	if p.Type != pdu.PDUTypeSuccessfulOutcome || p.ProcedureCode != pdu.ProcHandoverPreparation {
		t.Errorf("expected HO Command (succ, proc 0), got type=%d proc=%d", p.Type, p.ProcedureCode)
	}

	// UE should be in HOStateExecuting.
	ue.Lock()
	if ue.HOState != uecontext.HOStateExecuting {
		t.Errorf("expected HOStateExecuting, got %d", ue.HOState)
	}
	ue.Unlock()

	// Step 3: HO Notify from target.
	notifyIEs := buildHONotifyIEs(mmeID, tgtENBID)
	srv.handleHandoverNotify(tgtAddr, &pdu.PDU{}, notifyIEs)

	// Wait for goroutine (MBR + release + context update).
	time.Sleep(150 * time.Millisecond)

	// Source should receive UE Context Release.
	raw, ok = waitMsg(srcCh, 300*time.Millisecond)
	if !ok {
		t.Fatal("expected UE Context Release to source")
	}
	p, err = pdu.Decode(raw)
	if err != nil {
		t.Fatalf("PDU decode error: %v", err)
	}
	if p.Type != pdu.PDUTypeInitiatingMessage || p.ProcedureCode != pdu.ProcUEContextRelease {
		t.Errorf("expected UE Context Release (proc 23), got type=%d proc=%d", p.Type, p.ProcedureCode)
	}

	// Verify UE context is now on target eNB.
	ue.Lock()
	if ue.HOState != uecontext.HOStateNone {
		t.Errorf("HOState should be None after success, got %d", ue.HOState)
	}
	if ue.ENBGlobalID != tgtAddr {
		t.Errorf("UE.ENBGlobalID should be tgtAddr, got %q", ue.ENBGlobalID)
	}
	if ue.ENBS1APID != tgtENBID {
		t.Errorf("UE.ENBS1APID should be tgtENBID (%d), got %d", tgtENBID, ue.ENBS1APID)
	}
	if ue.ENBU_TEID != newTEID {
		t.Errorf("UE.ENBU_TEID should be %08X, got %08X", newTEID, ue.ENBU_TEID)
	}
	if !ue.ENBU_IP.Equal(newIP) {
		t.Errorf("UE.ENBU_IP should be %v, got %v", newIP, ue.ENBU_IP)
	}
	ue.Unlock()

	// MBR must have been called.
	mock.mu.Lock()
	nCalls := len(mock.mbrCalls)
	mock.mu.Unlock()
	if nCalls != 1 {
		t.Errorf("expected 1 MBR call, got %d", nCalls)
	}
}

// ── MBR failure: UE still moves to target ────────────────────────────────────

func TestHandover_MBRFailure(t *testing.T) {
	mock := newMBRMock(errMBR)
	srv, srcCh, tgtCh := setupTwoENBServer(mock)
	ue := makeHOUE(srv)
	mmeID := ue.MMEUES1APID

	// Full prep phase.
	targetID := buildTargetIDBytes(tgtGlobalID)
	srv.handleHandoverRequired(srcAddr, &pdu.PDU{}, buildHORequiredIEs(mmeID, srcENBID, targetID))
	if _, ok := waitMsg(tgtCh, 200*time.Millisecond); !ok {
		t.Fatal("expected HO Request")
	}

	newTEID := uint32(0xFACE0001)
	newIP := net.ParseIP("10.20.30.60").To4()
	srv.handleHandoverRequestAck(tgtAddr, &pdu.PDU{}, buildHORequestAckIEs(mmeID, tgtENBID, 5, newTEID, newIP))
	if _, ok := waitMsg(srcCh, 200*time.Millisecond); !ok {
		t.Fatal("expected HO Command")
	}

	srv.handleHandoverNotify(tgtAddr, &pdu.PDU{}, buildHONotifyIEs(mmeID, tgtENBID))
	time.Sleep(150 * time.Millisecond)

	// Even with MBR failure, UE should be on target and source released.
	ue.Lock()
	if ue.ENBGlobalID != tgtAddr {
		t.Errorf("UE should be on target even after MBR failure, got %q", ue.ENBGlobalID)
	}
	if ue.HOState != uecontext.HOStateNone {
		t.Errorf("HOState should be None, got %d", ue.HOState)
	}
	ue.Unlock()

	// Source should still receive release.
	raw, ok := waitMsg(srcCh, 300*time.Millisecond)
	if !ok {
		t.Fatal("expected UE Context Release to source even after MBR failure")
	}
	p, _ := pdu.Decode(raw)
	if p.ProcedureCode != pdu.ProcUEContextRelease {
		t.Errorf("expected UE Context Release, got proc %d", p.ProcedureCode)
	}
}

// ── NH/NCC advancement ────────────────────────────────────────────────────────

func TestHandover_NHAdvanced(t *testing.T) {
	srv, srcCh, tgtCh := setupTwoENBServer(newMBRMock(nil))
	ue := makeHOUE(srv)
	mmeID := ue.MMEUES1APID

	initialNH := append([]byte(nil), ue.NH...)
	initialNCC := ue.NCC

	// Full flow.
	targetID := buildTargetIDBytes(tgtGlobalID)
	srv.handleHandoverRequired(srcAddr, &pdu.PDU{}, buildHORequiredIEs(mmeID, srcENBID, targetID))
	if _, ok := waitMsg(tgtCh, 200*time.Millisecond); !ok {
		t.Fatal("expected HO Request")
	}
	srv.handleHandoverRequestAck(tgtAddr, &pdu.PDU{}, buildHORequestAckIEs(mmeID, tgtENBID, 5, 0x1001, net.ParseIP("10.1.1.1")))
	if _, ok := waitMsg(srcCh, 200*time.Millisecond); !ok {
		t.Fatal("expected HO Command")
	}
	srv.handleHandoverNotify(tgtAddr, &pdu.PDU{}, buildHONotifyIEs(mmeID, tgtENBID))
	time.Sleep(150 * time.Millisecond)

	ue.Lock()
	newNH := ue.NH
	newNCC := ue.NCC
	ue.Unlock()

	if bytes.Equal(newNH, initialNH) {
		t.Error("NH should have advanced after handover")
	}
	if newNCC == initialNCC {
		t.Errorf("NCC should have incremented (was %d, still %d)", initialNCC, newNCC)
	}
}

// ── Source eNB release cause ──────────────────────────────────────────────────

func TestHandover_OldENBReleased(t *testing.T) {
	srv, srcCh, tgtCh := setupTwoENBServer(newMBRMock(nil))
	ue := makeHOUE(srv)
	mmeID := ue.MMEUES1APID

	targetID := buildTargetIDBytes(tgtGlobalID)
	srv.handleHandoverRequired(srcAddr, &pdu.PDU{}, buildHORequiredIEs(mmeID, srcENBID, targetID))
	if _, ok := waitMsg(tgtCh, 200*time.Millisecond); !ok {
		t.Fatal("expected HO Request")
	}
	srv.handleHandoverRequestAck(tgtAddr, &pdu.PDU{}, buildHORequestAckIEs(mmeID, tgtENBID, 5, 0x2001, net.ParseIP("10.2.2.2")))
	if _, ok := waitMsg(srcCh, 200*time.Millisecond); !ok {
		t.Fatal("expected HO Command")
	}
	srv.handleHandoverNotify(tgtAddr, &pdu.PDU{}, buildHONotifyIEs(mmeID, tgtENBID))
	time.Sleep(150 * time.Millisecond)

	// Source should receive UE Context Release (proc 23, initiating).
	raw, ok := waitMsg(srcCh, 300*time.Millisecond)
	if !ok {
		t.Fatal("expected UE Context Release to source eNB")
	}
	p, err := pdu.Decode(raw)
	if err != nil {
		t.Fatalf("PDU decode error: %v", err)
	}
	if p.Type != pdu.PDUTypeInitiatingMessage {
		t.Errorf("expected InitiatingMessage, got %d", p.Type)
	}
	if p.ProcedureCode != pdu.ProcUEContextRelease {
		t.Errorf("expected ProcUEContextRelease (%d), got %d", pdu.ProcUEContextRelease, p.ProcedureCode)
	}
}

// ── Review fix 4: stale source release after HO ───────────────────────────────

// TestHandover_StaleSourceReleaseIgnored verifies that a UE Context Release Complete
// arriving from the *old source* eNB after a successful handover does NOT clobber the
// UE's new ENBGlobalID or transition it to ECM-IDLE. Previously this race caused the
// UE to appear idle+unaddressable immediately after handover.
func TestHandover_StaleSourceReleaseIgnored(t *testing.T) {
	srv, srcCh, tgtCh := setupTwoENBServer(newMBRMock(nil))
	ue := makeHOUE(srv)
	mmeID := ue.MMEUES1APID

	// Drive a full successful handover.
	targetID := buildTargetIDBytes(tgtGlobalID)
	srv.handleHandoverRequired(srcAddr, &pdu.PDU{}, buildHORequiredIEs(mmeID, srcENBID, targetID))
	if _, ok := waitMsg(tgtCh, 200*time.Millisecond); !ok {
		t.Fatal("expected HO Request")
	}
	srv.handleHandoverRequestAck(tgtAddr, &pdu.PDU{}, buildHORequestAckIEs(mmeID, tgtENBID, 5, 0x2001, net.ParseIP("10.2.2.2")))
	if _, ok := waitMsg(srcCh, 200*time.Millisecond); !ok {
		t.Fatal("expected HO Command")
	}
	srv.handleHandoverNotify(tgtAddr, &pdu.PDU{}, buildHONotifyIEs(mmeID, tgtENBID))

	// Wait for MBR + UE Context Release Command to source.
	if _, ok := waitMsg(srcCh, 300*time.Millisecond); !ok {
		t.Fatal("expected UE Context Release Command to source")
	}
	// Allow goroutine to settle and UE to be updated to target.
	time.Sleep(50 * time.Millisecond)

	// At this point the UE is connected to the target eNB.
	ue.Lock()
	enbAfterHO := ue.ENBGlobalID
	ecmAfterHO := ue.ECMState
	ue.Unlock()

	if enbAfterHO != tgtAddr {
		t.Fatalf("pre-condition: ENBGlobalID should be target after HO, got %q", enbAfterHO)
	}
	if ecmAfterHO != emm.ECMConnected {
		t.Errorf("pre-condition: ECMState should be Connected after HO, got %v", ecmAfterHO)
	}

	// Now simulate the source eNB sending UE Context Release Complete — this is the
	// stale release the source eNB sends after processing the UE Context Release Command.
	releaseIEs := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Value: encodeMMEUEID(mmeID)},
	}
	srv.handleUEContextReleaseComplete(srcAddr, &pdu.PDU{}, releaseIEs)

	// The UE must still be on the target eNB, not evicted to ECM-IDLE.
	ue.Lock()
	enbAfterStale := ue.ENBGlobalID
	ecmAfterStale := ue.ECMState
	ue.Unlock()

	if enbAfterStale != tgtAddr {
		t.Errorf("stale release clobbered ENBGlobalID: got %q, want %q", enbAfterStale, tgtAddr)
	}
	if ecmAfterStale != emm.ECMConnected {
		t.Errorf("stale release transitioned UE to ECM-IDLE: got %v", ecmAfterStale)
	}
}

// encodeMMEUEID encodes a single MME UE S1AP ID into an APER open-type value.
func encodeMMEUEID(mmeUEID uint32) []byte {
	w := aper.NewBitWriter()
	_ = aper.EncodeConstrainedWholeNumber(w, int64(mmeUEID), 0, 4294967295)
	raw := w.Bytes()
	// Wrap in open-type length prefix (1-byte for values ≤ 127 bytes).
	out := make([]byte, 1+len(raw))
	out[0] = byte(len(raw))
	copy(out[1:], raw)
	return out
}

// ── shared test error sentinel ────────────────────────────────────────────────

// errMBR is the sentinel error returned by the mock when MBR failure is requested.
var errMBR = errors.New("mock MBR failed")
