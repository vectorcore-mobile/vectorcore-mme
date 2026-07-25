package s1ap

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"github.com/vectorcore/mme/internal/uecontext"
)

func TestResetTypeCodecRoundTrips(t *testing.T) {
	cases := []resetType{
		{Kind: resetTypeS1Interface},
		{Kind: resetTypePartOfS1Interface, Items: []resetConnectionItem{{HasMMEUEID: true, MMEUEID: 0, HasENBUEID: true, ENBUEID: 0}}},
		{Kind: resetTypePartOfS1Interface, Items: []resetConnectionItem{{HasMMEUEID: true, MMEUEID: ^uint32(0)}}},
		{Kind: resetTypePartOfS1Interface, Items: []resetConnectionItem{{HasENBUEID: true, ENBUEID: 16777215}}},
		{Kind: resetTypePartOfS1Interface, Items: []resetConnectionItem{{HasMMEUEID: true, MMEUEID: 7}, {HasENBUEID: true, ENBUEID: 8}}},
	}
	for _, want := range cases {
		wire, err := encodeResetType(want)
		if err != nil {
			t.Fatalf("encode %#v: %v", want, err)
		}
		got, err := decodeResetType(wire)
		if err != nil {
			t.Fatalf("decode %x: %v", wire, err)
		}
		if got.Kind != want.Kind || len(got.Items) != len(want.Items) {
			t.Fatalf("round trip got %#v want %#v", got, want)
		}
		for i := range want.Items {
			if got.Items[i].HasMMEUEID != want.Items[i].HasMMEUEID || got.Items[i].MMEUEID != want.Items[i].MMEUEID || got.Items[i].HasENBUEID != want.Items[i].HasENBUEID || got.Items[i].ENBUEID != want.Items[i].ENBUEID {
				t.Fatalf("item %d got %#v want %#v", i, got.Items[i], want.Items[i])
			}
		}
	}
}

func TestHandlePartialResetOnlyClearsNamedBinding(t *testing.T) {
	srv := newTAUTestServer()
	const remote = "192.0.2.90:36412"
	ch := setupSendCapture(srv, remote)
	a := allocateTestUE(srv, remote, 0x10001, true)
	b := allocateTestUE(srv, remote, 0x10002, true)
	for _, v := range []struct {
		ue  *uecontext.Context
		enb uint32
	}{{a, 101}, {b, 102}} {
		v.ue.Lock()
		v.ue.ENBS1APID = v.enb
		v.ue.S1BindingGeneration = 9
		v.ue.S1BindingState = uecontext.S1BindingActive
		v.ue.SetEMMState(emm.StateRegistered)
		v.ue.SetECMState(emm.ECMConnected)
		v.ue.Unlock()
	}
	rt := resetType{Kind: resetTypePartOfS1Interface, Items: []resetConnectionItem{{HasMMEUEID: true, MMEUEID: a.MMEUES1APID, HasENBUEID: true, ENBUEID: 101}}}
	v, err := encodeResetType(rt)
	if err != nil {
		t.Fatal(err)
	}
	srv.handleMessage(remote, pdu.BuildInitiatingMessage(pdu.ProcReset, aper.CriticalityReject, []pdu.ProtocolIE{{ID: pdu.IECause, Criticality: aper.CriticalityIgnore, Value: ies.EncodeCause(ies.CauseGroupProtocol, 0)}, {ID: pdu.IEResetType, Criticality: aper.CriticalityReject, Value: v}}))
	msg := readCapturedPDU(t, ch)
	ackIEs, err := pdu.DecodeProcedureIEContainer(msg.Value)
	if err != nil {
		t.Fatal(err)
	}
	if len(ackIEs) != 1 || ackIEs[0].ID != pdu.IEUEAssociatedLogicalS1ConnectionListResAck {
		t.Fatalf("ack IEs %#v", ackIEs)
	}
	if got, err := decodeResetAcknowledgeList(ackIEs[0].Value); err != nil || len(got) != 1 {
		t.Fatalf("ack decode got %#v err %v", got, err)
	}
	a.Lock()
	aCleared := a.ENBS1APID == 0 && a.ENBGlobalID == "" && a.ECMState == emm.ECMIdle
	a.Unlock()
	b.Lock()
	bIntact := b.ENBS1APID == 102 && b.ENBGlobalID == remote && b.ECMState == emm.ECMConnected
	b.Unlock()
	if !aCleared || !bIntact {
		t.Fatalf("partial reset mutation a=%v b=%v", aCleared, bIntact)
	}
}

func TestPartialResetStaleAndContradictoryDoNotClear(t *testing.T) {
	srv := newTAUTestServer()
	const remote = "192.0.2.91:36412"
	_ = setupSendCapture(srv, remote)
	a := allocateTestUE(srv, remote, 0x20001, true)
	b := allocateTestUE(srv, remote, 0x20002, true)
	for _, v := range []struct {
		ue  *uecontext.Context
		enb uint32
	}{{a, 201}, {b, 202}} {
		v.ue.Lock()
		v.ue.ENBS1APID = v.enb
		v.ue.S1BindingGeneration = 3
		v.ue.S1BindingState = uecontext.S1BindingActive
		v.ue.SetEMMState(emm.StateRegistered)
		v.ue.Unlock()
	}
	rt := resetType{Kind: resetTypePartOfS1Interface, Items: []resetConnectionItem{{HasMMEUEID: true, MMEUEID: a.MMEUES1APID, HasENBUEID: true, ENBUEID: 202}, {HasMMEUEID: true, MMEUEID: a.MMEUES1APID, HasENBUEID: true, ENBUEID: 999}}}
	v, err := encodeResetType(rt)
	if err != nil {
		t.Fatal(err)
	}
	srv.handleReset(remote, &pdu.PDU{ProcedureCode: pdu.ProcReset, Type: pdu.PDUTypeInitiatingMessage, Criticality: aper.CriticalityReject}, []pdu.ProtocolIE{{ID: pdu.IECause, Criticality: aper.CriticalityIgnore, Value: ies.EncodeCause(ies.CauseGroupProtocol, 0)}, {ID: pdu.IEResetType, Criticality: aper.CriticalityReject, Value: v}})
	for _, ue := range []*uecontext.Context{a, b} {
		ue.Lock()
		intact := ue.ENBS1APID != 0 && ue.ENBGlobalID == remote
		ue.Unlock()
		if !intact {
			t.Fatal("stale/contradictory reset cleared a binding")
		}
	}
}

func TestPartialResetAcknowledgesEveryNonEmptyItemInOrder(t *testing.T) {
	srv := newTAUTestServer()
	const remote = "192.0.2.92:36412"
	ch := setupSendCapture(srv, remote)
	a := allocateTestUE(srv, remote, 0x30001, true)
	b := allocateTestUE(srv, remote, 0x30002, true)
	for _, v := range []struct {
		ue  *uecontext.Context
		enb uint32
	}{{a, 301}, {b, 302}} {
		v.ue.Lock()
		v.ue.ENBS1APID, v.ue.S1BindingGeneration, v.ue.S1BindingState = v.enb, 5, uecontext.S1BindingActive
		v.ue.SetEMMState(emm.StateRegistered)
		v.ue.SetECMState(emm.ECMConnected)
		v.ue.Unlock()
	}
	request := []resetConnectionItem{
		{HasMMEUEID: true, MMEUEID: a.MMEUES1APID, HasENBUEID: true, ENBUEID: 301}, // applied
		{HasMMEUEID: true, MMEUEID: a.MMEUES1APID, HasENBUEID: true, ENBUEID: 999}, // stale
		{HasMMEUEID: true, MMEUEID: 99999},                                         // unknown
		{HasMMEUEID: true, MMEUEID: a.MMEUES1APID, HasENBUEID: true, ENBUEID: 302}, // contradictory
		{HasMMEUEID: true, MMEUEID: b.MMEUES1APID},                                 // applied MME-only
		{HasENBUEID: true, ENBUEID: 302},                                           // stale after preceding item, still acked eNB-only
		{},                                                                         // empty is permitted and omitted from the acknowledgement
	}
	resetValue, err := encodeResetType(resetType{Kind: resetTypePartOfS1Interface, Items: request})
	if err != nil {
		t.Fatal(err)
	}
	srv.handleReset(remote, &pdu.PDU{ProcedureCode: pdu.ProcReset, Type: pdu.PDUTypeInitiatingMessage, Criticality: aper.CriticalityReject}, []pdu.ProtocolIE{{ID: pdu.IECause, Criticality: aper.CriticalityIgnore, Value: ies.EncodeCause(ies.CauseGroupProtocol, 0)}, {ID: pdu.IEResetType, Criticality: aper.CriticalityReject, Value: resetValue}})
	msg := readCapturedPDU(t, ch)
	iesOut, err := pdu.DecodeProcedureIEContainer(msg.Value)
	if err != nil {
		t.Fatal(err)
	}
	if len(iesOut) != 1 || iesOut[0].ID != pdu.IEUEAssociatedLogicalS1ConnectionListResAck {
		t.Fatalf("Reset Acknowledge IEs %#v", iesOut)
	}
	ack, err := decodeResetAcknowledgeList(iesOut[0].Value)
	if err != nil {
		t.Fatal(err)
	}
	if len(ack) != len(request)-1 {
		t.Fatalf("ack count got %d want %d", len(ack), len(request)-1)
	}
	for i := range ack {
		if ack[i].HasMMEUEID != request[i].HasMMEUEID || ack[i].MMEUEID != request[i].MMEUEID || ack[i].HasENBUEID != request[i].HasENBUEID || ack[i].ENBUEID != request[i].ENBUEID {
			t.Fatalf("ack[%d] got %#v want %#v", i, ack[i], request[i])
		}
	}
	for _, ue := range []*uecontext.Context{a, b} {
		ue.Lock()
		cleared := ue.ENBS1APID == 0 && ue.ENBGlobalID == "" && ue.ECMState == emm.ECMIdle
		ue.Unlock()
		if !cleared {
			t.Fatal("current matching binding was not cleared")
		}
	}
}

func TestResetTypeGoldenEricsson(t *testing.T) {
	wire, err := hex.DecodeString("4000005b0006601e80041759")
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeResetType(wire)
	if err != nil {
		t.Fatalf("golden decode: %v", err)
	}
	if got.Kind != resetTypePartOfS1Interface || len(got.Items) != 1 {
		t.Fatalf("golden type/items: %#v", got)
	}
	t.Logf("golden: type=%s count=%d item=%#v consumed=%d bytes/%d bits", got.Kind, len(got.Items), got.Items[0], got.BytesConsumed, got.BitsConsumed)
	if got.Items[0].IEID != 91 || got.Items[0].Criticality != aper.CriticalityReject {
		t.Fatalf("golden item header: %#v", got.Items[0])
	}
	reencoded, err := encodeResetType(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reencoded, wire) {
		t.Fatalf("golden re-encode got %x want %x", reencoded, wire)
	}
}

func TestResetTypeRejectsMalformedInput(t *testing.T) {
	for _, wire := range [][]byte{{}, {0x80}, {0x40}, {0x40, 0x00}, {0x40, 0x00, 0x00, 0x5b, 0x00, 0x04, 0x20, 0x04}} {
		if _, err := decodeResetType(wire); err == nil {
			t.Fatalf("accepted malformed %x", wire)
		}
	}
	if _, err := encodeResetType(resetType{Kind: resetTypePartOfS1Interface}); err == nil {
		t.Fatal("accepted zero list")
	}
}
