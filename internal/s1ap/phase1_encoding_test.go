package s1ap

import (
	"bytes"
	"testing"
	"time"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
)

func TestSendDownlinkNASTransportEncodesRel16IEs(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.10:36412"
	ch := setupSendCapture(srv, remoteAddr)
	ue := allocateTestUE(srv, remoteAddr, 0, true)
	ue.ENBS1APID = 0x010203

	nasPDU := emm.EncodeIdentityRequest(emm.IdentityTypeIMSI)
	if err := srv.SendDownlinkNAS(ue.MMEUES1APID, nasPDU); err != nil {
		t.Fatalf("SendDownlinkNAS: %v", err)
	}
	msg := readCapturedPDU(t, ch)
	assertPDUIEs(t, msg, pdu.PDUTypeInitiatingMessage, pdu.ProcDownlinkNASTransport, []uint16{
		pdu.IEMMEUES1APID,
		pdu.IEENBS1APID,
		pdu.IENAS_PDU,
	})
	assertNASPDU(t, msg, nasPDU)
}

func TestSendUEContextReleaseCommandEncodesRel16IEs(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.10:36412"
	ch := setupSendCapture(srv, remoteAddr)

	srv.sendUEContextReleaseCommand(remoteAddr, 1, 2)
	msg := readCapturedPDU(t, ch)
	assertPDUIEs(t, msg, pdu.PDUTypeInitiatingMessage, pdu.ProcUEContextRelease, []uint16{
		pdu.IEUES1APIDs,
		pdu.IECause,
	})
}

func TestProcedureCodesMatchRel16(t *testing.T) {
	if pdu.ProcReset != 14 {
		t.Fatalf("ProcReset: got %d, want 14", pdu.ProcReset)
	}
	if pdu.ProcErrorIndication != 15 {
		t.Fatalf("ProcErrorIndication: got %d, want 15", pdu.ProcErrorIndication)
	}
	if pdu.ProcNASNonDeliveryIndication != 16 {
		t.Fatalf("ProcNASNonDeliveryIndication: got %d, want 16", pdu.ProcNASNonDeliveryIndication)
	}
}

func TestHandleErrorIndicationDoesNotRespond(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.10:36412"
	ch := setupSendCapture(srv, remoteAddr)

	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeMMEUEApID(1)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeENBUEApID(2)},
		{ID: pdu.IECause, Criticality: aper.CriticalityIgnore, Value: ies.EncodeCause(ies.CauseGroupProtocol, 0)},
	}
	raw := pdu.BuildInitiatingMessage(pdu.ProcErrorIndication, aper.CriticalityIgnore, ieList)
	srv.handleMessage(remoteAddr, raw)

	select {
	case msg := <-ch:
		t.Fatalf("unexpected ErrorIndication response: %x", msg)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestSendInitialContextSetupEncodesRel16IEs(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.10:36412"
	ch := setupSendCapture(srv, remoteAddr)
	ue := allocateTestUE(srv, remoteAddr, 0, true)
	ue.ENBS1APID = 0x010203
	ue.KASME = make([]byte, 32)

	bearer := &BearerInfo{EBI: 5, SGWU_TEID: 0x01020304, SGWU_IP: []byte{10, 0, 0, 1}}
	if err := srv.SendInitialContextSetup(ue.MMEUES1APID, []byte{0x27, 0x42}, bearer); err != nil {
		t.Fatalf("SendInitialContextSetup: %v", err)
	}
	msg := readCapturedPDU(t, ch)
	assertPDUIEs(t, msg, pdu.PDUTypeInitiatingMessage, pdu.ProcInitialContextSetup, []uint16{
		pdu.IEMMEUES1APID,
		pdu.IEENBS1APID,
		pdu.IEUEAggregateMaxBitrate,
		pdu.IEERABToBeSetupListCtxtSUReq,
		pdu.IEUESecurityCapabilities,
		pdu.IESecurityKey,
	})
}

func readCapturedPDU(t *testing.T, ch <-chan []byte) *pdu.PDU {
	t.Helper()
	select {
	case raw := <-ch:
		msg, err := pdu.Decode(raw)
		if err != nil {
			t.Fatalf("Decode: %v", err)
		}
		return msg
	case <-time.After(200 * time.Millisecond):
		t.Fatal("no PDU captured")
	}
	return nil
}

func assertPDUIEs(t *testing.T, msg *pdu.PDU, typ pdu.PDUType, proc uint8, required []uint16) {
	t.Helper()
	if msg.Type != typ {
		t.Fatalf("PDU type: got %d, want %d", msg.Type, typ)
	}
	if msg.ProcedureCode != proc {
		t.Fatalf("procedureCode: got %d, want %d", msg.ProcedureCode, proc)
	}
	ies, err := pdu.DecodeProcedureIEContainer(msg.Value)
	if err != nil {
		t.Fatalf("DecodeProcedureIEContainer: %v", err)
	}
	byID := map[uint16]pdu.ProtocolIE{}
	for _, ie := range ies {
		byID[ie.ID] = ie
		meta, ok := pdu.Phase1ProcedureIEs[pdu.ProcedureIEKey{ProcedureCode: proc, PDUType: typ, IEID: ie.ID}]
		if ok && ie.Criticality != meta.Criticality {
			t.Fatalf("IE %d criticality: got %s, want %s", ie.ID, ie.Criticality, meta.Criticality)
		}
	}
	for _, id := range required {
		if _, ok := byID[id]; !ok {
			t.Fatalf("missing IE %d", id)
		}
	}
}

func assertNASPDU(t *testing.T, msg *pdu.PDU, want []byte) {
	t.Helper()
	container, err := pdu.DecodeProcedureIEContainer(msg.Value)
	if err != nil {
		t.Fatalf("DecodeProcedureIEContainer: %v", err)
	}
	for _, ie := range container {
		if ie.ID != pdu.IENAS_PDU {
			continue
		}
		got, err := ies.DecodeNASPDU(ie.Value)
		if err != nil {
			t.Fatalf("DecodeNASPDU: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("NAS-PDU: got %x, want %x", got, want)
		}
		return
	}
	t.Fatal("missing NAS-PDU IE")
}
