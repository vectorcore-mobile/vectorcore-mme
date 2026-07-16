package s1ap

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"github.com/vectorcore/mme/internal/uecontext"
)

func TestAttachWithCollidingGUTIDoesNotEvictCandidateUE(t *testing.T) {
	mock := &mockS11{}
	srv := newTestServer(mock)
	const addr = "192.0.2.20:36412"
	ch := setupSendCapture(srv, addr)

	collidingGUTI := &emm.GUTI{
		PLMN:  [3]byte{0x13, 0x51, 0x34},
		MMEGI: 1,
		MMEC:  1,
		MTMSI: 2,
	}
	realUE := srv.ueManager.Allocate()
	realUE.Lock()
	realUE.IMSI = "311435000070570"
	realUE.EMMState = emm.StateRegistered
	realUE.ECMState = emm.ECMIdle
	realUE.DefaultEBI = 5
	realUE.SGWC_TEID = 0xfbf8cf96
	realUE.SGWAddress = "10.90.250.59:2123"
	realUE.SGWC_IP = net.ParseIP("10.90.250.59").To4()
	realUE.GUTI = collidingGUTI
	realUE.Unlock()
	srv.ueManager.UpdateIMSI(realUE, "311435000070570")
	srv.ueManager.UpdateGUTI(realUE, collidingGUTI)

	nasPDU := buildAttachRequestWithGUTI(collidingGUTI)
	taiValue, err := ies.EncodeTAI(ies.TAI{MCC: "311", MNC: "435", TAC: 1})
	if err != nil {
		t.Fatal(err)
	}
	ecgiValue, err := ies.EncodeECGI(ies.ECGI{MCC: "311", MNC: "435", ECGI: 0x197})
	if err != nil {
		t.Fatal(err)
	}
	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(268276)},
		{ID: pdu.IENAS_PDU, Criticality: aper.CriticalityReject, Value: ies.EncodeNASPDU(nasPDU)},
		{ID: pdu.IETAI, Criticality: aper.CriticalityReject, Value: taiValue},
		{ID: pdu.IECGI, Criticality: aper.CriticalityIgnore, Value: ecgiValue},
		{ID: pdu.IERRCEstablishmentCause, Criticality: aper.CriticalityIgnore, Value: ies.EncodeRRCEstablishmentCause(3)},
	}

	srv.handleMessage(addr, pdu.BuildInitiatingMessage(pdu.ProcInitialUEMessage, aper.CriticalityIgnore, ieList))

	msg := readCapturedPDU(t, ch)
	downlinkNAS := decodeNASPDUFromPDU(t, msg)
	if !bytes.Equal(downlinkNAS, []byte{0x07, emm.MsgIdentityRequest, 0x01}) {
		t.Fatalf("downlink NAS got %x, want Identity Request for IMSI", downlinkNAS)
	}
	if len(mock.dsrCalls) != 0 {
		t.Fatalf("Delete Session sent for unverified GUTI candidate: %d calls", len(mock.dsrCalls))
	}
	found, ok := srv.ueManager.GetByGUTI(uecontext.SerialiseGUTI(collidingGUTI))
	if !ok || found != realUE {
		t.Fatalf("candidate UE GUTI mapping was not preserved")
	}
	realUE.Lock()
	imsi := realUE.IMSI
	emmState := realUE.EMMState
	ecmState := realUE.ECMState
	sgwcTEID := realUE.SGWC_TEID
	realUE.Unlock()
	if imsi != "311435000070570" || emmState != emm.StateRegistered || ecmState != emm.ECMIdle || sgwcTEID == 0 {
		t.Fatalf("candidate UE modified: imsi=%s emm=%s ecm=%s sgwc_teid=%#x", imsi, emmState, ecmState, sgwcTEID)
	}

	select {
	case extra := <-ch:
		t.Fatalf("unexpected extra PDU: %x", extra)
	case <-time.After(10 * time.Millisecond):
	}
}

func TestIdentityResponseDefersDuplicateIMSIEvictionUntilAuthentication(t *testing.T) {
	mock := &mockS11{}
	srv := newTAUTestServer()
	srv.s11 = mock
	srv.s6a = NoopS6aClient{}

	existing := srv.ueManager.Allocate()
	existing.Lock()
	existing.IMSI = "311435300070580"
	existing.EMMState = emm.StateRegistered
	existing.ECMState = emm.ECMIdle
	existing.DefaultEBI = 5
	existing.SGWC_TEID = 0x11112222
	existing.SGWAddress = "10.90.250.59:2123"
	existing.Unlock()
	srv.ueManager.UpdateIMSI(existing, "311435300070580")

	incoming := srv.ueManager.Allocate()
	incoming.Lock()
	incoming.CandidateGUTI = "13513400010100000002"
	incoming.CandidateIMSI = "311435000070570"
	incoming.Unlock()

	if err := srv.processIdentityResponse(incoming, identityResponseBody("311435300070580"), srv.log); err != nil {
		t.Fatalf("processIdentityResponse: %v", err)
	}
	if len(mock.dsrCalls) != 0 {
		t.Fatalf("Delete Session sent before authentication: %d calls", len(mock.dsrCalls))
	}
	indexed, ok := srv.ueManager.GetByIMSI("311435300070580")
	if !ok || indexed != existing {
		t.Fatalf("pre-auth IMSI index was not preserved for existing UE")
	}
	incoming.Lock()
	incomingIMSI := incoming.IMSI
	incoming.Unlock()
	if incomingIMSI != "311435300070580" {
		t.Fatalf("incoming IMSI = %q, want confirmed IMSI on context", incomingIMSI)
	}
}

func TestAuthenticatedIdentityOwnershipReplacesSameIMSIContext(t *testing.T) {
	mock := &mockS11{}
	srv := newTAUTestServer()
	srv.s11 = mock

	existing := srv.ueManager.Allocate()
	existing.Lock()
	existing.IMSI = "311435300070580"
	existing.EMMState = emm.StateRegistered
	existing.ECMState = emm.ECMIdle
	existing.DefaultEBI = 5
	existing.SGWC_TEID = 0x11112222
	existing.SGWAddress = "10.90.250.59:2123"
	existing.Unlock()
	srv.ueManager.UpdateIMSI(existing, "311435300070580")

	incoming := srv.ueManager.Allocate()
	incoming.Lock()
	incoming.IMSI = "311435300070580"
	incoming.CandidateGUTI = "13513400010100000002"
	incoming.CandidateIMSI = "311435300070580"
	incoming.Unlock()

	srv.confirmAuthenticatedIdentityOwnership(incoming, srv.log)

	if len(mock.dsrCalls) != 1 {
		t.Fatalf("Delete Session calls = %d, want 1 after authentication", len(mock.dsrCalls))
	}
	if _, ok := srv.ueManager.GetByMMEID(existing.MMEUES1APID); ok {
		t.Fatalf("old same-IMSI context still present after authenticated replacement")
	}
	indexed, ok := srv.ueManager.GetByIMSI("311435300070580")
	if !ok || indexed != incoming {
		t.Fatalf("authenticated incoming UE was not registered in IMSI index")
	}
}

func buildAttachRequestWithGUTI(guti *emm.GUTI) []byte {
	body := []byte{0x01}
	body = append(body, guti.Encode()...)
	body = append(body, 0x02, 0xf0, 0x70)
	body = append(body, 0x00, 0x05, 0x02, 0x01, 0xd0, 0x11, 0xd1)
	out := []byte{emm.PDEPSMobilityMgmt, emm.MsgAttachRequest}
	out = append(out, body...)
	return out
}

func identityResponseBody(imsi string) []byte {
	mobileID := emm.EPSMobileIdentityIMSI(imsi)
	body := []byte{byte(len(mobileID))}
	body = append(body, mobileID...)
	return body
}
