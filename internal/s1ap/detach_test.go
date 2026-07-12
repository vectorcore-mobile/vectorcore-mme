package s1ap

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/nas"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
)

func buildProtectedDetachPDU(t *testing.T, guti *emm.GUTI, detachType uint8, count uint32) []byte {
	t.Helper()
	gutiLV := guti.Encode()
	body := []byte{detachType}
	body = append(body, gutiLV...)
	plain := append([]byte{emm.PDEPSMobilityMgmt, emm.MsgDetachRequest}, body...)
	protected, err := nas.EncodeIntegrityProtected(plain, 0, nil, count)
	if err != nil {
		t.Fatalf("EncodeIntegrityProtected detach: %v", err)
	}
	return protected
}

func buildInitialUEWithDetach(t *testing.T, enbUEID uint32, nasPDU []byte) []byte {
	t.Helper()
	stmsi := mustHexS1AP(t, "004000000002")
	taiValue, err := ies.EncodeTAI(ies.TAI{MCC: "001", MNC: "01", TAC: 1})
	if err != nil {
		t.Fatal(err)
	}
	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(enbUEID)},
		{ID: pdu.IENAS_PDU, Criticality: aper.CriticalityReject, Value: ies.EncodeNASPDU(nasPDU)},
		{ID: pdu.IETAI, Criticality: aper.CriticalityReject, Value: taiValue},
		{ID: pdu.IESTMSI, Criticality: aper.CriticalityReject, Value: stmsi},
	}
	return pdu.BuildInitiatingMessage(pdu.ProcInitialUEMessage, aper.CriticalityIgnore, ieList)
}

func TestInitialUEDetachNonSwitchOffDeletesSession(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.0.0.40:36412"
	setupSendCapture(srv, addr)
	mock := &mockS11{}
	srv.s11 = mock

	realUE, _, _ := makeRegisteredIdleUE(srv, addr)
	guti := &emm.GUTI{PLMN: [3]byte{0x00, 0xF1, 0x10}, MMEGI: 1, MMEC: 1, MTMSI: 2}
	srv.ueManager.UpdateGUTI(realUE, guti)
	nasPDU := buildProtectedDetachPDU(t, guti, emm.DetachTypeNormal, 1)

	before := srv.ueManager.Count()
	srv.handleMessage(addr, buildInitialUEWithDetach(t, 3, nasPDU))

	if len(mock.dsrCalls) != 1 {
		t.Fatalf("DSR calls got %d, want 1", len(mock.dsrCalls))
	}
	if got := mock.dsrCalls[0].EBI; got != 5 {
		t.Fatalf("DSR EBI got %d, want 5", got)
	}
	if srv.ueManager.Count() != before {
		t.Fatalf("manager count before DSR result got %d, want %d", srv.ueManager.Count(), before)
	}
	realUE.Lock()
	emmState := realUE.EMMState
	enbUEID := realUE.ENBS1APID
	realUE.Unlock()
	if emmState != emm.StateDeregisteredInitiated {
		t.Fatalf("EMM state got %s, want DEREGISTERED-INITIATED", emmState)
	}
	if enbUEID != 3 {
		t.Fatalf("eNB UE ID got %d, want 3", enbUEID)
	}

	srv.HandleDSRResult(realUE.MMEUES1APID, nil)
	if _, ok := srv.ueManager.GetByMMEID(realUE.MMEUES1APID); ok {
		t.Fatal("UE still active after DSR success")
	}
}

func TestInitialUEDetachSwitchOffSuppressesDetachAccept(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.0.0.41:36412"
	ch := setupSendCapture(srv, addr)
	mock := &mockS11{}
	srv.s11 = mock

	realUE, _, _ := makeRegisteredIdleUE(srv, addr)
	guti := &emm.GUTI{PLMN: [3]byte{0x00, 0xF1, 0x10}, MMEGI: 1, MMEC: 1, MTMSI: 2}
	srv.ueManager.UpdateGUTI(realUE, guti)
	nasPDU := buildProtectedDetachPDU(t, guti, emm.DetachTypeSwitchOff|emm.DetachTypeNormal, 1)

	srv.handleMessage(addr, buildInitialUEWithDetach(t, 4, nasPDU))

	if len(mock.dsrCalls) != 1 {
		t.Fatalf("DSR calls got %d, want 1", len(mock.dsrCalls))
	}
	select {
	case got := <-ch:
		if hex.EncodeToString(got) == "" {
			t.Fatal("empty S1AP PDU")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected UE Context Release Command after switch-off detach")
	}
}

func TestReconstructFullULNASCountFirstProtectedSequenceZero(t *testing.T) {
	raw := []byte{0x47, 0, 0, 0, 0, 0, 0x07, emm.MsgSecurityModeComplete}
	count, seq, err := reconstructFullULNASCount(raw, 0)
	if err != nil {
		t.Fatalf("reconstructFullULNASCount: %v", err)
	}
	if seq != 0 {
		t.Fatalf("seq got %d, want 0", seq)
	}
	if count != 0 {
		t.Fatalf("count got %d, want 0", count)
	}
}

func TestReconstructFullULNASCountWrapsOnlyWhenCandidateBelowStored(t *testing.T) {
	raw := []byte{0x27, 0, 0, 0, 0, 1, 0x07, emm.MsgAttachComplete}
	count, _, err := reconstructFullULNASCount(raw, 255)
	if err != nil {
		t.Fatalf("reconstructFullULNASCount: %v", err)
	}
	if count != 257 {
		t.Fatalf("count got %d, want 257", count)
	}
}

func mustHexS1AP(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}
