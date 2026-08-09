package s1ap

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/gtpv2"
	"github.com/vectorcore/mme/internal/nas"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"github.com/vectorcore/mme/internal/sgsap"
	"github.com/vectorcore/mme/internal/uecontext"
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
	ecgiValue, err := ies.EncodeECGI(ies.ECGI{MCC: "001", MNC: "01", ECGI: 0x12345})
	if err != nil {
		t.Fatal(err)
	}
	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(enbUEID)},
		{ID: pdu.IENAS_PDU, Criticality: aper.CriticalityReject, Value: ies.EncodeNASPDU(nasPDU)},
		{ID: pdu.IETAI, Criticality: aper.CriticalityReject, Value: taiValue},
		{ID: pdu.IECGI, Criticality: aper.CriticalityIgnore, Value: ecgiValue},
		{ID: pdu.IERRCEstablishmentCause, Criticality: aper.CriticalityIgnore, Value: ies.EncodeRRCEstablishmentCause(3)},
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

	srv.HandleDSRResult(realUE.MMEUES1APID, 5, nil)
	if _, ok := srv.ueManager.GetByMMEID(realUE.MMEUES1APID); ok {
		t.Fatal("UE still active after DSR success")
	}
}

func TestInitialUEDetachAbortsSLgPositioning(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.0.0.41:36412"
	setupSendCapture(srv, addr)
	srv.s11 = &mockS11{}
	s6a := &capturingS6a{abortCalls: make(chan uint32, 1)}
	srv.s6a = s6a

	realUE, _, _ := makeRegisteredIdleUE(srv, addr)
	realUE.Lock()
	realUE.IMSI = "001010123456789"
	mmeUEID := realUE.MMEUES1APID
	realUE.Unlock()
	guti := &emm.GUTI{PLMN: [3]byte{0x00, 0xF1, 0x10}, MMEGI: 1, MMEC: 1, MTMSI: 2}
	srv.ueManager.UpdateGUTI(realUE, guti)
	nasPDU := buildProtectedDetachPDU(t, guti, emm.DetachTypeNormal, 1)

	srv.handleMessage(addr, buildInitialUEWithDetach(t, 3, nasPDU))

	select {
	case got := <-s6a.abortCalls:
		if got != mmeUEID {
			t.Fatalf("AbortSLgPositioning mmeUEID: got %d, want %d", got, mmeUEID)
		}
	case <-time.After(time.Second):
		t.Fatal("AbortSLgPositioning was not called on detach")
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

func TestInitialUEDetachDeletesAllActivePDNSessions(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.0.0.42:36412"
	setupSendCapture(srv, addr)
	mock := &mockS11{}
	srv.s11 = mock

	realUE, _, _ := makeRegisteredIdleUE(srv, addr)
	realUE.Lock()
	realUE.APN = "internet"
	realUE.SGWAddress = "10.90.250.59:2123"
	realUE.PDNs = map[string]*uecontext.PDNContext{
		"internet": {
			APN:        "internet",
			DefaultEBI: 5,
			SGWAddress: "10.90.250.59:2123",
			SGWC_TEID:  0xCCDD3344,
			State:      "active",
		},
		"ims": {
			APN:        "ims",
			DefaultEBI: 6,
			SGWAddress: "10.90.250.59:2123",
			SGWC_TEID:  0x11223344,
			State:      "active",
		},
	}
	realUE.Unlock()

	guti := &emm.GUTI{PLMN: [3]byte{0x00, 0xF1, 0x10}, MMEGI: 1, MMEC: 1, MTMSI: 2}
	srv.ueManager.UpdateGUTI(realUE, guti)
	nasPDU := buildProtectedDetachPDU(t, guti, emm.DetachTypeNormal, 1)

	srv.handleMessage(addr, buildInitialUEWithDetach(t, 5, nasPDU))

	if len(mock.dsrCalls) != 2 {
		t.Fatalf("DSR calls got %d, want 2", len(mock.dsrCalls))
	}
	seen := map[uint8]gtpv2.DeleteSessionRequest{}
	for _, call := range mock.dsrCalls {
		seen[call.EBI] = call
	}
	if _, ok := seen[5]; !ok {
		t.Fatal("missing internet DSR for EBI 5")
	}
	if _, ok := seen[6]; !ok {
		t.Fatal("missing IMS DSR for EBI 6")
	}

	srv.HandleDSRResult(realUE.MMEUES1APID, 6, nil)
	if _, ok := srv.ueManager.GetByMMEID(realUE.MMEUES1APID); !ok {
		t.Fatal("UE removed after first DSR result, want retained until all PDNs are deleted")
	}

	srv.HandleDSRResult(realUE.MMEUES1APID, 5, nil)
	if _, ok := srv.ueManager.GetByMMEID(realUE.MMEUES1APID); ok {
		t.Fatal("UE still active after all DSR results")
	}
}

func TestInitialUEDetachDeletesAllActivePDNSessionsOutOfOrderResponses(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.0.0.43:36412"
	setupSendCapture(srv, addr)
	mock := &mockS11{}
	srv.s11 = mock

	realUE, _, _ := makeRegisteredIdleUE(srv, addr)
	realUE.Lock()
	realUE.APN = "internet"
	realUE.SGWAddress = "10.90.250.59:2123"
	realUE.PDNs = map[string]*uecontext.PDNContext{
		"internet": {
			APN:        "internet",
			DefaultEBI: 5,
			SGWAddress: "10.90.250.59:2123",
			SGWC_TEID:  0xCCDD3344,
			State:      "active",
		},
		"ims": {
			APN:        "ims",
			DefaultEBI: 6,
			SGWAddress: "10.90.250.59:2123",
			SGWC_TEID:  0x11223344,
			State:      "active",
		},
	}
	realUE.Unlock()

	guti := &emm.GUTI{PLMN: [3]byte{0x00, 0xF1, 0x10}, MMEGI: 1, MMEC: 1, MTMSI: 2}
	srv.ueManager.UpdateGUTI(realUE, guti)
	nasPDU := buildProtectedDetachPDU(t, guti, emm.DetachTypeNormal, 1)

	srv.handleMessage(addr, buildInitialUEWithDetach(t, 6, nasPDU))

	srv.HandleDSRResult(realUE.MMEUES1APID, 6, nil)

	remaining, ok := srv.ueManager.GetByMMEID(realUE.MMEUES1APID)
	if !ok || remaining == nil {
		t.Fatal("UE removed after first out-of-order DSR result, want retained")
	}
	remaining.Lock()
	if _, ok := remaining.PDNs["ims"]; ok {
		remaining.Unlock()
		t.Fatal("IMS PDN still present after IMS DSR result")
	}
	if _, ok := remaining.PDNs["internet"]; !ok {
		remaining.Unlock()
		t.Fatal("internet PDN removed by wrong DSR correlation")
	}
	remaining.Unlock()

	srv.HandleDSRResult(realUE.MMEUES1APID, 5, nil)
	if _, ok := srv.ueManager.GetByMMEID(realUE.MMEUES1APID); ok {
		t.Fatal("UE still active after both out-of-order DSR results")
	}
}

func TestInitialUEDetachEPSOnlySendsEPSDetachIndicationAndAcceptsImmediately(t *testing.T) {
	srv, fake := sgsTestServer()
	const addr = "10.0.0.44:36412"
	ch := setupSendCapture(srv, addr)
	mock := &mockS11{}
	srv.s11 = mock

	realUE, _, _ := makeRegisteredIdleUE(srv, addr)
	realUE.SGsState = uecontext.SGsUEAssociated
	realUE.SGsVLRName = "vlr-1"
	guti := &emm.GUTI{PLMN: [3]byte{0x00, 0xF1, 0x10}, MMEGI: 1, MMEC: 1, MTMSI: 2}
	srv.ueManager.UpdateGUTI(realUE, guti)
	nasPDU := buildProtectedDetachPDU(t, guti, emm.DetachTypeNormal, 1)

	srv.handleMessage(addr, buildInitialUEWithDetach(t, 7, nasPDU))

	fake.mu.Lock()
	gotEPS := fake.lastEPSDetach
	fake.mu.Unlock()
	if gotEPS == nil || gotEPS.IMSI != realUE.IMSI || gotEPS.DetachType != sgsap.EPSDetachUEInitiated {
		t.Fatalf("expected EPS-DETACH-INDICATION sent, got %+v", gotEPS)
	}

	realUE.Lock()
	sgsState := realUE.SGsState
	realUE.Unlock()
	if sgsState != uecontext.SGsUENull {
		t.Fatalf("SGs state after EPS detach = %v, want SGs-NULL", sgsState)
	}

	select {
	case <-ch:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected Detach Accept sent immediately for an EPS-only detach")
	}
}

func TestInitialUEDetachIMSIOnlyWithholdsDetachAcceptUntilAck(t *testing.T) {
	srv, fake := sgsTestServer()
	srv.sgsCfg.RequestTimeout = 5 * time.Second
	const addr = "10.0.0.45:36412"
	ch := setupSendCapture(srv, addr)
	mock := &mockS11{}
	srv.s11 = mock

	realUE, _, _ := makeRegisteredIdleUE(srv, addr)
	realUE.SGsState = uecontext.SGsUEAssociated
	realUE.SGsVLRName = "vlr-1"
	srv.ueManager.Register(realUE)
	guti := &emm.GUTI{PLMN: [3]byte{0x00, 0xF1, 0x10}, MMEGI: 1, MMEC: 1, MTMSI: 2}
	srv.ueManager.UpdateGUTI(realUE, guti)
	nasPDU := buildProtectedDetachPDU(t, guti, emm.DetachTypeIMSIDetach, 1)

	srv.handleMessage(addr, buildInitialUEWithDetach(t, 8, nasPDU))

	fake.mu.Lock()
	gotIMSI := fake.lastIMSIDetach
	fake.mu.Unlock()
	if gotIMSI == nil || gotIMSI.IMSI != realUE.IMSI || gotIMSI.DetachType != sgsap.NonEPSDetachExplicitUEInitiated {
		t.Fatalf("expected IMSI-DETACH-INDICATION sent, got %+v", gotIMSI)
	}

	select {
	case <-ch:
		t.Fatal("Detach Accept must not be sent before SGsAP-IMSI-DETACH-ACK")
	case <-time.After(150 * time.Millisecond):
	}

	srv.HandleIMSIDetachAck("vlr-1", realUE.IMSI)

	select {
	case <-ch:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected Detach Accept sent after SGsAP-IMSI-DETACH-ACK arrived")
	}
}

func TestInitialUEDetachCombinedTimesOutAndSendsDetachAcceptAnyway(t *testing.T) {
	srv, _ := sgsTestServer()
	srv.sgsCfg.RequestTimeout = 50 * time.Millisecond
	const addr = "10.0.0.46:36412"
	ch := setupSendCapture(srv, addr)
	mock := &mockS11{}
	srv.s11 = mock

	realUE, _, _ := makeRegisteredIdleUE(srv, addr)
	realUE.SGsState = uecontext.SGsUEAssociated
	realUE.SGsVLRName = "vlr-1"
	guti := &emm.GUTI{PLMN: [3]byte{0x00, 0xF1, 0x10}, MMEGI: 1, MMEC: 1, MTMSI: 2}
	srv.ueManager.UpdateGUTI(realUE, guti)
	nasPDU := buildProtectedDetachPDU(t, guti, emm.DetachTypeEPSAndIMSI, 1)

	srv.handleMessage(addr, buildInitialUEWithDetach(t, 9, nasPDU))

	select {
	case <-ch:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected Detach Accept sent once the SGs request timeout elapsed without an ack")
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
