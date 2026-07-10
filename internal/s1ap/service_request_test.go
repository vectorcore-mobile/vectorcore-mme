package s1ap

import (
	"encoding/hex"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/gtpv2"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/security"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"github.com/vectorcore/mme/internal/uecontext"
)

// makeRegisteredIdleUE creates a UE in EMM-REGISTERED + ECM-IDLE with EIA0 security
// and a default bearer, registered in the manager under a known GUTI.
// Returns the UE and the MMEC/MTMSI values that form its S-TMSI.
func makeRegisteredIdleUE(srv *Server, remoteAddr string) (*uecontext.Context, uint8, uint32) {
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.ENBGlobalID = remoteAddr
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMIdle
	ue.IMSI = "001010099900001"
	ue.DefaultEBI = 5
	ue.SGWU_TEID = 0xAABB1122
	ue.SGWU_IP = net.ParseIP("10.99.0.1").To4()
	ue.SGWC_TEID = 0xCCDD3344
	ue.KNASint = make([]byte, 16) // EIA0 null key
	ue.KNASenc = make([]byte, 16)
	ue.IntAlg = 0
	ue.EncAlg = 0
	ue.KASME = make([]byte, 32) // required for DeriveKeNB in SendInitialContextSetup
	ue.Unlock()

	// MMEC=1, MTMSI=0xDEAD0001 — must match the server's own MMEC/MMEGI/PLMN
	const testMMEC uint8 = 1
	const testMTMSI uint32 = 0xDEAD0001
	guti := &emm.GUTI{
		PLMN:  [3]byte{0x00, 0xF1, 0x10}, // MCC=001, MNC=01
		MMEGI: 1,
		MMEC:  testMMEC,
		MTMSI: testMTMSI,
	}
	srv.ueManager.UpdateGUTI(ue, guti)
	return ue, testMMEC, testMTMSI
}

// buildSRPDU builds a 4-byte NAS Service Request PDU with EIA0 null MAC.
// SN must be > ULNASCount lower 5 bits to avoid the +0x20 wrap; SN=1 is safe for freshly
// allocated UEs (ULNASCount=0: count=1 > 0, MAC from EIA0 is {0,0,0,0}).
func buildSRPDU(sn uint8) []byte {
	return []byte{
		0xC7, // security header 0x0C | PD 0x07
		sn,   // KSI=0 | SN
		0x00, // ShortMAC high (EIA0 → 0)
		0x00, // ShortMAC low  (EIA0 → 0)
	}
}

// ── Tests ─────────────────────────────────────────────────────────────────────

func TestHandleServiceRequest_NoSTMSI(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.0.0.10:36412"
	ch := setupSendCapture(srv, addr)

	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 100
	tempUE.ENBGlobalID = addr
	tempUE.Unlock()

	before := srv.ueManager.Count()
	srv.handleServiceRequest(tempUE, 0, 0, nil, false /*stmsiPresent=false*/, nil, buildSRPDU(1))

	// Service Reject sent
	select {
	case <-ch:
	case <-time.After(100 * time.Millisecond):
		t.Error("no PDU sent for Service Reject")
	}
	// tempUE removed
	if srv.ueManager.Count() != before-1 {
		t.Errorf("manager count: got %d, want %d", srv.ueManager.Count(), before-1)
	}
}

func TestHandleServiceRequest_UnknownSTMSI(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.0.0.11:36412"
	ch := setupSendCapture(srv, addr)

	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 101
	tempUE.ENBGlobalID = addr
	tempUE.Unlock()

	before := srv.ueManager.Count()
	// MMEC/MTMSI not registered in the manager
	srv.handleServiceRequest(tempUE, 0xFE, 0xDEADFFFF, nil, true, nil, buildSRPDU(1))

	select {
	case <-ch:
	case <-time.After(100 * time.Millisecond):
		t.Error("no Service Reject sent for unknown S-TMSI")
	}
	if srv.ueManager.Count() != before-1 {
		t.Errorf("manager count: got %d, want %d", srv.ueManager.Count(), before-1)
	}
}

func TestHandleServiceRequest_AlreadyConnected(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.0.0.12:36412"
	ch := setupSendCapture(srv, addr)

	realUE, mmec, mtmsi := makeRegisteredIdleUE(srv, addr)
	// Override: UE already ECM-CONNECTED
	realUE.Lock()
	realUE.ECMState = emm.ECMConnected
	realUE.Unlock()

	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 102
	tempUE.ENBGlobalID = addr
	tempUE.Unlock()

	srv.handleServiceRequest(tempUE, mmec, mtmsi, nil, true, nil, buildSRPDU(1))

	select {
	case <-ch:
	case <-time.After(100 * time.Millisecond):
		t.Error("no Service Reject for already-connected UE")
	}
	// realUE should still be in the manager
	if _, ok := srv.ueManager.GetByMMEID(realUE.MMEUES1APID); !ok {
		t.Error("realUE was incorrectly removed from manager")
	}
}

func TestHandleServiceRequest_MissingBearer(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.0.0.13:36412"
	ch := setupSendCapture(srv, addr)

	realUE, mmec, mtmsi := makeRegisteredIdleUE(srv, addr)
	// Override: no bearer
	realUE.Lock()
	realUE.DefaultEBI = 0
	realUE.SGWU_TEID = 0
	realUE.Unlock()

	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 103
	tempUE.ENBGlobalID = addr
	tempUE.Unlock()

	srv.handleServiceRequest(tempUE, mmec, mtmsi, nil, true, nil, buildSRPDU(1))

	select {
	case <-ch:
	case <-time.After(100 * time.Millisecond):
		t.Error("no Service Reject for missing bearer")
	}
}

func TestHandleServiceRequest_InvalidMAC(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.0.0.14:36412"
	ch := setupSendCapture(srv, addr)

	_, mmec, mtmsi := makeRegisteredIdleUE(srv, addr)

	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 104
	tempUE.ENBGlobalID = addr
	tempUE.Unlock()

	// Wrong MAC bytes — EIA0 produces {0,0} but we send {0x01,0x02}
	badMAC := []byte{0xC7, 0x01, 0x01, 0x02}
	srv.handleServiceRequest(tempUE, mmec, mtmsi, nil, true, nil, badMAC)

	select {
	case <-ch:
	case <-time.After(100 * time.Millisecond):
		t.Error("no Service Reject for invalid MAC")
	}
}

func TestHandleServiceRequest_ValidKnownUE(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.0.0.15:36412"
	ch := setupSendCapture(srv, addr)

	realUE, mmec, mtmsi := makeRegisteredIdleUE(srv, addr)

	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 105
	tempUE.ENBGlobalID = addr
	tempUE.Unlock()

	countBefore := srv.ueManager.Count()
	srv.handleServiceRequest(tempUE, mmec, mtmsi, nil, true, nil, buildSRPDU(1))

	// ICS Request should be sent (tempUE removed, realUE still present)
	select {
	case <-ch:
	case <-time.After(200 * time.Millisecond):
		t.Error("no ICS Request PDU sent on valid Service Request")
	}

	// tempUE removed
	if srv.ueManager.Count() != countBefore-1 {
		t.Errorf("manager count: got %d, want %d (tempUE removed)", srv.ueManager.Count(), countBefore-1)
	}

	// realUE step set to WaitingICSRespSR
	realUE.Lock()
	step := realUE.AttachStep
	enbUEID := realUE.ENBS1APID
	realUE.Unlock()

	if step != uecontext.AttachStepWaitingICSRespSR {
		t.Errorf("AttachStep: got %d, want WaitingICSRespSR(%d)", step, uecontext.AttachStepWaitingICSRespSR)
	}
	if enbUEID != 105 {
		t.Errorf("ENBS1APID: got %d, want 105 (transferred from tempUE)", enbUEID)
	}
}

func TestHandleServiceRequest_DelaysResumeICSPendingReleaseComplete(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.0.0.15:36412"
	ch := setupSendCapture(srv, addr)

	realUE, mmec, mtmsi := makeRegisteredIdleUE(srv, addr)
	realUE.Lock()
	realUE.S1ReleasePending = true
	realUE.S1ReleaseENBID = 1
	realUE.S1ReleaseENBAddr = addr
	realUE.Unlock()

	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 106
	tempUE.ENBGlobalID = addr
	tempUE.Unlock()

	srv.handleServiceRequest(tempUE, mmec, mtmsi, nil, true, nil, buildSRPDU(1))

	select {
	case msg := <-ch:
		t.Fatalf("resume ICS sent before pending release debounce elapsed: %x", msg)
	case <-time.After(75 * time.Millisecond):
	}

	select {
	case <-ch:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("delayed resume ICS was not sent")
	}

	realUE.Lock()
	step := realUE.AttachStep
	enbUEID := realUE.ENBS1APID
	realUE.Unlock()

	if step != uecontext.AttachStepWaitingICSRespSR {
		t.Errorf("AttachStep: got %d, want WaitingICSRespSR(%d)", step, uecontext.AttachStepWaitingICSRespSR)
	}
	if enbUEID != 106 {
		t.Errorf("ENBS1APID: got %d, want 106", enbUEID)
	}
}

func TestHandleServiceRequest_ThreeDigitMNCGUTILookup(t *testing.T) {
	srv := newTAUTestServer()
	srv.nfCfg.MCC = "311"
	srv.nfCfg.MNC = "435"
	srv.nfCfg.MMEGI = 1
	srv.nfCfg.MMEC = 1
	gutiAlloc, err := uecontext.NewGUTIAllocator("311", "435", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	srv.gutiAlloc = gutiAlloc

	const addr = "10.0.0.17:36412"
	ch := setupSendCapture(srv, addr)

	realUE, _, _ := makeRegisteredIdleUE(srv, addr)
	plmn, err := security.EncodePLMN("311", "435")
	if err != nil {
		t.Fatal(err)
	}
	guti := &emm.GUTI{MMEGI: 1, MMEC: 1, MTMSI: 2}
	copy(guti.PLMN[:], plmn)
	if got, want := uecontext.SerialiseGUTI(guti), "13513400010100000002"; got != want {
		t.Fatalf("GUTI key got %s, want %s", got, want)
	}
	srv.ueManager.UpdateGUTI(realUE, guti)

	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 107
	tempUE.ENBGlobalID = addr
	tempUE.Unlock()

	before := srv.ueManager.Count()
	stmsiRaw, err := hex.DecodeString("004000000002")
	if err != nil {
		t.Fatal(err)
	}
	srv.handleServiceRequest(tempUE, 1, 2, stmsiRaw, true, nil, buildSRPDU(1))

	select {
	case <-ch:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("no ICS Request PDU sent on Service Request")
	}
	if srv.ueManager.Count() != before-1 {
		t.Fatalf("manager count got %d, want %d", srv.ueManager.Count(), before-1)
	}
	realUE.Lock()
	step := realUE.AttachStep
	enbUEID := realUE.ENBS1APID
	realUE.Unlock()
	if step != uecontext.AttachStepWaitingICSRespSR {
		t.Fatalf("AttachStep got %d, want WaitingICSRespSR", step)
	}
	if enbUEID != 107 {
		t.Fatalf("ENBS1APID got %d, want 107", enbUEID)
	}
}

func TestInitialUEMessageServiceRequestUsesSTMSIIE(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.0.0.16:36412"
	ch := setupSendCapture(srv, addr)
	realUE, _, _ := makeRegisteredIdleUE(srv, addr)
	guti := &emm.GUTI{PLMN: [3]byte{0x00, 0xF1, 0x10}, MMEGI: 1, MMEC: 1, MTMSI: 2}
	srv.ueManager.UpdateGUTI(realUE, guti)

	stmsi, err := hex.DecodeString("004000000002")
	if err != nil {
		t.Fatal(err)
	}
	taiValue, err := ies.EncodeTAI(ies.TAI{MCC: "001", MNC: "01", TAC: 1})
	if err != nil {
		t.Fatal(err)
	}
	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(106)},
		{ID: pdu.IENAS_PDU, Criticality: aper.CriticalityReject, Value: ies.EncodeNASPDU(buildSRPDU(1))},
		{ID: pdu.IETAI, Criticality: aper.CriticalityReject, Value: taiValue},
		{ID: pdu.IESTMSI, Criticality: aper.CriticalityReject, Value: stmsi},
	}

	before := srv.ueManager.Count()
	srv.handleMessage(addr, pdu.BuildInitiatingMessage(pdu.ProcInitialUEMessage, aper.CriticalityIgnore, ieList))
	select {
	case <-ch:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("no ICS Request PDU sent on Service Request")
	}
	if srv.ueManager.Count() != before {
		t.Fatalf("manager count got %d, want %d", srv.ueManager.Count(), before)
	}
	realUE.Lock()
	step := realUE.AttachStep
	enbUEID := realUE.ENBS1APID
	realUE.Unlock()
	if step != uecontext.AttachStepWaitingICSRespSR {
		t.Fatalf("AttachStep got %d, want WaitingICSRespSR", step)
	}
	if enbUEID != 106 {
		t.Fatalf("eNB UE ID got %d, want 106", enbUEID)
	}
}

// ── handleServiceRequestReestablished tests ───────────────────────────────────

func TestHandleServiceRequestReestablished_UpdatesState(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.0.0.20:36412"

	ue, _, _ := makeRegisteredIdleUE(srv, addr)
	ue.Lock()
	ue.SetECMState(emm.ECMConnected) // ICS Response already set this
	ue.AttachStep = uecontext.AttachStepWaitingICSRespSR
	ue.Unlock()

	log := srv.log.With(zap.String("test", "sr_reestablished"))
	srv.handleServiceRequestReestablished(ue, log)

	ue.Lock()
	state := ue.EMMState
	step := ue.AttachStep
	ue.Unlock()

	if state != emm.StateRegistered {
		t.Errorf("EMMState: got %v, want StateRegistered", state)
	}
	if step != uecontext.AttachStepNone {
		t.Errorf("AttachStep: got %d, want None(%d)", step, uecontext.AttachStepNone)
	}
}

func TestHandleServiceRequestReestablished_MBRSent(t *testing.T) {
	mbrCh := make(chan struct{}, 1)
	trackingS11 := &mbrTrackingS11{ch: mbrCh}

	srv := newTestServer(trackingS11)
	srv.gutiAlloc, _ = uecontext.NewGUTIAllocator("001", "01", 1, 1)

	const addr = "10.0.0.21:36412"

	ue, _, _ := makeRegisteredIdleUE(srv, addr)
	ue.Lock()
	ue.SetECMState(emm.ECMConnected)
	ue.AttachStep = uecontext.AttachStepWaitingICSRespSR
	ue.ENBU_TEID = 0xBEEF0001
	ue.ENBU_IP = net.ParseIP("192.168.10.1").To4()
	ue.Unlock()

	log := srv.log.With(zap.String("test", "sr_mbr"))
	srv.handleServiceRequestReestablished(ue, log)

	select {
	case <-mbrCh:
		// MBR was sent
	case <-time.After(500 * time.Millisecond):
		t.Error("SendMBR was not called after Service Request re-establishment")
	}
}

func TestErrorIndicationDuringServiceRequestResumeRestoresIdle(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.0.0.22:36412"

	ue, _, _ := makeRegisteredIdleUE(srv, addr)
	ue.Lock()
	ue.SetEMMState(emm.StateServiceRequestInitiated)
	ue.SetECMState(emm.ECMIdle)
	ue.AttachStep = uecontext.AttachStepWaitingICSRespSR
	ue.ENBS1APID = 2
	ue.ENBGlobalID = addr
	ue.ENBU_TEID = 0x11111111
	ue.ENBU_IP = net.ParseIP("192.168.105.34").To4()
	mmeID := ue.MMEUES1APID
	ue.Unlock()

	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeMMEUEApID(mmeID)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeENBUEApID(2)},
		{ID: pdu.IECause, Criticality: aper.CriticalityIgnore, Value: ies.EncodeCause(ies.CauseGroupRadioNetwork, ies.CauseRadioNetworkUserInactivity)},
	}
	srv.handleErrorIndication(addr, nil, ieList)

	found, ok := srv.ueManager.GetByMMEID(mmeID)
	if !ok {
		t.Fatal("UE removed from manager; expected idle retention")
	}
	found.Lock()
	emmState := found.EMMState
	ecmState := found.ECMState
	step := found.AttachStep
	enbUEID := found.ENBS1APID
	enbAddr := found.ENBGlobalID
	enbuTEID := found.ENBU_TEID
	found.Unlock()

	if emmState != emm.StateRegistered {
		t.Fatalf("EMMState got %v, want Registered", emmState)
	}
	if ecmState != emm.ECMIdle {
		t.Fatalf("ECMState got %v, want Idle", ecmState)
	}
	if step != uecontext.AttachStepNone {
		t.Fatalf("AttachStep got %d, want None", step)
	}
	if enbUEID != 0 || enbAddr != "" || enbuTEID != 0 {
		t.Fatalf("access context not cleared: enbUEID=%d enbAddr=%q enbuTEID=%#x", enbUEID, enbAddr, enbuTEID)
	}
}

// mbrTrackingS11 signals on ch whenever SendMBR is called.
type mbrTrackingS11 struct {
	ch chan struct{}
}

func (m *mbrTrackingS11) SendCSR(_ uint32, _ *gtpv2.CreateSessionRequest) error { return nil }
func (m *mbrTrackingS11) SendMBR(_ uint32, _ *gtpv2.ModifyBearerRequest) error {
	m.ch <- struct{}{}
	return nil
}
func (m *mbrTrackingS11) SendDSR(_ uint32, _ *gtpv2.DeleteSessionRequest) error { return nil }
