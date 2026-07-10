package s1ap

import (
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/peertracker"
	"github.com/vectorcore/mme/internal/uecontext"
)

// newTAUTestServer creates a Server with a GUTI allocator and a configured TAI list.
func newTAUTestServer() *Server {
	log, _ := zap.NewDevelopment()
	gutiAlloc, _ := uecontext.NewGUTIAllocator("001", "01", 1, 1)
	return &Server{
		s11:        NoopS11Client{},
		ueManager:  uecontext.NewManager(),
		enbTracker: peertracker.New(),
		store:      noopStore{},
		log:        log,
		gutiAlloc:  gutiAlloc,
		nfCfg: config.NFConfig{
			MCC:   "001",
			MNC:   "01",
			MMEGI: 1,
			MMEC:  1,
			TAIList: []config.TAIItem{
				{MCC: "001", MNC: "01", TAC: 1},
			},
		},
	}
}

// setupSendCapture registers an eNB and returns a bidirectional channel for reading PDUs.
func setupSendCapture(srv *Server, remoteAddr string) chan []byte {
	ch := make(chan []byte, 16)
	enb := &ENBContext{RemoteAddr: remoteAddr}
	srv.enbs.Store(remoteAddr, enb)
	// Store as send-only so type assertion in sendToAddr succeeds
	srv.sends.Store(remoteAddr, (chan<- []byte)(ch))
	return ch
}

// makeRegisteredUEWithNullKeys creates a registered UE with EIA0/EEA0 null security keys.
func makeRegisteredUEWithNullKeys(srv *Server, remoteAddr string) (*uecontext.Context, *emm.GUTI) {
	ue := allocateTestUE(srv, remoteAddr, 0, true)
	guti := &emm.GUTI{PLMN: [3]byte{0x00, 0xF1, 0x10}, MMEGI: 1, MMEC: 1, MTMSI: 0xAABBCCDD}
	ue.Lock()
	ue.KNASint = make([]byte, 16) // EIA0 null key (all zeros)
	ue.KNASenc = make([]byte, 16) // EEA0 null key (all zeros)
	ue.IntAlg = 0
	ue.EncAlg = 0
	ue.Unlock()
	srv.ueManager.UpdateGUTI(ue, guti)
	return ue, guti
}

// buildPlainTAUNASPDU returns a plain (unprotected) NAS PDU containing a TAU Request.
func buildPlainTAUNASPDU(updateType uint8, guti *emm.GUTI) []byte {
	// NAS header: [PD=0x07 (EMM, plain), msgType=0x48 (TAU Request)]
	// Body: byte0=(eKSI<<4)|updateType, LV=mobile identity (GUTI), LV=UE net cap
	body := []byte{(0x07 << 4) | (updateType & 0x07)}
	// LV: GUTI mobile identity
	gutiLV := guti.Encode() // [len=0x0B, 0xF6, PLMN(3), MMEGI(2), MMEC(1), MTMSI(4)]
	body = append(body, gutiLV...)
	// LV: UE network capability (length=2, EEA=0xE0, EIA=0xE0)
	body = append(body, 0x02, 0xE0, 0xE0)
	// Full NAS PDU: [PD|SHT, msgType, body...]
	return append([]byte{emm.PDEPSMobilityMgmt, emm.MsgTrackingAreaUpdateRequest}, body...)
}

// ── validateTAI tests ─────────────────────────────────────────────────────────

func TestValidateTAI_Matching(t *testing.T) {
	srv := newTAUTestServer()
	tai := &emm.TAI{PLMN: [3]byte{0x00, 0xF1, 0x10}, TAC: 1}
	// Must find TAC=1 in the configured TAI list
	if !srv.validateTAI(tai) {
		t.Error("validateTAI: expected true for matching TAI, got false")
	}
}

func TestValidateTAI_NotMatching(t *testing.T) {
	srv := newTAUTestServer()
	tai := &emm.TAI{PLMN: [3]byte{0x00, 0xF1, 0x10}, TAC: 99}
	if srv.validateTAI(tai) {
		t.Error("validateTAI: expected false for non-matching TAI, got true")
	}
}

// ── processTrackingAreaUpdate tests ──────────────────────────────────────────

func TestProcessTrackingAreaUpdate_Accept(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "10.0.0.1:36412"
	ch := setupSendCapture(srv, remoteAddr)

	ue, _ := makeRegisteredUEWithNullKeys(srv, remoteAddr)

	// Build a minimal TAU Request body (no security header — already decoded inner)
	innerBody := []byte{(0x07 << 4) | emm.EPSUpdateTypePeriodic}
	innerBody = append(innerBody, 0x00)       // mobile identity length = 0 (no GUTI — OK for connected TAU)
	innerBody = append(innerBody, 0x01, 0xE0) // UE net cap LV

	log := srv.log.With(zap.String("test", "tau"))
	if err := srv.processTrackingAreaUpdate(ue, innerBody, log); err != nil {
		t.Fatalf("processTrackingAreaUpdate error: %v", err)
	}

	// Something should have been sent on the channel
	select {
	case <-ch:
		// OK — TAU Accept (S1AP DL NAS Transport) was sent
	case <-time.After(100 * time.Millisecond):
		t.Error("no PDU sent after TAU Accept")
	}
}

func TestProcessTrackingAreaUpdate_InvalidTAI(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "10.0.0.1:36412"
	ch := setupSendCapture(srv, remoteAddr)

	ue, _ := makeRegisteredUEWithNullKeys(srv, remoteAddr)
	// Override UE's TAI with one not in the config
	ue.Lock()
	ue.TAI = &emm.TAI{PLMN: [3]byte{0x01, 0x01, 0x01}, TAC: 999}
	ue.Unlock()

	innerBody := []byte{(0x07 << 4) | emm.EPSUpdateTypePeriodic, 0x00, 0x01, 0xE0}
	log := srv.log.With(zap.String("test", "tau"))
	if err := srv.processTrackingAreaUpdate(ue, innerBody, log); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// TAU Reject should be sent
	select {
	case <-ch:
		// OK — TAU Reject was sent
	case <-time.After(100 * time.Millisecond):
		t.Error("no PDU sent after TAU Reject")
	}
}

// ── processTAUComplete tests ──────────────────────────────────────────────────

func TestProcessTAUComplete_UpdatesState(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "10.0.0.1:36412"
	_ = setupSendCapture(srv, remoteAddr)

	ue, _ := makeRegisteredUEWithNullKeys(srv, remoteAddr)

	// Simulate post-TAU-Accept state
	ue.Lock()
	ue.SetEMMState(emm.StateTrackingAreaUpdating)
	ue.AttachStep = uecontext.AttachStepWaitingTAUComplete
	ue.Unlock()

	log := srv.log.With(zap.String("test", "tau"))
	if err := srv.processTAUComplete(ue, log); err != nil {
		t.Fatalf("processTAUComplete error: %v", err)
	}

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

// ── handleIdleTAUMessage tests ────────────────────────────────────────────────

func TestHandleIdleTAUMessage_UnknownGUTI(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "10.0.0.2:36412"
	ch := setupSendCapture(srv, remoteAddr)

	// Temp UE (as allocated by handleInitialUEMessage)
	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 1001
	tempUE.ENBGlobalID = remoteAddr
	tempUE.Unlock()

	// GUTI that is NOT registered in the manager
	unknownGUTI := &emm.GUTI{PLMN: [3]byte{0xFF, 0xFF, 0xFF}, MMEGI: 9999, MMEC: 9, MTMSI: 0xDEAD1234}
	nasPDU := buildPlainTAUNASPDU(emm.EPSUpdateTypePeriodic, unknownGUTI)

	initialCount := srv.ueManager.Count()
	srv.handleIdleTAUMessage(tempUE, nil, nasPDU)

	// TAU Reject should be sent
	select {
	case <-ch:
		// OK
	case <-time.After(100 * time.Millisecond):
		t.Error("no PDU sent for TAU Reject")
	}

	// Temp UE removed from manager
	if srv.ueManager.Count() != initialCount-1 {
		t.Errorf("manager count: got %d, want %d (tempUE removed)", srv.ueManager.Count(), initialCount-1)
	}
}

func TestHandleIdleTAUMessage_KnownGUTI_Plain(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "10.0.0.3:36412"
	ch := setupSendCapture(srv, remoteAddr)

	// Real UE already in the manager with a known GUTI
	realUE, guti := makeRegisteredUEWithNullKeys(srv, remoteAddr)
	realUE.Lock()
	realUE.IMSI = "001010000000001"
	realUE.Unlock()

	// Temp UE (from handleInitialUEMessage)
	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 2002
	tempUE.ENBGlobalID = remoteAddr
	tempUE.Unlock()

	countBefore := srv.ueManager.Count() // realUE + tempUE
	nasPDU := buildPlainTAUNASPDU(emm.EPSUpdateTypePeriodic, guti)
	srv.handleIdleTAUMessage(tempUE, nil, nasPDU)

	// TAU Accept or something was sent
	select {
	case <-ch:
		// OK — some DL NAS PDU sent
	case <-time.After(100 * time.Millisecond):
		t.Error("no PDU sent after TAU Accept")
	}

	// tempUE removed; realUE remains
	if srv.ueManager.Count() != countBefore-1 {
		t.Errorf("manager count: got %d, want %d", srv.ueManager.Count(), countBefore-1)
	}

	// Real UE state updated to TAU flow
	realUE.Lock()
	state := realUE.EMMState
	enbUEID := realUE.ENBS1APID
	realUE.Unlock()
	if state != emm.StateTrackingAreaUpdating && state != emm.StateRegistered {
		t.Errorf("EMMState after TAU: got %v, want Updating or Registered", state)
	}
	if enbUEID != 2002 {
		t.Errorf("ENBS1APID: got %d, want 2002", enbUEID)
	}
}

// ── handleIdleTAUMessage: ECMState fix (review fix 1) ────────────────────────

func TestHandleIdleTAUMessage_SetsECMConnected(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "10.0.0.5:36412"
	ch := setupSendCapture(srv, remoteAddr)

	realUE, guti := makeRegisteredUEWithNullKeys(srv, remoteAddr)

	// Prime the real UE with ECM-IDLE as it would be before an idle TAU.
	realUE.Lock()
	realUE.SetECMState(emm.ECMIdle)
	realUE.Unlock()

	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 3003
	tempUE.ENBGlobalID = remoteAddr
	tempUE.Unlock()

	nasPDU := buildPlainTAUNASPDU(emm.EPSUpdateTypePeriodic, guti)
	srv.handleIdleTAUMessage(tempUE, nil, nasPDU)

	select {
	case <-ch:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no PDU sent — TAU Accept expected")
	}

	realUE.Lock()
	ecm := realUE.ECMState
	realUE.Unlock()

	if ecm != emm.ECMConnected {
		t.Errorf("ECMState after idle TAU: got %v, want ECMConnected", ecm)
	}
}

// TestHandleIdleTAU_DisconnectCleansUp verifies that when an eNB disconnects
// after an idle TAU (ECMConnected set), the UE is evicted and S11 session cleaned.
// Regression test for the ECMIdle guard that used to skip the UE.
func TestHandleIdleTAU_DisconnectCleansUp(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "10.0.0.6:36412"
	_ = setupSendCapture(srv, remoteAddr)

	realUE, guti := makeRegisteredUEWithNullKeys(srv, remoteAddr)
	realUE.Lock()
	realUE.SGWC_TEID = 0xBEEF // simulate active S11 session
	realUE.SetECMState(emm.ECMIdle)
	realUE.Unlock()

	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 4004
	tempUE.ENBGlobalID = remoteAddr
	tempUE.Unlock()

	nasPDU := buildPlainTAUNASPDU(emm.EPSUpdateTypePeriodic, guti)
	srv.handleIdleTAUMessage(tempUE, nil, nasPDU)

	// After idle TAU the realUE is ECMConnected. Simulate eNB disconnect.
	srv.handleDisconnect(remoteAddr)

	// UE must be evicted from the manager.
	if _, ok := srv.ueManager.GetByMMEID(realUE.MMEUES1APID); ok {
		t.Error("UE still in manager after eNB disconnect following idle TAU")
	}
}

// ── sendTAUAccept / GUTI update test ──────────────────────────────────────────

func TestSendTAUAccept_GUTIUpdated(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "10.0.0.4:36412"
	_ = setupSendCapture(srv, remoteAddr)

	ue, oldGUTI := makeRegisteredUEWithNullKeys(srv, remoteAddr)
	oldGUTIStr := uecontext.SerialiseGUTI(oldGUTI)

	log := srv.log.With(zap.String("test", "tau"))
	if err := srv.sendTAUAccept(ue, log); err != nil {
		t.Fatalf("sendTAUAccept error: %v", err)
	}

	// Old GUTI should no longer resolve to this UE
	_, ok := srv.ueManager.GetByGUTI(oldGUTIStr)
	if ok {
		t.Error("old GUTI still in manager after GUTI reallocation")
	}

	// New GUTI should resolve to the UE
	ue.Lock()
	newGUTI := ue.GUTI
	ue.Unlock()

	if newGUTI == nil {
		t.Fatal("ue.GUTI is nil after TAU Accept")
	}
	newGUTIStr := uecontext.SerialiseGUTI(newGUTI)
	if newGUTIStr == oldGUTIStr {
		t.Error("GUTI was not reallocated")
	}
	found, ok := srv.ueManager.GetByGUTI(newGUTIStr)
	if !ok || found != ue {
		t.Error("new GUTI does not resolve to the UE in manager")
	}
}
