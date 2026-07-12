package s1ap

import (
	"bytes"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/peertracker"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
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

func TestAttachAcceptResultForCombinedRequest(t *testing.T) {
	if got, want := attachAcceptResultForRequest(emm.AttachTypeCombinedEPSAndIMSI), emm.AttachTypeCombinedEPSAndIMSI; got != want {
		t.Fatalf("combined attach result got %#x, want %#x", got, want)
	}
	if got, want := attachAcceptResultForRequest(emm.AttachTypeEPSOnly), emm.AttachTypeEPSOnly; got != want {
		t.Fatalf("EPS-only attach result got %#x, want %#x", got, want)
	}
}

// ── processTrackingAreaUpdate tests ──────────────────────────────────────────

func TestProcessTrackingAreaUpdate_Accept(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "10.0.0.1:36412"
	ch := setupSendCapture(srv, remoteAddr)

	ue, _ := makeRegisteredUEWithNullKeys(srv, remoteAddr)
	ue.Lock()
	dlBefore := uint32(ue.DLNASCount)
	ue.Unlock()

	// Build a minimal TAU Request body (no security header — already decoded inner)
	innerBody := []byte{(0x07 << 4) | emm.EPSUpdateTypePeriodic}
	innerBody = append(innerBody, 0x00)       // mobile identity length = 0 (no GUTI — OK for connected TAU)
	innerBody = append(innerBody, 0x01, 0xE0) // UE net cap LV

	log := srv.log.With(zap.String("test", "tau"))
	if err := srv.processTrackingAreaUpdate(ue, innerBody, log); err != nil {
		t.Fatalf("processTrackingAreaUpdate error: %v", err)
	}

	// Something should have been sent on the channel
	var sent []byte
	select {
	case sent = <-ch:
		// OK — TAU Accept (S1AP DL NAS Transport) was sent
	case <-time.After(100 * time.Millisecond):
		t.Error("no PDU sent after TAU Accept")
	}
	gotNAS := decodeDownlinkNASFromRawPDU(t, sent)
	if len(gotNAS) < 6 {
		t.Fatalf("TAU Accept protected NAS too short: %x", gotNAS)
	}
	if gotNAS[5] != byte(dlBefore&0xff) {
		t.Fatalf("TAU Accept NAS sequence got %d, want %d", gotNAS[5], dlBefore&0xff)
	}

	ue.Lock()
	defer ue.Unlock()
	if got, want := uint32(ue.DLNASCount), dlBefore+1; got != want {
		t.Fatalf("DL NAS count after TAU Accept got %d, want %d", got, want)
	}
	if ue.AttachStep != uecontext.AttachStepNone {
		t.Fatalf("AttachStep got %d, want none when TAU Accept has no GUTI", ue.AttachStep)
	}
	if ue.GUTIReallocPending || ue.PendingGUTI != nil {
		t.Fatalf("same-MME TAU unexpectedly started GUTI reallocation: pending=%v pending_guti=%v", ue.GUTIReallocPending, ue.PendingGUTI)
	}
	if ue.EMMState != emm.StateRegistered {
		t.Fatalf("EMM state got %s, want registered after no-GUTI TAU Accept", ue.EMMState)
	}
}

func TestProcessTrackingAreaUpdate_CombinedRequestUsesCombinedResult(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "10.0.0.11:36412"
	ch := setupSendCapture(srv, remoteAddr)

	ue, _ := makeRegisteredUEWithNullKeys(srv, remoteAddr)
	innerBody := []byte{(0x07 << 4) | emm.EPSUpdateTypeCombinedIMSIAttach}
	innerBody = append(innerBody, 0x00)
	innerBody = append(innerBody, 0x01, 0xE0)

	if err := srv.processTrackingAreaUpdate(ue, innerBody, srv.log.With(zap.String("test", "tau-combined"))); err != nil {
		t.Fatalf("processTrackingAreaUpdate error: %v", err)
	}

	var sent []byte
	select {
	case sent = <-ch:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no PDU sent after TAU Accept")
	}
	gotNAS := decodeDownlinkNASFromRawPDU(t, sent)
	if len(gotNAS) < 9 {
		t.Fatalf("TAU Accept protected NAS too short: %x", gotNAS)
	}
	plain := gotNAS[6:]
	if plain[0] != emm.PDEPSMobilityMgmt || plain[1] != emm.MsgTrackingAreaUpdateAccept {
		t.Fatalf("plain NAS is not TAU Accept: %x", plain)
	}
	if got, want := plain[2], emm.EPSUpdateResultCombinedTALAUpdated; got != want {
		t.Fatalf("TAU update result got %#x, want combined TA/LA updated %#x", got, want)
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

// TestHandleIdleTAU_DisconnectPreservesEPSContext verifies that an eNB
// disconnect during TAU is S1-only cleanup. The registered UE and S11 session
// must survive so a retransmitted TAU/Service Request can rebind to it.
func TestHandleIdleTAU_DisconnectPreservesEPSContext(t *testing.T) {
	srv := newTAUTestServer()
	srv.operCfg.TAU.ReallocateGUTI = true
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

	found, ok := srv.ueManager.GetByMMEID(realUE.MMEUES1APID)
	if !ok {
		t.Fatal("UE removed after eNB disconnect during TAU")
	}
	found.Lock()
	ecmState := found.ECMState
	sgwcTEID := found.SGWC_TEID
	enbID := found.ENBGlobalID
	pending := found.GUTIReallocPending
	found.Unlock()
	if ecmState != emm.ECMIdle {
		t.Fatalf("ECM state got %s, want ECM-IDLE", ecmState)
	}
	if sgwcTEID != 0xBEEF {
		t.Fatalf("SGWC TEID got %#x, want %#x", sgwcTEID, uint32(0xBEEF))
	}
	if enbID != "" {
		t.Fatalf("ENBGlobalID got %q, want empty", enbID)
	}
	if !pending {
		t.Fatal("pending TAU GUTI reallocation state was cleared")
	}
}

// ── sendTAUAccept / GUTI update test ──────────────────────────────────────────

func TestSendTAUAccept_GUTIReallocationPendingAliases(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "10.0.0.4:36412"
	_ = setupSendCapture(srv, remoteAddr)

	ue, oldGUTI := makeRegisteredUEWithNullKeys(srv, remoteAddr)
	oldGUTIStr := uecontext.SerialiseGUTI(oldGUTI)

	log := srv.log.With(zap.String("test", "tau"))
	if err := srv.sendTAUAcceptWithGUTIReallocation(ue, log, "test"); err != nil {
		t.Fatalf("sendTAUAccept error: %v", err)
	}

	found, ok := srv.ueManager.GetByGUTI(oldGUTIStr)
	if !ok || found != ue {
		t.Fatal("old GUTI no longer resolves during pending GUTI reallocation")
	}

	ue.Lock()
	primaryGUTI := ue.GUTI
	pendingGUTI := ue.PendingGUTI
	pending := ue.GUTIReallocPending
	ue.Unlock()

	if !pending || pendingGUTI == nil {
		t.Fatalf("pending GUTI state not set: pending=%v pending_guti=%v", pending, pendingGUTI)
	}
	if primaryGUTI == nil || uecontext.SerialiseGUTI(primaryGUTI) != oldGUTIStr {
		t.Fatalf("primary GUTI changed before TAU Complete: got %v want %s", primaryGUTI, oldGUTIStr)
	}
	newGUTIStr := uecontext.SerialiseGUTI(pendingGUTI)
	if newGUTIStr == oldGUTIStr {
		t.Error("GUTI was not reallocated")
	}
	found, ok = srv.ueManager.GetByGUTI(newGUTIStr)
	if !ok || found != ue {
		t.Fatal("pending new GUTI does not resolve during pending GUTI reallocation")
	}

	if err := srv.processTAUComplete(ue, log); err != nil {
		t.Fatalf("processTAUComplete error: %v", err)
	}
	if _, ok := srv.ueManager.GetByGUTI(oldGUTIStr); ok {
		t.Fatal("old GUTI still resolves after TAU Complete commit")
	}
	found, ok = srv.ueManager.GetByGUTI(newGUTIStr)
	if !ok || found != ue {
		t.Fatal("new GUTI does not resolve after TAU Complete commit")
	}
	ue.Lock()
	primaryGUTI = ue.GUTI
	pendingGUTI = ue.PendingGUTI
	pending = ue.GUTIReallocPending
	ue.Unlock()
	if primaryGUTI == nil || uecontext.SerialiseGUTI(primaryGUTI) != newGUTIStr {
		t.Fatalf("primary GUTI not committed to new GUTI")
	}
	if pending || pendingGUTI != nil {
		t.Fatalf("pending GUTI state not cleared after commit: pending=%v pending_guti=%v", pending, pendingGUTI)
	}
}

func TestT3450RetransmitsStoredTAUAccept(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "10.0.0.8:36412"
	ch := setupSendCapture(srv, remoteAddr)

	ue, _ := makeRegisteredUEWithNullKeys(srv, remoteAddr)
	log := srv.log.With(zap.String("test", "tau-t3450"))
	if err := srv.sendTAUAcceptWithGUTIReallocation(ue, log, "test"); err != nil {
		t.Fatalf("sendTAUAccept error: %v", err)
	}

	var first []byte
	select {
	case first = <-ch:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no initial TAU Accept sent")
	}

	ue.Lock()
	stored := append([]byte(nil), ue.PendingTAUAcceptNAS...)
	retryBefore := ue.GUTIReallocRetry
	ue.StopTimer(uecontext.TimerT3450)
	ue.Unlock()
	if !bytes.Contains(first, stored) {
		t.Fatalf("sent S1AP PDU does not contain stored TAU Accept NAS: sent=%x stored=%x", first, stored)
	}

	srv.retransmitPendingTAUAccept(ue, log)

	var retry []byte
	select {
	case retry = <-ch:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no retransmitted TAU Accept sent")
	}
	if !bytes.Equal(retry, first) {
		t.Fatalf("T3450 retransmission changed TAU Accept bytes: first=%x retry=%x", first, retry)
	}
	ue.Lock()
	retryAfter := ue.GUTIReallocRetry
	ue.StopTimer(uecontext.TimerT3450)
	ue.Unlock()
	if retryAfter != retryBefore+1 {
		t.Fatalf("retry count got %d, want %d", retryAfter, retryBefore+1)
	}
}

func TestHandleIdleTAUMessage_RetransmitOldGUTIDuringPendingReallocation(t *testing.T) {
	srv := newTAUTestServer()
	srv.operCfg.TAU.ReallocateGUTI = true
	const remoteAddr = "10.0.0.7:36412"
	ch := setupSendCapture(srv, remoteAddr)

	realUE, oldGUTI := makeRegisteredUEWithNullKeys(srv, remoteAddr)
	oldGUTIStr := uecontext.SerialiseGUTI(oldGUTI)

	tempUE1 := srv.ueManager.Allocate()
	tempUE1.Lock()
	tempUE1.ENBS1APID = 5001
	tempUE1.ENBGlobalID = remoteAddr
	tempUE1.Unlock()

	srv.handleIdleTAUMessage(tempUE1, nil, buildPlainTAUNASPDU(emm.EPSUpdateTypePeriodic, oldGUTI))
	select {
	case <-ch:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no first TAU Accept sent")
	}

	realUE.Lock()
	firstPending := realUE.PendingGUTI
	pending := realUE.GUTIReallocPending
	realUE.Unlock()
	if !pending || firstPending == nil {
		t.Fatalf("first TAU did not create pending GUTI reallocation")
	}
	if found, ok := srv.ueManager.GetByGUTI(oldGUTIStr); !ok || found != realUE {
		t.Fatalf("old GUTI no longer resolves after first TAU Accept")
	}

	tempUE2 := srv.ueManager.Allocate()
	tempUE2.Lock()
	tempUE2.ENBS1APID = 5002
	tempUE2.ENBGlobalID = remoteAddr
	tempUE2.Unlock()

	srv.handleIdleTAUMessage(tempUE2, nil, buildPlainTAUNASPDU(emm.EPSUpdateTypePeriodic, oldGUTI))
	select {
	case <-ch:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no retransmitted TAU Accept sent")
	}

	if found, ok := srv.ueManager.GetByGUTI(oldGUTIStr); !ok || found != realUE {
		t.Fatalf("old GUTI no longer resolves after retransmitted TAU")
	}
	realUE.Lock()
	secondPending := realUE.PendingGUTI
	retry := realUE.GUTIReallocRetry
	enbUEID := realUE.ENBS1APID
	realUE.Unlock()
	if secondPending == nil || uecontext.SerialiseGUTI(secondPending) != uecontext.SerialiseGUTI(firstPending) {
		t.Fatalf("retransmitted TAU changed pending GUTI: first=%v second=%v", firstPending, secondPending)
	}
	if retry == 0 {
		t.Fatalf("GUTI reallocation retry count was not incremented")
	}
	if enbUEID != 5002 {
		t.Fatalf("UE was not rebound to retransmitted TAU S1 context: enb_ue_id=%d", enbUEID)
	}
	if _, ok := srv.ueManager.GetByMMEID(tempUE1.MMEUES1APID); ok {
		t.Fatalf("first temp UE context still present")
	}
	if _, ok := srv.ueManager.GetByMMEID(tempUE2.MMEUES1APID); ok {
		t.Fatalf("second temp UE context still present")
	}
}

func TestConnectedTAUDuringReleasePendingPreservesBindingAndSendsAccept(t *testing.T) {
	srv := newTAUTestServer()
	srv.operCfg.EMMInformation.Enabled = true
	srv.operCfg.EMMInformation.SendAfterTAU = true
	srv.operCfg.Name.Full = "Test Net"
	srv.operCfg.Name.ShowFull = true
	srv.operCfg.Name.Encoding = "gsm7"
	const remoteAddr = "10.0.0.9:36412"
	ch := setupSendCapture(srv, remoteAddr)

	ue, oldGUTI := makeRegisteredUEWithNullKeys(srv, remoteAddr)
	ue.Lock()
	ue.ENBS1APID = 77
	ue.S1BindingGeneration = 1
	ue.S1BindingState = uecontext.S1BindingActive
	mmeUEID := ue.MMEUES1APID
	ue.Unlock()

	srv.handleUEContextReleaseRequest(remoteAddr, nil, []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Value: ies.EncodeMMEUEApID(mmeUEID)},
		{ID: pdu.IEENBS1APID, Value: ies.EncodeENBUEApID(77)},
	})
	select {
	case <-ch:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no UE Context Release Command sent")
	}

	ue.Lock()
	if !ue.S1ReleasePending {
		ue.Unlock()
		t.Fatal("release was not marked pending")
	}
	releaseGeneration := ue.S1ReleaseGeneration
	ue.Unlock()

	tauBody := buildPlainTAUNASPDU(emm.EPSUpdateTypePeriodic, oldGUTI)[2:]
	if err := srv.processTrackingAreaUpdate(ue, tauBody, srv.log.With(zap.String("test", "tau-release-race"))); err != nil {
		t.Fatalf("processTrackingAreaUpdate: %v", err)
	}
	select {
	case <-ch:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no TAU Accept sent while release was pending")
	}

	ue.Lock()
	if ue.S1ReleasePending {
		t.Error("release pending was not cancelled by connected TAU")
	}
	if ue.ENBGlobalID != remoteAddr {
		t.Errorf("remote binding got %q, want %q", ue.ENBGlobalID, remoteAddr)
	}
	if ue.S1BindingGeneration <= releaseGeneration {
		t.Errorf("binding generation did not advance: release=%d current=%d", releaseGeneration, ue.S1BindingGeneration)
	}
	if ue.AttachStep != uecontext.AttachStepNone {
		t.Errorf("AttachStep got %d, want none for default no-GUTI TAU", ue.AttachStep)
	}
	if ue.GUTIReallocPending {
		t.Error("default connected TAU unexpectedly started GUTI reallocation")
	}
	ue.Unlock()

	srv.handleUEContextReleaseComplete(remoteAddr, nil, []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Value: ies.EncodeMMEUEApID(mmeUEID)},
		{ID: pdu.IEENBS1APID, Value: ies.EncodeENBUEApID(77)},
	})
	ue.Lock()
	enbAddr := ue.ENBGlobalID
	enbUEID := ue.ENBS1APID
	bindingState := ue.S1BindingState
	ue.StopTimer(uecontext.TimerT3450)
	ue.Unlock()
	if enbAddr != remoteAddr || enbUEID != 77 {
		t.Fatalf("stale Release Complete cleared active binding: remote=%q enb_ue_id=%d", enbAddr, enbUEID)
	}
	if bindingState != uecontext.S1BindingActive {
		t.Fatalf("binding state got %s, want active", bindingState)
	}
	select {
	case extra := <-ch:
		t.Fatalf("unexpected extra downlink after release-pending TAU, likely EMM Information: %x", extra)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestConnectedTAUSendFailureDoesNotAdvanceTAUState(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "10.0.0.10:36412"

	ue, oldGUTI := makeRegisteredUEWithNullKeys(srv, remoteAddr)
	ue.Lock()
	ue.ENBS1APID = 88
	ue.S1BindingGeneration = 1
	ue.S1BindingState = uecontext.S1BindingActive
	dlBefore := ue.DLNASCount
	ue.Unlock()

	tauBody := buildPlainTAUNASPDU(emm.EPSUpdateTypePeriodic, oldGUTI)[2:]
	if err := srv.processTrackingAreaUpdate(ue, tauBody, srv.log.With(zap.String("test", "tau-send-fail"))); err == nil {
		t.Fatal("processTrackingAreaUpdate succeeded without a send channel")
	}

	ue.Lock()
	defer ue.Unlock()
	if ue.GUTIReallocPending {
		t.Fatal("GUTI reallocation pending after failed TAU Accept send")
	}
	if ue.PendingGUTI != nil || len(ue.PendingTAUAcceptNAS) != 0 {
		t.Fatalf("pending TAU state retained after send failure: pending_guti=%v pdu_len=%d", ue.PendingGUTI, len(ue.PendingTAUAcceptNAS))
	}
	if ue.AttachStep == uecontext.AttachStepWaitingTAUComplete {
		t.Fatal("entered waiting TAU complete after failed send")
	}
	if ue.DLNASCount != dlBefore {
		t.Fatalf("DL NAS COUNT advanced on failed send: got %d want %d", ue.DLNASCount, dlBefore)
	}
	if ue.EMMState != emm.StateRegistered {
		t.Fatalf("EMM state got %s, want registered after failed TAU Accept send", ue.EMMState)
	}
}
