package s1ap

import (
	"bytes"
	"net"
	"reflect"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/security"
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

func newObservedLogger() (*zap.Logger, *observer.ObservedLogs) {
	core, logs := observer.New(zap.DebugLevel)
	return zap.New(core), logs
}

func findObservedEvent(t *testing.T, logs *observer.ObservedLogs, event string) map[string]interface{} {
	t.Helper()
	for _, entry := range logs.All() {
		ctx := entry.ContextMap()
		if ctx["event"] == event {
			return ctx
		}
	}
	t.Fatalf("event %q not found in logs", event)
	return nil
}

func findObservedEventWhere(t *testing.T, logs *observer.ObservedLogs, event string, pred func(map[string]interface{}) bool) map[string]interface{} {
	t.Helper()
	for _, entry := range logs.All() {
		ctx := entry.ContextMap()
		if ctx["event"] == event && pred(ctx) {
			return ctx
		}
	}
	t.Fatalf("event %q with predicate not found in logs", event)
	return nil
}

func decodeICSSecurityKeyBytes(t *testing.T, raw []byte) []byte {
	t.Helper()
	msg, err := pdu.Decode(raw)
	if err != nil {
		t.Fatalf("decode ICS PDU: %v", err)
	}
	ieList, err := pdu.DecodeIEContainer(msg.Value)
	if err != nil {
		t.Fatalf("decode ICS IE list: %v", err)
	}
	for _, ie := range ieList {
		if ie.ID != pdu.IESecurityKey {
			continue
		}
		bs, err := aper.DecodeBitString(aper.NewBitReader(ie.Value), 256, 256)
		if err != nil {
			t.Fatalf("decode SecurityKey BIT STRING: %v", err)
		}
		return append([]byte(nil), bs.Bytes...)
	}
	t.Fatal("ICS missing SecurityKey IE")
	return nil
}

// setupSendCapture registers an eNB and returns a bidirectional channel for reading PDUs.
func setupSendCapture(srv *Server, remoteAddr string) chan []byte {
	ch := make(chan []byte, 16)
	enb := &ENBContext{RemoteAddr: remoteAddr, SetupComplete: true}
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
	ue.KASME = make([]byte, 32) // required for DeriveKeNB when TAU active flag resumes user plane
	ue.UEAMBRDown = 100000000
	ue.UEAMBRUp = 100000000
	ue.Unlock()
	srv.ueManager.UpdateGUTI(ue, guti)
	return ue, guti
}

// buildPlainTAUNASPDU returns a plain (unprotected) NAS PDU containing a TAU Request.
func buildPlainTAUNASPDUWithActiveFlag(updateType uint8, active bool, guti *emm.GUTI) []byte {
	// NAS header: [PD=0x07 (EMM, plain), msgType=0x48 (TAU Request)]
	// Body: byte0=(eKSI<<4)|updateType, LV=mobile identity (GUTI), LV=UE net cap
	firstOctet := (0x07 << 4) | (updateType & 0x07)
	if active {
		firstOctet |= 0x08
	}
	body := []byte{firstOctet}
	// LV: GUTI mobile identity
	gutiLV := guti.Encode() // [len=0x0B, 0xF6, PLMN(3), MMEGI(2), MMEC(1), MTMSI(4)]
	body = append(body, gutiLV...)
	// LV: UE network capability (length=2, EEA=0xE0, EIA=0xE0)
	body = append(body, 0x02, 0xE0, 0xE0)
	// Full NAS PDU: [PD|SHT, msgType, body...]
	return append([]byte{emm.PDEPSMobilityMgmt, emm.MsgTrackingAreaUpdateRequest}, body...)
}

func buildPlainTAUNASPDU(updateType uint8, guti *emm.GUTI) []byte {
	return buildPlainTAUNASPDUWithActiveFlag(updateType, false, guti)
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

func TestAttachAcceptRegistrationUsesPerUECompletedSGdOutcome(t *testing.T) {
	srv := newTAUTestServer()
	for _, tc := range []struct {
		name       string
		attachType uint8
		sgdEnabled bool
		smsState   uecontext.SMSRegistrationState
		result     uint8
		f0         bool
	}{
		{"combined_registered", emm.AttachTypeCombinedEPSAndIMSI, true, uecontext.SMSRegistrationRegistered, emm.AttachTypeCombinedEPSAndIMSI, true},
		{"combined_sgd_disabled", emm.AttachTypeCombinedEPSAndIMSI, false, uecontext.SMSRegistrationRegistered, emm.AttachTypeEPSOnly, false},
		{"combined_pending", emm.AttachTypeCombinedEPSAndIMSI, true, uecontext.SMSRegistrationPending, emm.AttachTypeEPSOnly, false},
		{"combined_rejected", emm.AttachTypeCombinedEPSAndIMSI, true, uecontext.SMSRegistrationRejected, emm.AttachTypeEPSOnly, false},
		{"combined_not_requested", emm.AttachTypeCombinedEPSAndIMSI, true, uecontext.SMSRegistrationNotRequested, emm.AttachTypeEPSOnly, false},
		{"eps_only_registered", emm.AttachTypeEPSOnly, true, uecontext.SMSRegistrationRegistered, emm.AttachTypeEPSOnly, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv.sgdCfg = config.SGdConfig{Enabled: tc.sgdEnabled}
			got, additional := srv.attachAcceptRegistration(tc.attachType, tc.smsState)
			if got != tc.result {
				t.Fatalf("result got %#x, want %#x", got, tc.result)
			}
			if (additional != nil) != tc.f0 || additional != nil && *additional != 0 {
				t.Fatalf("additional update result got %v, want F0 present=%t", additional, tc.f0)
			}
		})
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

func TestProcessTrackingAreaUpdate_CombinedRequestWithoutSGsUsesEPSResultAndCause(t *testing.T) {
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
	accept, err := emm.DecodeTAUAccept(plain)
	if err != nil {
		t.Fatalf("decode TAU Accept: %v", err)
	}
	if got, want := accept.UpdateResult, emm.EPSUpdateResultTAUpdated; got != want {
		t.Fatalf("TAU update result got %#x, want TA updated %#x", got, want)
	}
	if accept.EMMCause == nil || *accept.EMMCause != emm.CauseCSDomainNotAvailable {
		t.Fatalf("TAU Accept EMM cause got %v, want CS domain not available (%#x)", accept.EMMCause, emm.CauseCSDomainNotAvailable)
	}
	if accept.GUTI != nil {
		t.Fatalf("EPS-only combined TAU unexpectedly fabricated GUTI/TMSI: %+v", accept.GUTI)
	}
}

func TestProcessTrackingAreaUpdate_CombinedRequestWithOperationalSMSInMMEUsesSMSOnlyResult(t *testing.T) {
	srv := newTAUTestServer()
	srv.sgdCfg = config.SGdConfig{Enabled: true}
	const remoteAddr = "10.0.0.12:36412"
	ch := setupSendCapture(srv, remoteAddr)
	ue, _ := makeRegisteredUEWithNullKeys(srv, remoteAddr)
	ue.Lock()
	ue.SMSRegistrationState = uecontext.SMSRegistrationRegistered
	ue.TAI = &emm.TAI{PLMN: [3]byte{0x00, 0xf1, 0x10}, TAC: 1}
	ue.PDNs["internet"] = &uecontext.PDNContext{APN: "internet", DefaultEBI: 5, SGWC_TEID: 0x1005, SGWU_TEID: 0x2005, State: "active", NASAccepted: true, ERABEstablished: true}
	ue.PDNs["ims"] = &uecontext.PDNContext{APN: "ims", DefaultEBI: 6, SGWC_TEID: 0x1006, SGWU_TEID: 0x2006, State: "active", NASAccepted: true, ERABEstablished: true}
	ue.DedicatedBearers[7] = &uecontext.DedicatedBearerContext{AssignedEBI: 7, LinkedEBI: 6, State: "active", NASAccepted: true, ERABEstablished: true}
	ue.DedicatedBearers[8] = &uecontext.DedicatedBearerContext{AssignedEBI: 8, LinkedEBI: 6, State: "active", NASAccepted: true, ERABEstablished: true}
	ue.DedicatedBearers[9] = &uecontext.DedicatedBearerContext{AssignedEBI: 9, LinkedEBI: 6, State: "active", NASAccepted: true, ERABEstablished: true}
	ue.Unlock()

	innerBody := []byte{(0x07 << 4) | emm.EPSUpdateTypeCombined, 0x00, 0x01, 0xe0}
	if err := srv.processTrackingAreaUpdate(ue, innerBody, srv.log.With(zap.String("test", "tau-sms-only"))); err != nil {
		t.Fatalf("processTrackingAreaUpdate error: %v", err)
	}
	select {
	case sent := <-ch:
		plain := decodeDownlinkNASFromRawPDU(t, sent)[6:]
		accept, err := emm.DecodeTAUAccept(plain)
		if err != nil {
			t.Fatalf("DecodeTAUAccept: %v", err)
		}
		if got, want := accept.UpdateResult, emm.EPSUpdateResultCombinedTALAUpdated; got != want {
			t.Fatalf("update result got %#x, want combined TA/LA updated %#x", got, want)
		}
		if accept.EMMCause != nil {
			t.Fatalf("SMS-in-MME TAU unexpectedly included EMM cause %#x", *accept.EMMCause)
		}
		if accept.AdditionalUpdateResult != nil {
			t.Fatalf("combined SGd TAU unexpectedly included Additional Update Result %#x", *accept.AdditionalUpdateResult)
		}
		if accept.LAI != nil {
			t.Fatalf("combined SGd TAU unexpectedly included LAI %+v", accept.LAI)
		}
		for _, ebi := range []uint8{5, 6, 7, 8, 9} {
			if accept.EPSBearerStatus == nil || !accept.EPSBearerStatus.HasEBI(ebi) {
				t.Fatalf("TAU Accept missing retained EBI %d: %+v", ebi, accept.EPSBearerStatus)
			}
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no TAU Accept sent")
	}
	ue.Lock()
	defer ue.Unlock()
	if ue.PDNs["ims"] == nil || ue.DedicatedBearers[7] == nil || ue.DedicatedBearers[8] == nil || ue.DedicatedBearers[9] == nil {
		t.Fatal("ordinary SMS-only TAU mutated IMS PDN or its linked dedicated bearers")
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

func TestBuildTAUAcceptNAS_UsesNASPLMNEncodingForConfiguredTAIList(t *testing.T) {
	srv := newTAUTestServer()
	srv.nfCfg.MCC = "311"
	srv.nfCfg.MNC = "435"
	srv.nfCfg.TAIList = []config.TAIItem{{MCC: "311", MNC: "435", TAC: 1}}

	ue, _ := makeRegisteredUEWithNullKeys(srv, "10.0.0.30:36412")
	ue.Lock()
	ue.TAI = &emm.TAI{TAC: 1}
	ue.Unlock()

	pdu, err := srv.buildTAUAcceptNAS(ue, zap.NewNop(), tauAcceptOptions{
		UpdateResult:    emm.EPSUpdateResultCombinedTALAUpdated,
		EPSBearerStatus: &emm.EPSBearerContextStatus{Bitmap: 1 << 5},
	})
	if err != nil {
		t.Fatalf("buildTAUAcceptNAS: %v", err)
	}
	plain := pdu
	if pdu[0]>>4 == emm.SecurityHeaderIntegrityProtected || pdu[0]>>4 == emm.SecurityHeaderIntegrityAndCipher {
		plain = pdu[6:]
	}
	accept, err := emm.DecodeTAUAccept(plain)
	if err != nil {
		t.Fatalf("DecodeTAUAccept: %v", err)
	}
	if len(accept.TAIList) != 1 {
		t.Fatalf("TAU Accept TAI list count got %d, want 1", len(accept.TAIList))
	}
	wantPLMN, err := security.EncodePLMN("311", "435")
	if err != nil {
		t.Fatal(err)
	}
	if got := accept.TAIList[0].PLMN[:]; !bytes.Equal(got, wantPLMN) {
		t.Fatalf("TAU Accept TAI PLMN got %x, want %x", got, wantPLMN)
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

func TestHandleIdleTAUMessage_InactiveInitialUEReleasesS1AfterTAUAccept(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "10.0.0.30:36412"
	ch := setupSendCapture(srv, remoteAddr)

	realUE, guti := makeRegisteredUEWithNullKeys(srv, remoteAddr)

	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 2030
	tempUE.ENBGlobalID = remoteAddr
	tempUE.Unlock()

	nasPDU := buildPlainTAUNASPDU(emm.EPSUpdateTypePeriodic, guti)
	srv.handleIdleTAUMessage(tempUE, nil, nasPDU)

	select {
	case <-ch:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no PDU sent after TAU Accept")
	}

	var release []byte
	select {
	case release = <-ch:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no UE Context Release Command after inactive InitialUE TAU")
	}
	msg, err := pdu.Decode(release)
	if err != nil {
		t.Fatalf("decode release command: %v", err)
	}
	if msg.Type != pdu.PDUTypeInitiatingMessage || msg.ProcedureCode != pdu.ProcUEContextRelease {
		t.Fatalf("PDU got type=%s proc=%d, want UE Context Release Command", msg.Type, msg.ProcedureCode)
	}

	realUE.Lock()
	defer realUE.Unlock()
	if !realUE.S1ReleasePending {
		t.Fatal("inactive InitialUE TAU did not start preserved S1 release")
	}
	if realUE.S1BindingState != uecontext.S1BindingReleasePending {
		t.Fatalf("S1BindingState got %s, want %s", realUE.S1BindingState, uecontext.S1BindingReleasePending)
	}
}

func TestHandleIdleTAUMessage_GUTIReallocationDefersReleaseUntilTAUComplete(t *testing.T) {
	srv := newTAUTestServer()
	srv.operCfg.TAU.ReallocateGUTI = true
	const remoteAddr = "10.0.0.31:36412"
	ch := setupSendCapture(srv, remoteAddr)

	realUE, guti := makeRegisteredUEWithNullKeys(srv, remoteAddr)
	realUE.Lock()
	realUE.PDNs["internet"] = &uecontext.PDNContext{APN: "internet", DefaultEBI: 5, State: "active"}
	realUE.Unlock()
	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 2031
	tempUE.ENBGlobalID = remoteAddr
	tempUE.Unlock()

	srv.handleIdleTAUMessage(tempUE, nil, buildPlainTAUNASPDU(emm.EPSUpdateTypePeriodic, guti))
	select {
	case <-ch: // TAU Accept, carrying the new GUTI
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no TAU Accept sent")
	}
	select {
	case unexpected := <-ch:
		t.Fatalf("release sent before required TAU Complete: %x", unexpected)
	case <-time.After(25 * time.Millisecond):
	}
	realUE.Lock()
	deferred := realUE.IdleTAUReleaseAfterComplete
	mmeID := realUE.MMEUES1APID
	realUE.Unlock()
	if !deferred {
		t.Fatal("InitialUE inactive TAU release was not deferred for TAU Complete")
	}
	if err := srv.processTAUComplete(realUE, srv.log); err != nil {
		t.Fatalf("process TAU Complete: %v", err)
	}
	select {
	case release := <-ch:
		msg, err := pdu.Decode(release)
		if err != nil || msg.ProcedureCode != pdu.ProcUEContextRelease {
			t.Fatalf("post-complete PDU is not UE Context Release Command: err=%v pdu=%x", err, release)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no release sent after TAU Complete")
	}
	srv.handleUEContextReleaseComplete(remoteAddr, nil, []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Value: ies.EncodeMMEUEApID(mmeID)},
		{ID: pdu.IEENBS1APID, Value: ies.EncodeENBUEApID(2031)},
	})
	realUE.Lock()
	defer realUE.Unlock()
	if realUE.ECMState != emm.ECMIdle {
		t.Fatalf("ECM state got %s, want ECM-IDLE after Release Complete", realUE.ECMState)
	}
	if realUE.PDNs["internet"] == nil {
		t.Fatal("S1 release removed retained PDN")
	}
}

func TestHandleIdleTAUMessage_RepeatedInactiveInitialUEBindingsDoNotAccumulate(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "10.0.0.32:36412"
	ch := setupSendCapture(srv, remoteAddr)
	realUE, guti := makeRegisteredUEWithNullKeys(srv, remoteAddr)
	realUE.Lock()
	realUE.PDNs["internet"] = &uecontext.PDNContext{APN: "internet", DefaultEBI: 5, State: "active"}
	mmeID := realUE.MMEUES1APID
	realUE.Unlock()

	for i := uint32(0); i < 5; i++ {
		enbID := uint32(2040) + i
		tempUE := srv.ueManager.Allocate()
		tempUE.Lock()
		tempUE.ENBS1APID = enbID
		tempUE.ENBGlobalID = remoteAddr
		tempUE.Unlock()
		srv.handleIdleTAUMessage(tempUE, nil, buildPlainTAUNASPDU(emm.EPSUpdateTypePeriodic, guti))
		if i > 0 {
			select {
			case oldRelease := <-ch:
				msg, err := pdu.Decode(oldRelease)
				if err != nil || msg.ProcedureCode != pdu.ProcUEContextRelease {
					t.Fatalf("iteration %d: expected targeted old-binding Release Command, err=%v pdu=%x", i, err, oldRelease)
				}
			case <-time.After(100 * time.Millisecond):
				t.Fatalf("iteration %d: no old-binding release", i)
			}
		}
		select {
		case <-ch: // TAU Accept
		case <-time.After(100 * time.Millisecond):
			t.Fatalf("iteration %d: no TAU Accept", i)
		}
		select {
		case release := <-ch:
			msg, err := pdu.Decode(release)
			if err != nil || msg.ProcedureCode != pdu.ProcUEContextRelease {
				t.Fatalf("iteration %d: expected UE Context Release Command, err=%v pdu=%x", i, err, release)
			}
		case <-time.After(100 * time.Millisecond):
			t.Fatalf("iteration %d: no S1 release", i)
		}
		if got, want := srv.ueManager.Count(), 1; got != want {
			t.Fatalf("iteration %d: temporary UE contexts got %d, want %d", i, got, want)
		}
	}

	// A Release Complete for the first obsolete S1 pair must not disturb the
	// newest binding or retained EPS session.
	srv.handleUEContextReleaseComplete(remoteAddr, nil, []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Value: ies.EncodeMMEUEApID(mmeID)},
		{ID: pdu.IEENBS1APID, Value: ies.EncodeENBUEApID(2040)},
	})
	realUE.Lock()
	defer realUE.Unlock()
	if realUE.ENBS1APID != 2044 || realUE.S1BindingGeneration != 5 {
		t.Fatalf("stale release changed newest binding: enb_ue_id=%d generation=%d", realUE.ENBS1APID, realUE.S1BindingGeneration)
	}
	if realUE.PDNs["internet"] == nil {
		t.Fatal("repeated TAU S1 releases removed retained PDN")
	}
}

// TestHandleIdleTAUMessage_MultipleObsoleteBindingsEachRetiredIndependently
// reproduces a UE reconnecting faster than the eNB acknowledges each S1
// release: two obsolete bindings end up outstanding for the same UE at once.
// Each must be matched and retired by its own (possibly out-of-order, possibly
// very late) Release Complete — a stale binding must never fall through to
// findUEForReleaseComplete and draw a spurious unknown-pair-ue-s1ap-id
// ErrorIndication.
func TestHandleIdleTAUMessage_MultipleObsoleteBindingsEachRetiredIndependently(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "10.0.0.33:36412"
	ch := setupSendCapture(srv, remoteAddr)
	realUE, guti := makeRegisteredUEWithNullKeys(srv, remoteAddr)
	realUE.Lock()
	mmeID := realUE.MMEUES1APID
	realUE.Unlock()

	enbIDs := []uint32{5000, 5001, 5002}
	for i, enbID := range enbIDs {
		tempUE := srv.ueManager.Allocate()
		tempUE.Lock()
		tempUE.ENBS1APID = enbID
		tempUE.ENBGlobalID = remoteAddr
		tempUE.Unlock()
		srv.handleIdleTAUMessage(tempUE, nil, buildPlainTAUNASPDU(emm.EPSUpdateTypePeriodic, guti))
		if i > 0 {
			select {
			case <-ch: // old-binding Release Command
			case <-time.After(100 * time.Millisecond):
				t.Fatalf("iteration %d: no old-binding release", i)
			}
		}
		select {
		case <-ch: // TAU Accept
		case <-time.After(100 * time.Millisecond):
			t.Fatalf("iteration %d: no TAU Accept", i)
		}
		select {
		case <-ch: // UE Context Release Command for this now-inactive binding
		case <-time.After(100 * time.Millisecond):
			t.Fatalf("iteration %d: no S1 release", i)
		}
	}

	// Two eNB-issued releases (5000 and 5001) are now outstanding at once,
	// neither yet acknowledged by the eNB.
	realUE.Lock()
	obsoleteCount := len(realUE.ObsoleteS1Releases)
	realUE.Unlock()
	if obsoleteCount != 2 {
		t.Fatalf("obsolete bindings got %d, want 2", obsoleteCount)
	}

	// The eNB acknowledges out of order and late: the *newer* stale binding
	// (5001) completes before the older one (5000).
	srv.handleUEContextReleaseComplete(remoteAddr, nil, []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Value: ies.EncodeMMEUEApID(mmeID)},
		{ID: pdu.IEENBS1APID, Value: ies.EncodeENBUEApID(5001)},
	})
	select {
	case unexpected := <-ch:
		t.Fatalf("obsolete binding 5001 Release Complete produced unexpected message: %x", unexpected)
	case <-time.After(25 * time.Millisecond):
	}
	realUE.Lock()
	if len(realUE.ObsoleteS1Releases) != 1 || realUE.ObsoleteS1Releases[0].ENBS1APID != 5000 {
		t.Fatalf("after retiring 5001, obsolete bindings got %+v, want only 5000", realUE.ObsoleteS1Releases)
	}
	realUE.Unlock()

	srv.handleUEContextReleaseComplete(remoteAddr, nil, []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Value: ies.EncodeMMEUEApID(mmeID)},
		{ID: pdu.IEENBS1APID, Value: ies.EncodeENBUEApID(5000)},
	})
	select {
	case unexpected := <-ch:
		t.Fatalf("obsolete binding 5000 Release Complete produced unexpected message: %x", unexpected)
	case <-time.After(25 * time.Millisecond):
	}

	realUE.Lock()
	defer realUE.Unlock()
	if len(realUE.ObsoleteS1Releases) != 0 {
		t.Fatalf("obsolete bindings got %+v, want none left", realUE.ObsoleteS1Releases)
	}
	if realUE.ENBS1APID != 5002 {
		t.Fatalf("current binding disturbed: enb_ue_id=%d, want 5002", realUE.ENBS1APID)
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

func TestHandleIdleTAUMessage_ActiveFlagTriggersInitialContextSetup(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "10.0.0.20:36412"
	ch := setupSendCapture(srv, remoteAddr)

	realUE, guti := makeRegisteredUEWithNullKeys(srv, remoteAddr)
	realUE.Lock()
	realUE.SetECMState(emm.ECMIdle)
	realUE.SGWAddress = "10.0.0.9:2123"
	realUE.SGWC_TEID = 0x1001
	realUE.SGWU_TEID = 0x2002
	realUE.SGWU_IP = bytes.Repeat([]byte{10}, 4)
	realUE.DefaultEBI = 5
	realUE.APN = "internet"
	realUE.SubscriberAPNConfigs = map[string]uecontext.SubscriberAPNConfig{
		"internet": {
			ServiceSelection:        "internet",
			PDNType:                 1,
			QCI:                     9,
			ARPPriority:             8,
			PreemptionCapability:    false,
			PreemptionVulnerability: false,
			APNAMBRDown:             100000,
			APNAMBRUp:               100000,
		},
	}
	realUE.Unlock()

	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 5005
	tempUE.ENBGlobalID = remoteAddr
	tempUE.Unlock()

	nasPDU := buildPlainTAUNASPDUWithActiveFlag(emm.EPSUpdateTypePeriodic, true, guti)
	srv.handleIdleTAUMessage(tempUE, nil, nasPDU)

	select {
	case first := <-ch:
		msg, err := pdu.Decode(first)
		if err != nil {
			t.Fatalf("decode ICS PDU: %v", err)
		}
		if msg.Type != pdu.PDUTypeInitiatingMessage || msg.ProcedureCode != pdu.ProcInitialContextSetup {
			t.Fatalf("PDU got type=%s proc=%d, want InitialContextSetup", msg.Type, msg.ProcedureCode)
		}
		gotNAS := decodeNASPDUFromInitialContextSetup(t, msg)
		if len(gotNAS) == 0 {
			t.Fatal("InitialContextSetup missing embedded TAU Accept NAS")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no Initial Context Setup sent for active-flag idle TAU")
	}

	realUE.Lock()
	defer realUE.Unlock()
	if realUE.AttachStep != uecontext.AttachStepWaitingICSRespTAU {
		t.Fatalf("AttachStep got %d, want WaitingICSRespTAU", realUE.AttachStep)
	}
}

func TestHandleIdleTAUMessage_DuplicateActiveFlagResumeRebindsAndRetransmitsICS(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "10.0.0.24:36412"
	ch := setupSendCapture(srv, remoteAddr)

	realUE, guti := makeRegisteredUEWithNullKeys(srv, remoteAddr)
	realUE.Lock()
	realUE.SetECMState(emm.ECMIdle)
	realUE.SGWAddress = "10.0.0.9:2123"
	realUE.SGWC_TEID = 0x1001
	realUE.SGWU_TEID = 0x2002
	realUE.SGWU_IP = []byte{10, 99, 0, 1}
	realUE.DefaultEBI = 5
	realUE.APN = "internet"
	realUE.SubscriberAPNConfigs = map[string]uecontext.SubscriberAPNConfig{
		"internet": {
			ServiceSelection:        "internet",
			PDNType:                 1,
			QCI:                     9,
			ARPPriority:             8,
			PreemptionCapability:    false,
			PreemptionVulnerability: false,
			APNAMBRDown:             100000,
			APNAMBRUp:               100000,
		},
		"ims": {
			ServiceSelection:        "ims",
			PDNType:                 1,
			QCI:                     5,
			ARPPriority:             1,
			PreemptionCapability:    false,
			PreemptionVulnerability: false,
			APNAMBRDown:             100000,
			APNAMBRUp:               100000,
		},
	}
	realUE.PDNs = map[string]*uecontext.PDNContext{
		"internet": {
			APN:                     "internet",
			DefaultEBI:              5,
			PDNType:                 1,
			QCI:                     9,
			ARPPriority:             8,
			PreemptionCapability:    false,
			PreemptionVulnerability: false,
			SGWC_TEID:               0x1001,
			SGWU_TEID:               0x2002,
			SGWU_IP:                 []byte{10, 99, 0, 1},
			NASAccepted:             true,
			ERABEstablished:         true,
			ModifyBearerSent:        true,
			ModifyBearerAccepted:    true,
		},
		"ims": {
			APN:                     "ims",
			DefaultEBI:              6,
			PDNType:                 1,
			QCI:                     5,
			ARPPriority:             1,
			PreemptionCapability:    false,
			PreemptionVulnerability: false,
			SGWC_TEID:               0x3003,
			SGWU_TEID:               0x4004,
			SGWU_IP:                 []byte{10, 99, 0, 2},
			NASAccepted:             true,
			ERABEstablished:         true,
			ModifyBearerSent:        true,
			ModifyBearerAccepted:    true,
		},
	}
	realUE.Unlock()

	tempUE1 := srv.ueManager.Allocate()
	tempUE1.Lock()
	tempUE1.ENBS1APID = 5101
	tempUE1.ENBGlobalID = remoteAddr
	tempUE1.Unlock()

	nasPDU := buildPlainTAUNASPDUWithActiveFlag(emm.EPSUpdateTypePeriodic, true, guti)
	srv.handleIdleTAUMessage(tempUE1, nil, nasPDU)

	select {
	case first := <-ch:
		msg, err := pdu.Decode(first)
		if err != nil {
			t.Fatalf("decode first ICS PDU: %v", err)
		}
		if msg.Type != pdu.PDUTypeInitiatingMessage || msg.ProcedureCode != pdu.ProcInitialContextSetup {
			t.Fatalf("first PDU got type=%s proc=%d, want InitialContextSetup", msg.Type, msg.ProcedureCode)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no first Initial Context Setup sent for active-flag idle TAU")
	}

	tempUE2 := srv.ueManager.Allocate()
	tempUE2.Lock()
	tempUE2.ENBS1APID = 5102
	tempUE2.ENBGlobalID = remoteAddr
	tempUE2.Unlock()

	srv.handleIdleTAUMessage(tempUE2, nil, nasPDU)

	select {
	case second := <-ch:
		msg, err := pdu.Decode(second)
		if err != nil {
			t.Fatalf("decode retransmitted ICS PDU: %v", err)
		}
		if msg.Type != pdu.PDUTypeInitiatingMessage || msg.ProcedureCode != pdu.ProcInitialContextSetup {
			t.Fatalf("retransmit PDU got type=%s proc=%d, want InitialContextSetup", msg.Type, msg.ProcedureCode)
		}
		gotNAS := decodeNASPDUFromInitialContextSetup(t, msg)
		if len(gotNAS) == 0 {
			t.Fatal("retransmitted InitialContextSetup missing embedded TAU Accept NAS")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no retransmitted Initial Context Setup sent for duplicate active-flag idle TAU")
	}

	realUE.Lock()
	defer realUE.Unlock()
	if realUE.ENBS1APID != 5102 {
		t.Fatalf("ENBS1APID got %d, want 5102", realUE.ENBS1APID)
	}
	if realUE.AttachStep != uecontext.AttachStepWaitingICSRespTAU {
		t.Fatalf("AttachStep got %d, want WaitingICSRespTAU", realUE.AttachStep)
	}
	if realUE.ECMState != emm.ECMConnected {
		t.Fatalf("ECMState got %v, want ECMConnected", realUE.ECMState)
	}
}

func TestHandleIdleTAUMessage_ActiveFlagResumesRetainedActiveBearers(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "10.0.0.23:36412"
	ch := setupSendCapture(srv, remoteAddr)

	realUE, guti := makeRegisteredUEWithNullKeys(srv, remoteAddr)
	realUE.Lock()
	realUE.SetECMState(emm.ECMIdle)
	realUE.SGWAddress = "10.0.0.9:2123"
	realUE.SGWC_TEID = 0x1001
	realUE.SGWU_TEID = 0x2002
	realUE.SGWU_IP = []byte{10, 99, 0, 1}
	realUE.DefaultEBI = 5
	realUE.APN = "internet"
	realUE.SubscriberAPNConfigs = map[string]uecontext.SubscriberAPNConfig{
		"internet": {
			ServiceSelection:        "internet",
			PDNType:                 1,
			QCI:                     9,
			ARPPriority:             8,
			PreemptionCapability:    false,
			PreemptionVulnerability: false,
			APNAMBRDown:             100000,
			APNAMBRUp:               100000,
		},
		"ims": {
			ServiceSelection:        "ims",
			PDNType:                 1,
			QCI:                     5,
			ARPPriority:             1,
			PreemptionCapability:    false,
			PreemptionVulnerability: false,
			APNAMBRDown:             100000,
			APNAMBRUp:               100000,
		},
		"mms": {
			ServiceSelection:        "mms",
			PDNType:                 1,
			QCI:                     8,
			ARPPriority:             8,
			PreemptionCapability:    false,
			PreemptionVulnerability: false,
			APNAMBRDown:             100000,
			APNAMBRUp:               100000,
		},
	}
	realUE.PDNs = map[string]*uecontext.PDNContext{
		"internet": {
			APN:                  "internet",
			DefaultEBI:           5,
			SGWC_TEID:            0x1001,
			SGWU_TEID:            0x2002,
			SGWU_IP:              []byte{10, 99, 0, 1},
			NASAccepted:          true,
			ERABEstablished:      true,
			ModifyBearerSent:     true,
			ModifyBearerAccepted: true,
			State:                "active",
		},
		"ims": {
			APN:                  "ims",
			DefaultEBI:           6,
			SGWC_TEID:            0x3003,
			SGWU_TEID:            0x4004,
			SGWU_IP:              []byte{10, 99, 0, 2},
			NASAccepted:          true,
			ERABEstablished:      true,
			ModifyBearerSent:     true,
			ModifyBearerAccepted: true,
			State:                "active",
		},
		"mms": {
			APN:                  "mms",
			DefaultEBI:           9,
			SGWC_TEID:            0x5005,
			SGWU_TEID:            0x6006,
			SGWU_IP:              []byte{10, 99, 0, 3},
			NASAccepted:          true,
			ERABEstablished:      true,
			ModifyBearerSent:     true,
			ModifyBearerAccepted: true,
			State:                "active",
		},
	}
	realUE.DedicatedBearers = map[uint8]*uecontext.DedicatedBearerContext{
		7: {
			AssignedEBI:     7,
			LinkedEBI:       6,
			QCI:             2,
			ARP:             0x10,
			SGWS1UTEID:      0x11111111,
			SGWS1UIP:        []byte{10, 99, 0, 4},
			NASAccepted:     true,
			ERABEstablished: true,
			State:           "active",
		},
		8: {
			AssignedEBI:     8,
			LinkedEBI:       6,
			QCI:             1,
			ARP:             0x08,
			SGWS1UTEID:      0x22222222,
			SGWS1UIP:        []byte{10, 99, 0, 5},
			NASAccepted:     true,
			ERABEstablished: true,
			State:           "active",
		},
	}
	clearUEAccessPathsLocked(realUE)
	realUE.Unlock()

	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 5008
	tempUE.ENBGlobalID = remoteAddr
	tempUE.Unlock()

	nasPDU := append(
		buildPlainTAUNASPDUWithActiveFlag(emm.EPSUpdateTypeCombinedIMSIAttach, true, guti),
		0x57, 0x02, 0x20, 0x00, // UE reports only EBI 5 active
	)
	srv.handleIdleTAUMessage(tempUE, nil, nasPDU)

	select {
	case second := <-ch:
		msg, err := pdu.Decode(second)
		if err != nil {
			t.Fatalf("decode ICS PDU: %v", err)
		}
		if msg.Type != pdu.PDUTypeInitiatingMessage || msg.ProcedureCode != pdu.ProcInitialContextSetup {
			t.Fatalf("PDU got type=%s proc=%d, want InitialContextSetup", msg.Type, msg.ProcedureCode)
		}
		gotNAS := decodeNASPDUFromInitialContextSetup(t, msg)
		if len(gotNAS) == 0 {
			t.Fatal("resume ICS missing embedded TAU Accept NAS")
		}
		plain := gotNAS
		if gotNAS[0]>>4 != 0 {
			plain = gotNAS[6:]
		}
		accept, err := emm.DecodeTAUAccept(plain)
		if err != nil {
			t.Fatalf("DecodeTAUAccept from resume ICS: %v plain=%x", err, plain)
		}
		if accept.EPSBearerStatus == nil {
			t.Fatal("resume ICS TAU Accept missing EPS bearer context status")
		}
		if got, want := accept.EPSBearerStatus.Bitmap, uint16(1<<5); got != want {
			t.Fatalf("resume ICS TAU Accept EPS bearer status got %#x, want %#x", got, want)
		}

		ieList, err := pdu.DecodeIEContainer(msg.Value)
		if err != nil {
			t.Fatalf("decode ICS IE list: %v", err)
		}
		var erabList []byte
		for _, ie := range ieList {
			if ie.ID == pdu.IEERABToBeSetupListCtxtSUReq {
				erabList = ie.Value
				break
			}
		}
		if len(erabList) == 0 {
			t.Fatal("resume ICS missing E-RABToBeSetupListCtxtSUReq")
		}
		items := decodeResumeICSErabList(t, erabList)
		if got, want := len(items), 1; got != want {
			t.Fatalf("resume ICS item count got %d, want %d", got, want)
		}
		gotEBIs := []uint8{items[0].EBI}
		if got, want := gotEBIs, []uint8{5}; !reflect.DeepEqual(got, want) {
			t.Fatalf("resume ICS EBIs got %v, want %v", got, want)
		}
		if !items[0].NASPDUPresent {
			t.Fatal("resume ICS first item missing embedded TAU Accept NAS")
		}
		if items[0].EBI != 5 {
			t.Fatalf("resume ICS first EBI got %d, want 5", items[0].EBI)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no Initial Context Setup sent for active-flag idle TAU")
	}
}

func TestHandleIdleTAUMessage_BearerStatusMismatchIncludesTAUAcceptStatus(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "10.0.0.21:36412"
	ch := setupSendCapture(srv, remoteAddr)

	realUE, guti := makeRegisteredUEWithNullKeys(srv, remoteAddr)
	realUE.Lock()
	realUE.SetECMState(emm.ECMIdle)
	realUE.DefaultEBI = 5
	realUE.SGWC_TEID = 0x1001
	realUE.SGWU_TEID = 0x2002
	realUE.PDNs = map[string]*uecontext.PDNContext{
		"internet": {
			APN:                  "internet",
			DefaultEBI:           5,
			SGWC_TEID:            0x1001,
			SGWU_TEID:            0x2002,
			NASAccepted:          true,
			ERABEstablished:      true,
			ModifyBearerSent:     true,
			ModifyBearerAccepted: true,
			State:                "active",
		},
		"ims": {
			APN:                  "ims",
			DefaultEBI:           6,
			SGWC_TEID:            0x3003,
			SGWU_TEID:            0x4004,
			NASAccepted:          true,
			ERABEstablished:      true,
			ModifyBearerSent:     true,
			ModifyBearerAccepted: true,
			State:                "active",
		},
	}
	realUE.Unlock()

	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 5006
	tempUE.ENBGlobalID = remoteAddr
	tempUE.Unlock()

	nasPDU := append(
		buildPlainTAUNASPDU(emm.EPSUpdateTypePeriodic, guti),
		0x57, 0x02, 0x20, 0x00, // UE reports only EBI 5 active; MME also has stale extra bearers
	)
	srv.handleIdleTAUMessage(tempUE, nil, nasPDU)

	select {
	case first := <-ch:
		gotNAS := decodeDownlinkNASFromRawPDU(t, first)
		if len(gotNAS) < 7 {
			t.Fatalf("TAU Accept NAS too short: %x", gotNAS)
		}
		plain := gotNAS
		if gotNAS[0]>>4 != 0 {
			plain = gotNAS[6:]
		}
		accept, err := emm.DecodeTAUAccept(plain)
		if err != nil {
			t.Fatalf("DecodeTAUAccept: %v plain=%x", err, plain)
		}
		if accept.EPSBearerStatus == nil {
			t.Fatal("TAU Accept missing EPS bearer context status on mismatch")
		}
		if got, want := accept.EPSBearerStatus.Bitmap, uint16(1<<5); got != want {
			t.Fatalf("TAU Accept EPS bearer status got %#x, want %#x", got, want)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no TAU Accept sent")
	}

	realUE.Lock()
	defer realUE.Unlock()
	if got := realUE.PDNs["internet"].State; got != "active" {
		t.Fatalf("internet PDN state got %q, want active", got)
	}
	if got := realUE.PDNs["ims"].State; got != "tau-suspended" {
		t.Fatalf("ims PDN state got %q, want tau-suspended", got)
	}
	if realUE.PDNs["ims"].NASAccepted || realUE.PDNs["ims"].ERABEstablished || realUE.PDNs["ims"].ModifyBearerAccepted {
		t.Fatal("ims PDN should be suspended in MME state after TAU mismatch")
	}
}

func TestHandleIdleTAUMessage_CombinedTAUMismatchPreservesRetainedBearers(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "10.0.0.24:36412"
	ch := setupSendCapture(srv, remoteAddr)

	realUE, guti := makeRegisteredUEWithNullKeys(srv, remoteAddr)
	realUE.Lock()
	realUE.SetECMState(emm.ECMIdle)
	realUE.DefaultEBI = 5
	realUE.SGWC_TEID = 0x1001
	realUE.SGWU_TEID = 0x2002
	realUE.PDNs = map[string]*uecontext.PDNContext{
		"internet": {
			APN:                  "internet",
			DefaultEBI:           5,
			SGWC_TEID:            0x1001,
			SGWU_TEID:            0x2002,
			NASAccepted:          true,
			ERABEstablished:      true,
			ModifyBearerSent:     true,
			ModifyBearerAccepted: true,
			State:                "idle",
		},
		"ims": {
			APN:                  "ims",
			DefaultEBI:           6,
			SGWC_TEID:            0x3003,
			SGWU_TEID:            0x4004,
			NASAccepted:          true,
			ERABEstablished:      false,
			ModifyBearerSent:     true,
			ModifyBearerAccepted: true,
			State:                "idle",
		},
		"mms": {
			APN:                  "mms",
			DefaultEBI:           9,
			SGWC_TEID:            0x5005,
			SGWU_TEID:            0x6006,
			NASAccepted:          true,
			ERABEstablished:      false,
			ModifyBearerSent:     true,
			ModifyBearerAccepted: true,
			State:                "idle",
		},
	}
	realUE.DedicatedBearers = map[uint8]*uecontext.DedicatedBearerContext{
		7: {
			AssignedEBI:     7,
			LinkedEBI:       6,
			QCI:             2,
			ARP:             0x10,
			SGWS1UTEID:      0x11111111,
			NASAccepted:     true,
			ERABEstablished: false,
			State:           "idle",
		},
		8: {
			AssignedEBI:     8,
			LinkedEBI:       6,
			QCI:             1,
			ARP:             0x08,
			SGWS1UTEID:      0x22222222,
			NASAccepted:     true,
			ERABEstablished: false,
			State:           "idle",
		},
	}
	realUE.Unlock()

	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 5009
	tempUE.ENBGlobalID = remoteAddr
	tempUE.Unlock()

	nasPDU := append(
		buildPlainTAUNASPDU(emm.EPSUpdateTypeCombined, guti),
		0x57, 0x02, 0x20, 0x00,
	)
	srv.handleIdleTAUMessage(tempUE, nil, nasPDU)

	select {
	case first := <-ch:
		gotNAS := decodeDownlinkNASFromRawPDU(t, first)
		if len(gotNAS) < 7 {
			t.Fatalf("TAU Accept NAS too short: %x", gotNAS)
		}
		plain := gotNAS
		if gotNAS[0]>>4 != 0 {
			plain = gotNAS[6:]
		}
		accept, err := emm.DecodeTAUAccept(plain)
		if err != nil {
			t.Fatalf("DecodeTAUAccept: %v plain=%x", err, plain)
		}
		if accept.EPSBearerStatus == nil {
			t.Fatal("TAU Accept missing EPS bearer context status on mismatch")
		}
		if got, want := accept.EPSBearerStatus.Bitmap, uint16((1<<5)|(1<<6)|(1<<7)|(1<<8)|(1<<9)); got != want {
			t.Fatalf("TAU Accept EPS bearer status got %#x, want %#x", got, want)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no TAU Accept sent")
	}

	realUE.Lock()
	defer realUE.Unlock()
	if got := realUE.PDNs["ims"].State; got != "idle" {
		t.Fatalf("ims PDN state got %q, want idle", got)
	}
	if got := realUE.PDNs["mms"].State; got != "idle" {
		t.Fatalf("mms PDN state got %q, want idle", got)
	}
	if got := realUE.DedicatedBearers[7].State; got != "idle" {
		t.Fatalf("dedicated bearer 7 state got %q, want idle", got)
	}
	if got := realUE.DedicatedBearers[8].State; got != "idle" {
		t.Fatalf("dedicated bearer 8 state got %q, want idle", got)
	}
}

func TestHandleIdleTAUMessage_IncludesMMEBearerStatusByDefault(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "10.0.0.22:36412"
	ch := setupSendCapture(srv, remoteAddr)

	realUE, guti := makeRegisteredUEWithNullKeys(srv, remoteAddr)
	realUE.Lock()
	realUE.SetECMState(emm.ECMIdle)
	realUE.DefaultEBI = 5
	realUE.SGWC_TEID = 0x1001
	realUE.SGWU_TEID = 0x2002
	realUE.PDNs = map[string]*uecontext.PDNContext{
		"internet": {
			APN:                  "internet",
			DefaultEBI:           5,
			SGWC_TEID:            0x1001,
			SGWU_TEID:            0x2002,
			NASAccepted:          true,
			ERABEstablished:      true,
			ModifyBearerSent:     true,
			ModifyBearerAccepted: true,
			State:                "active",
		},
		"ims": {
			APN:                  "ims",
			DefaultEBI:           6,
			SGWC_TEID:            0x3003,
			SGWU_TEID:            0x4004,
			NASAccepted:          true,
			ERABEstablished:      true,
			ModifyBearerSent:     true,
			ModifyBearerAccepted: true,
			State:                "active",
		},
	}
	realUE.Unlock()

	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 5007
	tempUE.ENBGlobalID = remoteAddr
	tempUE.Unlock()

	srv.handleIdleTAUMessage(tempUE, nil, buildPlainTAUNASPDU(emm.EPSUpdateTypePeriodic, guti))

	select {
	case first := <-ch:
		gotNAS := decodeDownlinkNASFromRawPDU(t, first)
		if len(gotNAS) < 7 {
			t.Fatalf("TAU Accept NAS too short: %x", gotNAS)
		}
		plain := gotNAS
		if gotNAS[0]>>4 != 0 {
			plain = gotNAS[6:]
		}
		accept, err := emm.DecodeTAUAccept(plain)
		if err != nil {
			t.Fatalf("DecodeTAUAccept: %v plain=%x", err, plain)
		}
		if accept.EPSBearerStatus == nil {
			t.Fatal("TAU Accept missing EPS bearer context status")
		}
		if got, want := accept.EPSBearerStatus.Bitmap, uint16((1<<5)|(1<<6)); got != want {
			t.Fatalf("TAU Accept EPS bearer status got %#x, want %#x", got, want)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no TAU Accept sent")
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

func TestActiveFlagResumeICSPreservesKeNBSnapshotAcrossLaterULCountChange(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "10.0.0.25:36412"
	ch := setupSendCapture(srv, remoteAddr)

	ue, _ := makeRegisteredUEWithNullKeys(srv, remoteAddr)
	ue.Lock()
	ue.SetECMState(emm.ECMConnected)
	ue.ENBS1APID = 0x4401
	ue.ENBGlobalID = remoteAddr
	ue.S1BindingGeneration = 9
	ue.S1BindingState = uecontext.S1BindingActive
	ue.KASME = bytes.Repeat([]byte{0x11}, 32)
	ue.ULNASCount = security.NASCount(7)
	ue.UENetworkCapability = []byte{0xf0, 0x70}
	ue.UEAMBRDown = 100000000
	ue.UEAMBRUp = 100000000
	if _, _, err := deriveAndStoreASContextLocked(ue); err != nil {
		ue.Unlock()
		t.Fatalf("deriveAndStoreASContextLocked: %v", err)
	}
	expectedKeNB := append([]byte(nil), ue.KeNB...)
	expectedULCount := ue.KeNBULCount
	ue.ULNASCount = security.NASCount(11)
	mmeUEID := ue.MMEUES1APID
	ue.Unlock()

	if err := srv.SendInitialContextSetupWithBearers(mmeUEID, []byte{0x07, 0x49, 0x01}, []BearerInfo{{
		EBI:         5,
		QCI:         9,
		ARPPriority: 8,
		SGWU_TEID:   0x1cf513e2,
		SGWU_IP:     net.ParseIP("10.90.250.59").To4(),
	}}); err != nil {
		t.Fatalf("SendInitialContextSetupWithBearers: %v", err)
	}

	raw := <-ch
	msg, err := pdu.Decode(raw)
	if err != nil {
		t.Fatalf("decode ICS PDU: %v", err)
	}
	ieList, err := pdu.DecodeIEContainer(msg.Value)
	if err != nil {
		t.Fatalf("decode ICS IE list: %v", err)
	}
	var gotSecurityKey []byte
	for _, ie := range ieList {
		if ie.ID == pdu.IESecurityKey {
			gotSecurityKey = append([]byte(nil), ie.Value...)
			break
		}
	}
	if len(gotSecurityKey) == 0 {
		t.Fatal("ICS missing SecurityKey IE")
	}
	if want := ies.EncodeSecurityKey(expectedKeNB); !bytes.Equal(gotSecurityKey, want) {
		t.Fatalf("ICS SecurityKey got %x, want %x", gotSecurityKey, want)
	}

	ue.Lock()
	defer ue.Unlock()
	if got := ue.KeNBULCount; got != expectedULCount {
		t.Fatalf("KeNB UL count snapshot got %d, want %d", got, expectedULCount)
	}
	if got := uint32(ue.ULNASCount); got != 11 {
		t.Fatalf("current UL NAS COUNT got %d, want 11", got)
	}
}

func TestActiveFlagTAUSecuritySnapshotLoggingAndICSKeySelection(t *testing.T) {
	srv := newTAUTestServer()
	logger, logs := newObservedLogger()
	srv.log = logger
	const remoteAddr = "10.0.0.26:36412"
	ch := setupSendCapture(srv, remoteAddr)

	realUE, guti := makeRegisteredUEWithNullKeys(srv, remoteAddr)
	realUE.Lock()
	realUE.SetECMState(emm.ECMIdle)
	realUE.SGWAddress = "10.0.0.9:2123"
	realUE.SGWC_TEID = 0x1001
	realUE.SGWU_TEID = 0x2002
	realUE.SGWU_IP = []byte{10, 99, 0, 1}
	realUE.DefaultEBI = 5
	realUE.APN = "internet"
	realUE.SubscriberAPNConfigs = map[string]uecontext.SubscriberAPNConfig{
		"internet": {
			ServiceSelection:        "internet",
			PDNType:                 1,
			QCI:                     9,
			ARPPriority:             8,
			PreemptionCapability:    false,
			PreemptionVulnerability: false,
			APNAMBRDown:             100000,
			APNAMBRUp:               100000,
		},
	}
	realUE.UEAMBRDown = 100000000
	realUE.UEAMBRUp = 100000000
	realUE.PDNs = map[string]*uecontext.PDNContext{
		"internet": {
			APN:                  "internet",
			DefaultEBI:           5,
			SGWC_TEID:            0x1001,
			SGWU_TEID:            0x2002,
			SGWU_IP:              []byte{10, 99, 0, 1},
			NASAccepted:          true,
			ERABEstablished:      true,
			ModifyBearerSent:     true,
			ModifyBearerAccepted: true,
			State:                "active",
		},
	}
	clearUEAccessPathsLocked(realUE)
	realUE.Unlock()

	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 5012
	tempUE.ENBGlobalID = remoteAddr
	tempUE.Unlock()

	nasPDU := append(buildPlainTAUNASPDUWithActiveFlag(emm.EPSUpdateTypePeriodic, true, guti), 0x57, 0x02, 0x20, 0x00)
	srv.handleIdleTAUMessage(tempUE, nil, nasPDU)

	var raw []byte
	select {
	case raw = <-ch:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no Initial Context Setup sent for active-flag TAU security snapshot test")
	}
	securityKey := decodeICSSecurityKeyBytes(t, raw)
	created := findObservedEventWhere(t, logs, "as_security_snapshot_created", func(m map[string]interface{}) bool {
		return m["procedure"] == "active_flag_tau"
	})
	selected := findObservedEventWhere(t, logs, "ics_security_key_selected", func(m map[string]interface{}) bool {
		return m["procedure"] == "active_flag_tau"
	})
	if got, want := selected["security_key_source"], "snapshot"; got != want {
		t.Fatalf("security_key_source got %v want %v", got, want)
	}
	_ = created
	if len(securityKey) == 0 {
		t.Fatal("expected ICS SecurityKey IE bytes")
	}
}

func TestResumeSecurityKeyComparisonAndDisabledLogging(t *testing.T) {
	srv := newTAUTestServer()
	logger, logs := newObservedLogger()
	srv.log = logger
	const remoteAddr = "10.0.0.27:36412"
	ch := setupSendCapture(srv, remoteAddr)

	ue, _ := makeRegisteredUEWithNullKeys(srv, remoteAddr)
	ue.Lock()
	ue.SetECMState(emm.ECMConnected)
	ue.ENBS1APID = 0x4402
	ue.ENBGlobalID = remoteAddr
	ue.S1BindingGeneration = 11
	ue.S1BindingState = uecontext.S1BindingActive
	ue.KASME = bytes.Repeat([]byte{0x23}, 32)
	ue.ULNASCount = security.NASCount(7)
	ue.UENetworkCapability = []byte{0xf0, 0x70}
	ue.UEAMBRDown = 100000000
	ue.UEAMBRUp = 100000000
	if err := srv.createASSecuritySnapshotLocked(ue, "active_flag_tau"); err != nil {
		ue.Unlock()
		t.Fatalf("createASSecuritySnapshotLocked: %v", err)
	}
	expected := append([]byte(nil), ue.KeNB...)
	ue.ULNASCount = security.NASCount(15)
	ue.AttachStep = uecontext.AttachStepWaitingICSRespTAU
	mmeUEID := ue.MMEUES1APID
	ue.Unlock()

	if err := srv.SendInitialContextSetupWithBearers(mmeUEID, []byte{0x07, 0x49, 0x01}, []BearerInfo{{
		EBI:         5,
		QCI:         9,
		ARPPriority: 8,
		SGWU_TEID:   0x11112222,
		SGWU_IP:     net.ParseIP("10.90.250.59").To4(),
	}}); err != nil {
		t.Fatalf("SendInitialContextSetupWithBearers: %v", err)
	}
	raw := <-ch
	if got := decodeICSSecurityKeyBytes(t, raw); !bytes.Equal(got, expected) {
		t.Fatalf("ICS key got %x want %x", got, expected)
	}
	selected := findObservedEvent(t, logs, "ics_security_key_selected")
	reused := findObservedEvent(t, logs, "as_security_snapshot_reused")
	if got, want := selected["security_key_source"], "snapshot"; got != want {
		t.Fatalf("security_key_source got %v want %v", got, want)
	}
	if _, ok := reused["ul_nas_count_at_snapshot"]; !ok {
		t.Fatal("expected ul_nas_count_at_snapshot in snapshot reuse log")
	}
}

func TestServiceRequestSnapshotsKeNBAndStaleReleaseCannotClearIt(t *testing.T) {
	srv := newTAUTestServer()
	logger, logs := newObservedLogger()
	srv.log = logger
	const addr = "10.0.0.28:36412"
	ch := setupSendCapture(srv, addr)

	realUE, mmec, mtmsi := makeRegisteredIdleUE(srv, addr)
	realUE.Lock()
	realUE.KASME = bytes.Repeat([]byte{0x45}, 32)
	realUE.Unlock()

	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 6001
	tempUE.ENBGlobalID = addr
	tempUE.Unlock()

	srv.handleServiceRequest(tempUE, mmec, mtmsi, nil, true, nil, buildSRPDU(1))
	raw := <-ch
	created := findObservedEventWhere(t, logs, "as_security_snapshot_created", func(m map[string]interface{}) bool {
		return m["procedure"] == "service_request"
	})
	key1 := decodeICSSecurityKeyBytes(t, raw)
	_ = created
	if len(key1) == 0 {
		t.Fatal("expected service-request ICS SecurityKey IE bytes")
	}

	realUE.Lock()
	mmeUEID := realUE.MMEUES1APID
	enbUEID := realUE.ENBS1APID
	snapshot := append([]byte(nil), realUE.KeNB...)
	if realUE.S1BindingGeneration < 2 {
		realUE.S1BindingGeneration = 2
	}
	realUE.S1ReleasePending = true
	realUE.S1ReleaseENBID = enbUEID
	realUE.S1ReleaseENBAddr = addr
	realUE.S1ReleaseGeneration = realUE.S1BindingGeneration - 1
	realUE.Unlock()

	srv.handleUEContextReleaseComplete(addr, nil, []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Value: ies.EncodeMMEUEApID(mmeUEID)},
		{ID: pdu.IEENBS1APID, Value: ies.EncodeENBUEApID(enbUEID)},
	})

	realUE.Lock()
	defer realUE.Unlock()
	if !bytes.Equal(realUE.KeNB, snapshot) {
		t.Fatalf("stale release changed snapshot: got %x want %x", realUE.KeNB, snapshot)
	}
	stale := findObservedEvent(t, logs, "stale_binding_mutation_rejected")
	if got, want := stale["mutation_type"], "ue-context-release-complete"; got != want {
		t.Fatalf("stale mutation_type got %v want %v", got, want)
	}
}
