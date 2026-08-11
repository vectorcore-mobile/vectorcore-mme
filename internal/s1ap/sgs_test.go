package s1ap

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/gateway"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/sgsap"
	"github.com/vectorcore/mme/internal/uecontext"
)

type fakeVLRManager struct {
	mu        sync.Mutex
	available bool
	mapping   config.SGsTAILAIMapItem
	mappingOK bool

	lastLURequest               *sgsap.LocationUpdateRequest
	lastUplink                  *sgsap.UplinkUnitdata
	lastServiceRequest          *sgsap.ServiceRequest
	lastPagingReject            *sgsap.Cause
	lastUEUnreachable           *sgsap.UEUnreachable
	lastMOCSFBIndication        *sgsap.MOCSFBIndication
	lastEPSDetach               *sgsap.EPSDetachIndication
	lastIMSIDetach              *sgsap.IMSIDetachIndication
	lastAlertAckIMSI            string
	lastAlertRejectCause        *sgsap.Cause
	lastTMSIReallocCompleteIMSI string
	sendErr                     error
}

func (f *fakeVLRManager) Available(string) bool { return f.available }
func (f *fakeVLRManager) LookupVLR(string, string, uint16) (config.SGsTAILAIMapItem, bool) {
	return f.mapping, f.mappingOK
}
func (f *fakeVLRManager) SendLocationUpdateRequest(_ string, r sgsap.LocationUpdateRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastLURequest = &r
	return f.sendErr
}
func (f *fakeVLRManager) SendUplinkUnitdata(_ string, u sgsap.UplinkUnitdata) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastUplink = &u
	return f.sendErr
}
func (f *fakeVLRManager) SendServiceRequest(_ string, r sgsap.ServiceRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastServiceRequest = &r
	return f.sendErr
}
func (f *fakeVLRManager) SendTMSIReallocationComplete(_ string, imsi string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastTMSIReallocCompleteIMSI = imsi
	return f.sendErr
}
func (f *fakeVLRManager) SendEPSDetachIndication(_ string, d sgsap.EPSDetachIndication) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastEPSDetach = &d
	return f.sendErr
}
func (f *fakeVLRManager) SendIMSIDetachIndication(_ string, d sgsap.IMSIDetachIndication) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastIMSIDetach = &d
	return f.sendErr
}
func (f *fakeVLRManager) SendPagingReject(_ string, _ string, c sgsap.Cause) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastPagingReject = &c
	return f.sendErr
}
func (f *fakeVLRManager) SendAlertAck(_ string, imsi string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastAlertAckIMSI = imsi
	return f.sendErr
}
func (f *fakeVLRManager) SendAlertReject(_ string, _ string, c sgsap.Cause) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastAlertRejectCause = &c
	return f.sendErr
}
func (f *fakeVLRManager) SendUEUnreachable(_ string, u sgsap.UEUnreachable) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastUEUnreachable = &u
	return f.sendErr
}
func (f *fakeVLRManager) SendUEActivityIndication(string, string) error { return nil }
func (f *fakeVLRManager) SendMOCSFBIndication(_ string, ind sgsap.MOCSFBIndication) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastMOCSFBIndication = &ind
	return f.sendErr
}

func sgsTestServer() (*Server, *fakeVLRManager) {
	srv := newTAUTestServer()
	fake := &fakeVLRManager{
		available: true,
		mappingOK: true,
		mapping: config.SGsTAILAIMapItem{
			TAI: config.TAIItem{MCC: "001", MNC: "01", TAC: 1},
			LAI: config.SGsLAIItem{MCC: "001", MNC: "01", LAC: 7},
			VLR: "vlr-1",
		},
	}
	srv.vlr = fake
	srv.sgsCfg = config.SGsConfig{Enabled: true, RequestTimeout: time.Second}
	return srv, fake
}

func TestMMEFQDNForSGs(t *testing.T) {
	srv := newTAUTestServer()
	got := srv.MMEFQDNForSGs()
	want := "mmec01.mmegi0001.mme.epc.mnc001.mcc001.3gppnetwork.org"
	if got != want {
		t.Fatalf("MMEFQDNForSGs() = %q, want %q", got, want)
	}
}

func TestMaybeSendSGsLocationUpdateRequest_SendsWhenCombinedRequested(t *testing.T) {
	srv, fake := sgsTestServer()
	ue := srv.ueManager.Allocate()
	ue.IMSI = "001010123456789"
	ue.TAI = &emm.TAI{PLMN: [3]byte{0x00, 0x10, 0x01}, TAC: 1}
	srv.ueManager.Register(ue)

	srv.maybeSendSGsLocationUpdateRequest(ue, true, false, sgsap.EPSLocationUpdateTypeIMSIAttach)

	fake.mu.Lock()
	req := fake.lastLURequest
	fake.mu.Unlock()
	if req == nil {
		t.Fatal("expected a Location Update Request to be sent")
	}
	if req.IMSI != ue.IMSI || req.UpdateType != sgsap.EPSLocationUpdateTypeIMSIAttach {
		t.Fatalf("unexpected LU request: %+v", req)
	}
	if req.NewLAI.LAC != 7 {
		t.Fatalf("LU request LAC = %d, want 7", req.NewLAI.LAC)
	}
	ue.Lock()
	state := ue.SGsState
	vlrName := ue.SGsVLRName
	ue.Unlock()
	if state != uecontext.SGsUELAUpdateRequested || vlrName != "vlr-1" {
		t.Fatalf("UE SGs state = %v vlr=%q, want LA-UPDATE-REQUESTED/vlr-1", state, vlrName)
	}
}

func TestMaybeSendSGsLocationUpdateRequest_SkipsWhenSGsDisabled(t *testing.T) {
	srv, fake := sgsTestServer()
	srv.sgsCfg.Enabled = false
	ue := srv.ueManager.Allocate()
	ue.IMSI = "001010123456789"
	ue.TAI = &emm.TAI{PLMN: [3]byte{0x00, 0x10, 0x01}, TAC: 1}

	srv.maybeSendSGsLocationUpdateRequest(ue, true, false, sgsap.EPSLocationUpdateTypeIMSIAttach)

	fake.mu.Lock()
	req := fake.lastLURequest
	fake.mu.Unlock()
	if req != nil {
		t.Fatalf("expected no LU request when SGs is disabled, got %+v", req)
	}
}

func TestMaybeSendSGsLocationUpdateRequest_SkipsWhenPSOnly(t *testing.T) {
	srv, fake := sgsTestServer()
	ue := srv.ueManager.Allocate()
	ue.IMSI = "001010123456789"
	ue.TAI = &emm.TAI{PLMN: [3]byte{0x00, 0x10, 0x01}, TAC: 1}
	ue.NetworkAccessMode = gateway.NAMOnlyPacket

	srv.maybeSendSGsLocationUpdateRequest(ue, true, false, sgsap.EPSLocationUpdateTypeIMSIAttach)

	fake.mu.Lock()
	req := fake.lastLURequest
	fake.mu.Unlock()
	if req != nil {
		t.Fatalf("expected no LU request for a PS-only subscription, got %+v", req)
	}
	ue.Lock()
	state := ue.SGsState
	ue.Unlock()
	if state != uecontext.SGsUENull {
		t.Fatalf("UE SGs state = %v, want SGsUENull", state)
	}
}

func TestMaybeSendSGsLocationUpdateRequest_SendsWhenPacketAndCircuit(t *testing.T) {
	srv, fake := sgsTestServer()
	ue := srv.ueManager.Allocate()
	ue.IMSI = "001010123456789"
	ue.TAI = &emm.TAI{PLMN: [3]byte{0x00, 0x10, 0x01}, TAC: 1}
	ue.NetworkAccessMode = gateway.NAMPacketAndCircuit

	srv.maybeSendSGsLocationUpdateRequest(ue, true, false, sgsap.EPSLocationUpdateTypeIMSIAttach)

	fake.mu.Lock()
	req := fake.lastLURequest
	fake.mu.Unlock()
	if req == nil {
		t.Fatal("expected a Location Update Request for a PACKET_AND_CIRCUIT subscription")
	}
}

func TestMaybeSendSGsLocationUpdateRequest_SkipsWhenNotCombinedOrSMSOnly(t *testing.T) {
	srv, fake := sgsTestServer()
	ue := srv.ueManager.Allocate()
	ue.IMSI = "001010123456789"
	ue.TAI = &emm.TAI{PLMN: [3]byte{0x00, 0x10, 0x01}, TAC: 1}

	srv.maybeSendSGsLocationUpdateRequest(ue, false, false, sgsap.EPSLocationUpdateTypeNormal)

	fake.mu.Lock()
	req := fake.lastLURequest
	fake.mu.Unlock()
	if req != nil {
		t.Fatalf("expected no LU request for a plain (non-combined, non-SMS-only) request, got %+v", req)
	}
}

func TestMaybeSendSGsLocationUpdateRequest_SkipsWhenNoVLRMapping(t *testing.T) {
	srv, fake := sgsTestServer()
	fake.mappingOK = false
	ue := srv.ueManager.Allocate()
	ue.IMSI = "001010123456789"
	ue.TAI = &emm.TAI{PLMN: [3]byte{0x00, 0x10, 0x01}, TAC: 1}

	srv.maybeSendSGsLocationUpdateRequest(ue, true, false, sgsap.EPSLocationUpdateTypeIMSIAttach)

	fake.mu.Lock()
	req := fake.lastLURequest
	fake.mu.Unlock()
	if req != nil {
		t.Fatalf("expected no LU request without a TAI-to-VLR mapping, got %+v", req)
	}
}

func TestMaybeSendSGsLocationUpdateRequest_SkipsWhenAlreadyAssociated(t *testing.T) {
	srv, fake := sgsTestServer()
	ue := srv.ueManager.Allocate()
	ue.IMSI = "001010123456789"
	ue.TAI = &emm.TAI{PLMN: [3]byte{0x00, 0x10, 0x01}, TAC: 1}
	ue.SGsState = uecontext.SGsUEAssociated

	srv.maybeSendSGsLocationUpdateRequest(ue, true, false, sgsap.EPSLocationUpdateTypeIMSIAttach)

	fake.mu.Lock()
	req := fake.lastLURequest
	fake.mu.Unlock()
	if req != nil {
		t.Fatalf("expected no duplicate LU request for an already-associated UE, got %+v", req)
	}
}

func TestHandleLocationUpdateAccept_SetsAssociatedState(t *testing.T) {
	srv, _ := sgsTestServer()
	ue := srv.ueManager.Allocate()
	ue.IMSI = "001010123456789"
	srv.ueManager.Register(ue)

	lai := sgsap.LAI{PLMN: [3]byte{0x00, 0x10, 0x01}, LAC: 7}
	srv.HandleLocationUpdateAccept("vlr-1", &sgsap.LocationUpdateAccept{IMSI: ue.IMSI, LAI: lai})

	ue.Lock()
	defer ue.Unlock()
	if ue.SGsState != uecontext.SGsUEAssociated || ue.SGsVLRName != "vlr-1" || ue.SGsLAI == nil || *ue.SGsLAI != lai {
		t.Fatalf("UE state after LU accept: state=%v vlr=%q lai=%+v", ue.SGsState, ue.SGsVLRName, ue.SGsLAI)
	}
}

func TestHandleLocationUpdateReject_RevertsToNull(t *testing.T) {
	srv, _ := sgsTestServer()
	ue := srv.ueManager.Allocate()
	ue.IMSI = "001010123456789"
	ue.SGsState = uecontext.SGsUELAUpdateRequested
	srv.ueManager.Register(ue)

	srv.HandleLocationUpdateReject("vlr-1", &sgsap.LocationUpdateReject{IMSI: ue.IMSI, Cause: 13})

	ue.Lock()
	defer ue.Unlock()
	if ue.SGsState != uecontext.SGsUENull || ue.SGsRejectCause != 13 {
		t.Fatalf("UE state after LU reject: state=%v cause=%v", ue.SGsState, ue.SGsRejectCause)
	}
}

func TestOnVLRReset_ClearsAssociatedUEs(t *testing.T) {
	srv, _ := sgsTestServer()
	associated := srv.ueManager.Allocate()
	associated.IMSI = "001010123456789"
	associated.SGsState = uecontext.SGsUEAssociated
	associated.SGsVLRName = "vlr-1"
	lai := emm.LAI{PLMN: [3]byte{0x00, 0x10, 0x01}, LAC: 7}
	associated.SGsLAI = &lai
	srv.ueManager.Register(associated)

	otherVLR := srv.ueManager.Allocate()
	otherVLR.IMSI = "001010123456780"
	otherVLR.SGsState = uecontext.SGsUEAssociated
	otherVLR.SGsVLRName = "vlr-2"
	srv.ueManager.Register(otherVLR)

	srv.OnVLRReset("vlr-1")

	associated.Lock()
	state := associated.SGsState
	laiAfter := associated.SGsLAI
	associated.Unlock()
	if state != uecontext.SGsUENull || laiAfter != nil {
		t.Fatalf("UE on reset VLR: state=%v lai=%+v, want SGs-NULL/nil", state, laiAfter)
	}

	otherVLR.Lock()
	otherState := otherVLR.SGsState
	otherVLR.Unlock()
	if otherState != uecontext.SGsUEAssociated {
		t.Fatalf("UE on unrelated VLR should be untouched, got state=%v", otherState)
	}
}

// ── SMS over SGs ──────────────────────────────────────────────────────────

func TestSelectSMSPath(t *testing.T) {
	for _, tc := range []struct {
		name               string
		sgsEnabled         bool
		sgdEnabled         bool
		sgsAssociated      bool
		sgdRegistered      bool
		preferredTransport string
		want               string
	}{
		{"neither", true, true, false, false, "sgd", ""},
		{"sgd_only", true, true, false, true, "sgd", "sgd"},
		{"sgs_only", true, true, true, false, "sgd", "sgs"},
		{"both_prefer_sgd", true, true, true, true, "sgd", "sgd"},
		{"both_prefer_sgs", true, true, true, true, "sgs", "sgs"},
		{"sgs_associated_but_sgs_disabled", false, true, true, false, "sgd", ""},
		{"sgd_registered_but_sgd_disabled", true, false, false, true, "sgd", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTAUTestServer()
			srv.sgsCfg.Enabled = tc.sgsEnabled
			srv.sgdCfg.Enabled = tc.sgdEnabled
			srv.smsCfg.PreferredTransport = tc.preferredTransport
			ue := uecontext.NewContext(1)
			if tc.sgsAssociated {
				ue.SGsState = uecontext.SGsUEAssociated
			}
			if tc.sgdRegistered {
				ue.SMSRegistrationState = uecontext.SMSRegistrationRegistered
			}
			if got := srv.selectSMSPath(ue); got != tc.want {
				t.Fatalf("selectSMSPath() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRelayUplinkSMSToSGs(t *testing.T) {
	srv, fake := sgsTestServer()
	ue := uecontext.NewContext(1)
	ue.IMSI = "001010123456789"
	ue.SGsVLRName = "vlr-1"
	ue.TAI = &emm.TAI{PLMN: [3]byte{0x00, 0x10, 0x01}, TAC: 1}

	cpdu := []byte{0x01, 0x02, 0x03}
	if err := srv.relayUplinkSMSToSGs(ue, cpdu); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	got := fake.lastUplink
	fake.mu.Unlock()
	if got == nil || got.IMSI != ue.IMSI || string(got.NASMessageContainer) != string(cpdu) {
		t.Fatalf("relayed uplink = %+v", got)
	}
}

func TestRelayUplinkSMSToSGs_NoVLRAssociation(t *testing.T) {
	srv, _ := sgsTestServer()
	ue := uecontext.NewContext(1)
	ue.IMSI = "001010123456789"
	if err := srv.relayUplinkSMSToSGs(ue, []byte{0x01}); err == nil {
		t.Fatal("expected error relaying uplink SMS without a VLR association")
	}
}

func TestHandleDownlinkUnitdata_UnknownIMSI(t *testing.T) {
	srv, _ := sgsTestServer()
	// Must not panic and must not create a pending entry.
	srv.HandleDownlinkUnitdata("vlr-1", &sgsap.DownlinkUnitdata{IMSI: "001010999999999", NASMessageContainer: []byte{0x01}})
	if _, ok := srv.pendingSGsMT.Load("001010999999999"); ok {
		t.Fatal("unexpected pending entry for unknown IMSI")
	}
}

func TestHandleDownlinkUnitdata_ConnectedUEDeliversImmediately(t *testing.T) {
	srv, _ := sgsTestServer()
	const remoteAddr = "10.0.0.1:36412"
	ch := setupSendCapture(srv, remoteAddr)

	ue := srv.ueManager.Allocate()
	ue.IMSI = "001010123456789"
	ue.ENBGlobalID = remoteAddr
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMConnected
	ue.KNASint = make([]byte, 16)
	ue.KNASenc = make([]byte, 16)
	srv.ueManager.Register(ue)

	srv.HandleDownlinkUnitdata("vlr-1", &sgsap.DownlinkUnitdata{IMSI: ue.IMSI, NASMessageContainer: []byte{0x01, 0x02, 0x03}})

	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("expected downlink NAS transport to be sent for a connected UE")
	}
	if _, ok := srv.pendingSGsMT.Load(ue.IMSI); ok {
		t.Fatal("connected-UE delivery must not leave a pending entry")
	}
}

func TestHandleDownlinkUnitdata_IdleUEQueuesAndDropsDuplicate(t *testing.T) {
	srv, _ := sgsTestServer()
	ue := srv.ueManager.Allocate()
	ue.IMSI = "001010123456789"
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMIdle
	srv.ueManager.Register(ue)

	// No eNB is registered, so PageUE will fail and the pending entry is
	// cleaned up - this still exercises the idle (non-immediate-delivery)
	// branch honestly, without asserting a paging success this test can't
	// actually set up.
	srv.HandleDownlinkUnitdata("vlr-1", &sgsap.DownlinkUnitdata{IMSI: ue.IMSI, NASMessageContainer: []byte{0x01}})
	if _, ok := srv.pendingSGsMT.Load(ue.IMSI); ok {
		t.Fatal("expected the pending entry to be cleaned up after paging failure (no eNB)")
	}

	// Pre-populate a pending entry to exercise the duplicate-drop path
	// directly (bypassing PageUE).
	srv.pendingSGsMT.Store(ue.IMSI, &pendingSGsMTSMS{nasContainer: []byte{0xAA}, state: "paging"})
	srv.HandleDownlinkUnitdata("vlr-1", &sgsap.DownlinkUnitdata{IMSI: ue.IMSI, NASMessageContainer: []byte{0x02}})
	v, ok := srv.pendingSGsMT.Load(ue.IMSI)
	if !ok {
		t.Fatal("expected the original pending entry to remain after a duplicate downlink arrives")
	}
	if string(v.(*pendingSGsMTSMS).nasContainer) != string([]byte{0xAA}) {
		t.Fatal("duplicate downlink must not overwrite the original pending payload")
	}
}

func TestDeliverPendingSGsMT_NoPendingIsNoop(t *testing.T) {
	srv, _ := sgsTestServer()
	ue := uecontext.NewContext(1)
	ue.IMSI = "001010123456789"
	srv.deliverPendingSGsMT(ue) // must not panic
}

func TestDeliverPendingSGsMT_DeliversAfterPaging(t *testing.T) {
	srv, _ := sgsTestServer()
	const remoteAddr = "10.0.0.1:36412"
	ch := setupSendCapture(srv, remoteAddr)

	ue := srv.ueManager.Allocate()
	ue.IMSI = "001010123456789"
	ue.ENBGlobalID = remoteAddr
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMConnected
	ue.KNASint = make([]byte, 16)
	ue.KNASenc = make([]byte, 16)
	srv.ueManager.Register(ue)

	srv.pendingSGsMT.Store(ue.IMSI, &pendingSGsMTSMS{nasContainer: []byte{0x01, 0x02}, state: "paging"})
	srv.deliverPendingSGsMT(ue)

	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("expected the deferred downlink SMS to be delivered")
	}
	if _, ok := srv.pendingSGsMT.Load(ue.IMSI); ok {
		t.Fatal("pending entry must be consumed after delivery")
	}
}

// ── MT CS Fallback paging ─────────────────────────────────────────────────

func TestHandlePagingRequest_UnknownIMSISendsReject(t *testing.T) {
	srv, fake := sgsTestServer()
	srv.HandlePagingRequest("vlr-1", &sgsap.PagingRequest{IMSI: "001010999999999", ServiceIndicator: sgsap.ServiceIndicatorCSCall})

	fake.mu.Lock()
	got := fake.lastPagingReject
	fake.mu.Unlock()
	if got == nil || *got != sgsap.CauseIMSIUnknown {
		t.Fatalf("expected PAGING-REJECT with CauseIMSIUnknown, got %v", got)
	}
}

func TestHandlePagingRequest_ConnectedUECompletesImmediately(t *testing.T) {
	srv, fake := sgsTestServer()
	ue := srv.ueManager.Allocate()
	ue.IMSI = "001010123456789"
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMConnected
	ue.TAI = &emm.TAI{PLMN: [3]byte{0x00, 0x10, 0x01}, TAC: 1}
	srv.ueManager.Register(ue)

	srv.HandlePagingRequest("vlr-1", &sgsap.PagingRequest{IMSI: ue.IMSI, ServiceIndicator: sgsap.ServiceIndicatorCSCall})

	fake.mu.Lock()
	got := fake.lastServiceRequest
	fake.mu.Unlock()
	if got == nil || got.IMSI != ue.IMSI || got.ServiceIndicator != sgsap.ServiceIndicatorCSCall || got.UEEMMMode != sgsap.UEEMMModeConnected {
		t.Fatalf("expected immediate SERVICE-REQUEST for a connected UE, got %+v", got)
	}
	ue.Lock()
	pending := ue.SGsPendingPaging
	ue.Unlock()
	if pending != nil {
		t.Fatalf("expected pending paging cleared after immediate completion, got %+v", pending)
	}
}

func TestHandlePagingRequest_IdleUEWithNoENBSendsReject(t *testing.T) {
	srv, fake := sgsTestServer()
	ue := srv.ueManager.Allocate()
	ue.IMSI = "001010123456789"
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMIdle
	ue.GUTI = &emm.GUTI{PLMN: [3]byte{0x00, 0x10, 0x01}, MMEGI: 1, MMEC: 1, MTMSI: 1}
	ue.TAI = &emm.TAI{PLMN: [3]byte{0x00, 0x10, 0x01}, TAC: 1}
	srv.ueManager.Register(ue)

	srv.HandlePagingRequest("vlr-1", &sgsap.PagingRequest{IMSI: ue.IMSI, ServiceIndicator: sgsap.ServiceIndicatorSMS})

	fake.mu.Lock()
	got := fake.lastPagingReject
	fake.mu.Unlock()
	if got == nil || *got != sgsap.CauseUEUnreachable {
		t.Fatalf("expected PAGING-REJECT (no eNB available), got %v", got)
	}
	ue.Lock()
	pending := ue.SGsPendingPaging
	cnDomain := ue.PagingCNDomain
	ue.Unlock()
	if pending != nil {
		t.Fatalf("expected pending paging cleared after paging failure, got %+v", pending)
	}
	_ = cnDomain
}

func TestCompleteSGsPaging_NoPendingIsNoop(t *testing.T) {
	srv, fake := sgsTestServer()
	ue := uecontext.NewContext(1)
	ue.IMSI = "001010123456789"
	srv.completeSGsPaging(ue)

	fake.mu.Lock()
	got := fake.lastServiceRequest
	fake.mu.Unlock()
	if got != nil {
		t.Fatalf("expected no SERVICE-REQUEST without a pending paging, got %+v", got)
	}
}

func TestReportSGsUEUnreachable(t *testing.T) {
	srv, fake := sgsTestServer()
	srv.reportSGsUEUnreachable("vlr-1", "001010123456789")

	fake.mu.Lock()
	got := fake.lastUEUnreachable
	fake.mu.Unlock()
	if got == nil || got.IMSI != "001010123456789" || got.Cause != sgsap.CauseUEUnreachable {
		t.Fatalf("unexpected UE-UNREACHABLE = %+v", got)
	}
}

func TestPageUEForCSFB_SetsCorrectCNDomain(t *testing.T) {
	srv, _ := sgsTestServer()
	const remoteAddr = "10.0.0.1:36412"
	setupSendCapture(srv, remoteAddr)

	ue := srv.ueManager.Allocate()
	ue.IMSI = "001010123456789"
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMIdle
	ue.ENBGlobalID = remoteAddr
	ue.GUTI = &emm.GUTI{PLMN: [3]byte{0x00, 0x10, 0x01}, MMEGI: 1, MMEC: 1, MTMSI: 1}
	ue.TAI = &emm.TAI{PLMN: [3]byte{0x00, 0x10, 0x01}, TAC: 1}
	srv.ueManager.Register(ue)
	srv.enbs.Store(remoteAddr, &ENBContext{RemoteAddr: remoteAddr, SetupComplete: true})

	if err := srv.PageUEForCSFB(ue.IMSI); err != nil {
		t.Fatal(err)
	}
	ue.Lock()
	cnDomain := ue.PagingCNDomain
	attempts := ue.PagingAttempts
	ue.Unlock()
	if cnDomain != 1 {
		t.Fatalf("PageUEForCSFB: PagingCNDomain = %d, want 1 (cs)", cnDomain)
	}
	if attempts == 0 {
		t.Fatal("PageUEForCSFB: expected a paging cycle to be recorded")
	}
}

func TestPageUE_StillUsesPSDomain(t *testing.T) {
	srv, _ := sgsTestServer()
	const remoteAddr = "10.0.0.1:36412"
	setupSendCapture(srv, remoteAddr)

	ue := srv.ueManager.Allocate()
	ue.IMSI = "001010123456789"
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMIdle
	ue.ENBGlobalID = remoteAddr
	ue.GUTI = &emm.GUTI{PLMN: [3]byte{0x00, 0x10, 0x01}, MMEGI: 1, MMEC: 1, MTMSI: 1}
	ue.TAI = &emm.TAI{PLMN: [3]byte{0x00, 0x10, 0x01}, TAC: 1}
	srv.ueManager.Register(ue)
	srv.enbs.Store(remoteAddr, &ENBContext{RemoteAddr: remoteAddr, SetupComplete: true})

	if err := srv.PageUE(ue.IMSI); err != nil {
		t.Fatal(err)
	}
	ue.Lock()
	cnDomain := ue.PagingCNDomain
	ue.Unlock()
	if cnDomain != 0 {
		t.Fatalf("PageUE: PagingCNDomain = %d, want 0 (ps) - CSFB paging must never regress plain PageUE callers (SGd/SGs MT SMS, admin API)", cnDomain)
	}
}

func TestHandleAlertRequest_KnownIMSISendsAck(t *testing.T) {
	srv, fake := sgsTestServer()
	ue := srv.ueManager.Allocate()
	ue.IMSI = "001010123456789"
	srv.ueManager.Register(ue)

	srv.HandleAlertRequest("vlr-1", ue.IMSI)

	fake.mu.Lock()
	gotAck := fake.lastAlertAckIMSI
	gotReject := fake.lastAlertRejectCause
	fake.mu.Unlock()
	if gotAck != ue.IMSI || gotReject != nil {
		t.Fatalf("expected ALERT-ACK for a known IMSI, got ack=%q reject=%v", gotAck, gotReject)
	}
}

func TestHandleAlertRequest_UnknownIMSISendsReject(t *testing.T) {
	srv, fake := sgsTestServer()

	srv.HandleAlertRequest("vlr-1", "001010000000000")

	fake.mu.Lock()
	gotAck := fake.lastAlertAckIMSI
	gotReject := fake.lastAlertRejectCause
	fake.mu.Unlock()
	if gotAck != "" || gotReject == nil || *gotReject != sgsap.CauseIMSIUnknown {
		t.Fatalf("expected ALERT-REJECT(IMSI unknown) for an unknown IMSI, got ack=%q reject=%v", gotAck, gotReject)
	}
}

func TestHandleReleaseRequest_IMSIUnknownCauseResetsSGsState(t *testing.T) {
	srv, _ := sgsTestServer()
	ue := srv.ueManager.Allocate()
	ue.IMSI = "001010123456789"
	ue.SGsState = uecontext.SGsUEAssociated
	ue.SGsVLRName = "vlr-1"
	srv.ueManager.Register(ue)

	cause := sgsap.CauseIMSIUnknown
	srv.HandleReleaseRequest("vlr-1", ue.IMSI, &cause)

	ue.Lock()
	state := ue.SGsState
	vlrName := ue.SGsVLRName
	ue.Unlock()
	if state != uecontext.SGsUENull || vlrName != "" {
		t.Fatalf("expected SGs state reset to SGs-NULL on an IMSI-unknown RELEASE-REQUEST, got state=%v vlr=%q", state, vlrName)
	}
}

func TestHandleReleaseRequest_OtherCauseLeavesSGsStateAlone(t *testing.T) {
	srv, _ := sgsTestServer()
	ue := srv.ueManager.Allocate()
	ue.IMSI = "001010123456789"
	ue.SGsState = uecontext.SGsUEAssociated
	ue.SGsVLRName = "vlr-1"
	srv.ueManager.Register(ue)

	srv.HandleReleaseRequest("vlr-1", ue.IMSI, nil)

	ue.Lock()
	state := ue.SGsState
	ue.Unlock()
	if state != uecontext.SGsUEAssociated {
		t.Fatalf("expected SGs state untouched by a plain RELEASE-REQUEST, got %v", state)
	}
}

func TestHandleServiceAbortRequest_ClearsPendingCSFBPaging(t *testing.T) {
	srv, _ := sgsTestServer()
	ue := srv.ueManager.Allocate()
	ue.IMSI = "001010123456789"
	ue.SGsPendingPaging = &uecontext.SGsPagingContext{VLRName: "vlr-1", ServiceIndicator: 1}
	ue.PagingAttempts = 1
	srv.ueManager.Register(ue)

	srv.HandleServiceAbortRequest("vlr-1", ue.IMSI)

	ue.Lock()
	pending := ue.SGsPendingPaging
	attempts := ue.PagingAttempts
	ue.Unlock()
	if pending != nil || attempts != 0 {
		t.Fatalf("expected pending CSFB paging cleared, got pending=%+v attempts=%d", pending, attempts)
	}
}

func TestHandleMMInformationRequest_RelaysToUEAsEMMInformation(t *testing.T) {
	srv, _ := sgsTestServer()
	const remoteAddr = "10.0.0.94:36412"
	ch := setupSendCapture(srv, remoteAddr)
	ue, _ := makeRegisteredUEWithNullKeys(srv, remoteAddr)
	ue.Lock()
	ue.IMSI = "001010123456789"
	ue.Unlock()
	srv.ueManager.Register(ue)

	mmInformation := []byte{0x43, 0x02, 0x00, 0x41}
	srv.HandleMMInformationRequest("vlr-1", &sgsap.MMInformationRequest{IMSI: ue.IMSI, MMInformation: mmInformation})

	select {
	case sent := <-ch:
		nasPDU := decodeDownlinkNASFromRawPDU(t, sent)
		if len(nasPDU) < 8 || nasPDU[6] != emm.PDEPSMobilityMgmt || nasPDU[7] != emm.MsgEMMInformation {
			t.Fatalf("expected EMM Information NAS PDU, got %x", nasPDU)
		}
		if !bytes.Equal(nasPDU[8:], mmInformation) {
			t.Fatalf("EMM Information body = %x, want %x", nasPDU[8:], mmInformation)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected MM Information relayed to UE as EMM Information")
	}
}
