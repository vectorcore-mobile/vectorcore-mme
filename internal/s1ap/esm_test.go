package s1ap

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/gtpv2"
	"github.com/vectorcore/mme/internal/peertracker"
	"go.uber.org/zap"

	nas "github.com/vectorcore/mme/internal/nas"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/esm"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"github.com/vectorcore/mme/internal/uecontext"
)

type capturingCSRS11 struct {
	csrCalls []gtpv2.CreateSessionRequest
}

func (m *capturingCSRS11) SendCSR(_ uint32, req *gtpv2.CreateSessionRequest) error {
	m.csrCalls = append(m.csrCalls, *req)
	return nil
}
func (m *capturingCSRS11) SendMBR(_ uint32, _ *gtpv2.ModifyBearerRequest) error  { return nil }
func (m *capturingCSRS11) SendDSR(_ uint32, _ *gtpv2.DeleteSessionRequest) error { return nil }

func loadS1APHexFixture(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", path, err)
	}
	clean := strings.Join(strings.Fields(string(raw)), "")
	b, err := hex.DecodeString(clean)
	if err != nil {
		t.Fatalf("DecodeString(%s): %v", path, err)
	}
	return b
}

func TestProcessESM_PDNDisconnectRequestMarksTargetPDN(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "10.0.0.19:36412"
	_ = setupSendCapture(srv, remoteAddr)
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070570"
	ue.ENBGlobalID = remoteAddr
	ue.ENBS1APID = 199
	ue.KNASint = make([]byte, 16)
	ue.KNASenc = make([]byte, 16)
	ue.IntAlg = 0
	ue.EncAlg = 0
	ue.PDNs = map[string]*uecontext.PDNContext{
		"ims": {
			APN:        "ims",
			DefaultEBI: 6,
			State:      "active",
		},
	}
	ue.Unlock()

	result := &nas.DecodeResult{
		Plain: append(loadS1APHexFixture(t, "testdata/legacy_iphone/pdn_disconnect_request_ebi6.hex"), 0x27, 0x03, 0x80, 0x00, 0x0d),
	}
	if err := srv.processESM(ue, result, zap.NewNop()); err != nil {
		t.Fatalf("processESM: %v", err)
	}

	ue.Lock()
	defer ue.Unlock()
	pdn := ue.PDNs["ims"]
	if pdn == nil {
		t.Fatal("IMS PDN context missing")
	}
	if !pdn.DisconnectRequested {
		t.Fatal("DisconnectRequested=false, want true")
	}
	if pdn.DisconnectPTI != 3 {
		t.Fatalf("DisconnectPTI got %d, want 3", pdn.DisconnectPTI)
	}
	if pdn.State != "pdn-disconnect-deactivate-sent" {
		t.Fatalf("state got %q, want pdn-disconnect-deactivate-sent", pdn.State)
	}
}

func TestPendingPDNDefaultEBIIsReservedForDedicatedAllocation(t *testing.T) {
	ue := uecontext.NewContext(1)
	ue.Lock()
	ue.PendingPDN = &uecontext.PDNContext{
		APN:                    "mms",
		ProcedureTransactionID: 5,
		DefaultEBI:             9,
		State:                  "csr-sent",
	}
	ue.Unlock()

	bearers := []gtpv2.CreateBearerBearer{
		{RequestedEBI: 0},
	}

	ue.Lock()
	if err := assignDedicatedEBIsLocked(ue, bearers); err != nil {
		ue.Unlock()
		t.Fatalf("assignDedicatedEBIsLocked: %v", err)
	}
	got := bearers[0].AssignedEBI
	ue.Unlock()

	if got == 9 {
		t.Fatalf("assigned EBI got %d, want value other than pending PDN default EBI 9", got)
	}
}

func TestAllocateDefaultBearerIDSkipsPendingPDNDefaultEBI(t *testing.T) {
	ue := uecontext.NewContext(1)
	ue.Lock()
	ue.PendingPDN = &uecontext.PDNContext{
		APN:                    "ims",
		ProcedureTransactionID: 2,
		DefaultEBI:             6,
		State:                  "csr-sent",
	}
	got := allocateDefaultBearerIDLocked(ue)
	ue.Unlock()

	if got == 6 {
		t.Fatalf("allocated default EBI got %d, want value other than pending PDN default EBI 6", got)
	}
}

func TestProcessESM_PDNDisconnectRequestSendsDeactivateDefaultBearer(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "10.0.0.20:36412"
	ch := setupSendCapture(srv, remoteAddr)

	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070570"
	ue.ENBGlobalID = remoteAddr
	ue.ENBS1APID = 200
	ue.KNASint = make([]byte, 16)
	ue.KNASenc = make([]byte, 16)
	ue.IntAlg = 0
	ue.EncAlg = 0
	ue.PDNs = map[string]*uecontext.PDNContext{
		"ims": {
			APN:        "ims",
			DefaultEBI: 6,
			State:      "active",
		},
	}
	ue.Unlock()

	result := &nas.DecodeResult{
		Plain: loadS1APHexFixture(t, "testdata/legacy_iphone/pdn_disconnect_request_ebi6.hex"),
	}
	if err := srv.processESM(ue, result, zap.NewNop()); err != nil {
		t.Fatalf("processESM: %v", err)
	}

	var raw []byte
	select {
	case raw = <-ch:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no Downlink NAS sent")
	}
	gotNAS := decodeDownlinkNASFromRawPDU(t, raw)
	if len(gotNAS) < 10 {
		t.Fatalf("protected NAS too short: %x", gotNAS)
	}
	plain := gotNAS[6:]
	if got, want := plain[0]>>4, uint8(6); got != want {
		t.Fatalf("deactivate EBI got %d, want %d", got, want)
	}
	if got, want := plain[0]&0x0f, esm.PDEPSSessionMgmt; got != want {
		t.Fatalf("deactivate PD got %d, want %d", got, want)
	}
	if got, want := plain[1], uint8(3); got != want {
		t.Fatalf("deactivate PTI got %d, want %d", got, want)
	}
	if got, want := plain[2], esm.MsgDeactivateEPSBearerContextRequest; got != want {
		t.Fatalf("deactivate msg type got %#x, want %#x", got, want)
	}
	if got, want := plain[3], esm.ESMCauseRegularDeactivation; got != want {
		t.Fatalf("deactivate cause got %#x, want %#x", got, want)
	}

	ue.Lock()
	pdn := ue.PDNs["ims"]
	ue.Unlock()
	if pdn == nil || pdn.State != "pdn-disconnect-deactivate-sent" {
		t.Fatalf("IMS PDN state got %+v, want pdn-disconnect-deactivate-sent", pdn)
	}
}

func TestProcessESM_PDNDisconnectRequestUnknownLinkedBearerSendsReject(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "10.0.0.21:36412"
	ch := setupSendCapture(srv, remoteAddr)

	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.ENBGlobalID = remoteAddr
	ue.ENBS1APID = 201
	ue.KNASint = make([]byte, 16)
	ue.KNASenc = make([]byte, 16)
	ue.IntAlg = 0
	ue.EncAlg = 0
	ue.ECMState = emm.ECMConnected
	ue.Unlock()

	result := &nas.DecodeResult{
		Plain: loadS1APHexFixture(t, "testdata/legacy_iphone/pdn_disconnect_request_ebi6.hex"),
	}
	if err := srv.processESM(ue, result, zap.NewNop()); err != nil {
		t.Fatalf("processESM: %v", err)
	}

	var raw []byte
	select {
	case raw = <-ch:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no Downlink NAS reject sent")
	}
	gotNAS := decodeDownlinkNASFromRawPDU(t, raw)
	plain := gotNAS[6:]
	if got, want := plain[2], esm.MsgPDNDisconnectReject; got != want {
		t.Fatalf("reject msg type got %#x, want %#x", got, want)
	}
	if got, want := plain[3], esm.ESMCauseProtocolError; got != want {
		t.Fatalf("reject cause got %#x, want %#x", got, want)
	}
}

func TestProcessESM_BearerResourceModificationRequestSendsModify(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "10.0.0.23:36412"
	ch := setupSendCapture(srv, remoteAddr)

	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.ENBGlobalID = remoteAddr
	ue.ENBS1APID = 223
	ue.KNASint = make([]byte, 16)
	ue.KNASenc = make([]byte, 16)
	ue.IntAlg = 0
	ue.EncAlg = 0
	ue.ECMState = emm.ECMConnected
	ue.DedicatedBearers[9] = &uecontext.DedicatedBearerContext{
		AssignedEBI: 9,
		LinkedEBI:   6,
		PTI:         1,
		QCI:         5,
		BearerQoS:   []byte{0x44, 0x05, 0x00, 0x00, 0x00},
		TFT:         []byte{0x05, 0xa4, 0x00, 0x01},
		State:       "active",
	}
	ue.Unlock()

	result := &nas.DecodeResult{
		Plain: []byte{0x02, 0x02, esm.MsgBearerResourceModificationRequest, 0x09, 0x05, 0xa4, 0x20, 0x21, 0x12, 0x13, 0x58, 0x24},
	}
	if err := srv.processESM(ue, result, zap.NewNop()); err != nil {
		t.Fatalf("processESM: %v", err)
	}

	var raw []byte
	select {
	case raw = <-ch:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no Downlink NAS modify sent")
	}
	gotNAS := decodeDownlinkNASFromRawPDU(t, raw)
	plain := gotNAS[6:]
	if got, want := plain[2], esm.MsgModifyEPSBearerContextRequest; got != want {
		t.Fatalf("modify msg type got %#x, want %#x", got, want)
	}
	if got, want := plain[0]>>4, uint8(9); got != want {
		t.Fatalf("modify EBI got %d, want %d", got, want)
	}
	if got, want := plain[1], uint8(2); got != want {
		t.Fatalf("modify PTI got %d, want %d", got, want)
	}

	ue.Lock()
	defer ue.Unlock()
	if got := len(ue.PendingBearerTransactions); got != 1 {
		t.Fatalf("pending transactions got %d, want 1", got)
	}
	for _, tx := range ue.PendingBearerTransactions {
		if tx.Kind != bearerTxLocalUpdate {
			t.Fatalf("transaction kind got %q, want %q", tx.Kind, bearerTxLocalUpdate)
		}
		if proc := tx.Bearers[9]; proc == nil || hex.EncodeToString(proc.TFT) != "05a4202112135824" {
			t.Fatalf("pending TFT got %+v, want 05a4202112135824", proc)
		}
	}
}

func TestProcessESM_BearerResourceModificationAcceptUpdatesBearer(t *testing.T) {
	srv := newTAUTestServer()
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.DedicatedBearers[9] = &uecontext.DedicatedBearerContext{
		AssignedEBI: 9,
		LinkedEBI:   6,
		PTI:         1,
		QCI:         5,
		BearerQoS:   []byte{0x44, 0x05, 0x00, 0x00, 0x00},
		TFT:         []byte{0x05, 0xa4, 0x00, 0x01},
		State:       "active",
	}
	ue.PendingBearerTransactions["brm|1|9|2"] = &uecontext.DedicatedBearerTransaction{
		ID:   "brm-1-09-02",
		Kind: bearerTxLocalUpdate,
		Bearers: map[uint8]*uecontext.DedicatedBearerContext{
			9: {
				AssignedEBI: 9,
				LinkedEBI:   6,
				PTI:         2,
				QCI:         5,
				BearerQoS:   []byte{0x44, 0x05, 0x00, 0x00, 0x00},
				TFT:         []byte{0x05, 0xa4, 0x20, 0x21, 0x12, 0x13, 0x58, 0x24},
				State:       "active",
			},
		},
	}
	ue.Unlock()

	result := &nas.DecodeResult{Plain: []byte{0x92, 0x02, esm.MsgModifyEPSBearerContextAccept}}
	if err := srv.processESM(ue, result, zap.NewNop()); err != nil {
		t.Fatalf("processESM: %v", err)
	}

	ue.Lock()
	defer ue.Unlock()
	if got := len(ue.PendingBearerTransactions); got != 0 {
		t.Fatalf("pending transactions got %d, want 0", got)
	}
	if got := hex.EncodeToString(ue.DedicatedBearers[9].TFT); got != "05a4202112135824" {
		t.Fatalf("active bearer TFT got %s, want %s", got, "05a4202112135824")
	}
}

func TestProcessESM_PDNDisconnectDeactivateAcceptAdvancesState(t *testing.T) {
	srv := newTAUTestServer()
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.PDNs = map[string]*uecontext.PDNContext{
		"ims": {
			APN:                   "ims",
			DefaultEBI:            6,
			SGWAddress:            "10.90.250.59:2123",
			SGWC_TEID:             0x06f718d5,
			DisconnectPTI:         3,
			DisconnectRequested:   true,
			State:                 "pdn-disconnect-deactivate-sent",
			DisconnectNASAccepted: false,
		},
	}
	ue.Unlock()

	result := &nas.DecodeResult{
		Plain: []byte{
			0x62, 0x03, esm.MsgDeactivateEPSBearerContextAccept,
		},
	}
	if err := srv.processESM(ue, result, zap.NewNop()); err != nil {
		t.Fatalf("processESM: %v", err)
	}

	ue.Lock()
	defer ue.Unlock()
	pdn := ue.PDNs["ims"]
	if !pdn.DisconnectNASAccepted {
		t.Fatal("DisconnectNASAccepted=false, want true")
	}
	if pdn.State != "pdn-disconnect-delete-session-pending" {
		t.Fatalf("state got %q, want pdn-disconnect-delete-session-pending", pdn.State)
	}
}

func TestProcessESM_PDNDisconnectDeactivateAcceptMatchesZeroPTI(t *testing.T) {
	mock := &mockS11{}
	srv := newTestServer(mock)
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.PDNs = map[string]*uecontext.PDNContext{
		"ims": {
			APN:                   "ims",
			DefaultEBI:            6,
			SGWAddress:            "10.90.250.59:2123",
			SGWC_TEID:             0x06f718d5,
			DisconnectPTI:         2,
			DisconnectRequested:   true,
			State:                 "pdn-disconnect-deactivate-sent",
			DisconnectNASAccepted: false,
		},
	}
	ue.Unlock()

	result := &nas.DecodeResult{Plain: []byte{0x62, 0x00, esm.MsgDeactivateEPSBearerContextAccept}}
	if err := srv.processESM(ue, result, zap.NewNop()); err != nil {
		t.Fatalf("processESM: %v", err)
	}
	if len(mock.dsrCalls) != 1 {
		t.Fatalf("DSR calls got %d, want 1", len(mock.dsrCalls))
	}
	if got := mock.dsrCalls[0].EBI; got != 6 {
		t.Fatalf("DSR EBI got %d, want 6", got)
	}

	ue.Lock()
	defer ue.Unlock()
	pdn := ue.PDNs["ims"]
	if pdn == nil {
		t.Fatal("IMS PDN context missing")
	}
	if !pdn.DisconnectNASAccepted {
		t.Fatal("DisconnectNASAccepted=false, want true")
	}
	if pdn.State != "pdn-disconnect-delete-session-pending" {
		t.Fatalf("state got %q, want pdn-disconnect-delete-session-pending", pdn.State)
	}
}

func TestProcessESM_PDNDisconnectDeactivateAcceptSendsDSRWithoutDedicatedBearers(t *testing.T) {
	mock := &mockS11{}
	srv := newTestServer(mock)
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070570"
	ue.PDNs = map[string]*uecontext.PDNContext{
		"ims": {
			APN:                   "ims",
			DefaultEBI:            6,
			SGWAddress:            "10.90.250.59:2123",
			SGWC_TEID:             0x06f718d5,
			DisconnectPTI:         3,
			DisconnectRequested:   true,
			DisconnectNASAccepted: false,
			State:                 "pdn-disconnect-deactivate-sent",
		},
	}
	ue.Unlock()

	result := &nas.DecodeResult{Plain: []byte{0x62, 0x03, esm.MsgDeactivateEPSBearerContextAccept}}
	if err := srv.processESM(ue, result, zap.NewNop()); err != nil {
		t.Fatalf("processESM: %v", err)
	}
	if len(mock.dsrCalls) != 1 {
		t.Fatalf("DSR calls got %d, want 1", len(mock.dsrCalls))
	}
	if got := mock.dsrCalls[0].EBI; got != 6 {
		t.Fatalf("DSR EBI got %d, want 6", got)
	}
	ue.Lock()
	defer ue.Unlock()
	if pdn := ue.PDNs["ims"]; pdn == nil || pdn.State != "pdn-disconnect-delete-session-pending" {
		t.Fatalf("IMS PDN state got %+v, want pdn-disconnect-delete-session-pending", pdn)
	}
}

func TestProcessESM_PDNDisconnectDeactivateAcceptReleasesDedicatedBearersBeforeDSR(t *testing.T) {
	mock := &mockS11{}
	srv := newTestServer(mock)
	const remoteAddr = "10.0.0.22:36412"
	ch := registerTestENBWithChan(srv, remoteAddr)
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070572"
	ue.ENBGlobalID = remoteAddr
	ue.ENBS1APID = 222
	ue.ECMState = emm.ECMConnected
	ue.S1BindingState = uecontext.S1BindingActive
	ue.S1BindingGeneration = 2
	ue.PDNs = map[string]*uecontext.PDNContext{
		"ims": {
			APN:                   "ims",
			DefaultEBI:            6,
			SGWAddress:            "10.90.250.59:2123",
			SGWC_TEID:             0x06f718d5,
			DisconnectPTI:         3,
			DisconnectRequested:   true,
			DisconnectNASAccepted: false,
			State:                 "pdn-disconnect-deactivate-sent",
		},
	}
	ue.DedicatedBearers[9] = &uecontext.DedicatedBearerContext{AssignedEBI: 9, LinkedEBI: 6, ERABEstablished: true, ENBS1UTEID: 0x9001}
	ue.DedicatedBearers[10] = &uecontext.DedicatedBearerContext{AssignedEBI: 10, LinkedEBI: 6, ERABEstablished: true, ENBS1UTEID: 0x9002}
	mmeUEID := ue.MMEUES1APID
	enbUEID := ue.ENBS1APID
	ue.Unlock()

	result := &nas.DecodeResult{Plain: []byte{0x62, 0x03, esm.MsgDeactivateEPSBearerContextAccept}}
	if err := srv.processESM(ue, result, zap.NewNop()); err != nil {
		t.Fatalf("processESM: %v", err)
	}
	if len(mock.dsrCalls) != 0 {
		t.Fatalf("DSR calls before release response got %d, want 0", len(mock.dsrCalls))
	}

	raw := <-ch
	msg, err := pdu.Decode(raw)
	if err != nil {
		t.Fatalf("decode release request: %v", err)
	}
	if msg.ProcedureCode != pdu.ProcERABRelease {
		t.Fatalf("procedure code got %d, want %d", msg.ProcedureCode, pdu.ProcERABRelease)
	}

	respRaw := pdu.BuildSuccessfulOutcome(pdu.ProcERABRelease, aper.CriticalityIgnore, []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeMMEUEApID(mmeUEID)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeENBUEApID(enbUEID)},
		{ID: pdu.IEERABReleaseListERABRelComp, Criticality: aper.CriticalityIgnore, Value: encodeERABReleaseResponseListForTest([]uint8{9, 10})},
	})
	srv.handleMessage(remoteAddr, respRaw)

	if len(mock.dsrCalls) != 1 {
		t.Fatalf("DSR calls after release response got %d, want 1", len(mock.dsrCalls))
	}
	ue.Lock()
	defer ue.Unlock()
	if _, ok := ue.DedicatedBearers[9]; ok {
		t.Fatal("dedicated bearer 9 still present")
	}
	if _, ok := ue.DedicatedBearers[10]; ok {
		t.Fatal("dedicated bearer 10 still present")
	}
	if pdn := ue.PDNs["ims"]; pdn == nil || pdn.State != "pdn-disconnect-delete-session-pending" {
		t.Fatalf("IMS PDN state got %+v, want pdn-disconnect-delete-session-pending", pdn)
	}
}

func TestHandleDSRResultRemovesDisconnectedPDNButKeepsUE(t *testing.T) {
	srv := newTestServer(&mockS11{})
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070570"
	ue.EMMState = emm.StateRegistered
	ue.PDNs = map[string]*uecontext.PDNContext{
		"internet": {
			APN:        "internet",
			DefaultEBI: 5,
			State:      "active",
		},
		"ims": {
			APN:        "ims",
			DefaultEBI: 6,
			State:      "pdn-disconnect-delete-session-pending",
		},
	}
	ue.DedicatedBearers[9] = &uecontext.DedicatedBearerContext{AssignedEBI: 9, LinkedEBI: 6}
	mmeUEID := ue.MMEUES1APID
	ue.Unlock()

	srv.HandleDSRResult(mmeUEID, 6, nil)

	remaining, ok := srv.ueManager.GetByMMEID(mmeUEID)
	if !ok || remaining == nil {
		t.Fatal("UE was removed, want retained")
	}
	remaining.Lock()
	defer remaining.Unlock()
	if _, ok := remaining.PDNs["ims"]; ok {
		t.Fatal("IMS PDN still present after DSRsp")
	}
	if _, ok := remaining.PDNs["internet"]; !ok {
		t.Fatal("internet PDN unexpectedly removed")
	}
	if _, ok := remaining.DedicatedBearers[9]; ok {
		t.Fatal("linked dedicated bearer still present after IMS DSRsp")
	}
}

func TestLinkedBearerReadyFalseWhilePDNDisconnectPending(t *testing.T) {
	srv := newTestServer(&mockS11{})
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.PDNs = map[string]*uecontext.PDNContext{
		"ims": {
			APN:                   "ims",
			DefaultEBI:            6,
			NASAccepted:           true,
			ERABEstablished:       true,
			ModifyBearerAccepted:  true,
			DisconnectRequested:   true,
			DisconnectNASAccepted: true,
			State:                 "pdn-disconnect-delete-session-pending",
		},
	}
	ready := linkedBearerReadyLocked(ue, 6)
	active := linkedBearerActiveLocked(ue, 6)
	ue.Unlock()
	if ready {
		t.Fatal("linkedBearerReadyLocked=true, want false during PDN disconnect")
	}
	if active {
		t.Fatal("linkedBearerActiveLocked=true, want false during PDN disconnect")
	}
}

func TestProcessESM_ESMStatusLogsCauseName(t *testing.T) {
	srv := newTAUTestServer()
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070572"
	ue.LastDownlinkNASMessage = "Activate Dedicated EPS Bearer Context Request"
	ue.Unlock()

	result := &nas.DecodeResult{
		SecHeaderType: 2,
		Count:         5,
		Sequence:      5,
		MAC:           []byte{0xb1, 0xd2, 0x67, 0xd7},
		Plain:         []byte{0x72, 0x03, esm.MsgESMStatus, 0x62},
		MsgType:       esm.MsgESMStatus,
	}

	if err := srv.processESM(ue, result, zap.NewNop()); err != nil {
		t.Fatalf("processESM: %v", err)
	}
}

func TestProcessESM_PDNConnectivityRequestAllocatesDefaultBearerAroundDedicatedBearers(t *testing.T) {
	mock := &capturingCSRS11{}
	srv := newTestServer(mock)
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070572"
	ue.APN = "internet"
	ue.DefaultEBI = 5
	ue.SubscriberAPNs = []string{"ims", "mms"}
	ue.SubscriberAPNConfigs = map[string]uecontext.SubscriberAPNConfig{
		"ims": {
			ServiceSelection: "ims",
			PDNType:          gtpv2.PDNTypeIPv4,
			QCI:              5,
			ARPPriority:      8,
			APNAMBRUp:        384,
			APNAMBRDown:      512,
		},
		"mms": {
			ServiceSelection: "mms",
			PDNType:          gtpv2.PDNTypeIPv4,
			QCI:              9,
			ARPPriority:      8,
			APNAMBRUp:        384,
			APNAMBRDown:      512,
		},
	}
	ue.PDNs = map[string]*uecontext.PDNContext{
		"internet": {
			APN:        "internet",
			DefaultEBI: 5,
		},
		"ims": {
			APN:        "ims",
			DefaultEBI: 6,
		},
	}
	ue.DedicatedBearers[7] = &uecontext.DedicatedBearerContext{AssignedEBI: 7, LinkedEBI: 6, State: "active"}
	ue.DedicatedBearers[8] = &uecontext.DedicatedBearerContext{AssignedEBI: 8, LinkedEBI: 6, State: "active"}
	ue.Unlock()

	result := &nas.DecodeResult{
		Plain: []byte{
			0x02, 0x09, esm.MsgPDNConnectivityRequest, 0x31,
			0x28, 0x04, 0x03, 'm', 'm', 's',
		},
	}
	if err := srv.processESM(ue, result, zap.NewNop()); err != nil {
		t.Fatalf("processESM: %v", err)
	}
	if len(mock.csrCalls) != 1 {
		t.Fatalf("CSR calls got %d, want 1", len(mock.csrCalls))
	}
	if got, want := mock.csrCalls[0].DefaultEBI, uint8(9); got != want {
		t.Fatalf("allocated default EBI got %d, want %d", got, want)
	}
}

func TestProcessESM_PDNConnectivityRequestAlreadyActiveSendsReject(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "10.0.0.24:36412"
	ch := setupSendCapture(srv, remoteAddr)

	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070572"
	ue.ENBGlobalID = remoteAddr
	ue.ENBS1APID = 224
	ue.KNASint = make([]byte, 16)
	ue.KNASenc = make([]byte, 16)
	ue.IntAlg = 0
	ue.EncAlg = 0
	ue.ECMState = emm.ECMConnected
	ue.SubscriberAPNs = []string{"ims"}
	ue.SubscriberAPNConfigs = map[string]uecontext.SubscriberAPNConfig{
		"ims": {ServiceSelection: "ims"},
	}
	ue.PDNs = map[string]*uecontext.PDNContext{
		"ims": {
			APN:        "ims",
			DefaultEBI: 6,
			State:      "active",
		},
	}
	ue.Unlock()

	result := &nas.DecodeResult{
		Plain: []byte{
			0x02, 0x01, esm.MsgPDNConnectivityRequest, 0x31,
			0x28, 0x04, 0x03, 'i', 'm', 's',
		},
	}
	if err := srv.processESM(ue, result, zap.NewNop()); err != nil {
		t.Fatalf("processESM: %v", err)
	}

	var raw []byte
	select {
	case raw = <-ch:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no Downlink NAS reject sent")
	}
	gotNAS := decodeDownlinkNASFromRawPDU(t, raw)
	plain := gotNAS[6:]
	if got, want := plain[2], esm.MsgPDNConnectivityReject; got != want {
		t.Fatalf("reject msg type got %#x, want %#x", got, want)
	}
	if got, want := plain[3], esm.ESMCauseRequestRejectedUnspecified; got != want {
		t.Fatalf("reject cause got %#x, want %#x", got, want)
	}

	ue.Lock()
	defer ue.Unlock()
	if ue.PendingPDN != nil {
		t.Fatalf("PendingPDN got %+v, want nil", ue.PendingPDN)
	}
}

func TestProcessESM_PDNConnectivityRequestUsesSubscribedQoSAndAMBR(t *testing.T) {
	mock := &capturingCSRS11{}
	srv := newTestServer(mock)
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070572"
	ue.APN = "internet"
	ue.SubscriberAPNs = []string{"ims"}
	ue.SubscriberAPNConfigs = map[string]uecontext.SubscriberAPNConfig{
		"ims": {
			ServiceSelection:        "ims",
			PDNType:                 gtpv2.PDNTypeIPv4,
			QCI:                     1,
			ARPPriority:             4,
			PreemptionCapability:    true,
			PreemptionVulnerability: false,
			APNAMBRUp:               384,
			APNAMBRDown:             512,
		},
	}
	ue.Unlock()

	result := &nas.DecodeResult{
		Plain: []byte{
			0x02, 0x01, esm.MsgPDNConnectivityRequest, 0x31,
			0x28, 0x04, 0x03, 'i', 'm', 's',
		},
	}
	if err := srv.processESM(ue, result, zap.NewNop()); err != nil {
		t.Fatalf("processESM: %v", err)
	}
	if len(mock.csrCalls) != 1 {
		t.Fatalf("CSR calls got %d, want 1", len(mock.csrCalls))
	}
	csr := mock.csrCalls[0]
	if got, want := csr.PDNType, uint8(gtpv2.PDNTypeIPv4); got != want {
		t.Fatalf("PDN type got %d, want %d", got, want)
	}
	if got, want := csr.BearerQCI, uint8(1); got != want {
		t.Fatalf("BearerQCI got %d, want %d", got, want)
	}
	if got, want := csr.BearerPriorityLevel, uint8(4); got != want {
		t.Fatalf("BearerPriorityLevel got %d, want %d", got, want)
	}
	if got, want := csr.PreemptionCapability, true; got != want {
		t.Fatalf("PreemptionCapability got %t, want %t", got, want)
	}
	if got, want := csr.PreemptionVulnerability, false; got != want {
		t.Fatalf("PreemptionVulnerability got %t, want %t", got, want)
	}
	if got, want := csr.UplinkAMBRKbps, uint32(384); got != want {
		t.Fatalf("UplinkAMBRKbps got %d, want %d", got, want)
	}
	if got, want := csr.DownlinkAMBRKbps, uint32(512); got != want {
		t.Fatalf("DownlinkAMBRKbps got %d, want %d", got, want)
	}
}

func TestHandlePendingPDNCSRResult_UsesPDNQoSForERABSetup(t *testing.T) {
	srv := newTestServer(&mockS11{})
	srv.enbTracker = peertracker.New()
	const remoteAddr = "10.0.0.25:36412"
	ch := registerTestENBWithChan(srv, remoteAddr)

	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070572"
	ue.ENBGlobalID = remoteAddr
	ue.ENBS1APID = 225
	ue.ECMState = emm.ECMConnected
	ue.UEAMBRDown = 100000000
	ue.UEAMBRUp = 100000000
	ue.KNASint = make([]byte, 16)
	ue.KNASenc = make([]byte, 16)
	ue.IntAlg = 0
	ue.EncAlg = 0
	ue.PendingPDN = &uecontext.PDNContext{
		APN:                     "mms",
		ProcedureTransactionID:  5,
		PDNType:                 gtpv2.PDNTypeIPv4,
		DefaultEBI:              9,
		QCI:                     8,
		ARPPriority:             8,
		PreemptionCapability:    false,
		PreemptionVulnerability: false,
		State:                   "csr-sent",
	}
	ue.Unlock()

	resp := &gtpv2.CreateSessionResponse{
		Cause:     gtpv2.CauseRequestAccepted,
		EBI:       9,
		SGWC_TEID: 0xa8495b5e,
		SGWC_IP:   []byte{10, 90, 250, 59},
		SGWU_TEID: 0x1c455a86,
		SGWU_IP:   []byte{10, 90, 250, 59},
		UEIPv4:    []byte{10, 150, 6, 93},
	}

	srv.handlePendingPDNCSRResult(ue, resp, nil, zap.NewNop())

	var raw []byte
	select {
	case raw = <-ch:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no S1AP message sent")
	}

	req := decodeERABSetupRequest(t, raw)
	if len(req.Items) != 1 {
		t.Fatalf("E-RAB item count got %d, want 1", len(req.Items))
	}
	item := req.Items[0]
	if got, want := item.EBI, uint8(9); got != want {
		t.Fatalf("E-RAB ID got %d, want %d", got, want)
	}
	if got, want := item.QCI, uint8(8); got != want {
		t.Fatalf("QCI got %d, want %d", got, want)
	}
	if got, want := item.ARPPriority, uint8(8); got != want {
		t.Fatalf("ARP priority got %d, want %d", got, want)
	}
	if got, want := item.PreemptionCapability, false; got != want {
		t.Fatalf("PreemptionCapability got %t, want %t", got, want)
	}
	if got, want := item.PreemptionVulnerability, false; got != want {
		t.Fatalf("PreemptionVulnerability got %t, want %t", got, want)
	}
}

func TestProcessESM_PDNConnectivityRequestMatchesAPNCaseInsensitively(t *testing.T) {
	mock := &capturingCSRS11{}
	srv := newTestServer(mock)
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070573"
	ue.APN = "internet"
	ue.SubscriberAPNs = []string{"ims"}
	ue.SubscriberAPNConfigs = map[string]uecontext.SubscriberAPNConfig{
		"ims": {
			ServiceSelection: "ims",
			PDNType:          gtpv2.PDNTypeIPv4,
			QCI:              5,
			ARPPriority:      8,
			APNAMBRUp:        384,
			APNAMBRDown:      512,
		},
	}
	ue.Unlock()

	result := &nas.DecodeResult{
		Plain: []byte{
			0x02, 0x01, esm.MsgPDNConnectivityRequest, 0x31,
			0x28, 0x04, 0x03, 'I', 'M', 'S',
		},
	}
	if err := srv.processESM(ue, result, zap.NewNop()); err != nil {
		t.Fatalf("processESM: %v", err)
	}
	if len(mock.csrCalls) != 1 {
		t.Fatalf("CSR calls got %d, want 1", len(mock.csrCalls))
	}
	if got, want := mock.csrCalls[0].APN, "ims"; got != want {
		t.Fatalf("CSR APN got %q, want %q", got, want)
	}
}
