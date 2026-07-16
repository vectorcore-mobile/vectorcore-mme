package s1ap

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/gtpv2"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/esm"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"github.com/vectorcore/mme/internal/uecontext"
)

type bearerResponderMock struct {
	mockS11
	mu              sync.Mutex
	createResponses []createBearerResponseCall
	updateResponses []updateBearerResponseCall
	deleteResponses []deleteBearerResponseCall
}

type createBearerResponseCall struct {
	Peer    string
	TEID    uint32
	Seq     uint32
	Cause   uint8
	Bearers []gtpv2.CreateBearerBearer
	Meta    *gtpv2.CreateBearerResponseMeta
}

type updateBearerResponseCall struct {
	Peer    string
	TEID    uint32
	Seq     uint32
	Cause   uint8
	Bearers []gtpv2.UpdateBearerBearer
	Meta    *gtpv2.UpdateBearerResponseMeta
}

type deleteBearerResponseCall struct {
	Peer  string
	TEID  uint32
	Seq   uint32
	Cause uint8
	EBIs  []uint8
	Meta  *gtpv2.DeleteBearerResponseMeta
}

func (m *bearerResponderMock) SendCreateBearerResponse(peer string, teid uint32, seq uint32, cause uint8, bearers []gtpv2.CreateBearerBearer, meta *gtpv2.CreateBearerResponseMeta) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createResponses = append(m.createResponses, createBearerResponseCall{
		Peer: peer, TEID: teid, Seq: seq, Cause: cause, Bearers: append([]gtpv2.CreateBearerBearer(nil), bearers...), Meta: meta,
	})
	return nil
}

func (m *bearerResponderMock) createResponseCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.createResponses)
}

func (m *bearerResponderMock) createResponseAt(i int) createBearerResponseCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.createResponses[i]
}

func (m *bearerResponderMock) createResponsesSnapshot() []createBearerResponseCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]createBearerResponseCall(nil), m.createResponses...)
}

func (m *bearerResponderMock) SendUpdateBearerResponse(peer string, teid uint32, seq uint32, cause uint8, bearers []gtpv2.UpdateBearerBearer, meta *gtpv2.UpdateBearerResponseMeta) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updateResponses = append(m.updateResponses, updateBearerResponseCall{
		Peer: peer, TEID: teid, Seq: seq, Cause: cause, Bearers: append([]gtpv2.UpdateBearerBearer(nil), bearers...), Meta: meta,
	})
	return nil
}

func (m *bearerResponderMock) SendDeleteBearerResponse(peer string, teid uint32, seq uint32, cause uint8, ebis []uint8, meta *gtpv2.DeleteBearerResponseMeta) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteResponses = append(m.deleteResponses, deleteBearerResponseCall{
		Peer: peer, TEID: teid, Seq: seq, Cause: cause, EBIs: append([]uint8(nil), ebis...), Meta: meta,
	})
	return nil
}

func waitForCreateResponseCount(t *testing.T, mock *bearerResponderMock, want int) {
	t.Helper()
	deadline := time.After(250 * time.Millisecond)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if got := mock.createResponseCount(); got == want {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("Create Bearer responses got %d, want %d", mock.createResponseCount(), want)
		case <-ticker.C:
		}
	}
}

func waitForUpdateResponseCount(t *testing.T, mock *bearerResponderMock, want int) {
	t.Helper()
	deadline := time.After(250 * time.Millisecond)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		mock.mu.Lock()
		got := len(mock.updateResponses)
		mock.mu.Unlock()
		if got == want {
			return
		}
		select {
		case <-deadline:
			mock.mu.Lock()
			got = len(mock.updateResponses)
			mock.mu.Unlock()
			t.Fatalf("Update Bearer responses got %d, want %d", got, want)
		case <-ticker.C:
		}
	}
}

func (m *bearerResponderMock) updateResponseAt(i int) updateBearerResponseCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.updateResponses[i]
}

func waitForDeleteResponseCount(t *testing.T, mock *bearerResponderMock, want int) {
	t.Helper()
	deadline := time.After(250 * time.Millisecond)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		mock.mu.Lock()
		got := len(mock.deleteResponses)
		mock.mu.Unlock()
		if got == want {
			return
		}
		select {
		case <-deadline:
			mock.mu.Lock()
			got = len(mock.deleteResponses)
			mock.mu.Unlock()
			t.Fatalf("Delete Bearer responses got %d, want %d", got, want)
		case <-ticker.C:
		}
	}
}

func (m *bearerResponderMock) deleteResponseCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.deleteResponses)
}

func (m *bearerResponderMock) deleteResponseAt(i int) deleteBearerResponseCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.deleteResponses[i]
}

func waitForPDU(t *testing.T, ch <-chan []byte, name string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(250 * time.Millisecond):
		t.Fatalf("expected %s", name)
	}
}

func singlePendingCreateKey(t *testing.T, ue *uecontext.Context) string {
	t.Helper()
	ue.Lock()
	defer ue.Unlock()
	if len(ue.PendingBearerTransactions) != 1 {
		t.Fatalf("pending transactions got %d, want 1", len(ue.PendingBearerTransactions))
	}
	for key := range ue.PendingBearerTransactions {
		return key
	}
	t.Fatal("pending transaction missing")
	return ""
}

func makeIdleDedicatedBearerUE(t *testing.T, srv *Server, enbAddr string) (*uecontext.Context, chan []byte) {
	t.Helper()
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070572"
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMIdle
	ue.S1BindingState = uecontext.S1BindingReleased
	ue.DefaultEBI = 5
	ue.LocalS11TEID = 0x0f
	ue.KNASint = make([]byte, 16)
	ue.KNASenc = make([]byte, 16)
	ue.IntAlg = 0
	ue.EncAlg = 0
	ue.KASME = make([]byte, 32)
	ue.PDNs["ims"] = &uecontext.PDNContext{
		APN:                  "ims",
		DefaultEBI:           6,
		LocalS11TEID:         0x0f,
		NASAccepted:          true,
		ERABEstablished:      true,
		ModifyBearerAccepted: true,
		State:                "active",
	}
	ue.Unlock()
	srv.ueManager.Register(ue)
	ch := registerTestENBWithChan(srv, enbAddr)
	return ue, ch
}

func TestHandleCreateBearerRequestMatchesPendingLinkedBearer(t *testing.T) {
	mock := &bearerResponderMock{}
	srv := newTestServer(mock)

	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070573"
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMConnected
	ue.S1BindingState = uecontext.S1BindingActive
	ue.ENBGlobalID = "192.168.105.247:36422"
	ue.ENBS1APID = 262258
	ue.MMEUES1APID = 1
	ue.KNASint = make([]byte, 16)
	ue.KNASenc = make([]byte, 16)
	ue.IntAlg = 0
	ue.EncAlg = 0
	ue.KASME = make([]byte, 32)
	ue.PendingPDN = &uecontext.PDNContext{
		APN:          "ims",
		DefaultEBI:   6,
		LocalS11TEID: 2,
		SGWU_TEID:    0x11111111,
		SGWU_IP:      net.IPv4(10, 90, 250, 59),
		State:        "csr-sent",
	}
	ue.Unlock()

	req := &gtpv2.CreateBearerRequest{
		TEID:      2,
		SeqNum:    371,
		LinkedEBI: 6,
		Bearers: []gtpv2.CreateBearerBearer{
			{
				QCI:        1,
				SGWS1UTEID: 0x22222222,
				SGWS1UIP:   net.IPv4(10, 90, 250, 59),
				BearerQoS: []byte{
					0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x80,
					0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
					0x80, 0x00, 0x00, 0x00, 0x00, 0x80,
				},
				TFT: []byte{0x21, 0x30, 0x30, 0x0b, 0x10, 0x0a, 0x96, 0x03, 0xf1, 0xff, 0xff, 0xff, 0x30, 0x11},
			},
		},
	}

	srv.HandleCreateBearerRequest("10.90.250.59:2123", req)

	ue.Lock()
	defer ue.Unlock()
	if len(ue.PendingBearerTransactions) != 1 {
		t.Fatalf("pending transactions got %d, want 1", len(ue.PendingBearerTransactions))
	}
	if mock.createResponseCount() != 0 {
		t.Fatalf("create bearer responses got %d, want 0", mock.createResponseCount())
	}
}

func sonimStormCreateBearer(seq uint32, teid1 uint32, teid2 uint32) *gtpv2.CreateBearerRequest {
	return &gtpv2.CreateBearerRequest{
		TEID:      0x0f,
		SeqNum:    seq,
		LinkedEBI: 6,
		Bearers: []gtpv2.CreateBearerBearer{
			{
				RequestedEBI:       0,
				NeedsEBIAllocation: true,
				QCI:                2,
				ARP:                0x10,
				TFT:                []byte{0x21, 0x30, 0x30, 0x0b, 0x10, 0x0a, 0x96, 0x03, 0x8a, 0xff, 0xff, 0xff, 0xff, 0x30, 0x11},
				SGWS1UTEID:         teid1,
				SGWS1UIP:           net.ParseIP("10.90.250.59").To4(),
			},
			{
				RequestedEBI:       0,
				NeedsEBIAllocation: true,
				QCI:                1,
				ARP:                0x08,
				TFT:                []byte{0x21, 0x30, 0x35, 0x0b, 0x10, 0x0a, 0x96, 0x03, 0x8a, 0xff, 0xff, 0xff, 0xff, 0x30, 0x11},
				SGWS1UTEID:         teid2,
				SGWS1UIP:           net.ParseIP("10.90.250.59").To4(),
			},
		},
	}
}

func TestCreateBearerForECMIdleUETriggersPaging(t *testing.T) {
	mock := &bearerResponderMock{}
	srv := newTestServer(mock)
	ue, _ := makeIdleDedicatedBearerUE(t, srv, "10.0.0.1:36412")

	srv.HandleCreateBearerRequest("10.90.250.59:2123", sonimStormCreateBearer(2753, 0x11111111, 0x22222222))

	ue.Lock()
	attempts := ue.PagingAttempts
	pending := len(ue.PendingBearerTransactions)
	reservations := len(ue.EBIReservations)
	ue.Unlock()
	if attempts != 1 {
		t.Fatalf("PagingAttempts got %d, want 1", attempts)
	}
	if pending != 1 {
		t.Fatalf("pending transactions got %d, want 1", pending)
	}
	if reservations != 2 {
		t.Fatalf("EBI reservations got %d, want 2", reservations)
	}
	if mock.createResponseCount() != 0 {
		t.Fatalf("Create Bearer response sent immediately: %+v", mock.createResponsesSnapshot())
	}
}

func TestCreateBearerUsesZeroPTIForDedicatedBearers(t *testing.T) {
	mock := &bearerResponderMock{}
	srv := newTestServer(mock)
	ue, _ := makeIdleDedicatedBearerUE(t, srv, "10.0.0.11:36412")

	srv.HandleCreateBearerRequest("10.90.250.59:2123", sonimStormCreateBearer(2753, 0x11111111, 0x22222222))

	ue.Lock()
	defer ue.Unlock()
	if len(ue.PendingBearerTransactions) != 1 {
		t.Fatalf("pending transactions got %d, want 1", len(ue.PendingBearerTransactions))
	}
	for _, tx := range ue.PendingBearerTransactions {
		for _, proc := range tx.Bearers {
			if proc == nil {
				continue
			}
			if proc.PTI != 0 {
				t.Fatalf("dedicated bearer PTI got %d, want 0", proc.PTI)
			}
		}
	}
}

func TestEquivalentCreateBearerWhilePagingDoesNotAllocateMoreEBIs(t *testing.T) {
	mock := &bearerResponderMock{}
	srv := newTestServer(mock)
	ue, _ := makeIdleDedicatedBearerUE(t, srv, "10.0.0.2:36412")

	srv.HandleCreateBearerRequest("10.90.250.59:2123", sonimStormCreateBearer(2753, 0x11111111, 0x22222222))
	srv.HandleCreateBearerRequest("10.90.250.59:2123", sonimStormCreateBearer(2754, 0x33333333, 0x44444444))

	ue.Lock()
	pending := len(ue.PendingBearerTransactions)
	reservations := len(ue.EBIReservations)
	attempts := ue.PagingAttempts
	var seq uint32
	var ebis []uint8
	for _, tx := range ue.PendingBearerTransactions {
		seq = tx.SequenceNum
		ebis = append(ebis, tx.EBIs...)
	}
	ue.Unlock()
	if pending != 1 {
		t.Fatalf("pending transactions got %d, want 1", pending)
	}
	if reservations != 2 {
		t.Fatalf("EBI reservations got %d, want 2", reservations)
	}
	if attempts != 1 {
		t.Fatalf("PagingAttempts got %d, want 1", attempts)
	}
	if seq != 2754 {
		t.Fatalf("collapsed transaction seq got %d, want latest 2754", seq)
	}
	if len(ebis) != 2 || ebis[0] != 7 || ebis[1] != 8 {
		t.Fatalf("reserved EBIs got %v, want [7 8]", ebis)
	}
}

func TestPendingCreateBearerResumesAfterS1BindingRestored(t *testing.T) {
	mock := &bearerResponderMock{}
	srv := newTestServer(mock)
	enbAddr := "10.0.0.3:36412"
	ue, ch := makeIdleDedicatedBearerUE(t, srv, enbAddr)

	srv.HandleCreateBearerRequest("10.90.250.59:2123", sonimStormCreateBearer(2753, 0x11111111, 0x22222222))
	ue.Lock()
	ue.ECMState = emm.ECMConnected
	ue.S1BindingState = uecontext.S1BindingActive
	ue.ENBGlobalID = enbAddr
	ue.ENBS1APID = 77
	ue.Unlock()

	srv.ResumePendingNetworkBearerProcedures(ue)

	select {
	case <-ch: // paging PDU
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected paging PDU")
	}
	select {
	case <-ch: // E-RAB Setup Request
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected E-RAB Setup PDU after resume")
	}
	if mock.createResponseCount() != 0 {
		t.Fatalf("Create Bearer response sent before NAS/E-RAB completion: %+v", mock.createResponsesSnapshot())
	}
	ue.Lock()
	defer ue.Unlock()
	for _, tx := range ue.PendingBearerTransactions {
		if tx.CreateState != uecontext.CreateBearerWaitingResults {
			t.Fatalf("transaction state got %s, want waiting_results", tx.CreateState)
		}
		return
	}
	t.Fatal("pending transaction missing after resume")
}

func TestPendingCreateBearerCompletesAfterNASAndERAB(t *testing.T) {
	mock := &bearerResponderMock{}
	srv := newTestServer(mock)
	enbAddr := "10.0.0.4:36412"
	ue, ch := makeIdleDedicatedBearerUE(t, srv, enbAddr)

	srv.HandleCreateBearerRequest("10.90.250.59:2123", sonimStormCreateBearer(2753, 0x11111111, 0x22222222))
	ue.Lock()
	ue.ECMState = emm.ECMConnected
	ue.S1BindingState = uecontext.S1BindingActive
	ue.ENBGlobalID = enbAddr
	ue.ENBS1APID = 77
	ue.Unlock()
	srv.ResumePendingNetworkBearerProcedures(ue)
	waitForPDU(t, ch, "paging PDU")
	waitForPDU(t, ch, "E-RAB Setup Request")

	srv.completeDedicatedERABSetupForBearer(ue, ERABSetupResult{
		EBI:        7,
		Success:    true,
		ENBS1UIPv4: net.ParseIP("192.168.105.247").To4(),
		ENBS1UTEID: 0x77770001,
	}, srv.log)
	srv.handleDedicatedBearerNASResponse(ue, &esm.BearerProcedureResponse{
		EPSBearerID: 7,
		MessageType: esm.MsgActivateDedicatedEPSBearerContextAccept,
	}, srv.log)
	srv.handleDedicatedBearerNASResponse(ue, &esm.BearerProcedureResponse{
		EPSBearerID: 8,
		MessageType: esm.MsgActivateDedicatedEPSBearerContextAccept,
	}, srv.log)
	if mock.createResponseCount() != 0 {
		t.Fatalf("response sent before all E-RAB results: %+v", mock.createResponsesSnapshot())
	}
	srv.completeDedicatedERABSetupForBearer(ue, ERABSetupResult{
		EBI:        8,
		Success:    true,
		ENBS1UIPv4: net.ParseIP("192.168.105.247").To4(),
		ENBS1UTEID: 0x77770002,
	}, srv.log)

	waitForCreateResponseCount(t, mock, 1)
	resp := mock.createResponseAt(0)
	if resp.Seq != 2753 || resp.Cause != gtpv2.CauseRequestAccepted {
		t.Fatalf("response got seq=%d cause=%d, want seq=2753 cause=16", resp.Seq, resp.Cause)
	}
	if len(resp.Bearers) != 2 {
		t.Fatalf("response bearer count got %d, want 2", len(resp.Bearers))
	}
	// Duplicate late callbacks must be ignored by the response guard.
	srv.completeDedicatedERABSetupForBearer(ue, ERABSetupResult{EBI: 8, Success: true}, srv.log)
	if mock.createResponseCount() != 1 {
		t.Fatalf("duplicate callback sent another response: %d", mock.createResponseCount())
	}
}

func TestPendingCreateBearerRejectReleasesEstablishedERABs(t *testing.T) {
	mock := &bearerResponderMock{}
	srv := newTestServer(mock)
	enbAddr := "10.0.0.44:36412"
	ue, ch := makeIdleDedicatedBearerUE(t, srv, enbAddr)

	srv.HandleCreateBearerRequest("10.90.250.59:2123", sonimStormCreateBearer(2753, 0x11111111, 0x22222222))
	ue.Lock()
	ue.ECMState = emm.ECMConnected
	ue.S1BindingState = uecontext.S1BindingActive
	ue.ENBGlobalID = enbAddr
	ue.ENBS1APID = 77
	mmeUEID := ue.MMEUES1APID
	ue.Unlock()
	srv.ResumePendingNetworkBearerProcedures(ue)
	waitForPDU(t, ch, "paging PDU")
	waitForPDU(t, ch, "E-RAB Setup Request")

	srv.completeDedicatedERABSetupForBearer(ue, ERABSetupResult{
		EBI:        7,
		Success:    true,
		ENBS1UIPv4: net.ParseIP("192.168.105.247").To4(),
		ENBS1UTEID: 0x77770001,
	}, srv.log)
	srv.completeDedicatedERABSetupForBearer(ue, ERABSetupResult{
		EBI:        8,
		Success:    true,
		ENBS1UIPv4: net.ParseIP("192.168.105.247").To4(),
		ENBS1UTEID: 0x77770002,
	}, srv.log)
	srv.handleDedicatedBearerNASResponse(ue, &esm.BearerProcedureResponse{
		EPSBearerID: 7,
		MessageType: esm.MsgActivateDedicatedEPSBearerContextReject,
		Cause:       esm.ESMCauseServiceOptionNotSupported,
	}, srv.log)
	srv.handleDedicatedBearerNASResponse(ue, &esm.BearerProcedureResponse{
		EPSBearerID: 8,
		MessageType: esm.MsgActivateDedicatedEPSBearerContextReject,
		Cause:       esm.ESMCauseServiceOptionNotSupported,
	}, srv.log)

	waitForPDU(t, ch, "E-RAB Release Request")
	if got := mock.createResponseCount(); got != 0 {
		t.Fatalf("response sent before E-RAB cleanup: %+v", mock.createResponsesSnapshot())
	}

	raw := pdu.BuildSuccessfulOutcome(pdu.ProcERABRelease, aper.CriticalityIgnore, []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeMMEUEApID(mmeUEID)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeENBUEApID(77)},
		{ID: pdu.IEERABReleaseListERABRelComp, Criticality: aper.CriticalityIgnore, Value: encodeERABReleaseResponseListForTest([]uint8{7, 8})},
	})
	srv.handleMessage(enbAddr, raw)

	waitForCreateResponseCount(t, mock, 1)
	resp := mock.createResponseAt(0)
	if resp.Cause != gtpv2.CauseUERefuses {
		t.Fatalf("response cause got %d, want UE refuses (%d)", resp.Cause, gtpv2.CauseUERefuses)
	}
	for _, b := range resp.Bearers {
		if b.Cause != gtpv2.CauseRequestRejected {
			t.Fatalf("bearer cause got %d, want request rejected", b.Cause)
		}
	}
}

func TestCreateBearerTimeoutReleasesEBIs(t *testing.T) {
	mock := &bearerResponderMock{}
	srv := newTestServer(mock)
	ue, _ := makeIdleDedicatedBearerUE(t, srv, "10.0.0.5:36412")

	srv.HandleCreateBearerRequest("10.90.250.59:2123", sonimStormCreateBearer(2753, 0x11111111, 0x22222222))
	key := singlePendingCreateKey(t, ue)

	srv.onCreateBearerTimeout(ue, key)

	waitForCreateResponseCount(t, mock, 1)
	resp := mock.createResponseAt(0)
	if resp.Cause != gtpv2.CauseRequestDenied {
		t.Fatalf("timeout response cause got %d, want request denied", resp.Cause)
	}
	ue.Lock()
	pending := len(ue.PendingBearerTransactions)
	reservations := len(ue.EBIReservations)
	ue.Unlock()
	if pending != 0 {
		t.Fatalf("pending transactions after timeout got %d, want 0", pending)
	}
	if reservations != 0 {
		t.Fatalf("EBI reservations after timeout got %d, want 0", reservations)
	}

	srv.onCreateBearerTimeout(ue, key)
	if mock.createResponseCount() != 1 {
		t.Fatalf("second timeout sent duplicate response: %d", mock.createResponseCount())
	}
}

func TestModifyBearerRejectMapsToUERefuses(t *testing.T) {
	mock := &bearerResponderMock{}
	srv := newTestServer(mock)
	ue, _ := makeIdleDedicatedBearerUE(t, srv, "10.0.0.7:36412")

	ue.Lock()
	ue.PendingBearerTransactions["update-test"] = &uecontext.DedicatedBearerTransaction{
		ID:          "tx-update-1",
		Kind:        bearerTxUpdate,
		PeerAddress: "10.90.250.59:2123",
		LocalTEID:   0x0f,
		SequenceNum: 0x23d,
		Bearers: map[uint8]*uecontext.DedicatedBearerContext{
			9: {AssignedEBI: 9, QCI: 5, ARP: 1},
		},
	}
	ue.Unlock()

	srv.handleDedicatedBearerNASResponse(ue, &esm.BearerProcedureResponse{
		MessageType: esm.MsgModifyEPSBearerContextReject,
		EPSBearerID: 9,
	}, srv.log)

	waitForUpdateResponseCount(t, mock, 1)
	resp := mock.updateResponseAt(0)
	if resp.Cause != gtpv2.CauseUERefuses {
		t.Fatalf("update reject response cause got %d, want UE refuses (%d)", resp.Cause, gtpv2.CauseUERefuses)
	}
	if resp.Seq != 0x23d {
		t.Fatalf("update reject response seq got %d, want %d", resp.Seq, 0x23d)
	}
	if len(resp.Bearers) != 1 || resp.Bearers[0].EBI != 9 {
		t.Fatalf("update reject response bearers got %+v, want EBI 9", resp.Bearers)
	}
}

func TestCompletedCreateBearerRetransmissionUsesCachedResponse(t *testing.T) {
	mock := &bearerResponderMock{}
	srv := newTestServer(mock)
	enbAddr := "10.0.0.6:36412"
	ue, ch := makeIdleDedicatedBearerUE(t, srv, enbAddr)

	req := sonimStormCreateBearer(2753, 0x11111111, 0x22222222)
	srv.HandleCreateBearerRequest("10.90.250.59:2123", req)
	ue.Lock()
	ue.ECMState = emm.ECMConnected
	ue.S1BindingState = uecontext.S1BindingActive
	ue.ENBGlobalID = enbAddr
	ue.ENBS1APID = 77
	ue.Unlock()
	srv.ResumePendingNetworkBearerProcedures(ue)
	waitForPDU(t, ch, "paging PDU")
	waitForPDU(t, ch, "E-RAB Setup Request")
	srv.handleDedicatedBearerNASResponse(ue, &esm.BearerProcedureResponse{
		EPSBearerID: 7, MessageType: esm.MsgActivateDedicatedEPSBearerContextAccept,
	}, srv.log)
	srv.handleDedicatedBearerNASResponse(ue, &esm.BearerProcedureResponse{
		EPSBearerID: 8, MessageType: esm.MsgActivateDedicatedEPSBearerContextAccept,
	}, srv.log)
	srv.completeDedicatedERABSetupForBearer(ue, ERABSetupResult{
		EBI:        7,
		Success:    true,
		ENBS1UIPv4: net.ParseIP("192.168.105.247").To4(),
		ENBS1UTEID: 0x77770001,
	}, srv.log)
	srv.completeDedicatedERABSetupForBearer(ue, ERABSetupResult{
		EBI:        8,
		Success:    true,
		ENBS1UIPv4: net.ParseIP("192.168.105.247").To4(),
		ENBS1UTEID: 0x77770002,
	}, srv.log)
	waitForCreateResponseCount(t, mock, 1)

	srv.HandleCreateBearerRequest("10.90.250.59:2123", req)
	waitForCreateResponseCount(t, mock, 2)
	first := mock.createResponseAt(0)
	second := mock.createResponseAt(1)
	if second.Seq != first.Seq || second.Cause != first.Cause || len(second.Bearers) != len(first.Bearers) {
		t.Fatalf("cached retransmission response got %+v, want %+v", second, first)
	}
	ue.Lock()
	defer ue.Unlock()
	if got := len(ue.PendingBearerTransactions); got != 0 {
		t.Fatalf("pending transactions after cached retransmission got %d, want 0", got)
	}
	if got := len(ue.EBIReservations); got != 0 {
		t.Fatalf("EBI reservations after cached retransmission got %d, want 0", got)
	}
}

func TestNewEquivalentRequestAllowedAfterOldTransactionTimeout(t *testing.T) {
	mock := &bearerResponderMock{}
	srv := newTestServer(mock)
	ue, _ := makeIdleDedicatedBearerUE(t, srv, "10.0.0.7:36412")

	srv.HandleCreateBearerRequest("10.90.250.59:2123", sonimStormCreateBearer(2753, 0x11111111, 0x22222222))
	key := singlePendingCreateKey(t, ue)
	srv.onCreateBearerTimeout(ue, key)
	waitForCreateResponseCount(t, mock, 1)

	srv.HandleCreateBearerRequest("10.90.250.59:2123", sonimStormCreateBearer(2754, 0x33333333, 0x44444444))

	ue.Lock()
	defer ue.Unlock()
	if got := len(ue.PendingBearerTransactions); got != 1 {
		t.Fatalf("pending transactions got %d, want 1", got)
	}
	if got := len(ue.EBIReservations); got != 2 {
		t.Fatalf("EBI reservations got %d, want 2", got)
	}
	for _, tx := range ue.PendingBearerTransactions {
		if tx.SequenceNum != 2754 {
			t.Fatalf("new pending sequence got %d, want 2754", tx.SequenceNum)
		}
	}
}

func TestDedicatedBearerWaitsForLinkedBearerReadiness(t *testing.T) {
	mock := &bearerResponderMock{}
	srv := newTestServer(mock)
	enbAddr := "10.0.0.8:36412"
	ue, _ := makeIdleDedicatedBearerUE(t, srv, enbAddr)

	ue.Lock()
	ue.ECMState = emm.ECMConnected
	ue.S1BindingState = uecontext.S1BindingActive
	ue.ENBGlobalID = enbAddr
	ue.ENBS1APID = 91
	ue.PDNs["ims"].ERABEstablished = false
	ue.PDNs["ims"].ModifyBearerAccepted = false
	ue.Unlock()

	srv.HandleCreateBearerRequest("10.90.250.59:2123", sonimStormCreateBearer(2753, 0x11111111, 0x22222222))

	ue.Lock()
	defer ue.Unlock()
	for _, tx := range ue.PendingBearerTransactions {
		if tx.CreateState != uecontext.CreateBearerWaitingForLink {
			t.Fatalf("transaction state got %s, want %s", tx.CreateState, uecontext.CreateBearerWaitingForLink)
		}
	}
	if mock.createResponseCount() != 0 {
		t.Fatalf("Create Bearer response sent immediately: %+v", mock.createResponsesSnapshot())
	}
}

func TestPendingCreateBearerProceedsOnceLinkedAccessPathReady(t *testing.T) {
	mock := &bearerResponderMock{}
	srv := newTestServer(mock)
	enbAddr := "10.0.0.9:36412"
	ue, ch := makeIdleDedicatedBearerUE(t, srv, enbAddr)

	ue.Lock()
	ue.PDNs["ims"].ModifyBearerAccepted = false
	ue.ECMState = emm.ECMConnected
	ue.S1BindingState = uecontext.S1BindingActive
	ue.ENBGlobalID = enbAddr
	ue.ENBS1APID = 88
	ue.Unlock()

	srv.HandleCreateBearerRequest("10.90.250.59:2123", sonimStormCreateBearer(2753, 0x11111111, 0x22222222))

	waitForPDU(t, ch, "E-RAB Setup Request")
}

func TestMaybeAdvanceDefaultBearerResumesPendingCreateBearerWhenMBRDeferred(t *testing.T) {
	mock := &bearerResponderMock{}
	srv := newTestServer(mock)
	enbAddr := "10.0.0.10:36412"
	ue, ch := makeIdleDedicatedBearerUE(t, srv, enbAddr)

	ue.Lock()
	ue.PDNs["ims"].ERABEstablished = false
	ue.PDNs["ims"].ModifyBearerAccepted = false
	ue.PDNs["ims"].ModifyBearerSent = false
	ue.PDNs["ims"].State = "activating"
	ue.ECMState = emm.ECMConnected
	ue.S1BindingState = uecontext.S1BindingActive
	ue.ENBGlobalID = enbAddr
	ue.ENBS1APID = 92
	ue.Unlock()

	srv.HandleCreateBearerRequest("10.90.250.59:2123", sonimStormCreateBearer(2754, 0x11111111, 0x22222222))

	key := singlePendingCreateKey(t, ue)
	ue.Lock()
	tx := ue.PendingBearerTransactions[key]
	if tx.CreateState != uecontext.CreateBearerWaitingForLink {
		ue.Unlock()
		t.Fatalf("transaction state got %s, want %s", tx.CreateState, uecontext.CreateBearerWaitingForLink)
	}
	ue.PDNs["ims"].ERABEstablished = true
	ue.Unlock()

	srv.maybeAdvanceDefaultBearer(ue, 6, "test", srv.log)

	waitForPDU(t, ch, "E-RAB Setup Request")

	ue.Lock()
	defer ue.Unlock()
	tx = ue.PendingBearerTransactions[key]
	if tx == nil {
		t.Fatalf("pending transaction missing after resume")
	}
	if tx.CreateState == uecontext.CreateBearerWaitingForLink {
		t.Fatalf("transaction state got %s, want resumed state", tx.CreateState)
	}
}

func TestUEContextReleaseCompleteFailsWaitingLinkedCreateBearer(t *testing.T) {
	mock := &bearerResponderMock{}
	srv := newTestServer(mock)
	enbAddr := "10.0.0.10:36412"
	ue, _ := makeIdleDedicatedBearerUE(t, srv, enbAddr)

	ue.Lock()
	ue.PDNs["ims"].ERABEstablished = false
	ue.PDNs["ims"].ModifyBearerAccepted = false
	ue.PDNs["ims"].ModifyBearerSent = false
	ue.PDNs["ims"].State = "activating"
	ue.ECMState = emm.ECMConnected
	ue.S1BindingState = uecontext.S1BindingActive
	ue.ENBGlobalID = enbAddr
	ue.ENBS1APID = 92
	mmeUEID := ue.MMEUES1APID
	enbUEID := ue.ENBS1APID
	ue.Unlock()

	srv.HandleCreateBearerRequest("10.90.250.59:2123", sonimStormCreateBearer(2754, 0x11111111, 0x22222222))

	key := singlePendingCreateKey(t, ue)
	ue.Lock()
	tx := ue.PendingBearerTransactions[key]
	if tx == nil {
		ue.Unlock()
		t.Fatal("pending transaction missing")
	}
	if tx.CreateState != uecontext.CreateBearerWaitingForLink {
		ue.Unlock()
		t.Fatalf("transaction state got %s, want %s", tx.CreateState, uecontext.CreateBearerWaitingForLink)
	}
	ue.Unlock()

	raw := pdu.BuildSuccessfulOutcome(pdu.ProcUEContextRelease, aper.CriticalityIgnore, []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeMMEUEApID(mmeUEID)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeENBUEApID(enbUEID)},
	})
	srv.handleMessage(enbAddr, raw)

	waitForCreateResponseCount(t, mock, 1)
	resp := mock.createResponseAt(0)
	if resp.Seq != 2754 {
		t.Fatalf("Create Bearer response seq got %d, want 2754", resp.Seq)
	}
	if resp.Cause != gtpv2.CauseRequestRejected {
		t.Fatalf("Create Bearer response cause got %d, want %d", resp.Cause, gtpv2.CauseRequestRejected)
	}

	ue.Lock()
	defer ue.Unlock()
	if got := len(ue.PendingBearerTransactions); got != 0 {
		t.Fatalf("pending transactions got %d, want 0", got)
	}
	if got := len(ue.EBIReservations); got != 0 {
		t.Fatalf("EBI reservations got %d, want 0", got)
	}
	if ue.ECMState != emm.ECMIdle {
		t.Fatalf("ECM state got %s, want %s", ue.ECMState, emm.ECMIdle)
	}
}

func TestDeleteBearerWaitsForERABReleaseWhenS1Active(t *testing.T) {
	mock := &bearerResponderMock{}
	srv := newTestServer(mock)
	enbAddr := "10.0.0.11:36412"
	ue, ch := makeIdleDedicatedBearerUE(t, srv, enbAddr)

	ue.Lock()
	ue.ECMState = emm.ECMConnected
	ue.S1BindingState = uecontext.S1BindingActive
	ue.ENBGlobalID = enbAddr
	ue.ENBS1APID = 93
	ue.S1BindingGeneration = 4
	ue.DedicatedBearers[9] = &uecontext.DedicatedBearerContext{
		AssignedEBI:     9,
		PTI:             1,
		ERABEstablished: true,
		ENBS1UTEID:      0x99990001,
		ENBS1UIP:        net.ParseIP("192.0.2.9").To4(),
		SGWS1UTEID:      0x11110001,
		SGWS1UIP:        net.ParseIP("198.51.100.10").To4(),
		State:           "active",
		TransactionID:   "existing",
	}
	mmeUEID := ue.MMEUES1APID
	enbUEID := ue.ENBS1APID
	ue.Unlock()

	srv.HandleDeleteBearerRequest("10.90.250.59:2123", &gtpv2.DeleteBearerRequest{
		TEID:   0x0f,
		SeqNum: 0x2a,
		EBIs:   []uint8{9},
	})
	waitForPDU(t, ch, "Deactivate EPS Bearer Context Request")

	srv.handleDedicatedBearerNASResponse(ue, &esm.BearerProcedureResponse{
		MessageType: esm.MsgDeactivateEPSBearerContextAccept,
		EPSBearerID: 9,
	}, srv.log)

	var releaseReq []byte
	select {
	case releaseReq = <-ch:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("expected E-RAB Release Request")
	}
	if got := mock.deleteResponseCount(); got != 0 {
		t.Fatalf("Delete Bearer response sent before E-RAB release completion: %d", got)
	}
	p, err := pdu.Decode(releaseReq)
	if err != nil {
		t.Fatalf("decode release request: %v", err)
	}
	if p.ProcedureCode != pdu.ProcERABRelease {
		t.Fatalf("procedure code got %d, want %d", p.ProcedureCode, pdu.ProcERABRelease)
	}
	ieList, err := pdu.DecodeProcedureIEContainer(p.Value)
	if err != nil {
		t.Fatalf("decode release request IEs: %v", err)
	}
	var releaseList []uint8
	for _, ie := range ieList {
		if ie.ID == pdu.IEERABToBeReleasedList {
			releaseList, err = decodeERABReleaseListBearerRelComp(ie.Value)
			if err == nil {
				t.Fatalf("request list unexpectedly decoded as response list")
			}
			releaseList, err = decodeReleaseRequestEBIsForTest(ie.Value)
			if err != nil {
				t.Fatalf("decode release request list: %v", err)
			}
		}
	}
	if len(releaseList) != 1 || releaseList[0] != 9 {
		t.Fatalf("release request EBI list got %v, want [9]", releaseList)
	}

	raw := pdu.BuildSuccessfulOutcome(pdu.ProcERABRelease, aper.CriticalityIgnore, []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeMMEUEApID(mmeUEID)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeENBUEApID(enbUEID)},
		{ID: pdu.IEERABReleaseListERABRelComp, Criticality: aper.CriticalityIgnore, Value: encodeERABReleaseResponseListForTest([]uint8{9})},
	})
	srv.handleMessage(enbAddr, raw)

	waitForDeleteResponseCount(t, mock, 1)
	resp := mock.deleteResponseAt(0)
	if resp.Cause != gtpv2.CauseRequestAccepted {
		t.Fatalf("Delete Bearer response cause got %d, want %d", resp.Cause, gtpv2.CauseRequestAccepted)
	}
	if len(resp.EBIs) != 1 || resp.EBIs[0] != 9 {
		t.Fatalf("Delete Bearer response EBIs got %v, want [9]", resp.EBIs)
	}
	ue.Lock()
	defer ue.Unlock()
	if _, ok := ue.DedicatedBearers[9]; ok {
		t.Fatal("dedicated bearer still present after E-RAB release completion")
	}
}

func TestDeleteBearerERABReleasePartialMapsToAcceptedPartially(t *testing.T) {
	mock := &bearerResponderMock{}
	srv := newTestServer(mock)
	enbAddr := "10.0.0.13:36412"
	ue, ch := makeIdleDedicatedBearerUE(t, srv, enbAddr)

	ue.Lock()
	ue.ECMState = emm.ECMConnected
	ue.S1BindingState = uecontext.S1BindingActive
	ue.ENBGlobalID = enbAddr
	ue.ENBS1APID = 95
	ue.S1BindingGeneration = 5
	ue.DedicatedBearers[9] = &uecontext.DedicatedBearerContext{AssignedEBI: 9, PTI: 1, ERABEstablished: true, ENBS1UTEID: 0x9001, State: "active"}
	ue.DedicatedBearers[10] = &uecontext.DedicatedBearerContext{AssignedEBI: 10, PTI: 1, ERABEstablished: true, ENBS1UTEID: 0x9002, State: "active"}
	mmeUEID := ue.MMEUES1APID
	enbUEID := ue.ENBS1APID
	ue.Unlock()

	srv.HandleDeleteBearerRequest("10.90.250.59:2123", &gtpv2.DeleteBearerRequest{
		TEID:   0x0f,
		SeqNum: 0x2c,
		EBIs:   []uint8{9, 10},
	})
	waitForPDU(t, ch, "Deactivate EPS Bearer Context Request 1")
	waitForPDU(t, ch, "Deactivate EPS Bearer Context Request 2")
	srv.handleDedicatedBearerNASResponse(ue, &esm.BearerProcedureResponse{MessageType: esm.MsgDeactivateEPSBearerContextAccept, EPSBearerID: 9}, srv.log)
	srv.handleDedicatedBearerNASResponse(ue, &esm.BearerProcedureResponse{MessageType: esm.MsgDeactivateEPSBearerContextAccept, EPSBearerID: 10}, srv.log)
	waitForPDU(t, ch, "E-RAB Release Request")

	raw := pdu.BuildSuccessfulOutcome(pdu.ProcERABRelease, aper.CriticalityIgnore, []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeMMEUEApID(mmeUEID)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeENBUEApID(enbUEID)},
		{ID: pdu.IEERABReleaseListERABRelComp, Criticality: aper.CriticalityIgnore, Value: encodeERABReleaseResponseListForTest([]uint8{9})},
		{ID: pdu.IEERABFailedToReleaseList, Criticality: aper.CriticalityIgnore, Value: encodeERABFailedToReleaseListForTest([]uint8{10})},
	})
	srv.handleMessage(enbAddr, raw)

	waitForDeleteResponseCount(t, mock, 1)
	resp := mock.deleteResponseAt(0)
	if resp.Cause != gtpv2.CauseRequestAcceptedPartially {
		t.Fatalf("Delete Bearer response cause got %d, want %d", resp.Cause, gtpv2.CauseRequestAcceptedPartially)
	}
	ue.Lock()
	defer ue.Unlock()
	if _, ok := ue.DedicatedBearers[9]; ok {
		t.Fatal("released bearer 9 still present")
	}
	if proc := ue.DedicatedBearers[10]; proc == nil || proc.State != "release-failed" {
		t.Fatalf("failed bearer 10 state got %+v, want release-failed", proc)
	}
}

func TestDeleteBearerERABReleaseMissingResultsMapsToRejectedAndRetainsBearer(t *testing.T) {
	mock := &bearerResponderMock{}
	srv := newTestServer(mock)
	enbAddr := "10.0.0.14:36412"
	ue, ch := makeIdleDedicatedBearerUE(t, srv, enbAddr)

	ue.Lock()
	ue.ECMState = emm.ECMConnected
	ue.S1BindingState = uecontext.S1BindingActive
	ue.ENBGlobalID = enbAddr
	ue.ENBS1APID = 96
	ue.S1BindingGeneration = 6
	ue.DedicatedBearers[11] = &uecontext.DedicatedBearerContext{AssignedEBI: 11, PTI: 1, ERABEstablished: true, ENBS1UTEID: 0x9003, State: "active"}
	mmeUEID := ue.MMEUES1APID
	enbUEID := ue.ENBS1APID
	ue.Unlock()

	srv.HandleDeleteBearerRequest("10.90.250.59:2123", &gtpv2.DeleteBearerRequest{
		TEID:   0x0f,
		SeqNum: 0x2d,
		EBIs:   []uint8{11},
	})
	waitForPDU(t, ch, "Deactivate EPS Bearer Context Request")
	srv.handleDedicatedBearerNASResponse(ue, &esm.BearerProcedureResponse{MessageType: esm.MsgDeactivateEPSBearerContextAccept, EPSBearerID: 11}, srv.log)
	waitForPDU(t, ch, "E-RAB Release Request")

	raw := pdu.BuildSuccessfulOutcome(pdu.ProcERABRelease, aper.CriticalityIgnore, []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeMMEUEApID(mmeUEID)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeENBUEApID(enbUEID)},
	})
	srv.handleMessage(enbAddr, raw)

	waitForDeleteResponseCount(t, mock, 1)
	resp := mock.deleteResponseAt(0)
	if resp.Cause != gtpv2.CauseRequestDenied {
		t.Fatalf("Delete Bearer response cause got %d, want %d", resp.Cause, gtpv2.CauseRequestDenied)
	}
	ue.Lock()
	defer ue.Unlock()
	if proc := ue.DedicatedBearers[11]; proc == nil || proc.State != "release-missing" {
		t.Fatalf("missing-result bearer 11 state got %+v, want release-missing", proc)
	}
}

func TestDeleteBearerCompletesImmediatelyWithoutERABBinding(t *testing.T) {
	mock := &bearerResponderMock{}
	srv := newTestServer(mock)
	enbAddr := "10.0.0.12:36412"
	ue, ch := makeIdleDedicatedBearerUE(t, srv, enbAddr)

	ue.Lock()
	ue.ECMState = emm.ECMConnected
	ue.S1BindingState = uecontext.S1BindingActive
	ue.ENBGlobalID = enbAddr
	ue.ENBS1APID = 94
	ue.DedicatedBearers[9] = &uecontext.DedicatedBearerContext{
		AssignedEBI: 9,
		PTI:         1,
		State:       "active",
	}
	ue.Unlock()

	srv.HandleDeleteBearerRequest("10.90.250.59:2123", &gtpv2.DeleteBearerRequest{
		TEID:   0x0f,
		SeqNum: 0x2b,
		EBIs:   []uint8{9},
	})
	waitForPDU(t, ch, "Deactivate EPS Bearer Context Request")
	srv.handleDedicatedBearerNASResponse(ue, &esm.BearerProcedureResponse{
		MessageType: esm.MsgDeactivateEPSBearerContextAccept,
		EPSBearerID: 9,
	}, srv.log)

	waitForDeleteResponseCount(t, mock, 1)
	resp := mock.deleteResponseAt(0)
	if resp.Cause != gtpv2.CauseRequestAccepted {
		t.Fatalf("Delete Bearer response cause got %d, want %d", resp.Cause, gtpv2.CauseRequestAccepted)
	}
}

func encodeERABReleaseResponseListForTest(ebis []uint8) []byte {
	w := aper.NewBitWriter()
	_ = aper.EncodeConstrainedWholeNumber(w, int64(len(ebis)), 1, 256)
	w.AlignToByte()
	for _, ebi := range ebis {
		body := encodeERABReleaseResponseItemForTest(ebi)
		inner := pdu.EncodeIEContainer([]pdu.ProtocolIE{{
			ID:          pdu.IEERABReleaseItemBearerRelComp,
			Criticality: aper.CriticalityIgnore,
			Value:       body,
		}})
		if len(inner) >= 2 {
			inner = inner[2:]
		}
		w.WriteOctets(inner)
	}
	return w.Bytes()
}

func encodeERABFailedToReleaseListForTest(ebis []uint8) []byte {
	w := aper.NewBitWriter()
	_ = aper.EncodeConstrainedWholeNumber(w, int64(len(ebis)), 1, 256)
	w.AlignToByte()
	for _, ebi := range ebis {
		body := encodeERABFailedToReleaseItemForTest(ebi)
		inner := pdu.EncodeIEContainer([]pdu.ProtocolIE{{
			ID:          pdu.IEERABItem,
			Criticality: aper.CriticalityIgnore,
			Value:       body,
		}})
		if len(inner) >= 2 {
			inner = inner[2:]
		}
		w.WriteOctets(inner)
	}
	return w.Bytes()
}

func encodeERABFailedToReleaseItemForTest(ebi uint8) []byte {
	w := aper.NewBitWriter()
	w.WriteBit(0)
	w.WriteBit(0)
	w.WriteBit(0)
	_ = aper.EncodeConstrainedWholeNumber(w, int64(ebi), 0, 15)
	w.WriteOctets(ies.EncodeCause(ies.CauseGroupRadioNetwork, ies.CauseRadioNetworkUnspecified))
	return w.Bytes()
}

func encodeERABReleaseResponseItemForTest(ebi uint8) []byte {
	w := aper.NewBitWriter()
	w.WriteBit(0)
	w.WriteBit(0)
	w.WriteBit(0)
	_ = aper.EncodeConstrainedWholeNumber(w, int64(ebi), 0, 15)
	return w.Bytes()
}

func decodeReleaseRequestEBIsForTest(data []byte) ([]uint8, error) {
	r := aper.NewBitReader(data)
	count, err := aper.DecodeConstrainedWholeNumber(r, 1, 256)
	if err != nil {
		return nil, err
	}
	r.AlignToByte()
	out := make([]uint8, 0, int(count))
	for i := 0; i < int(count); i++ {
		ieID, err := aper.DecodeConstrainedWholeNumber(r, 0, 65535)
		if err != nil {
			return nil, err
		}
		if uint16(ieID) != pdu.IEERABItem {
			return nil, fmt.Errorf("unexpected E-RAB item IE ID %d", ieID)
		}
		if _, err := aper.DecodeCriticality(r); err != nil {
			return nil, err
		}
		itemBytes, err := aper.ReadOpenType(r)
		if err != nil {
			return nil, err
		}
		ebi, err := decodeERABReleaseItemBearerRelComp(itemBytes)
		if err != nil {
			return nil, err
		}
		out = append(out, ebi)
	}
	return out, nil
}
