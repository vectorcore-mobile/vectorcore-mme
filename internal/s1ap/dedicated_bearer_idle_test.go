package s1ap

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/vectorcore/mme/internal/gtpv2"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/esm"
	"github.com/vectorcore/mme/internal/uecontext"
)

type bearerResponderMock struct {
	mockS11
	mu              sync.Mutex
	createResponses []createBearerResponseCall
}

type createBearerResponseCall struct {
	Peer    string
	TEID    uint32
	Seq     uint32
	Cause   uint8
	Bearers []gtpv2.CreateBearerBearer
}

func (m *bearerResponderMock) SendCreateBearerResponse(peer string, teid uint32, seq uint32, cause uint8, bearers []gtpv2.CreateBearerBearer) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createResponses = append(m.createResponses, createBearerResponseCall{
		Peer: peer, TEID: teid, Seq: seq, Cause: cause, Bearers: append([]gtpv2.CreateBearerBearer(nil), bearers...),
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

func (m *bearerResponderMock) SendUpdateBearerResponse(string, uint32, uint32, uint8, []gtpv2.UpdateBearerBearer) error {
	return nil
}

func (m *bearerResponderMock) SendDeleteBearerResponse(string, uint32, uint32, uint8, []uint8) error {
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
		APN:          "ims",
		DefaultEBI:   6,
		LocalS11TEID: 0x0f,
		State:        "active",
	}
	ue.Unlock()
	srv.ueManager.Register(ue)
	ch := registerTestENBWithChan(srv, enbAddr)
	return ue, ch
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
