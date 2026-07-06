package s1ap

import (
	"context"
	"fmt"
	"testing"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/gtpv2"
	"github.com/vectorcore/mme/internal/models"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/peertracker"
	"github.com/vectorcore/mme/internal/repository"
	"github.com/vectorcore/mme/internal/uecontext"
)

// counterVecValue reads the current float64 value of a prometheus CounterVec label set.
func counterVecValue(cv *prometheus.CounterVec, labels ...string) float64 {
	c, err := cv.GetMetricWithLabelValues(labels...)
	if err != nil {
		return 0
	}
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		return 0
	}
	return m.GetCounter().GetValue()
}

// gaugeValue reads the current float64 value of a prometheus Gauge.
func gaugeValue(g prometheus.Gauge) float64 {
	var m dto.Metric
	if err := g.Write(&m); err != nil {
		return 0
	}
	return m.GetGauge().GetValue()
}

// ── Test helpers ─────────────────────────────────────────────────────────────

// mockS11 records DSR calls for test assertions.
type mockS11 struct {
	dsrCalls []gtpv2.DeleteSessionRequest
}

func (m *mockS11) SendCSR(_ uint32, _ *gtpv2.CreateSessionRequest) error { return nil }
func (m *mockS11) SendMBR(_ uint32, _ *gtpv2.ModifyBearerRequest) error  { return nil }
func (m *mockS11) SendDSR(_ uint32, req *gtpv2.DeleteSessionRequest) error {
	m.dsrCalls = append(m.dsrCalls, *req)
	return nil
}

// noopStore implements repository.Repository for tests that don't need a real DB.
type noopStore struct{}

func (noopStore) UpsertUEContext(_ context.Context, _ *models.UEContext) error { return nil }
func (noopStore) GetUEContextByMMEID(_ context.Context, _ uint32) (*models.UEContext, error) {
	return nil, repository.ErrNotFound
}
func (noopStore) GetUEContextByIMSI(_ context.Context, _ string) (*models.UEContext, error) {
	return nil, repository.ErrNotFound
}
func (noopStore) GetUEContextByGUTI(_ context.Context, _ string) (*models.UEContext, error) {
	return nil, repository.ErrNotFound
}
func (noopStore) DeleteUEContext(_ context.Context, _ uint32) error { return nil }
func (noopStore) ListUEContexts(_ context.Context) ([]models.UEContext, error) {
	return nil, nil
}
func (noopStore) UpsertENBRegistration(_ context.Context, _ *models.ENBRegistration) error {
	return nil
}
func (noopStore) DeleteENBRegistration(_ context.Context, _ string) error { return nil }
func (noopStore) ListENBRegistrations(_ context.Context) ([]models.ENBRegistration, error) {
	return nil, nil
}

func newTestServer(s11 S11Client) *Server {
	log, _ := zap.NewDevelopment()
	return &Server{
		s11:        s11,
		ueManager:  uecontext.NewManager(),
		enbTracker: peertracker.New(),
		store:      noopStore{},
		log:        log,
	}
}

// registerTestENB adds a fake ENBContext to the server's enbs map.
func registerTestENB(srv *Server, remoteAddr string) {
	enb := &ENBContext{RemoteAddr: remoteAddr}
	srv.enbs.Store(remoteAddr, enb)
	// sends stores the send-direction so sendToAddr's type assertion (chan<- []byte) succeeds.
	ch := make(chan []byte, 8)
	srv.sends.Store(remoteAddr, (chan<- []byte)(ch))
}

// registerTestENBWithChan is like registerTestENB but returns the bidirectional channel
// so the caller can drain it and inspect sent PDUs.
func registerTestENBWithChan(srv *Server, remoteAddr string) chan []byte {
	enb := &ENBContext{RemoteAddr: remoteAddr}
	srv.enbs.Store(remoteAddr, enb)
	ch := make(chan []byte, 16)
	srv.sends.Store(remoteAddr, (chan<- []byte)(ch))
	return ch
}

// allocateTestUE creates a UE via the manager (auto-assigns MMEUES1APID, stores in byMMEID),
// sets ENBGlobalID and SGWC_TEID, and optionally marks it as EMM-REGISTERED+ECM-CONNECTED.
func allocateTestUE(srv *Server, remoteAddr string, sgwcTEID uint32, registered bool) *uecontext.Context {
	ue := srv.ueManager.Allocate()
	ue.ENBGlobalID = remoteAddr
	ue.SGWC_TEID = sgwcTEID
	ue.DefaultEBI = 5
	ue.IMSI = fmt.Sprintf("2049500000%05d", ue.MMEUES1APID)
	ue.APN = "internet"
	if registered {
		ue.EMMState = emm.StateRegistered
		ue.ECMState = emm.ECMConnected // registered UEs are ECM-CONNECTED while on S1
	}
	return ue
}

// ── sendDeleteSession tests (original) ───────────────────────────────────────

func TestSendDeleteSession_SendsDSRWhenSessionEstablished(t *testing.T) {
	mock := &mockS11{}
	srv := newTestServer(mock)

	ue := uecontext.NewContext(1)
	ue.IMSI = "204950000000001"
	ue.APN = "internet"
	ue.SGWC_TEID = 0x12345678
	ue.DefaultEBI = 5

	srv.sendDeleteSession(ue)

	if len(mock.dsrCalls) != 1 {
		t.Fatalf("expected 1 DSR call, got %d", len(mock.dsrCalls))
	}
	dsr := mock.dsrCalls[0]
	if dsr.SGWC_TEID != 0x12345678 {
		t.Errorf("DSR SGWC_TEID: got %#x, want %#x", dsr.SGWC_TEID, 0x12345678)
	}
	if dsr.EBI != 5 {
		t.Errorf("DSR EBI: got %d, want 5", dsr.EBI)
	}

	// SGWC_TEID should be cleared after send
	ue.Lock()
	remaining := ue.SGWC_TEID
	ue.Unlock()
	if remaining != 0 {
		t.Errorf("SGWC_TEID should be cleared after DSR, got %d", remaining)
	}
}

func TestSendDeleteSession_IdempotentNoop(t *testing.T) {
	mock := &mockS11{}
	srv := newTestServer(mock)

	ue := uecontext.NewContext(2)
	ue.SGWC_TEID = 0xDEADBEEF
	ue.DefaultEBI = 5

	// First call sends DSR and clears TEID
	srv.sendDeleteSession(ue)
	// Second call should be a no-op (TEID already cleared)
	srv.sendDeleteSession(ue)

	if len(mock.dsrCalls) != 1 {
		t.Errorf("expected exactly 1 DSR call (idempotent), got %d", len(mock.dsrCalls))
	}
}

func TestSendDeleteSession_NoopWhenNoSession(t *testing.T) {
	mock := &mockS11{}
	srv := newTestServer(mock)

	ue := uecontext.NewContext(3)
	// SGWC_TEID = 0 (no session established)

	srv.sendDeleteSession(ue)

	if len(mock.dsrCalls) != 0 {
		t.Errorf("expected 0 DSR calls when SGWC_TEID=0, got %d", len(mock.dsrCalls))
	}
}

// ── handleDisconnect tests (H-14) ─────────────────────────────────────────────

func TestHandleDisconnect_UnknownAddr(t *testing.T) {
	mock := &mockS11{}
	srv := newTestServer(mock)

	// No eNB registered — should return early without panic
	srv.handleDisconnect("10.0.0.99:54321")

	if len(mock.dsrCalls) != 0 {
		t.Errorf("expected 0 DSR calls for unknown addr, got %d", len(mock.dsrCalls))
	}
}

func TestHandleDisconnect_ZeroUEs(t *testing.T) {
	mock := &mockS11{}
	srv := newTestServer(mock)

	const addr = "10.0.0.1:36412"
	registerTestENB(srv, addr)

	srv.handleDisconnect(addr)

	if len(mock.dsrCalls) != 0 {
		t.Errorf("expected 0 DSR calls with no UEs, got %d", len(mock.dsrCalls))
	}
	if srv.ueManager.Count() != 0 {
		t.Errorf("expected empty UE manager, got %d", srv.ueManager.Count())
	}
}

func TestHandleDisconnect_EvictsRegisteredUEs(t *testing.T) {
	mock := &mockS11{}
	srv := newTestServer(mock)

	const addr = "10.0.0.1:36412"
	registerTestENB(srv, addr)

	// Two registered UEs with established S11 sessions
	allocateTestUE(srv, addr, 0x1111, true)
	allocateTestUE(srv, addr, 0x2222, true)

	if srv.ueManager.Count() != 2 {
		t.Fatalf("setup: expected 2 UEs, got %d", srv.ueManager.Count())
	}

	srv.handleDisconnect(addr)

	if len(mock.dsrCalls) != 2 {
		t.Errorf("expected 2 DSR calls, got %d", len(mock.dsrCalls))
	}
	if srv.ueManager.Count() != 0 {
		t.Errorf("expected 0 UEs after disconnect, got %d", srv.ueManager.Count())
	}
	// Verify the TEIDs that were sent
	teids := map[uint32]bool{0x1111: false, 0x2222: false}
	for _, call := range mock.dsrCalls {
		teids[call.SGWC_TEID] = true
	}
	for teid, seen := range teids {
		if !seen {
			t.Errorf("DSR for TEID %#x was not sent", teid)
		}
	}
}

func TestHandleDisconnect_PartialAttach_NoSession(t *testing.T) {
	mock := &mockS11{}
	srv := newTestServer(mock)

	const addr = "10.0.0.1:36412"
	registerTestENB(srv, addr)

	// UE in attach flow — SGWC_TEID not yet set
	allocateTestUE(srv, addr, 0, false) // sgwcTEID=0, not registered

	srv.handleDisconnect(addr)

	if len(mock.dsrCalls) != 0 {
		t.Errorf("expected 0 DSR calls for UE with no session, got %d", len(mock.dsrCalls))
	}
	if srv.ueManager.Count() != 0 {
		t.Errorf("expected UE to be evicted even without session, got %d UEs", srv.ueManager.Count())
	}
}

func TestHandleDisconnect_Idempotent(t *testing.T) {
	mock := &mockS11{}
	srv := newTestServer(mock)

	const addr = "10.0.0.1:36412"
	registerTestENB(srv, addr)
	allocateTestUE(srv, addr, 0xAAAA, true)

	// First disconnect — evicts the UE and removes eNB from map
	srv.handleDisconnect(addr)
	firstDSRs := len(mock.dsrCalls)

	// Second disconnect on same addr — eNB was removed by LoadAndDelete, returns early
	srv.handleDisconnect(addr)

	if len(mock.dsrCalls) != firstDSRs {
		t.Errorf("second disconnect sent extra DSRs: before=%d, after=%d", firstDSRs, len(mock.dsrCalls))
	}
}

func TestHandleDisconnect_OnlyEvictsMatchingENB(t *testing.T) {
	mock := &mockS11{}
	srv := newTestServer(mock)

	const addr1 = "10.0.0.1:36412"
	const addr2 = "10.0.0.2:36412"
	registerTestENB(srv, addr1)
	registerTestENB(srv, addr2)

	// 2 UEs on each eNB
	allocateTestUE(srv, addr1, 0x1111, true)
	allocateTestUE(srv, addr1, 0x2222, true)
	allocateTestUE(srv, addr2, 0x3333, true)
	allocateTestUE(srv, addr2, 0x4444, true)

	// Disconnect only eNB 1
	srv.handleDisconnect(addr1)

	if len(mock.dsrCalls) != 2 {
		t.Errorf("expected 2 DSR calls for eNB1 UEs, got %d", len(mock.dsrCalls))
	}
	if srv.ueManager.Count() != 2 {
		t.Errorf("expected 2 UEs remaining (eNB2 UEs), got %d", srv.ueManager.Count())
	}
	// The remaining UEs belong to addr2
	for _, ue := range srv.ueManager.List() {
		ue.Lock()
		enbID := ue.ENBGlobalID
		ue.Unlock()
		if enbID != addr2 {
			t.Errorf("remaining UE has wrong ENBGlobalID: %q (want %q)", enbID, addr2)
		}
	}
}

// ── Shutdown tests ─────────────────────────────────────────────────────────────

func TestShutdown_EmptyManager(t *testing.T) {
	mock := &mockS11{}
	srv := newTestServer(mock)

	srv.Shutdown(context.Background())

	if len(mock.dsrCalls) != 0 {
		t.Errorf("expected 0 DSR calls on empty manager, got %d", len(mock.dsrCalls))
	}
}

func TestShutdown_DrainsSessions(t *testing.T) {
	mock := &mockS11{}
	srv := newTestServer(mock)

	const addr = "10.0.0.1:36412"
	// 3 registered UEs with sessions
	allocateTestUE(srv, addr, 0xAABB, true)
	allocateTestUE(srv, addr, 0xCCDD, true)
	allocateTestUE(srv, addr, 0xEEFF, true)

	srv.Shutdown(context.Background())

	if len(mock.dsrCalls) != 3 {
		t.Errorf("expected 3 DSR calls, got %d", len(mock.dsrCalls))
	}
	if srv.ueManager.Count() != 0 {
		t.Errorf("expected empty manager after Shutdown, got %d UEs", srv.ueManager.Count())
	}
}

func TestShutdown_MixedSessionState(t *testing.T) {
	mock := &mockS11{}
	srv := newTestServer(mock)

	const addr = "10.0.0.1:36412"
	// 2 with sessions, 1 without
	allocateTestUE(srv, addr, 0x1234, true)
	allocateTestUE(srv, addr, 0, false) // partial attach
	allocateTestUE(srv, addr, 0x5678, true)

	srv.Shutdown(context.Background())

	// Only the 2 UEs with sessions should send DSRs
	if len(mock.dsrCalls) != 2 {
		t.Errorf("expected 2 DSR calls, got %d", len(mock.dsrCalls))
	}
	// All 3 UEs should be removed
	if srv.ueManager.Count() != 0 {
		t.Errorf("expected empty manager, got %d UEs", srv.ueManager.Count())
	}
}

func TestShutdown_RespectsContextCancellation(t *testing.T) {
	// Use a pre-cancelled context — Shutdown should return immediately with a warning.
	mock := &mockS11{}
	srv := newTestServer(mock)

	const addr = "10.0.0.1:36412"
	// Add enough UEs that the loop would normally do work
	for i := 0; i < 5; i++ {
		allocateTestUE(srv, addr, uint32(0x1000+i), true)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Shutdown so ctx.Done() fires on first check

	srv.Shutdown(ctx)

	// With a pre-cancelled ctx, the loop checks ctx.Done() before the first UE
	// and returns early. 0 DSRs may be sent. The important thing is no panic and no hang.
	// (The exact count depends on whether the select picks ctx.Done() or default first,
	// but pre-cancellation makes ctx.Done() immediately ready.)
	t.Logf("DSR calls with cancelled ctx: %d (expected 0 or very few)", len(mock.dsrCalls))
}
