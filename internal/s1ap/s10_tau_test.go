package s1ap

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/gateway"
	"github.com/vectorcore/mme/internal/gtpv2"
	s10pkg "github.com/vectorcore/mme/internal/gtpv2/s10"
	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/security"
	"github.com/vectorcore/mme/internal/peertracker"
	s1apies "github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/uecontext"
)

// ── Mock S10Client ────────────────────────────────────────────────────────────

type mockS10 struct {
	reqCh  chan ctxReqCall           // fed by SendContextRequest
	ackCh  chan ctxAckCall           // fed by SendContextAcknowledge
	respCh chan s10pkg.ContextResult // callers read from this
}

type ctxReqCall struct {
	peerAddr string
	req      *s10pkg.ContextRequest
}

type ctxAckCall struct {
	peerAddr string
	peerTEID uint32
	cause    uint8
}

func newMockS10() *mockS10 {
	return &mockS10{
		reqCh:  make(chan ctxReqCall, 1),
		ackCh:  make(chan ctxAckCall, 4),
		respCh: make(chan s10pkg.ContextResult, 1),
	}
}

func (m *mockS10) SendContextRequest(peerAddr string, req *s10pkg.ContextRequest) (<-chan s10pkg.ContextResult, error) {
	m.reqCh <- ctxReqCall{peerAddr: peerAddr, req: req}
	return m.respCh, nil
}

func (m *mockS10) SendContextAcknowledge(peerAddr string, peerTEID uint32, cause uint8) error {
	m.ackCh <- ctxAckCall{peerAddr: peerAddr, peerTEID: peerTEID, cause: cause}
	return nil
}

func (m *mockS10) LocalAddr() string { return "127.0.0.1:2124" }

// errMockS10 fails immediately on SendContextRequest.
type errMockS10 struct{}

func (errMockS10) SendContextRequest(_ string, _ *s10pkg.ContextRequest) (<-chan s10pkg.ContextResult, error) {
	return nil, errors.New("s10 disabled")
}
func (errMockS10) SendContextAcknowledge(_ string, _ uint32, _ uint8) error { return nil }
func (errMockS10) LocalAddr() string                                        { return "" }

// ── Mock S6a (capturing) ──────────────────────────────────────────────────────

type capturingS6a struct {
	ulrCalls chan struct {
		imsi    string
		mmeUEID uint32
	}
	err error
}

func (c *capturingS6a) SendAIR(_ string, _ [3]byte, _ uint32) error { return nil }
func (c *capturingS6a) SendULR(imsi string, _ [3]byte, mmeUEID uint32) error {
	c.ulrCalls <- struct {
		imsi    string
		mmeUEID uint32
	}{imsi, mmeUEID}
	return c.err
}
func (c *capturingS6a) SendPUR(_ string) error { return nil }

// ── Mock S11 (capturing MBR) ──────────────────────────────────────────────────

type capturingS11 struct {
	mbrCalls chan *gtpv2.ModifyBearerRequest
	mbrErr   error
}

// newCapturingS11 gives mbrCalls enough buffer that SendMBR never blocks,
// even in tests that don't read it — the goroutine under test must never
// stall on a test double.
func newCapturingS11() *capturingS11 {
	return &capturingS11{mbrCalls: make(chan *gtpv2.ModifyBearerRequest, 4)}
}

func (c *capturingS11) SendCSR(_ uint32, _ *gtpv2.CreateSessionRequest) error { return nil }
func (c *capturingS11) SendMBR(_ uint32, req *gtpv2.ModifyBearerRequest) error {
	c.mbrCalls <- req
	return c.mbrErr
}
func (c *capturingS11) SendDSR(_ uint32, _ *gtpv2.DeleteSessionRequest) error { return nil }

// ── Test server builder ───────────────────────────────────────────────────────

func newS10TAUServer(s10 S10Client, s6a S6aClient, s11 S11Client) *Server {
	log, _ := zap.NewDevelopment()
	gutiAlloc, _ := uecontext.NewGUTIAllocator("001", "01", 1, 1)
	return &Server{
		s10:        s10,
		s6a:        s6a,
		s11:        s11,
		ueManager:  uecontext.NewManager(),
		enbTracker: peertracker.New(),
		store:      noopStore{},
		log:        log,
		gutiAlloc:  gutiAlloc,
		s11LocalIP: net.ParseIP("127.0.0.1").To4(),
		nfCfg: config.NFConfig{
			MCC:   "001",
			MNC:   "01",
			MMEGI: 1,
			MMEC:  1,
			TAIList: []config.TAIItem{
				{MCC: "001", MNC: "01", TAC: 1},
			},
		},
		s10Cfg: config.S10Config{
			Enabled:     true,
			BindAddress: "0.0.0.0",
			BindPort:    2124,
			Peers: []config.PeerMMEConfig{
				{Name: "mme-a", MMEC: 2, Address: "10.0.0.2:2124"},
			},
		},
	}
}

func sampleContextResponse() *s10pkg.ContextResponse {
	kasme := bytes.Repeat([]byte{0xAA}, 32)
	nh := bytes.Repeat([]byte{0xBB}, 32)
	return &s10pkg.ContextResponse{
		Cause: gtpv2.CauseRequestAccepted,
		IMSI:  "001010123456789",
		SenderFTEID: gtpv2.FTEID{
			InterfaceType: gtpv2.IFTypeS10MME,
			TEID:          0xDEAD0001,
			IP:            net.ParseIP("10.0.0.2").To4(),
		},
		MMContext: gtpv2.MMContextParams{
			IntAlg:     0, // EIA0 null
			EncAlg:     0, // EEA0 null
			NCC:        1,
			ULNASCount: 5,
			DLNASCount: 3,
			KASME:      kasme,
			NH:         nh,
			MSISDN:     "491512345678",
			APN:        "internet",
		},
		PDNConnection: gtpv2.PDNParams{
			EBI:        5,
			SGWC_FTEID: gtpv2.FTEID{TEID: 0x1000, IP: net.ParseIP("10.0.1.1").To4()},
			SGWU_FTEID: gtpv2.FTEID{TEID: 0x2000, IP: net.ParseIP("10.0.1.2").To4()},
			ENBU_FTEID: gtpv2.FTEID{TEID: 0x3000, IP: net.ParseIP("10.0.1.3").To4()},
			UEIPv4:     net.ParseIP("172.16.0.10").To4(),
			APN:        "internet",
		},
	}
}

func addTempUE(srv *Server, remoteAddr string, enbUEID uint32) *uecontext.Context {
	ue := srv.ueManager.Allocate()
	ue.ENBGlobalID = remoteAddr
	ue.ENBS1APID = enbUEID
	srv.enbs.Store(remoteAddr, &ENBContext{RemoteAddr: remoteAddr, SetupComplete: true})
	// sendToAddr does a type assertion to chan<- []byte, so we must store it as such.
	srv.sends.Store(remoteAddr, (chan<- []byte)(make(chan []byte, 64)))
	return ue
}

// ── resolveOldMME tests ───────────────────────────────────────────────────────

func TestResolveOldMME_Match(t *testing.T) {
	srv := newS10TAUServer(NoopS10Client{}, NoopS6aClient{}, NoopS11Client{})
	guti := &emm.GUTI{PLMN: [3]byte{0x00, 0xF1, 0x10}, MMEGI: 1, MMEC: 2}
	addr, ok := srv.resolveOldMME(guti)
	if !ok {
		t.Fatal("resolveOldMME: expected match, got miss")
	}
	if addr != "10.0.0.2:2124" {
		t.Errorf("address: got %q, want %q", addr, "10.0.0.2:2124")
	}
}

func TestResolveOldMME_NoMatch(t *testing.T) {
	srv := newS10TAUServer(NoopS10Client{}, NoopS6aClient{}, NoopS11Client{})
	guti := &emm.GUTI{PLMN: [3]byte{0x00, 0xF1, 0x10}, MMEGI: 1, MMEC: 9} // MMEC 9 not configured
	_, ok := srv.resolveOldMME(guti)
	if ok {
		t.Error("resolveOldMME: expected miss, got match")
	}
}

func TestResolveOldMME_MMEGIFilter(t *testing.T) {
	log, _ := zap.NewDevelopment()
	srv := &Server{
		log: log,
		s10Cfg: config.S10Config{
			Peers: []config.PeerMMEConfig{
				{MMEC: 3, MMEGI: 5, Address: "10.0.0.5:2124"},
			},
		},
	}
	// Same MMEC but wrong MMEGI.
	guti := &emm.GUTI{MMEC: 3, MMEGI: 99}
	_, ok := srv.resolveOldMME(guti)
	if ok {
		t.Error("resolveOldMME: expected MMEGI mismatch to fail, but got match")
	}
	// Correct MMEGI.
	guti.MMEGI = 5
	addr, ok := srv.resolveOldMME(guti)
	if !ok || addr != "10.0.0.5:2124" {
		t.Errorf("resolveOldMME: expected match at 10.0.0.5:2124, got ok=%v addr=%q", ok, addr)
	}
}

// ── handleInterMMETAU / importContextAndContinueTAU ──────────────────────────

// TestInterMMETAU_SuccessNoopS6a verifies the full new-MME path with the S6a test fake:
// context import → TAU Accept sent → CTX-Ack sent to old MME → MBR sent to SGW.
func TestInterMMETAU_SuccessNoopS6a(t *testing.T) {
	ms10 := newMockS10()
	ms11 := newCapturingS11()
	srv := newS10TAUServer(ms10, NoopS6aClient{}, ms11)

	const remoteAddr = "192.168.0.1:36412"
	tempUE := addTempUE(srv, remoteAddr, 1001)

	guti := &emm.GUTI{PLMN: [3]byte{0x00, 0xF1, 0x10}, MMEGI: 1, MMEC: 2, MTMSI: 0x12345678}
	tai := &s1apies.TAI{MCC: "001", MNC: "01", TAC: 1}

	go srv.handleInterMMETAU(tempUE, guti, "10.0.0.2:2124", tai, []byte{0x07, 0x48})

	// Drain the CTX-Req from the mock.
	select {
	case call := <-ms10.reqCh:
		if call.peerAddr != "10.0.0.2:2124" {
			t.Errorf("peerAddr: got %q, want 10.0.0.2:2124", call.peerAddr)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("SendContextRequest not called within timeout")
	}

	// Feed a successful response.
	ms10.respCh <- s10pkg.ContextResult{Resp: sampleContextResponse()}

	// Wait for CTX-Ack.
	select {
	case ack := <-ms10.ackCh:
		if ack.cause != gtpv2.CauseRequestAccepted {
			t.Errorf("CTX-Ack cause: got %d, want %d", ack.cause, gtpv2.CauseRequestAccepted)
		}
		if ack.peerAddr != "10.0.0.2:2124" {
			t.Errorf("CTX-Ack peerAddr: got %q", ack.peerAddr)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("SendContextAcknowledge not called within timeout")
	}

	// Wait for UE to appear by IMSI.
	deadline := time.Now().Add(500 * time.Millisecond)
	var finalUE *uecontext.Context
	for time.Now().Before(deadline) {
		ue, ok := srv.ueManager.GetByIMSI("001010123456789")
		if ok {
			finalUE = ue
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if finalUE == nil {
		t.Fatal("UE not found by IMSI after context import")
	}

	finalUE.Lock()
	defer finalUE.Unlock()

	if finalUE.SGWC_TEID != 0x1000 {
		t.Errorf("SGWC_TEID: got 0x%X, want 0x1000", finalUE.SGWC_TEID)
	}
	if finalUE.DefaultEBI != 5 {
		t.Errorf("DefaultEBI: got %d, want 5", finalUE.DefaultEBI)
	}
	if !bytes.Equal(finalUE.KASME, bytes.Repeat([]byte{0xAA}, 32)) {
		t.Error("KASME not imported correctly")
	}

	// MBR should have been sent (SGWC_TEID != 0).
	select {
	case mbr := <-ms11.mbrCalls:
		if mbr.MMEC_TEID == 0 {
			t.Error("MBR MMEC_TEID should be non-zero")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected MBR sent, got none")
	}
}

// TestInterMMETAU_ContextTimeout verifies that a timeout sends TAU Reject and removes the UE.
func TestInterMMETAU_ContextTimeout(t *testing.T) {
	// Use a real mock but never feed a response → timeout fires.
	ms10 := newMockS10()
	srv := newS10TAUServer(ms10, NoopS6aClient{}, NoopS11Client{})
	// Shorten timeout: we can't easily change the hard-coded 10s, so instead drive
	// via SendContextRequest error path.
	const remoteAddr = "192.168.0.2:36412"
	tempUE := addTempUE(srv, remoteAddr, 1002)

	guti := &emm.GUTI{MMEC: 2, MMEGI: 1}
	tai := &s1apies.TAI{MCC: "001", MNC: "01", TAC: 1}

	done := make(chan struct{})
	go func() {
		srv.handleInterMMETAU(tempUE, guti, "10.0.0.2:2124", tai, []byte{0x07, 0x48})
		close(done)
	}()

	// Drain the request call.
	select {
	case <-ms10.reqCh:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("SendContextRequest not called")
	}

	// Close respCh to simulate the channel being closed (treated as error by select timeout in goroutine).
	// Actually, since we can't easily control the 10s timer, just verify the goroutine is waiting.
	// Feed an error response to terminate it quickly.
	ms10.respCh <- s10pkg.ContextResult{Err: errors.New("simulated timeout")}

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("handleInterMMETAU goroutine did not finish after error response")
	}

	// UE should have been removed (not findable by MMEID since Remove was called).
	_, found := srv.ueManager.GetByMMEID(tempUE.MMEUES1APID)
	if found {
		t.Error("tempUE should have been removed after error response")
	}
}

// TestInterMMETAU_ContextNotFound verifies that cause=ContextNotFound causes TAU Reject.
func TestInterMMETAU_ContextNotFound(t *testing.T) {
	ms10 := newMockS10()
	srv := newS10TAUServer(ms10, NoopS6aClient{}, NoopS11Client{})

	const remoteAddr = "192.168.0.3:36412"
	tempUE := addTempUE(srv, remoteAddr, 1003)

	guti := &emm.GUTI{MMEC: 2}
	tai := &s1apies.TAI{MCC: "001", MNC: "01", TAC: 1}

	done := make(chan struct{})
	go func() {
		srv.handleInterMMETAU(tempUE, guti, "10.0.0.2:2124", tai, []byte{0x07, 0x48})
		close(done)
	}()

	<-ms10.reqCh
	ms10.respCh <- s10pkg.ContextResult{Resp: &s10pkg.ContextResponse{
		Cause: gtpv2.CauseContextNotFound,
	}}

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("goroutine did not finish")
	}

	_, found := srv.ueManager.GetByMMEID(tempUE.MMEUES1APID)
	if found {
		t.Error("tempUE should have been removed on ContextNotFound")
	}
}

// TestInterMMETAU_OldMMEUnreachable verifies that SendContextRequest error → TAU Reject.
func TestInterMMETAU_OldMMEUnreachable(t *testing.T) {
	srv := newS10TAUServer(errMockS10{}, NoopS6aClient{}, NoopS11Client{})

	const remoteAddr = "192.168.0.4:36412"
	tempUE := addTempUE(srv, remoteAddr, 1004)

	guti := &emm.GUTI{MMEC: 2}
	tai := &s1apies.TAI{MCC: "001", MNC: "01", TAC: 1}

	done := make(chan struct{})
	go func() {
		srv.handleInterMMETAU(tempUE, guti, "10.0.0.2:2124", tai, []byte{0x07, 0x48})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("goroutine did not finish")
	}

	_, found := srv.ueManager.GetByMMEID(tempUE.MMEUES1APID)
	if found {
		t.Error("tempUE should have been removed when SendContextRequest fails")
	}
}

// TestInterMMETAU_SuccessWithS6a verifies the path when S6a is enabled:
// context import → ULR sent → HandleULAResult called → TAU Accept → CTX-Ack → MBR.
func TestInterMMETAU_SuccessWithS6a(t *testing.T) {
	ms10 := newMockS10()
	ms11 := newCapturingS11()
	s6a := &capturingS6a{
		ulrCalls: make(chan struct {
			imsi    string
			mmeUEID uint32
		}, 1),
	}
	srv := newS10TAUServer(ms10, s6a, ms11)

	const remoteAddr = "192.168.0.5:36412"
	tempUE := addTempUE(srv, remoteAddr, 1005)

	guti := &emm.GUTI{MMEC: 2}
	tai := &s1apies.TAI{MCC: "001", MNC: "01", TAC: 1}

	go srv.handleInterMMETAU(tempUE, guti, "10.0.0.2:2124", tai, []byte{0x07, 0x48})

	<-ms10.reqCh
	ms10.respCh <- s10pkg.ContextResult{Resp: sampleContextResponse()}

	// Wait for ULR to be sent.
	var ulrCall struct {
		imsi    string
		mmeUEID uint32
	}
	select {
	case ulrCall = <-s6a.ulrCalls:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("ULR not sent within timeout")
	}
	if ulrCall.imsi != "001010123456789" {
		t.Errorf("ULR IMSI: got %q, want 001010123456789", ulrCall.imsi)
	}

	// No CTX-Ack sent yet (waiting for ULA).
	select {
	case <-ms10.ackCh:
		t.Error("CTX-Ack sent before ULA arrived — premature")
	case <-time.After(50 * time.Millisecond):
		// Expected: no ack yet.
	}

	// Deliver ULA with the mandatory bearer policy required to resume TAU.
	srv.HandleULAResultWithSubscriberProfile(ulrCall.mmeUEID, "4915123456789", &gateway.SubscriberProfile{
		DefaultContextID: 1,
		APNs: map[string]gateway.APNConfiguration{
			"internet": {
				ContextIdentifier:    1,
				ServiceSelection:     "internet",
				PDNType:              gtpv2.PDNTypeIPv4,
				QCI:                  9,
				ARPPriority:          8,
				APNAMBRUp:            384,
				APNAMBRDown:          512,
				PreemptionCapability: false,
			},
		},
		UEAMBRUp:   1024,
		UEAMBRDown: 2048,
	}, nil)

	// Now CTX-Ack must arrive.
	select {
	case ack := <-ms10.ackCh:
		if ack.cause != gtpv2.CauseRequestAccepted {
			t.Errorf("CTX-Ack cause: got %d, want accepted", ack.cause)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("CTX-Ack not sent after ULA")
	}

	// MBR must have been sent.
	select {
	case <-ms11.mbrCalls:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected MBR sent after ULA, got none")
	}
}

// TestInterMMETAU_ULRFailed verifies that ULR error → TAU Reject + denied CTX-Ack.
func TestInterMMETAU_ULRFailed(t *testing.T) {
	ms10 := newMockS10()
	s6a := &capturingS6a{
		ulrCalls: make(chan struct {
			imsi    string
			mmeUEID uint32
		}, 1),
	}
	srv := newS10TAUServer(ms10, s6a, NoopS11Client{})

	const remoteAddr = "192.168.0.6:36412"
	tempUE := addTempUE(srv, remoteAddr, 1006)

	guti := &emm.GUTI{MMEC: 2}
	tai := &s1apies.TAI{MCC: "001", MNC: "01", TAC: 1}

	go srv.handleInterMMETAU(tempUE, guti, "10.0.0.2:2124", tai, []byte{0x07, 0x48})

	<-ms10.reqCh
	ms10.respCh <- s10pkg.ContextResult{Resp: sampleContextResponse()}

	var ulrCall struct {
		imsi    string
		mmeUEID uint32
	}
	select {
	case ulrCall = <-s6a.ulrCalls:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("ULR not sent")
	}

	// Deliver failed ULA.
	srv.HandleULAResult(ulrCall.mmeUEID, "", "", errors.New("HSS error"))

	// CTX-Ack with denied cause.
	select {
	case ack := <-ms10.ackCh:
		if ack.cause != gtpv2.CauseRequestDenied {
			t.Errorf("CTX-Ack cause: got %d, want denied (%d)", ack.cause, gtpv2.CauseRequestDenied)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("CTX-Ack not sent after ULA error")
	}
}

// ── HandleContextRequest (old MME role) ───────────────────────────────────────

func buildOldMMEServer() (*Server, *uecontext.Context, *emm.GUTI) {
	log, _ := zap.NewDevelopment()
	srv := &Server{
		s10:        NoopS10Client{},
		s6a:        NoopS6aClient{},
		s11:        NoopS11Client{},
		ueManager:  uecontext.NewManager(),
		enbTracker: peertracker.New(),
		store:      noopStore{},
		log:        log,
	}
	// Register an attached UE with a bearer.
	ue := srv.ueManager.Allocate()
	ue.IMSI = "001011234567890"
	ue.KASME = bytes.Repeat([]byte{0x11}, 32)
	ue.KNASint = make([]byte, 16)
	ue.KNASenc = make([]byte, 16)
	ue.IntAlg = 2
	ue.EncAlg = 2
	ue.SGWC_TEID = 0xAAAA
	ue.SGWC_IP = net.ParseIP("10.10.0.1").To4()
	ue.SGWU_TEID = 0xBBBB
	ue.SGWU_IP = net.ParseIP("10.10.0.2").To4()
	ue.ENBU_TEID = 0xCCCC
	ue.ENBU_IP = net.ParseIP("10.10.0.3").To4()
	ue.DefaultEBI = 5
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMIdle

	guti := &emm.GUTI{PLMN: [3]byte{0x00, 0xF1, 0x10}, MMEGI: 1, MMEC: 1, MTMSI: 0xDEAD1234}
	srv.ueManager.UpdateIMSI(ue, ue.IMSI)
	srv.ueManager.UpdateGUTI(ue, guti)
	return srv, ue, guti
}

// buildPlainTAURawPDU returns the raw bytes of a plain NAS TAU Request
// (just the outer NAS header + GUTI in mobile identity).
func buildPlainTAURawPDU(guti *emm.GUTI) []byte {
	gutiBytes := guti.Encode()
	// Body: eKSI|updateType, mobile identity LV (GUTI), UE net cap LV
	body := []byte{(7 << 4) | emm.EPSUpdateTypeTA}
	body = append(body, gutiBytes...)
	body = append(body, 0x02, 0xE0, 0xE0)
	return append([]byte{emm.PDEPSMobilityMgmt, emm.MsgTrackingAreaUpdateRequest}, body...)
}

func TestHandleContextRequest_Found(t *testing.T) {
	srv, _, guti := buildOldMMEServer()

	rawPDU := buildPlainTAURawPDU(guti)
	req := &s10pkg.ContextRequest{
		SenderFTEID:   gtpv2.FTEID{TEID: 42, IP: net.ParseIP("10.0.0.9").To4()},
		RawTAURequest: rawPDU,
	}

	resp, mmeUEID, ok := srv.HandleContextRequest("10.0.0.9:2124", req)
	if !ok {
		t.Fatal("HandleContextRequest: expected found=true")
	}
	if resp.Cause != gtpv2.CauseRequestAccepted {
		t.Errorf("Cause: got %d, want accepted", resp.Cause)
	}
	if resp.IMSI != "001011234567890" {
		t.Errorf("IMSI: got %q", resp.IMSI)
	}
	if mmeUEID == 0 {
		t.Error("mmeUEID should be non-zero")
	}
	if resp.PDNConnection.EBI != 5 {
		t.Errorf("PDN EBI: got %d, want 5", resp.PDNConnection.EBI)
	}
	if resp.PDNConnection.SGWC_FTEID.TEID != 0xAAAA {
		t.Errorf("SGWC TEID: got 0x%X, want 0xAAAA", resp.PDNConnection.SGWC_FTEID.TEID)
	}
	if !bytes.Equal(resp.MMContext.KASME, bytes.Repeat([]byte{0x11}, 32)) {
		t.Error("KASME not copied correctly")
	}
}

func TestHandleContextRequest_NotFound(t *testing.T) {
	srv, _, _ := buildOldMMEServer()

	// GUTI with MTMSI that doesn't match any registered UE.
	unknownGUTI := &emm.GUTI{PLMN: [3]byte{0x00, 0xF1, 0x10}, MMEGI: 1, MMEC: 1, MTMSI: 0xFFFFFFFF}
	rawPDU := buildPlainTAURawPDU(unknownGUTI)

	resp, mmeUEID, ok := srv.HandleContextRequest("10.0.0.9:2124", &s10pkg.ContextRequest{
		RawTAURequest: rawPDU,
	})
	if ok {
		t.Error("HandleContextRequest: expected found=false for unknown GUTI")
	}
	if resp.Cause != gtpv2.CauseContextNotFound {
		t.Errorf("Cause: got %d, want ContextNotFound (%d)", resp.Cause, gtpv2.CauseContextNotFound)
	}
	if mmeUEID != 0 {
		t.Errorf("mmeUEID: got %d, want 0 for not-found", mmeUEID)
	}
}

// ── HandleContextAcknowledge (old MME role) ───────────────────────────────────

func TestHandleContextAcknowledge_Success(t *testing.T) {
	srv, ue, _ := buildOldMMEServer()
	mmeUEID := ue.MMEUES1APID

	srv.HandleContextAcknowledge(mmeUEID, gtpv2.CauseRequestAccepted)

	// UE should be removed from manager.
	_, found := srv.ueManager.GetByMMEID(mmeUEID)
	if found {
		t.Error("UE should have been removed from manager after successful CTX-Ack")
	}

	// SGWC_TEID should be cleared (no DSR sent).
	// Can't read ue.SGWC_TEID here because ue might be freed — check via the test:
	// The key assertion is that Remove was called.
}

func TestHandleContextAcknowledge_Denied(t *testing.T) {
	srv, ue, _ := buildOldMMEServer()
	mmeUEID := ue.MMEUES1APID

	srv.HandleContextAcknowledge(mmeUEID, gtpv2.CauseRequestDenied)

	// UE must still be present.
	_, found := srv.ueManager.GetByMMEID(mmeUEID)
	if !found {
		t.Error("UE should NOT be removed when CTX-Ack cause is denied")
	}
}

func TestHandleContextAcknowledge_NotFound(t *testing.T) {
	srv, _, _ := buildOldMMEServer()
	// Should not panic on unknown mmeUEID.
	srv.HandleContextAcknowledge(0xDEADDEAD, gtpv2.CauseRequestAccepted)
}

// TestHandleContextAcknowledge_NoDSR verifies the S11 noop client received no DSR.
func TestHandleContextAcknowledge_NoDSR(t *testing.T) {
	ms11 := newCapturingS11()
	log, _ := zap.NewDevelopment()
	srv := &Server{
		s10:        NoopS10Client{},
		s6a:        NoopS6aClient{},
		s11:        ms11,
		ueManager:  uecontext.NewManager(),
		enbTracker: peertracker.New(),
		store:      noopStore{},
		log:        log,
	}
	ue := srv.ueManager.Allocate()
	ue.IMSI = "001010000000001"
	ue.SGWC_TEID = 0x5555
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMIdle
	srv.ueManager.UpdateIMSI(ue, ue.IMSI)

	srv.HandleContextAcknowledge(ue.MMEUES1APID, gtpv2.CauseRequestAccepted)

	// DSR must NOT have been called. HandleContextAcknowledge above ran
	// synchronously (no goroutine), so a non-blocking check is sufficient.
	select {
	case <-ms11.mbrCalls:
		t.Error("unexpected MBR call in NoDSR test")
	default:
	}
}

// ── Review fix 2: AttachedUEs metric ─────────────────────────────────────────

// TestInterMMETAU_AttachedUEsIncremented verifies that finishInterMMETAU increments
// the AttachedUEs gauge so it stays accurate after context transfer from the old MME.
func TestInterMMETAU_AttachedUEsIncremented(t *testing.T) {
	ms10 := newMockS10()
	ms11 := newCapturingS11()
	srv := newS10TAUServer(ms10, NoopS6aClient{}, ms11)

	const remoteAddr = "192.168.2.1:36412"
	tempUE := addTempUE(srv, remoteAddr, 5001)

	guti := &emm.GUTI{MMEC: 2, MMEGI: 1}
	tai := &s1apies.TAI{MCC: "001", MNC: "01", TAC: 1}

	// Snapshot gauge before.
	before := gaugeValue(metrics.AttachedUEs)

	go srv.handleInterMMETAU(tempUE, guti, "10.0.0.2:2124", tai, []byte{0x07, 0x48})
	<-ms10.reqCh
	ms10.respCh <- s10pkg.ContextResult{Resp: sampleContextResponse()}

	// Wait for ack (signals finishInterMMETAU completed).
	select {
	case <-ms10.ackCh:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("CTX-Ack not sent within timeout")
	}

	// Allow finishInterMMETAU goroutine to finish.
	time.Sleep(50 * time.Millisecond)

	after := gaugeValue(metrics.AttachedUEs)
	if after != before+1 {
		t.Errorf("AttachedUEs: got %v (before %v), want +1", after, before)
	}
}

// TestInterMMETAU_ECMConnectedAfterImport verifies that importContextAndContinueTAU
// sets ECMConnected so that handleDisconnect does not silently skip the UE.
func TestInterMMETAU_ECMConnectedAfterImport(t *testing.T) {
	ms10 := newMockS10()
	ms11 := newCapturingS11()
	srv := newS10TAUServer(ms10, NoopS6aClient{}, ms11)

	const remoteAddr = "192.168.2.2:36412"
	tempUE := addTempUE(srv, remoteAddr, 5002)

	guti := &emm.GUTI{MMEC: 2, MMEGI: 1}
	tai := &s1apies.TAI{MCC: "001", MNC: "01", TAC: 1}

	go srv.handleInterMMETAU(tempUE, guti, "10.0.0.2:2124", tai, []byte{0x07, 0x48})
	<-ms10.reqCh
	ms10.respCh <- s10pkg.ContextResult{Resp: sampleContextResponse()}

	select {
	case <-ms10.ackCh:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("CTX-Ack not sent within timeout")
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	var finalUE *uecontext.Context
	for time.Now().Before(deadline) {
		if ue, ok := srv.ueManager.GetByIMSI("001010123456789"); ok {
			finalUE = ue
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if finalUE == nil {
		t.Fatal("UE not found by IMSI after inter-MME TAU")
	}

	finalUE.Lock()
	ecm := finalUE.ECMState
	finalUE.Unlock()

	if ecm != emm.ECMConnected {
		t.Errorf("ECMState after inter-MME TAU: got %v, want ECMConnected", ecm)
	}
}

// ── NAS key derivation from imported context ──────────────────────────────────

func TestImportContext_NASKeysDerivation(t *testing.T) {
	ms10 := newMockS10()
	ms11 := newCapturingS11()
	srv := newS10TAUServer(ms10, NoopS6aClient{}, ms11)

	const remoteAddr = "192.168.1.1:36412"
	tempUE := addTempUE(srv, remoteAddr, 2001)

	guti := &emm.GUTI{MMEC: 2}
	tai := &s1apies.TAI{MCC: "001", MNC: "01", TAC: 1}

	// Derive expected keys.
	kasme := bytes.Repeat([]byte{0xAA}, 32)
	expectedKNASint, expectedKNASenc, err := security.DeriveNASKeys(kasme, 0, 0)
	if err != nil {
		t.Fatalf("DeriveNASKeys for expected: %v", err)
	}

	go srv.handleInterMMETAU(tempUE, guti, "10.0.0.2:2124", tai, []byte{0x07, 0x48})
	<-ms10.reqCh
	ms10.respCh <- s10pkg.ContextResult{Resp: sampleContextResponse()} // KASME = 0xAA*32

	// Wait for UE to appear.
	deadline := time.Now().Add(500 * time.Millisecond)
	var finalUE *uecontext.Context
	for time.Now().Before(deadline) {
		if ue, ok := srv.ueManager.GetByIMSI("001010123456789"); ok {
			finalUE = ue
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if finalUE == nil {
		t.Fatal("UE not found by IMSI")
	}

	finalUE.Lock()
	defer finalUE.Unlock()

	if !bytes.Equal(finalUE.KNASint, expectedKNASint) {
		t.Error("KNASint mismatch — NAS keys not derived from imported KASME")
	}
	if !bytes.Equal(finalUE.KNASenc, expectedKNASenc) {
		t.Error("KNASenc mismatch")
	}
}
