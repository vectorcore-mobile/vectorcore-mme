package s6a

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/fiorix/go-diameter/v4/diam/avp"
	"github.com/fiorix/go-diameter/v4/diam/datatype"
	"github.com/fiorix/go-diameter/v4/diam/dict"
	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/diameter/sgd"
	"github.com/vectorcore/mme/internal/gateway"
)

func TestMTTFRResultCacheOnlyMatchesExactDiameterTransaction(t *testing.T) {
	h := &Handlers{}
	request := func(sessionID string, hop, end uint32) *diam.Message {
		m := diam.NewRequest(sgd.CommandMTForwardShortMessage, sgd.ApplicationID, dict.Default)
		m.Header.HopByHopID = hop
		m.Header.EndToEndID = end
		_ = sessionID
		return m
	}
	req := &sgd.MTRequest{SessionID: "smsc;1", IMSI: "001010123456789", SMRPUI: []byte{4, 1, 2, 3}}
	m := request(req.SessionID, 1, 2)
	key := mtTFRCacheKey(m, req)
	h.storeMTResult(key, sgd.MTDelivered([]byte{0, 0}))
	cached, ok := h.lookupMTResult(key)
	if !ok || cached.ResultCode != diam.Success || !bytes.Equal(cached.SMRPUI, []byte{0, 0}) {
		t.Fatalf("cached TFA = %+v %v", cached, ok)
	}
	newTransaction := *req
	newTransaction.SessionID = "smsc;2"
	if _, ok := h.lookupMTResult(mtTFRCacheKey(request(newTransaction.SessionID, 3, 4), &newTransaction)); ok {
		t.Fatal("new Diameter transaction incorrectly deduplicated")
	}
}

// recordingConn is a diam.Conn that hands every written message to a channel.
type recordingConn struct {
	discardConn
	writes  chan []byte
	failErr error
}

func newRecordingConn() *recordingConn { return &recordingConn{writes: make(chan []byte, 16)} }

func (c *recordingConn) Write(b []byte) (int, error) {
	if c.failErr != nil {
		return 0, c.failErr
	}
	c.writes <- append([]byte(nil), b...)
	return len(b), nil
}

func (c *recordingConn) WriteStream(b []byte, _ uint) (int, error) { return c.Write(b) }

func (c *recordingConn) nextAnswer(t *testing.T, timeout time.Duration) *diam.Message {
	t.Helper()
	select {
	case b := <-c.writes:
		m, err := diam.ReadMessage(bytes.NewReader(b), dict.Default)
		if err != nil {
			t.Fatalf("decode written message: %v", err)
		}
		return m
	case <-time.After(timeout):
		t.Fatal("no TFA written")
		return nil
	}
}

func (c *recordingConn) expectNoAnswer(t *testing.T, wait time.Duration) {
	t.Helper()
	select {
	case <-c.writes:
		t.Fatal("unexpected TFA written")
	case <-time.After(wait):
	}
}

// blockingMTReceiver is a NAS stub whose HandleSGdMT blocks per IMSI until
// the test releases it with a result code.
type blockingMTReceiver struct {
	mu      sync.Mutex
	calls   map[string]int
	release map[string]chan sgd.MTOutcome
	entered chan string
}

func newBlockingMTReceiver(imsis ...string) *blockingMTReceiver {
	r := &blockingMTReceiver{calls: map[string]int{}, release: map[string]chan sgd.MTOutcome{}, entered: make(chan string, 16)}
	for _, imsi := range imsis {
		r.release[imsi] = make(chan sgd.MTOutcome, 1)
	}
	return r
}

func (r *blockingMTReceiver) HandleAIAResult(uint32, []byte, []byte, []byte, []byte, error) {}
func (r *blockingMTReceiver) HandleULAResultWithSubscriberProfile(uint32, string, *gateway.SubscriberProfile, error) {
}

func (r *blockingMTReceiver) HandleSGdMT(req *sgd.MTRequest) sgd.MTOutcome {
	r.mu.Lock()
	r.calls[req.IMSI]++
	ch := r.release[req.IMSI]
	r.mu.Unlock()
	r.entered <- req.IMSI
	return <-ch
}

func (r *blockingMTReceiver) callCount(imsi string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[imsi]
}

func (r *blockingMTReceiver) waitEntered(t *testing.T, imsi string) {
	t.Helper()
	select {
	case got := <-r.entered:
		if got != imsi {
			t.Fatalf("HandleSGdMT entered for %s, want %s", got, imsi)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("HandleSGdMT not entered for %s", imsi)
	}
}

func newTFRTestHandlers(nas ResultHandler) *Handlers {
	return &Handlers{
		nas:         nas,
		log:         zap.NewNop(),
		diameterCfg: config.DiameterConfig{OriginHost: "mme.test", OriginRealm: "test"},
	}
}

func buildTestTFR(sessionID, imsi string, hop, end uint32) *diam.Message {
	m := diam.NewRequest(sgd.CommandMTForwardShortMessage, sgd.ApplicationID, dict.Default)
	m.Header.HopByHopID = hop
	m.Header.EndToEndID = end
	m.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String(sessionID))
	m.NewAVP(avp.UserName, avp.Mbit, 0, datatype.UTF8String(imsi))
	m.NewAVP(3300, avp.Vbit|avp.Mbit, sgd.VendorID, datatype.OctetString([]byte{0x51, 0x55, 0x21, 0x03, 0x00, 0xf0}))
	m.NewAVP(3301, avp.Vbit|avp.Mbit, sgd.VendorID, datatype.OctetString([]byte{0x04, 0x01, 0x02, 0x03}))
	return m
}

func answerResultCode(t *testing.T, m *diam.Message) uint32 {
	t.Helper()
	a, err := m.FindAVP(avp.ResultCode, 0)
	if err != nil {
		t.Fatalf("TFA missing Result-Code: %v", err)
	}
	return uint32(a.Data.(datatype.Unsigned32))
}

const (
	tfrIMSIA = "001010000000001"
	tfrIMSIB = "001010000000002"
)

func TestHandleTFRReturnsBeforeDeliveryCompletes(t *testing.T) {
	recv := newBlockingMTReceiver(tfrIMSIA)
	h := newTFRTestHandlers(recv)
	conn := newRecordingConn()

	returned := make(chan struct{})
	go func() {
		h.handleTFR(conn, buildTestTFR("smsc;1", tfrIMSIA, 1, 1))
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("handleTFR blocked the Diameter read loop while delivery was pending")
	}
	recv.waitEntered(t, tfrIMSIA)
	conn.expectNoAnswer(t, 50*time.Millisecond)

	recv.release[tfrIMSIA] <- sgd.MTDelivered([]byte{0x00, 0x00})
	ans := conn.nextAnswer(t, 2*time.Second)
	if got := answerResultCode(t, ans); got != diam.Success {
		t.Fatalf("TFA Result-Code = %d, want %d", got, diam.Success)
	}
	if ans.Header.HopByHopID != 1 || ans.Header.EndToEndID != 1 {
		t.Fatalf("TFA identifiers = %d/%d, want 1/1", ans.Header.HopByHopID, ans.Header.EndToEndID)
	}
}

func TestHandleTFRDifferentSubscribersCompleteIndependently(t *testing.T) {
	recv := newBlockingMTReceiver(tfrIMSIA, tfrIMSIB)
	h := newTFRTestHandlers(recv)
	conn := newRecordingConn()

	h.handleTFR(conn, buildTestTFR("smsc;a", tfrIMSIA, 1, 1))
	recv.waitEntered(t, tfrIMSIA)
	h.handleTFR(conn, buildTestTFR("smsc;b", tfrIMSIB, 2, 2))
	recv.waitEntered(t, tfrIMSIB)

	recv.release[tfrIMSIB] <- sgd.MTDelivered([]byte{0x00, 0x00})
	ans := conn.nextAnswer(t, 2*time.Second)
	if ans.Header.HopByHopID != 2 {
		t.Fatalf("first TFA hop-by-hop = %d, want UE-B's 2 while UE-A is still pending", ans.Header.HopByHopID)
	}
	recv.release[tfrIMSIA] <- sgd.MTDelivered([]byte{0x00, 0x00})
	if ans := conn.nextAnswer(t, 2*time.Second); ans.Header.HopByHopID != 1 {
		t.Fatalf("second TFA hop-by-hop = %d, want 1", ans.Header.HopByHopID)
	}
}

func TestHandleTFRRetransmissionWaitsForOriginalDelivery(t *testing.T) {
	recv := newBlockingMTReceiver(tfrIMSIA)
	h := newTFRTestHandlers(recv)
	original := newRecordingConn()
	retransmit := newRecordingConn() // e.g. arrived on a new connection after failover

	h.handleTFR(original, buildTestTFR("smsc;1", tfrIMSIA, 7, 8))
	recv.waitEntered(t, tfrIMSIA)
	dup := buildTestTFR("smsc;1", tfrIMSIA, 7, 8)
	dup.Header.CommandFlags |= diam.RetransmittedFlag
	h.handleTFR(retransmit, dup)
	retransmit.expectNoAnswer(t, 50*time.Millisecond)

	recv.release[tfrIMSIA] <- sgd.MTDelivered([]byte{0x00, 0x00})
	for name, conn := range map[string]*recordingConn{"original": original, "retransmit": retransmit} {
		if got := answerResultCode(t, conn.nextAnswer(t, 2*time.Second)); got != diam.Success {
			t.Fatalf("%s TFA Result-Code = %d, want %d", name, got, diam.Success)
		}
	}
	if n := recv.callCount(tfrIMSIA); n != 1 {
		t.Fatalf("HandleSGdMT called %d times, want 1", n)
	}
}

func TestHandleTFRRetransmissionAfterFailedWriteUsesCache(t *testing.T) {
	recv := newBlockingMTReceiver(tfrIMSIA)
	h := newTFRTestHandlers(recv)
	dead := newRecordingConn()
	dead.failErr = errors.New("connection closed")

	recv.release[tfrIMSIA] <- sgd.MTDelivered([]byte{0x00, 0x00})
	h.handleTFR(dead, buildTestTFR("smsc;1", tfrIMSIA, 7, 8))
	recv.waitEntered(t, tfrIMSIA)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, ok := h.lookupMTResult(mtTFRCacheKey(buildTestTFR("smsc;1", tfrIMSIA, 7, 8), &sgd.MTRequest{SessionID: "smsc;1", IMSI: tfrIMSIA, SMRPUI: []byte{0x04, 0x01, 0x02, 0x03}})); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("result not cached after failed TFA write")
		}
		time.Sleep(5 * time.Millisecond)
	}

	retry := newRecordingConn()
	h.handleTFR(retry, buildTestTFR("smsc;1", tfrIMSIA, 7, 8))
	if got := answerResultCode(t, retry.nextAnswer(t, 2*time.Second)); got != diam.Success {
		t.Fatalf("retransmitted TFA Result-Code = %d, want %d", got, diam.Success)
	}
	if n := recv.callCount(tfrIMSIA); n != 1 {
		t.Fatalf("HandleSGdMT called %d times, want 1 (UE re-delivery)", n)
	}
}

// TestPendingTFRDoesNotStallWatchdogOnRealConnection runs the handler behind
// go-diameter's real per-connection read loop (sequential dispatch, as used by
// NewConn and diam.Serve for SGd peers) and checks a DWR sent while a TFR is
// still waiting on the UE is answered promptly.
func TestPendingTFRDoesNotStallWatchdogOnRealConnection(t *testing.T) {
	recv := newBlockingMTReceiver(tfrIMSIA)
	h := newTFRTestHandlers(recv)
	defer func() { recv.release[tfrIMSIA] <- sgd.MTDelivered([]byte{0x00, 0x00}) }()

	mux := diam.NewServeMux()
	mux.HandleIdx(diam.CommandIndex{AppID: sgd.ApplicationID, Code: sgd.CommandMTForwardShortMessage, Request: true}, diam.HandlerFunc(h.handleTFR))
	mux.HandleIdx(diam.CommandIndex{AppID: 0, Code: diam.DeviceWatchdog, Request: true}, diam.HandlerFunc(func(c diam.Conn, m *diam.Message) {
		a := m.Answer(diam.Success)
		a.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("mme.test"))
		a.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("test"))
		_, _ = a.WriteTo(c)
	}))

	mmeSide, peerSide := net.Pipe()
	defer peerSide.Close()
	if _, err := diam.NewConn(mmeSide, "pipe", mux, dict.Default); err != nil {
		t.Fatalf("NewConn: %v", err)
	}

	answers := make(chan *diam.Message, 4)
	go func() {
		for {
			m, err := diam.ReadMessage(peerSide, dict.Default)
			if err != nil {
				return
			}
			answers <- m
		}
	}()

	if _, err := buildTestTFR("smsc;1", tfrIMSIA, 1, 1).WriteTo(peerSide); err != nil {
		t.Fatalf("write TFR: %v", err)
	}
	recv.waitEntered(t, tfrIMSIA)

	dwr := diam.NewRequest(diam.DeviceWatchdog, 0, dict.Default)
	dwr.Header.HopByHopID = 99
	dwr.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity("smsc.test"))
	dwr.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity("test"))
	// net.Pipe is unbuffered: with a blocked read loop this write would never
	// return, so send it asynchronously and let the timeout below report it.
	go func() { _, _ = dwr.WriteTo(peerSide) }()
	select {
	case a := <-answers:
		if a.Header.CommandCode != diam.DeviceWatchdog || a.Header.HopByHopID != 99 {
			t.Fatalf("first answer = command %d hop %d, want DWA hop 99", a.Header.CommandCode, a.Header.HopByHopID)
		}
	case <-time.After(time.Second):
		t.Fatal("DWR not answered within 1s while a TFR was pending")
	}
}

func TestHandleTFRSendsExperimentalResultAndCachesIt(t *testing.T) {
	recv := newBlockingMTReceiver(tfrIMSIA)
	h := newTFRTestHandlers(recv)
	recv.release[tfrIMSIA] <- sgd.MTDeliveryFailure(sgd.DeliveryFailureMemoryCapacityExceeded, []byte{0x00, 0xd2, 0x00})

	check := func(conn *recordingConn) {
		t.Helper()
		ans := conn.nextAnswer(t, 2*time.Second)
		if _, err := ans.FindAVP(avp.ResultCode, 0); err == nil {
			t.Fatal("TFA carries Result-Code with an Experimental-Result outcome")
		}
		er, err := ans.FindAVP(avp.ExperimentalResultCode, 0)
		if err != nil || uint32(er.Data.(datatype.Unsigned32)) != sgd.ResultErrorSMDeliveryFailure {
			t.Fatalf("Experimental-Result-Code = %v, %v", er, err)
		}
		if _, err := ans.FindAVP(3303, sgd.VendorID); err != nil {
			t.Fatalf("SM-Delivery-Failure-Cause missing: %v", err)
		}
	}
	first := newRecordingConn()
	h.handleTFR(first, buildTestTFR("smsc;1", tfrIMSIA, 3, 4))
	check(first)
	retransmit := newRecordingConn()
	h.handleTFR(retransmit, buildTestTFR("smsc;1", tfrIMSIA, 3, 4))
	check(retransmit)
	if n := recv.callCount(tfrIMSIA); n != 1 {
		t.Fatalf("HandleSGdMT called %d times, want 1", n)
	}
}
