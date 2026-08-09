package s1ap

import (
	"testing"
	"time"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/lcsnotify"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
)

func TestHandleUplinkLCSNotificationDeliversToWaiter(t *testing.T) {
	s := newTAUTestServer()
	const mme = 7
	ch := make(chan lcsNotifyResult, 1)
	s.lcsNotifyMu.Lock()
	s.lcsNotifyPending = map[uint32]chan lcsNotifyResult{mme: ch}
	s.lcsNotifyMu.Unlock()

	releaseComplete := []byte{0x8B, 0x2A, 0x1C, 0x05, 0xA2, 0x03, 0x02, 0x01, 0x01} // bare Return Result: implicit grant
	if err := s.handleUplinkLCSNotification(mme, releaseComplete); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-ch:
		if r.err != nil || !r.granted {
			t.Fatalf("got %+v, want granted=true err=nil", r)
		}
	default:
		t.Fatal("no result delivered to waiter")
	}
}

func TestHandleUplinkLCSNotificationDropsResultWithNoWaiter(t *testing.T) {
	s := newTAUTestServer()
	releaseComplete := []byte{0x8B, 0x2A}
	if err := s.handleUplinkLCSNotification(99, releaseComplete); err != nil {
		t.Fatalf("want no error when no waiter is pending, got %v", err)
	}
}

func TestSendLocationNotificationUnknownUEFailsWithoutLeakingWaiter(t *testing.T) {
	s := newTAUTestServer()
	// No UE is registered under mme=1: SendLocationNotification must return
	// the underlying send error promptly (not hang) and must not leave a
	// waiter registered in s.lcsNotifyPending for a send that never went out.
	granted, err := s.SendLocationNotification(1, lcsnotify.NotifyLocationAllowed, true, time.Second)
	if err == nil {
		t.Fatal("want error for unknown UE")
	}
	if granted {
		t.Fatal("want granted=false on error")
	}
	s.lcsNotifyMu.Lock()
	_, leaked := s.lcsNotifyPending[1]
	s.lcsNotifyMu.Unlock()
	if leaked {
		t.Fatal("waiter leaked after failed send")
	}
}

type lppaCapture struct {
	mme     uint32
	route   uint8
	payload []byte
}

func (c *lppaCapture) HandleUplinkLPPa(m uint32, r uint8, b []byte) error {
	c.mme = m
	c.route = r
	c.payload = append([]byte(nil), b...)
	return nil
}
func TestUEAssociatedLPPaRelay(t *testing.T) {
	s := newTAUTestServer()
	const remote = "192.0.2.10:36412"
	ch := setupSendCapture(s, remote)
	ue := allocateTestUE(s, remote, 0, true)
	ue.ENBS1APID = 9
	payload := []byte{1, 2, 3}
	if err := s.SendDownlinkLPPa(ue.MMEUES1APID, 7, payload); err != nil {
		t.Fatal(err)
	}
	msg := readCapturedPDU(t, ch)
	assertPDUIEs(t, msg, pdu.PDUTypeInitiatingMessage, pdu.ProcDownlinkUEAssociatedLPPaTransport, []uint16{pdu.IEMMEUES1APID, pdu.IEENBS1APID, pdu.IERoutingID, pdu.IELPPaPDU})
	cap := &lppaCapture{}
	s.SetLPPaSink(cap)
	list := []pdu.ProtocolIE{{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeMMEUEApID(ue.MMEUES1APID)}, {ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(9)}, {ID: pdu.IERoutingID, Criticality: aper.CriticalityReject, Value: []byte{7}}, {ID: pdu.IELPPaPDU, Criticality: aper.CriticalityReject, Value: payload}}
	s.handleMessage(remote, pdu.BuildInitiatingMessage(pdu.ProcUplinkUEAssociatedLPPaTransport, aper.CriticalityIgnore, list))
	if cap.mme != ue.MMEUES1APID || cap.route != 7 || string(cap.payload) != string(payload) {
		t.Fatalf("relay=%+v", cap)
	}
}

// TestSendDownlinkLPPaQueuesAndPagesWhenUEIdle guards the fix for a real bug:
// SendDownlinkLPPa used to fail immediately ("s1ap: positioning UE has no S1
// binding") for any UE that was simply ECM-IDLE at the moment an
// LPPaECID positioning job started — the ordinary case, not an error — with
// no paging/retry fallback, unlike the LPP path (sendOrQueueGenericNAS).
// This mirrors TestCreateBearerForECMIdleUETriggersPaging's setup for the
// analogous ECM-IDLE-triggers-paging behavior on the dedicated-bearer path.
func TestSendDownlinkLPPaQueuesAndPagesWhenUEIdle(t *testing.T) {
	s := newTAUTestServer()
	const remote = "192.0.2.20:36412"
	ch := setupSendCapture(s, remote)
	ue := allocateTestUE(s, remote, 0, true)
	ue.Lock()
	ue.ECMState = emm.ECMIdle
	ue.ENBGlobalID = ""
	ue.ENBS1APID = 0
	ue.Unlock()
	s.ueManager.Register(ue)
	s.ueManager.UpdateGUTI(ue, &emm.GUTI{PLMN: [3]byte{0x00, 0xf1, 0x10}, MMEGI: 1, MMEC: 1, MTMSI: 0xaabbccdd})
	ue.Lock()
	ue.TAI = &emm.TAI{PLMN: [3]byte{0x00, 0xf1, 0x10}, TAC: 1}
	ue.Unlock()

	payload := []byte{9, 8, 7}
	if err := s.SendDownlinkLPPa(ue.MMEUES1APID, 3, payload); err != nil {
		t.Fatalf("expected queue-and-page, not an error, got %v", err)
	}
	// The only immediate send while ECM-IDLE should be the Paging PDU
	// itself — never a Downlink UE Associated LPPa Transport (that has to
	// wait for the S1 binding the page is trying to establish).
	paging := readCapturedPDU(t, ch)
	if paging.ProcedureCode != pdu.ProcPaging {
		t.Fatalf("immediate send procedure = %d, want Paging (%d)", paging.ProcedureCode, pdu.ProcPaging)
	}
	select {
	case got := <-ch:
		t.Fatalf("expected no further S1AP send while UE is ECM-IDLE, got %d more bytes", len(got))
	default:
	}
	ue.Lock()
	attempts := ue.PagingAttempts
	ue.Unlock()
	if attempts != 1 {
		t.Fatalf("PagingAttempts = %d, want 1", attempts)
	}
	s.lppPendingMu.Lock()
	queued := len(s.lppaPending[ue.MMEUES1APID])
	s.lppPendingMu.Unlock()
	if queued != 1 {
		t.Fatalf("lppaPending depth = %d, want 1", queued)
	}

	// Simulate the Service-Request-reestablished path restoring the S1
	// binding, then resuming — the queued LPPa Initiation Request must now
	// actually be delivered.
	ue.Lock()
	ue.ENBGlobalID = remote
	ue.ENBS1APID = 42
	ue.Unlock()
	s.ResumePendingLPPa(ue)

	msg := readCapturedPDU(t, ch)
	assertPDUIEs(t, msg, pdu.PDUTypeInitiatingMessage, pdu.ProcDownlinkUEAssociatedLPPaTransport, []uint16{pdu.IEMMEUES1APID, pdu.IEENBS1APID, pdu.IERoutingID, pdu.IELPPaPDU})

	s.lppPendingMu.Lock()
	remaining := len(s.lppaPending[ue.MMEUES1APID])
	s.lppPendingMu.Unlock()
	if remaining != 0 {
		t.Fatalf("expected lppaPending drained after resume, got %d remaining", remaining)
	}
}

// TestClearPendingLPPaDropsQueuedRequest guards ClearPendingLPPa: once the S1
// binding a queued LPPa request was waiting for is gone for good (e.g. eNB
// disconnect), the stale request must not be deliverable through a later,
// unrelated service resumption.
func TestClearPendingLPPaDropsQueuedRequest(t *testing.T) {
	s := newTAUTestServer()
	const remote = "192.0.2.21:36412"
	setupSendCapture(s, remote)
	ue := allocateTestUE(s, remote, 0, true)
	ue.Lock()
	ue.ECMState = emm.ECMIdle
	ue.ENBGlobalID = ""
	ue.ENBS1APID = 0
	ue.Unlock()
	s.ueManager.Register(ue)
	s.ueManager.UpdateGUTI(ue, &emm.GUTI{PLMN: [3]byte{0x00, 0xf1, 0x10}, MMEGI: 1, MMEC: 1, MTMSI: 0x11223344})
	ue.Lock()
	ue.TAI = &emm.TAI{PLMN: [3]byte{0x00, 0xf1, 0x10}, TAC: 1}
	ue.Unlock()

	if err := s.SendDownlinkLPPa(ue.MMEUES1APID, 1, []byte{1}); err != nil {
		t.Fatal(err)
	}
	s.ClearPendingLPPa(ue.MMEUES1APID)
	s.lppPendingMu.Lock()
	remaining := len(s.lppaPending[ue.MMEUES1APID])
	s.lppPendingMu.Unlock()
	if remaining != 0 {
		t.Fatalf("expected lppaPending cleared, got %d remaining", remaining)
	}
}
