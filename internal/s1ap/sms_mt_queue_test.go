package s1ap

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/fiorix/go-diameter/v4/diam"

	"github.com/vectorcore/mme/internal/diameter/sgd"
	"github.com/vectorcore/mme/internal/uecontext"
)

func mtRequestWithSession(sid string) *sgd.MTRequest {
	r := mtRequest()
	r.SessionID = sid
	return r
}

func (s *Server) mtQueueLen(imsi string) (running bool, waiting int) {
	s.smsMu.Lock()
	defer s.smsMu.Unlock()
	q, ok := s.mtQueues[imsi]
	if !ok {
		return false, 0
	}
	return true, len(q.waiters)
}

// rpAckFor builds the UE's CP-DATA(RP-ACK) for the running MT transaction.
func rpAckFor(p *pendingMTSMS) []byte {
	cp := []byte{0x80 | p.ti<<4 | 0x09, 0x01, 2, 0x02, p.rpReference}
	return append([]byte{byte(len(cp))}, cp...)
}

func TestConcurrentMTsForOneIMSIAreDeliveredInOrder(t *testing.T) {
	s, ue, _ := newMTOutcomeServer(t, true)
	s.smsTimeout = 5 * time.Second

	type result struct {
		sid     string
		outcome sgd.MTOutcome
	}
	results := make(chan result, 3)
	for i := 1; i <= 3; i++ {
		sid := fmt.Sprintf("tfr-%d", i)
		go func() { results <- result{sid, s.HandleSGdMT(mtRequestWithSession(sid))} }()
		// Arrival order: each TFR is registered (running or queued) before the next.
		waitFor(t, "TFR "+sid+" registered", func() bool {
			running, waiting := s.mtQueueLen(mtOutcomeIMSI)
			return running && waiting == i-1
		})
	}

	var order []string
	for i := 0; i < 3; i++ {
		var p *pendingMTSMS
		waitFor(t, "next MT transaction", func() bool {
			v, ok := s.pendingMTSMS.Load(mtOutcomeIMSI)
			if !ok {
				return false
			}
			p = v.(*pendingMTSMS)
			return len(order) == 0 || p.request.SessionID != order[len(order)-1]
		})
		order = append(order, p.request.SessionID)
		if err := s.processUplinkSMS(ue, rpAckFor(p)); err != nil {
			t.Fatalf("RP-ACK for %s: %v", p.request.SessionID, err)
		}
	}
	if fmt.Sprint(order) != "[tfr-1 tfr-2 tfr-3]" {
		t.Fatalf("delivery order = %v, want arrival order", order)
	}
	for i := 0; i < 3; i++ {
		r := <-results
		if r.outcome.ResultCode != diam.Success {
			t.Fatalf("%s outcome = %+v, want 2001", r.sid, r.outcome)
		}
	}
	if running, _ := s.mtQueueLen(mtOutcomeIMSI); running {
		t.Fatal("MT queue not cleared after the last transaction")
	}
}

func TestQueuedMTPastDeadlineIsUserBusy(t *testing.T) {
	s, _, downlink := newMTOutcomeServer(t, true)
	s.smsTimeout = 50 * time.Millisecond
	release, _, ok := s.acquireMTTurn(mtRequestWithSession("holder"), time.Now().Add(time.Minute))
	if !ok {
		t.Fatal("could not take the MT turn")
	}
	got := s.HandleSGdMT(mtRequest())
	if got.ExperimentalResultCode != sgd.ResultErrorUserBusyForMTSMS {
		t.Fatalf("outcome = %+v, want 5551", got)
	}
	select {
	case <-downlink:
		t.Fatal("queued MT sent CP-DATA without getting its turn")
	default:
	}
	if _, waiting := s.mtQueueLen(mtOutcomeIMSI); waiting != 0 {
		t.Fatalf("timed-out TFR still queued (%d waiting)", waiting)
	}
	release()
	if running, _ := s.mtQueueLen(mtOutcomeIMSI); running {
		t.Fatal("queue not cleared after release")
	}
}

func TestMTQueueFullIsUserBusy(t *testing.T) {
	s, _, _ := newMTOutcomeServer(t, true)
	s.smsTimeout = 300 * time.Millisecond
	release, _, _ := s.acquireMTTurn(mtRequestWithSession("holder"), time.Now().Add(time.Minute))
	var wg sync.WaitGroup
	for i := 0; i < maxQueuedMTPerIMSI; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s.HandleSGdMT(mtRequestWithSession(fmt.Sprintf("q-%d", i)))
		}(i)
	}
	waitFor(t, "queue full", func() bool { _, n := s.mtQueueLen(mtOutcomeIMSI); return n == maxQueuedMTPerIMSI })
	start := time.Now()
	got := s.HandleSGdMT(mtRequestWithSession("overflow"))
	if got.ExperimentalResultCode != sgd.ResultErrorUserBusyForMTSMS || time.Since(start) > 100*time.Millisecond {
		t.Fatalf("overflow outcome = %+v after %v, want immediate 5551", got, time.Since(start))
	}
	release()
	wg.Wait()
}

func TestQueuedMTRechecksUEAfterWaiting(t *testing.T) {
	s, ue, downlink := newMTOutcomeServer(t, true)
	s.smsTimeout = 2 * time.Second
	release, _, _ := s.acquireMTTurn(mtRequestWithSession("holder"), time.Now().Add(time.Minute))
	done := make(chan sgd.MTOutcome, 1)
	go func() { done <- s.HandleSGdMT(mtRequest()) }()
	waitFor(t, "TFR queued", func() bool { _, n := s.mtQueueLen(mtOutcomeIMSI); return n == 1 })

	ue.Lock()
	ue.SMSRegistrationState = uecontext.SMSRegistrationRemoved
	ue.Unlock()
	release()

	got := <-done
	assertAbsentUser(t, "deregistered while queued", got, sgd.AbsentDiagIMSIDetached)
	select {
	case <-downlink:
		t.Fatal("CP-DATA sent to a UE that deregistered while the TFR was queued")
	default:
	}
}
