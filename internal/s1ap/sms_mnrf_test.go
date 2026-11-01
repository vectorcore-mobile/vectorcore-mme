package s1ap

import (
	"errors"
	"testing"
	"time"

	"github.com/vectorcore/mme/internal/diameter/sgd"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/roaming"
	"github.com/vectorcore/mme/internal/uecontext"
)

func mnrf(ue *uecontext.Context) bool {
	ue.Lock()
	defer ue.Unlock()
	return ue.SMSNotReachableFlag
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (f *fakeNotifyS6a) snapshot() ([]roaming.S6aRequest, int32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]roaming.S6aRequest(nil), f.calls...), f.reason
}

func TestAbsentUserMTSetsMNRF(t *testing.T) {
	s, ue, _ := newMTOutcomeServer(t, true)
	s.smsTimeout = 20 * time.Millisecond
	if got := s.HandleSGdMT(mtRequest()); got.ExperimentalResultCode != sgd.ResultErrorAbsentUser {
		t.Fatalf("outcome = %+v, want absent user", got)
	}
	if !mnrf(ue) {
		t.Fatal("MNRF not set after absent-user MT")
	}

	// Other outcomes leave MNRF alone.
	ue.Lock()
	ue.SMSNotReachableFlag = false
	ue.Unlock()
	s.markNotReachableForSMS(mtOutcomeIMSI, sgd.MTDelivered(nil))
	s.markNotReachableForSMS(mtOutcomeIMSI, sgd.MTUserBusy())
	s.markNotReachableForSMS(mtOutcomeIMSI, sgd.MTDeliveryFailure(sgd.DeliveryFailureMemoryCapacityExceeded, nil))
	if mnrf(ue) {
		t.Fatal("MNRF set for a non-absent outcome")
	}
	// Unknown IMSI: no context, nothing to flag, no panic.
	s.markNotReachableForSMS("001019999999999", sgd.MTAbsentUser(sgd.AbsentDiagIMSIDetached))
}

func newRegisteredMNRFServer(t *testing.T, f S6aClient) (*Server, *uecontext.Context) {
	t.Helper()
	s, ue, _ := newMTOutcomeServer(t, true)
	s.s6a = f
	ue.Lock()
	ue.EMMState = emm.StateRegistered
	ue.SMSNotReachableFlag = true
	ue.Unlock()
	return s, ue
}

func TestUEActivityWithMNRFNotifiesUEPresent(t *testing.T) {
	f := &fakeNotifyS6a{code: 2001}
	s, ue := newRegisteredMNRFServer(t, f)

	s.refreshReachability(ue, "test-activity")
	waitFor(t, "NOR", func() bool { calls, _ := f.snapshot(); return len(calls) == 1 })
	calls, reason := f.snapshot()
	if calls[0].SubscriberIMSI != mtOutcomeIMSI || reason != alertReasonUEPresent {
		t.Fatalf("NOR = %+v reason %d, want %s UE_PRESENT", calls[0], reason, mtOutcomeIMSI)
	}
	if mnrf(ue) {
		t.Fatal("MNRF still set after successful notify")
	}

	// Further activity with MNRF clear sends nothing.
	s.refreshReachability(ue, "test-activity")
	time.Sleep(50 * time.Millisecond)
	if calls, _ := f.snapshot(); len(calls) != 1 {
		t.Fatalf("NOR sent %d times, want 1", len(calls))
	}
}

func TestFailedUEPresentNotifyKeepsMNRF(t *testing.T) {
	for name, f := range map[string]*fakeNotifyS6a{
		"transport error": {err: errors.New("no peer")},
		"HSS error":       {code: 5012},
	} {
		t.Run(name, func(t *testing.T) {
			s, ue := newRegisteredMNRFServer(t, f)
			s.refreshReachability(ue, "test-activity")
			waitFor(t, "NOR", func() bool { calls, _ := f.snapshot(); return len(calls) == 1 })
			waitFor(t, "MNRF restored", func() bool { return mnrf(ue) })
		})
	}
	t.Run("user unknown is not retried", func(t *testing.T) {
		f := &fakeNotifyS6a{code: 5001}
		s, ue := newRegisteredMNRFServer(t, f)
		s.refreshReachability(ue, "test-activity")
		waitFor(t, "NOR", func() bool { calls, _ := f.snapshot(); return len(calls) == 1 })
		time.Sleep(50 * time.Millisecond)
		if mnrf(ue) {
			t.Fatal("MNRF restored after DIAMETER_ERROR_USER_UNKNOWN")
		}
	})
}

func TestUEActivityWithoutNotifySupportKeepsMNRF(t *testing.T) {
	s, ue := newRegisteredMNRFServer(t, NoopS6aClient{})
	s.refreshReachability(ue, "test-activity")
	if !mnrf(ue) {
		t.Fatal("MNRF cleared although no NOR could be sent")
	}
}
