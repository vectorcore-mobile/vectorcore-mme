package s1ap

import (
	"testing"
	"time"

	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/models"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/uecontext"
)

func newReachabilityTestServer() *Server {
	s := newTestServer(&mockS11{})
	s.nasCfg.Timers.T3412 = 2 // smallest representable GPRS timer duration
	s.emmTimersCfg = config.EMMTimersConfig{MobileReachableGuardSeconds: 0, ImplicitDetachSeconds: 1}
	return s
}

func TestMobileReachableExpiryPreservesPDNsAndStartsImplicitDetach(t *testing.T) {
	s := newReachabilityTestServer()
	ue := s.ueManager.Allocate()
	ue.IMSI = "001010000000001"
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMIdle
	ue.PDNs["internet"] = &uecontext.PDNContext{APN: "internet", DefaultEBI: 5, SGWC_TEID: 100}
	s.armReachabilityForIdle(ue, "test")
	time.Sleep(2100 * time.Millisecond)
	ue.Lock()
	defer ue.Unlock()
	if ue.EMMState != emm.StateRegistered || len(ue.PDNs) != 1 {
		t.Fatalf("mobile expiry changed registration/session: state=%s pdns=%d", ue.EMMState, len(ue.PDNs))
	}
	if ue.ReachabilityState != "implicit-detach-pending" || !ue.ImplicitDetachTimerActive {
		t.Fatalf("unexpected reachability state: %q active=%v", ue.ReachabilityState, ue.ImplicitDetachTimerActive)
	}
}

func TestReachabilityRefreshCancelsPendingImplicitDetach(t *testing.T) {
	s := newReachabilityTestServer()
	ue := s.ueManager.Allocate()
	ue.EMMState, ue.ECMState = emm.StateRegistered, emm.ECMIdle
	ue.ReachabilityState = "implicit-detach-pending"
	ue.ImplicitDetachTimerActive = true
	ue.ImplicitDetachDeadline = time.Now().Add(time.Hour)
	ue.StartTimer(uecontext.TimerImplicitDetach, time.Hour, func() { t.Fatal("cancelled implicit timer fired") })
	s.refreshReachability(ue, "verified-tau")
	ue.Lock()
	defer ue.Unlock()
	if ue.ReachabilityState != "reachable" || ue.ImplicitDetachTimerActive || !ue.MobileReachableTimerActive {
		t.Fatalf("refresh did not restore reachability: %+v", ue)
	}
}

func TestImplicitDetachCleanupTimeoutFinalizesStuckPDN(t *testing.T) {
	s := newReachabilityTestServer()
	s.emmTimersCfg.ImplicitDetachCleanupTimeoutSeconds = 1
	ue := s.ueManager.Allocate()
	ue.IMSI = "001010000000002"
	ue.EMMState, ue.ECMState = emm.StateRegistered, emm.ECMIdle
	ue.ImplicitDetachGeneration = 1
	ue.ImplicitDetachTimerActive = true
	ue.PDNs["internet"] = &uecontext.PDNContext{APN: "internet", DefaultEBI: 5, SGWC_TEID: 100, SGWAddress: "192.0.2.1:2123"}
	s.onImplicitDetachExpiry(ue.MMEUES1APID, ue, 1)
	if _, ok := s.ueManager.GetByMMEID(ue.MMEUES1APID); !ok {
		t.Fatal("UE finalized before bounded cleanup deadline")
	}
	time.Sleep(1100 * time.Millisecond)
	if _, ok := s.ueManager.GetByMMEID(ue.MMEUES1APID); ok {
		t.Fatal("UE remained after implicit-detach cleanup timeout")
	}
}

// ── RestoreReachability tests ───────────────────────────────────────────────

func TestRestoreReachability_NoopWhenNotPersistent(t *testing.T) {
	s := newReachabilityTestServer()
	s.recoveryPersistent = false
	ue := s.ueManager.Allocate()
	ue.IMSI = "001010000000010"
	rec := models.UERecoveryRecord{IMSI: ue.IMSI, MobileReachableDeadline: futureTime(time.Hour)}

	s.RestoreReachability(ue, rec)

	ue.Lock()
	defer ue.Unlock()
	if ue.MobileReachableTimerActive {
		t.Fatal("RestoreReachability armed a timer while recovery persistence is disabled")
	}
}

func TestRestoreReachability_ArmsMobileReachableFromFutureDeadline(t *testing.T) {
	s := newReachabilityTestServer()
	s.recoveryPersistent = true
	ue := s.ueManager.Allocate()
	ue.IMSI = "001010000000011"
	deadline := time.Now().Add(time.Hour)
	rec := models.UERecoveryRecord{IMSI: ue.IMSI, MobileReachableDeadline: &deadline}

	s.RestoreReachability(ue, rec)

	ue.Lock()
	defer ue.Unlock()
	if !ue.MobileReachableTimerActive || ue.ReachabilityState != "reachable" {
		t.Fatalf("expected an armed mobile-reachable timer, got active=%v state=%q", ue.MobileReachableTimerActive, ue.ReachabilityState)
	}
	if !ue.MobileReachableDeadline.Equal(deadline) {
		t.Fatalf("deadline not preserved: got %v, want %v", ue.MobileReachableDeadline, deadline)
	}
}

func TestRestoreReachability_ArmsImplicitDetachFromFutureDeadline(t *testing.T) {
	s := newReachabilityTestServer()
	s.recoveryPersistent = true
	ue := s.ueManager.Allocate()
	ue.IMSI = "001010000000012"
	deadline := time.Now().Add(time.Hour)
	rec := models.UERecoveryRecord{IMSI: ue.IMSI, ImplicitDetachDeadline: &deadline}

	s.RestoreReachability(ue, rec)

	ue.Lock()
	defer ue.Unlock()
	if !ue.ImplicitDetachTimerActive || ue.ReachabilityState != "implicit-detach-pending" {
		t.Fatalf("expected an armed implicit-detach timer, got active=%v state=%q", ue.ImplicitDetachTimerActive, ue.ReachabilityState)
	}
}

func TestRestoreReachability_ExpiredMobileReachableConvergesToImplicitDetach(t *testing.T) {
	s := newReachabilityTestServer()
	s.recoveryPersistent = true
	s.emmTimersCfg.ImplicitDetachSeconds = 1
	ue := s.ueManager.Allocate()
	ue.IMSI = "001010000000013"
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMIdle
	past := time.Now().Add(-time.Minute)
	rec := models.UERecoveryRecord{IMSI: ue.IMSI, MobileReachableDeadline: &past}

	s.RestoreReachability(ue, rec)

	// A deadline already in the past fires the expiry goroutine asynchronously.
	deadlineAt := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadlineAt) {
		ue.Lock()
		state := ue.ReachabilityState
		ue.Unlock()
		if state == "implicit-detach-pending" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("expired mobile-reachable deadline did not converge to implicit-detach-pending")
}

func TestRestoreReachability_TerminalCleanupActiveResendsDeleteSessions(t *testing.T) {
	mock := &mockS11{}
	s := newTestServer(mock)
	s.nasCfg.Timers.T3412 = 2
	s.emmTimersCfg = config.EMMTimersConfig{MobileReachableGuardSeconds: 0, ImplicitDetachSeconds: 1, ImplicitDetachCleanupTimeoutSeconds: 5}
	s.recoveryPersistent = true
	ue := s.ueManager.Allocate()
	ue.IMSI = "001010000000014"
	ue.SGWC_TEID = 0x99887766
	ue.DefaultEBI = 5
	deadline := time.Now().Add(time.Hour)
	rec := models.UERecoveryRecord{IMSI: ue.IMSI, TerminalCleanupActive: true, TerminalCleanupDeadline: &deadline}

	s.RestoreReachability(ue, rec)

	ue.Lock()
	cleanupStarted := ue.ImplicitDetachCleanupStarted
	emmState := ue.EMMState
	ue.Unlock()
	if !cleanupStarted || emmState != emm.StateDeregisteredInitiated {
		t.Fatalf("expected terminal cleanup resumed, got started=%v emm=%s", cleanupStarted, emmState)
	}
	if len(mock.dsrCalls) != 1 {
		t.Fatalf("expected 1 re-driven DSR for the in-flight terminal cleanup, got %d", len(mock.dsrCalls))
	}
}

func futureTime(d time.Duration) *time.Time {
	t := time.Now().Add(d)
	return &t
}
