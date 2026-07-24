package s1ap

import (
	"testing"
	"time"

	"github.com/vectorcore/mme/internal/config"
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
