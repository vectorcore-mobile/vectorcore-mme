package s1ap

import (
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/models"
	"github.com/vectorcore/mme/internal/nas/emm"
	nastimer "github.com/vectorcore/mme/internal/nas/timer"
	"github.com/vectorcore/mme/internal/uecontext"
)

// RestoreReachability restores persisted absolute deadlines after the caller
// has reconstructed and registered the UE context. It never grants a fresh
// T3412 interval. New generations fence callbacks created by a prior process.
func (s *Server) RestoreReachability(ue *uecontext.Context, rec models.UERecoveryRecord) {
	if !s.recoveryPersistent || ue == nil || rec.IMSI == "" {
		return
	}
	now := time.Now().UTC()
	ue.Lock()
	if ue.IMSI != rec.IMSI || ue.ImplicitDetachCleanupStarted {
		ue.Unlock()
		return
	}
	ue.MobileReachableGeneration++
	ue.ImplicitDetachGeneration++
	ue.ImplicitDetachCleanupGeneration++
	ue.StopTimer(uecontext.TimerMobileReachable)
	ue.StopTimer(uecontext.TimerImplicitDetach)
	ue.StopTimer(uecontext.TimerImplicitDetachCleanup)
	mmeID := ue.MMEUES1APID
	owner := ue
	// Terminal cleanup has precedence over the other persisted states.
	if rec.TerminalCleanupActive {
		ue.ImplicitDetachCleanupStarted = true
		ue.ReachabilityState = "terminal-cleanup"
		ue.SetEMMState(emm.StateDeregisteredInitiated)
		ue.ImplicitDetachCleanupGeneration++
		gen := ue.ImplicitDetachCleanupGeneration
		deadline := rec.TerminalCleanupDeadline
		if deadline == nil || !deadline.After(now) {
			ue.Unlock()
			go s.onImplicitDetachCleanupTimeout(mmeID, owner, gen)
			return
		}
		d := time.Until(*deadline)
		ue.ImplicitDetachCleanupDeadline = deadline.UTC()
		ue.ImplicitDetachCleanupTimerActive = true
		ue.StartTimer(uecontext.TimerImplicitDetachCleanup, d, func() { s.onImplicitDetachCleanupTimeout(mmeID, owner, gen) })
		ue.Unlock()
		// Conservative restart policy: prior S11 transactions are not durable;
		// re-drive only PDNs still carrying a control TEID (the sender clears it
		// atomically, so duplicate callbacks cannot create duplicate DSRs).
		s.sendDeleteSessionsForDetach(owner)
		return
	}
	if rec.ImplicitDetachDeadline != nil || rec.ReachabilityState == "implicit-detach-pending" {
		ue.ReachabilityState = "implicit-detach-pending"
		ue.ImplicitDetachGeneration++
		gen := ue.ImplicitDetachGeneration
		deadline := rec.ImplicitDetachDeadline
		if deadline == nil || !deadline.After(now) {
			ue.ImplicitDetachTimerActive = true
			ue.Unlock()
			go s.onImplicitDetachExpiry(mmeID, owner, gen)
			return
		}
		ue.ImplicitDetachDeadline = deadline.UTC()
		ue.ImplicitDetachTimerActive = true
		ue.StartTimer(uecontext.TimerImplicitDetach, time.Until(*deadline), func() { s.onImplicitDetachExpiry(mmeID, owner, gen) })
		ue.Unlock()
		return
	}
	// A missing mobile deadline is invalid recovery data: conservatively enter
	// implicit detach rather than silently extending registration indefinitely.
	deadline := rec.MobileReachableDeadline
	if deadline == nil || !deadline.After(now) {
		ue.ReachabilityState = "reachable"
		ue.MobileReachableGeneration++
		gen := ue.MobileReachableGeneration
		ue.MobileReachableTimerActive = true
		ue.MobileReachableDeadline = now
		ue.Unlock()
		go s.onMobileReachableExpiry(mmeID, owner, gen)
		return
	}
	ue.ReachabilityState = "reachable"
	ue.MobileReachableGeneration++
	gen := ue.MobileReachableGeneration
	ue.MobileReachableDeadline = deadline.UTC()
	ue.MobileReachableTimerActive = true
	ue.StartTimer(uecontext.TimerMobileReachable, time.Until(*deadline), func() { s.onMobileReachableExpiry(mmeID, owner, gen) })
	ue.Unlock()
}

// refreshReachability records authenticated UE activity. The selected policy
// follows TS 23.401 §4.3.5: supervision is active in ECM-IDLE only. Connected
// UEs cannot age into implicit detach merely because they are busy for a long
// time.
func (s *Server) refreshReachability(ue *uecontext.Context, reason string) {
	if ue == nil {
		return
	}
	ue.Lock()
	if ue.EMMState != emm.StateRegistered || ue.ImplicitDetachCleanupStarted {
		ue.Unlock()
		return
	}
	wasPending := ue.ImplicitDetachTimerActive || ue.ReachabilityState != "reachable"
	ue.ImplicitDetachGeneration++
	ue.ImplicitDetachTimerActive = false
	ue.ImplicitDetachDeadline = time.Time{}
	ue.StopTimer(uecontext.TimerImplicitDetach)
	ue.MobileReachableGeneration++
	ue.MobileReachableTimerActive = false
	ue.StopTimer(uecontext.TimerMobileReachable)
	ue.ReachabilityState = "reachable"
	ue.LastReachabilityRefresh = time.Now().UTC()
	ue.LastReachabilityReason = reason
	if ue.ECMState == emm.ECMIdle {
		s.startMobileReachableLocked(ue)
	}
	imsi, mmeID := ue.IMSI, ue.MMEUES1APID
	ue.Unlock()
	if wasPending {
		metrics.NASProceduresTotal.WithLabelValues("ImplicitDetach", "recovered").Inc()
		metrics.ImplicitDetachRecoveriesTotal.Inc()
	}
	s.log.Info("emm: UE reachability refreshed", zap.Uint32("mme_ue_id", mmeID), zap.String("imsi", imsi), zap.String("reason", reason), zap.Bool("implicit_detach_cancelled", wasPending))
}

// armReachabilityForIdle is called only after a valid registered UE loses S1.
func (s *Server) armReachabilityForIdle(ue *uecontext.Context, reason string) {
	if ue == nil {
		return
	}
	ue.Lock()
	if ue.EMMState == emm.StateRegistered && ue.ECMState == emm.ECMIdle && !ue.ImplicitDetachCleanupStarted {
		ue.LastReachabilityRefresh = time.Now().UTC()
		ue.LastReachabilityReason = reason
		ue.ReachabilityState = "reachable"
		s.startMobileReachableLocked(ue)
	}
	ue.Unlock()
}

func (s *Server) startMobileReachableLocked(ue *uecontext.Context) {
	// Use the encoded value's decoded duration, not the raw configuration:
	// GPRS timer encoding can quantize a requested T3412 value.
	encoded, err := nastimer.EncodeGPRSTimer(s.nasCfg.Timers.T3412)
	if err != nil {
		s.log.Error("emm: cannot derive effective T3412 for mobile reachability", zap.Error(err))
		return
	}
	seconds := nastimer.DecodeGPRSTimer(encoded) + s.emmTimersCfg.MobileReachableGuardSeconds
	if seconds <= 0 { // validated at startup; defensive for unit-built servers.
		return
	}
	ue.MobileReachableGeneration++
	generation := ue.MobileReachableGeneration
	mmeID := ue.MMEUES1APID
	d := time.Duration(seconds) * time.Second
	ue.MobileReachableDeadline = time.Now().UTC().Add(d)
	ue.MobileReachableTimerActive = true
	ue.StopTimer(uecontext.TimerMobileReachable)
	ue.StartTimer(uecontext.TimerMobileReachable, d, func() { s.onMobileReachableExpiry(mmeID, ue, generation) })
	s.log.Info("emm: mobile-reachable timer started", zap.Uint32("mme_ue_id", mmeID), zap.Uint64("timer_generation", generation), zap.Int("duration_seconds", seconds))
}

func (s *Server) onMobileReachableExpiry(mmeID uint32, owner *uecontext.Context, generation uint64) {
	ue, ok := s.ueManager.GetByMMEID(mmeID)
	if !ok || ue != owner { // protects ID/GUTI reuse after finalization.
		return
	}
	ue.Lock()
	if ue.MobileReachableGeneration != generation || !ue.MobileReachableTimerActive || ue.EMMState != emm.StateRegistered || ue.ECMState != emm.ECMIdle || ue.ImplicitDetachCleanupStarted {
		ue.Unlock()
		return
	}
	ue.MobileReachableTimerActive = false
	ue.MobileReachableDeadline = time.Time{}
	ue.ReachabilityState = "implicit-detach-pending"
	ue.ImplicitDetachGeneration++
	idGen := ue.ImplicitDetachGeneration
	d := time.Duration(s.emmTimersCfg.ImplicitDetachSeconds) * time.Second
	ue.ImplicitDetachDeadline = time.Now().UTC().Add(d)
	ue.ImplicitDetachTimerActive = true
	ue.StopTimer(uecontext.TimerImplicitDetach)
	ue.StartTimer(uecontext.TimerImplicitDetach, d, func() { s.onImplicitDetachExpiry(mmeID, owner, idGen) })
	imsi := ue.IMSI
	ue.Unlock()
	metrics.NASProceduresTotal.WithLabelValues("MobileReachable", "expired").Inc()
	metrics.MobileReachableExpiriesTotal.Inc()
	s.log.Info("emm: mobile-reachable timer expired", zap.Uint32("mme_ue_id", mmeID), zap.String("imsi", imsi), zap.Uint64("timer_generation", generation), zap.Int("implicit_detach_seconds", s.emmTimersCfg.ImplicitDetachSeconds), zap.String("action", "mark-unreachable-and-start-implicit-detach"))
}

func (s *Server) onImplicitDetachExpiry(mmeID uint32, owner *uecontext.Context, generation uint64) {
	ue, ok := s.ueManager.GetByMMEID(mmeID)
	if !ok || ue != owner {
		return
	}
	ue.Lock()
	if ue.ImplicitDetachGeneration != generation || !ue.ImplicitDetachTimerActive || ue.EMMState != emm.StateRegistered || ue.ImplicitDetachCleanupStarted {
		ue.Unlock()
		return
	}
	// Claim terminal cleanup while holding the context lock; no return path can
	// subsequently revive this context.
	ue.ImplicitDetachCleanupStarted = true
	ue.ImplicitDetachCleanupGeneration++
	cleanupGeneration := ue.ImplicitDetachCleanupGeneration
	cleanupDuration := time.Duration(s.emmTimersCfg.ImplicitDetachCleanupTimeoutSeconds) * time.Second
	ue.ImplicitDetachCleanupDeadline = time.Now().UTC().Add(cleanupDuration)
	ue.ImplicitDetachCleanupTimerActive = true
	ue.StopTimer(uecontext.TimerImplicitDetachCleanup)
	ue.StartTimer(uecontext.TimerImplicitDetachCleanup, cleanupDuration, func() {
		s.onImplicitDetachCleanupTimeout(mmeID, owner, cleanupGeneration)
	})
	ue.ImplicitDetachTimerActive = false
	ue.ImplicitDetachDeadline = time.Time{}
	ue.ReachabilityState = "terminal-cleanup"
	ue.SetEMMState(emm.StateDeregisteredInitiated)
	ue.PagingAttempts = 0
	imsi := ue.IMSI
	ue.Unlock()
	metrics.NASProceduresTotal.WithLabelValues("ImplicitDetach", "expired").Inc()
	metrics.ImplicitDetachExpiriesTotal.Inc()
	s.log.Info("emm: implicit-detach timer expired; terminal cleanup claimed", zap.Uint32("mme_ue_id", mmeID), zap.String("imsi", imsi), zap.Uint64("timer_generation", generation))
	// Existing detach code sends exactly one DSR for each PDN and tracks DSRsp.
	s.sendDeleteSessionsForDetach(ue)
	if s.detachedUEDeleteSessionsComplete(mmeID) {
		s.cleanupDetachedUE(mmeID, "implicit-detach")
	}
}

// onImplicitDetachCleanupTimeout is deliberately an overall, bounded policy:
// this release sends no retries. A DSR is idempotently sent once per PDN; an
// unavailable SGW or late response cannot retain the local context forever.
func (s *Server) onImplicitDetachCleanupTimeout(mmeID uint32, owner *uecontext.Context, generation uint64) {
	ue, ok := s.ueManager.GetByMMEID(mmeID)
	if !ok || ue != owner {
		return
	}
	ue.Lock()
	if !ue.ImplicitDetachCleanupStarted || !ue.ImplicitDetachCleanupTimerActive || ue.ImplicitDetachCleanupGeneration != generation {
		ue.Unlock()
		return
	}
	ue.ImplicitDetachCleanupTimerActive = false
	ue.ImplicitDetachCleanupDeadline = time.Time{}
	imsi := ue.IMSI
	ue.Unlock()
	metrics.NASProceduresTotal.WithLabelValues("ImplicitDetach", "cleanup_timeout").Inc()
	metrics.ImplicitDetachCleanupTimeoutsTotal.Inc()
	s.log.Warn("emm: implicit-detach terminal cleanup timed out; finalizing local context", zap.Uint32("mme_ue_id", mmeID), zap.String("imsi", imsi), zap.Uint64("cleanup_generation", generation))
	s.cleanupUEOwnedSMS(ue)
	s.cleanupDetachedUE(mmeID, "implicit-detach-cleanup-timeout")
}

func (s *Server) cleanupUEOwnedSMS(ue *uecontext.Context) {
	if ue == nil {
		return
	}
	ue.Lock()
	imsi := ue.IMSI
	ue.Unlock()
	if s.sms != nil {
		s.sms.RemovePendingMT(imsi)
	}
	if v, ok := s.pendingMTSMS.LoadAndDelete(imsi); ok {
		pending := v.(*pendingMTSMS)
		select {
		case pending.result <- mtSMSResult{}:
		default:
		}
	}
	s.pendingMOSMS.Range(func(key, _ any) bool {
		if len(imsi) > 0 {
			if text, ok := key.(string); ok && len(text) >= len(imsi) && text[:len(imsi)] == imsi {
				s.pendingMOSMS.Delete(key)
			}
		}
		return true
	})
}

func (s *Server) cancelReachabilityForDetach(ue *uecontext.Context) {
	ue.Lock()
	ue.MobileReachableGeneration++
	ue.ImplicitDetachGeneration++
	ue.MobileReachableTimerActive = false
	ue.ImplicitDetachTimerActive = false
	ue.ImplicitDetachCleanupGeneration++
	ue.ImplicitDetachCleanupTimerActive = false
	ue.MobileReachableDeadline = time.Time{}
	ue.ImplicitDetachDeadline = time.Time{}
	ue.StopTimer(uecontext.TimerMobileReachable)
	ue.StopTimer(uecontext.TimerImplicitDetach)
	ue.StopTimer(uecontext.TimerImplicitDetachCleanup)
	ue.Unlock()
}
