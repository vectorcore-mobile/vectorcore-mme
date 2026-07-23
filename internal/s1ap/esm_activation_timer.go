package s1ap

import (
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/gtpv2"
	"github.com/vectorcore/mme/internal/uecontext"
)

// TS 24.301, 6.4.2 uses T3485 for network-initiated default and dedicated
// EPS bearer activation. The fifth expiry is terminal: the initial send is
// followed by four retransmissions.
const (
	t3485Duration       = 8 * time.Second
	t3485MaxRetransmits = 4
)

func t3485TimerName(ebi uint8) string { return fmt.Sprintf("T3485:%d", ebi) }

// startDedicatedT3485 records the payload which was actually sent in an E-RAB
// Setup and only then starts the NAS activation timer.
func (s *Server) startDedicatedT3485(ue *uecontext.Context, key string, ebi uint8, protected []byte) {
	if ue == nil || len(protected) == 0 {
		return
	}
	ue.Lock()
	tx := ue.PendingBearerTransactions[key]
	if tx == nil || tx.Kind != bearerTxCreate {
		ue.Unlock()
		return
	}
	proc := tx.Bearers[ebi]
	if proc == nil || proc.NASAccepted || proc.NASRejected || proc.ActivationTimerActive {
		ue.Unlock()
		return
	}
	proc.ActivationNAS = append([]byte(nil), protected...)
	proc.ActivationRetryCount = 0
	proc.ActivationTimedOut = false
	proc.ActivationTimerGeneration++
	proc.ActivationTimerActive = true
	generation := proc.ActivationTimerGeneration
	mmeUEID := ue.MMEUES1APID
	ue.StartTimer(t3485TimerName(ebi), t3485Duration, func() {
		s.onDedicatedT3485Expiry(mmeUEID, key, ebi, generation)
	})
	ue.Unlock()
	s.log.Info("s1ap: T3485 started", zap.Uint32("mme_ue_id", mmeUEID), zap.Uint8("ebi", ebi), zap.String("transaction_key", key), zap.Uint64("timer_generation", generation), zap.Uint8("retry_count", 0))
}

func stopDedicatedT3485Locked(ue *uecontext.Context, proc *uecontext.DedicatedBearerContext) {
	if ue == nil || proc == nil {
		return
	}
	proc.ActivationTimerActive = false
	proc.ActivationTimerGeneration++
	ue.StopTimer(t3485TimerName(proc.AssignedEBI))
}

func (s *Server) onDedicatedT3485Expiry(mmeUEID uint32, key string, ebi uint8, generation uint64) {
	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		return
	}
	var payload []byte
	var terminal bool
	var retries uint8
	ue.Lock()
	tx := ue.PendingBearerTransactions[key]
	if tx == nil || tx.Kind != bearerTxCreate {
		ue.Unlock()
		return
	}
	proc := tx.Bearers[ebi]
	if proc == nil || !proc.ActivationTimerActive || proc.ActivationTimerGeneration != generation || proc.NASAccepted || proc.NASRejected {
		ue.Unlock()
		return
	}
	if proc.ActivationRetryCount >= t3485MaxRetransmits {
		proc.ActivationTimerActive = false
		proc.ActivationTimerGeneration++
		proc.ActivationTimedOut = true
		proc.NASRejected = true
		proc.FailureCause = gtpv2.CauseUEIsNotResponding
		ue.StopTimer(t3485TimerName(ebi))
		terminal = true
	} else if !hasActiveS1BindingLocked(ue) {
		// Do not emit NAS onto a stale S1 binding. Keep the bounded lifecycle
		// running so an access restoration can still receive the next retry.
		proc.ActivationRetryCount++
		proc.ActivationTimerGeneration++
		generation = proc.ActivationTimerGeneration
		retries = proc.ActivationRetryCount
		ue.StartTimer(t3485TimerName(ebi), t3485Duration, func() { s.onDedicatedT3485Expiry(mmeUEID, key, ebi, generation) })
	} else {
		payload = append([]byte(nil), proc.ActivationNAS...)
		proc.ActivationRetryCount++
		proc.ActivationTimerGeneration++
		generation = proc.ActivationTimerGeneration
		retries = proc.ActivationRetryCount
		ue.StartTimer(t3485TimerName(ebi), t3485Duration, func() { s.onDedicatedT3485Expiry(mmeUEID, key, ebi, generation) })
	}
	ue.Unlock()
	if terminal {
		s.log.Warn("s1ap: T3485 terminal expiry", zap.Uint32("mme_ue_id", mmeUEID), zap.Uint8("ebi", ebi), zap.String("transaction_key", key), zap.Uint8("cause", gtpv2.CauseUEIsNotResponding))
		ue.Lock()
		tx = ue.PendingBearerTransactions[key]
		if tx != nil {
			s.maybeCompleteCreateBearerLocked(ue, key, tx)
		}
		ue.Unlock()
		return
	}
	if len(payload) != 0 {
		if err := s.SendDownlinkNAS(mmeUEID, payload); err != nil {
			s.log.Warn("s1ap: T3485 NAS retransmission failed", zap.Uint32("mme_ue_id", mmeUEID), zap.Uint8("ebi", ebi), zap.Error(err))
		} else {
			s.log.Info("s1ap: T3485 retransmission sent", zap.Uint32("mme_ue_id", mmeUEID), zap.Uint8("ebi", ebi), zap.Uint8("retry_count", retries), zap.Uint64("timer_generation", generation))
		}
	}
}

func (s *Server) startDefaultT3485(ue *uecontext.Context, ebi uint8, protected []byte) {
	if ue == nil || len(protected) == 0 {
		return
	}
	ue.Lock()
	pdn := findPDNByLinkedEBILocked(ue, ebi)
	if pdn == nil || pdn.NASAccepted || pdn.ActivationTimerActive {
		ue.Unlock()
		return
	}
	pdn.ActivationNAS = append([]byte(nil), protected...)
	pdn.ActivationRetryCount = 0
	pdn.ActivationTimedOut = false
	pdn.ActivationTimerGeneration++
	pdn.ActivationTimerActive = true
	generation := pdn.ActivationTimerGeneration
	mmeUEID := ue.MMEUES1APID
	ue.StartTimer(t3485TimerName(ebi), t3485Duration, func() { s.onDefaultT3485Expiry(mmeUEID, ebi, generation) })
	ue.Unlock()
	s.log.Info("s1ap: T3485 started", zap.Uint32("mme_ue_id", mmeUEID), zap.Uint8("ebi", ebi), zap.Uint64("timer_generation", generation), zap.Uint8("retry_count", 0))
}

func stopDefaultT3485Locked(ue *uecontext.Context, pdn *uecontext.PDNContext) {
	if ue == nil || pdn == nil {
		return
	}
	pdn.ActivationTimerActive = false
	pdn.ActivationTimerGeneration++
	ue.StopTimer(t3485TimerName(pdn.DefaultEBI))
}

func (s *Server) onDefaultT3485Expiry(mmeUEID uint32, ebi uint8, generation uint64) {
	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		return
	}
	var plain []byte
	var terminal bool
	var retries uint8
	ue.Lock()
	pdn := findPDNByLinkedEBILocked(ue, ebi)
	if pdn == nil || !pdn.ActivationTimerActive || pdn.ActivationTimerGeneration != generation || pdn.NASAccepted {
		ue.Unlock()
		return
	}
	if pdn.ActivationRetryCount >= t3485MaxRetransmits {
		stopDefaultT3485Locked(ue, pdn)
		pdn.ActivationTimedOut = true
		pdn.State = "activation-timeout"
		terminal = true
	} else if !hasActiveS1BindingLocked(ue) {
		// The release path owns explicit cleanup when access disappears. Do not
		// emit NAS against a stale S1 binding from a racing timer callback.
		ue.Unlock()
		return
	} else {
		plain = append([]byte(nil), pdn.ActivationPlainNAS...)
		pdn.ActivationRetryCount++
		retries = pdn.ActivationRetryCount
		pdn.ActivationTimerGeneration++
		generation = pdn.ActivationTimerGeneration
		ue.StartTimer(t3485TimerName(ebi), t3485Duration, func() { s.onDefaultT3485Expiry(mmeUEID, ebi, generation) })
	}
	ue.Unlock()
	if terminal {
		s.log.Warn("s1ap: default bearer T3485 terminal expiry", zap.Uint32("mme_ue_id", mmeUEID), zap.Uint8("ebi", ebi), zap.Uint8("cause", gtpv2.CauseUEIsNotResponding))
		s.failLinkedCreateBearerTransactions(ue, ebi, gtpv2.CauseUEIsNotResponding)
		s.sendDeleteSessionForPDN(ue, ebi, s.log)
		return
	}
	if len(plain) != 0 {
		// A retransmission is the same ESM procedure, but a new protected NAS
		// transmission with the current DL NAS COUNT.
		protected, _, err := s.protectNAS(ue, plain)
		if err != nil {
			s.log.Warn("s1ap: default T3485 NAS reprotection failed", zap.Uint32("mme_ue_id", mmeUEID), zap.Uint8("ebi", ebi), zap.Error(err))
			return
		}
		ue.Lock()
		ue.DLNASCount.Increment()
		ue.Unlock()
		if err := s.SendDownlinkNAS(mmeUEID, protected); err != nil {
			s.log.Warn("s1ap: default T3485 NAS retransmission failed", zap.Uint32("mme_ue_id", mmeUEID), zap.Uint8("ebi", ebi), zap.Error(err))
		} else {
			s.log.Info("s1ap: default T3485 retransmission sent", zap.Uint32("mme_ue_id", mmeUEID), zap.Uint8("ebi", ebi), zap.Uint8("retry_count", retries), zap.Uint64("timer_generation", generation))
		}
	}
}

func (s *Server) failLinkedCreateBearerTransactions(ue *uecontext.Context, linkedEBI uint8, cause uint8) {
	ue.Lock()
	keys := make([]string, 0)
	for key, tx := range ue.PendingBearerTransactions {
		if tx != nil && tx.Kind == bearerTxCreate && tx.LinkedEBI == linkedEBI {
			keys = append(keys, key)
		}
	}
	ue.Unlock()
	for _, key := range keys {
		s.failCreateBearerTransaction(ue, key, cause)
	}
}

// terminateIncompleteIMSActivationForS1Release is used only when S1 access is
// being released while IMS default activation is incomplete. This MME does not
// page to continue T3485 delivery after release, so retaining an activation
// with stopped timers would strand both ESM and Create Bearer state.
func (s *Server) terminateIncompleteIMSActivationForS1Release(ue *uecontext.Context) bool {
	if ue == nil {
		return false
	}
	ue.Lock()
	var linkedEBI uint8
	for _, pdn := range ue.PDNs {
		if pdn == nil || pdn.APN != "ims" {
			continue
		}
		if !pdn.NASAccepted || !pdn.ModifyBearerAccepted || pdn.ActivationTimerActive {
			linkedEBI = pdn.DefaultEBI
			stopDefaultT3485Locked(ue, pdn)
			pdn.State = "activation-release-cleanup"
			break
		}
	}
	if linkedEBI == 0 {
		ue.Unlock()
		return false
	}
	keys := make([]string, 0)
	for key, tx := range ue.PendingBearerTransactions {
		if tx == nil || tx.Kind != bearerTxCreate || tx.LinkedEBI != linkedEBI {
			continue
		}
		for _, proc := range tx.Bearers {
			stopDedicatedT3485Locked(ue, proc)
		}
		keys = append(keys, key)
	}
	for id, procedure := range ue.PendingERABProcedures {
		if _, expected := procedure.ExpectedEBIs[linkedEBI]; expected {
			delete(ue.PendingERABProcedures, id)
		}
	}
	ue.Unlock()

	for _, key := range keys {
		s.failCreateBearerTransaction(ue, key, gtpv2.CauseUEIsNotResponding)
	}
	s.sendDeleteSessionForPDN(ue, linkedEBI, s.log)
	s.log.Warn("s1ap: incomplete IMS activation terminated on S1 release", zap.Uint8("linked_ebi", linkedEBI), zap.Int("failed_create_bearers", len(keys)), zap.Uint8("cause", gtpv2.CauseUEIsNotResponding))
	return true
}
