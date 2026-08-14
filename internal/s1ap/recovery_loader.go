package s1ap

import (
	"context"
	"net"
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/models"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/security"
	"github.com/vectorcore/mme/internal/repository"
	"github.com/vectorcore/mme/internal/uecontext"
)

// recoverUEFromStore is the lazy recovery loader: it is called only after an
// in-memory GUTI lookup misses, which after a restart is the normal case for
// every UE that was MM-REGISTERED / ECM-IDLE before the process restarted.
// It rehydrates just enough of the persisted snapshot to let the TAU or
// Service Request that triggered the lookup be evaluated against a real
// context instead of forcing a full re-attach: identity, NAS security
// context, and reachability timers. Data-plane bearer state (SGW/eNB U-plane
// TEIDs) is deliberately left unset — those bindings do not survive an MME
// restart and must be re-established fresh via ICS/Modify Bearer regardless.
//
// Returns (nil, false) if the record does not exist, is not eligible for
// recovery (the UE was explicitly detached or its cleanup already
// completed), or the reconstructed context lost a race against another
// recovery for the same IMSI.
func (s *Server) recoverUEFromStore(gutiStr string) (*uecontext.Context, bool) {
	if !s.recoveryPersistent || s.store == nil || gutiStr == "" {
		return nil, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rec, err := s.store.GetUERecoveryByGUTI(ctx, gutiStr)
	if err != nil {
		if err != repository.ErrNotFound {
			s.log.Warn("s1ap: recovery lookup by GUTI failed", zap.String("guti", gutiStr), zap.Error(err))
		}
		return nil, false
	}
	if !recoveryEligible(rec.RecoveryState) {
		return nil, false
	}
	if rec.IMSI == "" {
		return nil, false
	}
	if _, ok := s.ueManager.GetByIMSI(rec.IMSI); ok {
		// Already recovered (or freshly attached) by a racing goroutine.
		return nil, false
	}

	guti, err := uecontext.DeserialiseGUTI(rec.CurrentGUTI)
	if err != nil {
		s.log.Warn("s1ap: recovery record has unparsable GUTI", zap.String("imsi", rec.IMSI), zap.Error(err))
		return nil, false
	}

	var sess *models.SessionRecoveryRecord
	if sessions, err := s.store.ListSessionRecoveryRecords(ctx, rec.IMSI); err != nil {
		s.log.Warn("s1ap: failed to load session recovery records", zap.String("imsi", rec.IMSI), zap.Error(err))
	} else if len(sessions) > 0 {
		sess = &sessions[0] // most recently updated, per store ordering
	}

	ue := s.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = rec.IMSI
	ue.IMEI = rec.IMEISV
	ue.MSISDN = rec.MSISDN
	ue.GUTI = guti
	ue.KASME = append([]byte(nil), rec.KASME...)
	ue.NASKSI = rec.NASKSI
	ue.ULNASCount = security.NASCount(rec.UplinkNASCount)
	ue.DLNASCount = security.NASCount(rec.DownlinkNASCount)
	if err := ue.ActivateSecurityContext(rec.NASIntegrityAlg, rec.NASCipheringAlg); err != nil {
		ue.Unlock()
		s.ueManager.Remove(ue)
		s.log.Warn("s1ap: recovery: failed to derive NAS keys", zap.String("imsi", rec.IMSI), zap.Error(err))
		return nil, false
	}
	if sess != nil {
		ue.APN = sess.APN
		ue.DefaultEBI = sess.DefaultEBI
		ue.LocalS11TEID = sess.MMES11TEID
		ue.SGWC_TEID = sess.SGWS11TEID
		ue.SGWAddress = sess.SGWS11IP
		if ip := net.ParseIP(sess.SGWS11IP); ip != nil {
			ue.SGWC_IP = ip
		}
		if ip := net.ParseIP(sess.UEIPv4); ip != nil {
			ue.UEIPv4 = ip
		}
	}
	ue.SetEMMState(emm.StateRegistered)
	ue.SetECMState(emm.ECMIdle)
	mmeID := ue.MMEUES1APID
	ue.Unlock()

	s.ueManager.Register(ue)
	// A racing recovery (or fresh attach) may have registered this IMSI
	// between the check above and Register(); the loser yields.
	if winner, ok := s.ueManager.GetByIMSI(rec.IMSI); !ok || winner != ue {
		s.ueManager.Remove(ue)
		return nil, false
	}

	s.RestoreReachability(ue, *rec)

	s.log.Info("s1ap: recovered UE context from persisted store",
		zap.Uint32("mme_ue_id", mmeID), zap.String("imsi", rec.IMSI), zap.String("guti", gutiStr),
		zap.String("recovery_state", rec.RecoveryState))
	return ue, true
}

func recoveryEligible(state string) bool {
	switch state {
	case models.RecoveryStateDetached, models.RecoveryStateExpired, models.RecoveryStateCleanedUp:
		return false
	default:
		return true
	}
}
