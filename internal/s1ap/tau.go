package s1ap

import (
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/models"
	nas "github.com/vectorcore/mme/internal/nas"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/security"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/uecontext"
)

// validateTAI returns true if tai is in the configured TAI list.
// An empty TAI list permits all TAIs (permissive mode for unconfigured deployments).
func (s *Server) validateTAI(tai *emm.TAI) bool {
	if len(s.nfCfg.TAIList) == 0 {
		return true
	}
	for _, item := range s.nfCfg.TAIList {
		if item.TAC != tai.TAC {
			continue
		}
		plmn, err := encodeNASPLMN(item.MCC, item.MNC)
		if err != nil {
			continue
		}
		if plmn == tai.PLMN {
			return true
		}
	}
	return false
}

// taiFromIE converts an S1AP TAI IE to an EMM TAI.
func taiFromIE(t *ies.TAI) *emm.TAI {
	return emmTAIFromS1AP(t)
}

// handleIdleTAUMessage handles a TAU Request that arrived via Initial UE Message
// (ECM-IDLE path). tempUE is a freshly allocated context that must be removed
// before this function returns.
func (s *Server) handleIdleTAUMessage(tempUE *uecontext.Context, tai *ies.TAI, nasPDU []byte) {
	tempUE.Lock()
	remoteAddr := tempUE.ENBGlobalID
	tempMmeUEID := tempUE.MMEUES1APID
	enbUEID := tempUE.ENBS1APID
	tempUE.Unlock()

	log := s.log.With(
		zap.String("remote", remoteAddr),
		zap.String("procedure", "IdleTAU"),
	)

	// Peek into the NAS PDU to get the TAU Request body without verifying MAC yet.
	secHdr, _, _ := emm.DecodeSecurityHeader(nasPDU)
	protected := secHdr == emm.SecurityHeaderIntegrityProtected ||
		secHdr == emm.SecurityHeaderIntegrityAndCipher

	var tauBody []byte
	if protected {
		_, _, innerNAS, err := emm.ParseSecurityProtected(nasPDU)
		if err != nil {
			log.Warn("nas: idle TAU: parse security-protected failed", zap.Error(err))
			s.ueManager.Remove(tempUE)
			return
		}
		_, payload, err := emm.ParsePlainNASMessage(innerNAS)
		if err != nil {
			log.Warn("nas: idle TAU: parse inner NAS failed", zap.Error(err))
			s.ueManager.Remove(tempUE)
			return
		}
		tauBody = payload
	} else {
		if len(nasPDU) < 2 {
			s.ueManager.Remove(tempUE)
			return
		}
		tauBody = nasPDU[2:]
	}

	tauReq, err := emm.DecodeTAURequest(tauBody)
	if err != nil {
		log.Warn("nas: idle TAU: decode failed", zap.Error(err))
		s.sendTAUReject(tempMmeUEID, emm.CauseProtocolError)
		s.ueManager.Remove(tempUE)
		return
	}

	metrics.NASProceduresTotal.WithLabelValues("TAU", "request").Inc()
	log = log.With(
		zap.Uint8("update_type", tauReq.EPSUpdateType),
		zap.Bool("active_flag", tauReq.ActiveFlag),
		zap.Bool("security_protected", protected),
	)

	if tauReq.OldGUTI == nil {
		log.Warn("nas: idle TAU: no GUTI in TAU Request")
		s.sendTAUReject(tempMmeUEID, emm.CauseImplicitlyDetached)
		s.ueManager.Remove(tempUE)
		return
	}

	// Validate TAI
	if emmTAI := taiFromIE(tai); emmTAI != nil {
		if !s.validateTAI(emmTAI) {
			log.Warn("nas: idle TAU: TAI not in configured list", zap.Uint16("tac", emmTAI.TAC))
			s.sendTAUReject(tempMmeUEID, emm.CauseTrackingAreaNotAllowed)
			s.ueManager.Remove(tempUE)
			return
		}
	}

	// Find UE by old GUTI
	gutiStr := uecontext.SerialiseGUTI(tauReq.OldGUTI)
	ue, ok := s.ueManager.GetByGUTI(gutiStr)
	if !ok {
		// Try inter-MME TAU: resolve the old MME from the GUTI MMEC.
		if s.s10Cfg.Enabled {
			if peerAddr, found := s.resolveOldMME(tauReq.OldGUTI); found {
				go s.handleInterMMETAU(tempUE, tauReq.OldGUTI, peerAddr, tai, nasPDU)
				return
			}
		}
		log.Warn("nas: idle TAU: UE not found by GUTI", zap.String("guti", gutiStr))
		s.sendTAUReject(tempMmeUEID, emm.CauseImplicitlyDetached)
		s.ueManager.Remove(tempUE)
		return
	}

	ue.Lock()
	preEMMState := ue.EMMState.String()
	preECMState := ue.ECMState.String()
	preAttachStep := fmt.Sprintf("%d", ue.AttachStep)
	resumePending := tauReq.ActiveFlag &&
		ue.ECMState == emm.ECMConnected &&
		isResumeICSAttachStep(ue.AttachStep)
	preReleasePending := ue.S1ReleasePending
	preReleaseENBID := ue.S1ReleaseENBID
	preReleaseENBAddr := ue.S1ReleaseENBAddr
	preBearerStatus, preActiveBearers, preSkippedBearers := tauMMEBearerContextStatusSnapshotLocked(ue)
	ue.Unlock()
	log.Info("nas: idle TAU: matched retained UE context",
		zap.String("guti", gutiStr),
		zap.String("pre_emm_state", preEMMState),
		zap.String("pre_ecm_state", preECMState),
		zap.String("pre_attach_step", preAttachStep),
		zap.Bool("pre_s1_release_pending", preReleasePending),
		zap.Uint32("pre_s1_release_enb_ue_id", preReleaseENBID),
		zap.String("pre_s1_release_enb_addr", preReleaseENBAddr),
		zap.String("pre_eps_bearer_status_hex", tauBearerStatusHex(preBearerStatus)),
		zap.String("pre_active_bearers", preActiveBearers),
		zap.String("pre_skipped_bearers", preSkippedBearers))

	// Verify NAS MAC if security-protected
	if protected {
		ue.Lock()
		intAlg := ue.IntAlg
		encAlg := ue.EncAlg
		knasInt := ue.KNASint
		knasEnc := ue.KNASenc
		storedCount := uint32(ue.ULNASCount)
		ue.Unlock()

		sn := nasPDU[5]
		count := (storedCount & 0xFFFFFF00) | uint32(sn)
		if count <= storedCount {
			count += 0x100
		}

		if _, decErr := nas.Decode(nasPDU, intAlg, encAlg, knasInt, knasEnc, count); decErr != nil {
			log.Warn("nas: idle TAU: MAC verification failed", zap.Error(decErr))
			s.sendTAUReject(tempMmeUEID, emm.CauseMACFailure)
			s.ueManager.Remove(tempUE)
			return
		}

		ue.Lock()
		ue.ULNASCount = security.NASCount(count)
		ue.Unlock()
	}

	if resumePending {
		s.ueManager.Remove(tempUE)

		ue.Lock()
		oldENBUEID := ue.ENBS1APID
		oldRemoteAddr := ue.ENBGlobalID
		oldBindingGeneration := ue.S1BindingGeneration
		ue.ENBS1APID = enbUEID
		ue.ENBGlobalID = remoteAddr
		ue.S1BindingGeneration++
		ue.S1BindingState = uecontext.S1BindingActive
		ue.S1ReleasePending = false
		if emmTAI := taiFromIE(tai); emmTAI != nil {
			ue.TAI = emmTAI
		}
		mmeUEID := ue.MMEUES1APID
		newBindingGeneration := ue.S1BindingGeneration
		ue.Unlock()

		log.Info("nas: idle TAU duplicate active-flag resume rebound; retransmitting Initial Context Setup",
			zap.Uint32("mme_ue_id", mmeUEID),
			zap.Uint32("old_enb_ue_id", oldENBUEID),
			zap.Uint32("new_enb_ue_id", enbUEID),
			zap.String("old_remote", oldRemoteAddr),
			zap.String("new_remote", remoteAddr),
			zap.Uint64("old_binding_generation", oldBindingGeneration),
			zap.Uint64("new_binding_generation", newBindingGeneration))
		if err := s.sendIdleActiveTAUAcceptAndResume(ue, log, tauReq); err != nil {
			log.Warn("nas: idle TAU duplicate active-flag resume retransmit failed", zap.Error(err))
		}
		return
	}

	// Remove temp context before updating the real UE
	s.ueManager.Remove(tempUE)

	// Update UE context with new S1AP IDs, TAI, and state.
	// ECMConnected must be set here: the Initial UE Message opened a new S1 connection
	// so the UE is physically connected even before TAU Accept is sent. Without this,
	// handleDisconnect silently skips the UE (ECMIdle guard) and the S11 session leaks.
	ue.Lock()
	oldENBUEID := ue.ENBS1APID
	oldENBAddr := ue.ENBGlobalID
	oldBindingGeneration := ue.S1BindingGeneration
	oldMMEUEID := ue.MMEUES1APID
	obsoleteRelease := oldENBUEID != 0 && oldENBAddr != "" &&
		(oldENBUEID != enbUEID || oldENBAddr != remoteAddr)
	if obsoleteRelease {
		// A UE that reconnects faster than the eNB acknowledges a release can
		// leave more than one superseded binding outstanding at once; each is
		// tracked and retired independently as its own Release Complete arrives.
		ue.AddObsoleteS1Release(&uecontext.ObsoleteS1BindingRelease{
			MMEUES1APID:       oldMMEUEID,
			ENBS1APID:         oldENBUEID,
			ENBAddr:           oldENBAddr,
			BindingGeneration: oldBindingGeneration,
			CleanupGeneration: oldBindingGeneration + 1,
			Deadline:          time.Now().Add(30 * time.Second),
		})
	}
	ue.ENBS1APID = enbUEID
	ue.ENBGlobalID = remoteAddr
	ue.S1BindingGeneration++
	ue.S1BindingState = uecontext.S1BindingActive
	ue.S1ReleasePending = false
	// This is a new InitialUE-originated binding.  A deferred release from an
	// older TAU Complete must never be applied to this replacement binding.
	ue.IdleTAUReleaseAfterComplete = false
	if emmTAI := taiFromIE(tai); emmTAI != nil {
		ue.TAI = emmTAI
	}
	ue.SetEMMState(emm.StateTrackingAreaUpdating)
	ue.SetECMState(emm.ECMConnected)
	mmeUEID := ue.MMEUES1APID
	newBindingGeneration := ue.S1BindingGeneration
	ue.Unlock()
	if obsoleteRelease {
		log.Info("nas: idle TAU replacement binding old release sent",
			zap.Uint32("mme_ue_id", mmeUEID), zap.Uint32("old_enb_ue_id", oldENBUEID), zap.String("old_enb_addr", oldENBAddr),
			zap.Uint64("old_binding_generation", oldBindingGeneration), zap.Uint32("new_enb_ue_id", enbUEID),
			zap.String("new_enb_addr", remoteAddr), zap.Uint64("new_binding_generation", newBindingGeneration),
			zap.String("action", "old-binding-release-sent"))
		s.sendUEContextReleaseCommand(oldENBAddr, oldMMEUEID, oldENBUEID)
		s.scheduleObsoleteS1BindingCleanup(ue, oldBindingGeneration)
	}

	log.Info("nas: idle TAU: UE found, sending TAU Accept",
		zap.Uint32("mme_ue_id", mmeUEID))

	if tauReq.ActiveFlag && !s.operCfg.TAU.ReallocateGUTI {
		if err := s.sendIdleActiveTAUAcceptAndResume(ue, log, tauReq); err != nil {
			log.Warn("nas: idle TAU: active-flag TAU resume failed", zap.Error(err))
			return
		}
	} else {
		if err := s.sendTAUAcceptForRequest(ue, log, tauReq); err != nil {
			log.Warn("nas: idle TAU: sendTAUAccept failed", zap.Error(err))
			return
		}
		if tauReq.ActiveFlag {
			s.resumeIdleTAUUserPlane(ue, tauReq.EPSBearerStatus, nil, log)
		}
	}
	// When no GUTI realloc is pending the UE is immediately StateRegistered;
	// processTAUComplete never fires, so send EMM Information here.
	ue.Lock()
	step := ue.AttachStep
	ue.Unlock()
	if step == uecontext.AttachStepNone &&
		s.operCfg.EMMInformation.Enabled && s.operCfg.EMMInformation.SendAfterTAU {
		go s.sendEMMInformation(mmeUEID, "tau", log)
	}
	// InitialUE created this S1 signalling connection even if the retained
	// context says ECM-CONNECTED. An inactive TAU without a pending TAU Complete
	// or downlink follow-up must release that new access binding explicitly.
	if !tauReq.ActiveFlag && !(s.operCfg.EMMInformation.Enabled && s.operCfg.EMMInformation.SendAfterTAU) {
		if step == uecontext.AttachStepNone {
			s.beginIdleTAUPostAcceptRelease(ue, log)
		} else if step == uecontext.AttachStepWaitingTAUComplete {
			ue.Lock()
			ue.IdleTAUReleaseAfterComplete = true
			ue.Unlock()
		}
	}
}

// processTrackingAreaUpdate handles a TAU Request from a connected UE.
func (s *Server) processTrackingAreaUpdate(ue *uecontext.Context, inner []byte, log *zap.Logger) error {
	tauReq, err := emm.DecodeTAURequest(inner)
	if err != nil {
		return fmt.Errorf("processTrackingAreaUpdate: decode: %w", err)
	}

	metrics.NASProceduresTotal.WithLabelValues("TAU", "request").Inc()

	ue.Lock()
	mmeUEID := ue.MMEUES1APID
	tai := ue.TAI
	releaseWasPending := ue.S1ReleasePending
	ue.Unlock()

	if tai != nil && !s.validateTAI(tai) {
		log.Warn("nas: connected TAU: TAI not in configured list",
			zap.Uint32("mme_ue_id", mmeUEID))
		s.sendTAUReject(mmeUEID, emm.CauseTrackingAreaNotAllowed)
		return nil
	}

	ue.Lock()
	ue.SetEMMState(emm.StateTrackingAreaUpdating)
	if ue.S1ReleasePending {
		oldGeneration := ue.S1BindingGeneration
		ue.S1BindingGeneration++
		ue.S1BindingState = uecontext.S1BindingActive
		ue.S1ReleasePending = false
		log.Info("nas: connected TAU received during S1 release; preserving binding",
			zap.Uint32("mme_ue_id", mmeUEID),
			zap.Uint64("old_binding_generation", oldGeneration),
			zap.Uint64("binding_generation", ue.S1BindingGeneration),
			zap.String("selected_resolution", "release_cancelled_process_tau"),
			zap.Bool("release_cancelled", true),
			zap.Bool("binding_preserved", true))
	}
	ue.Unlock()

	log.Info("nas: connected TAU: sending TAU Accept",
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.Uint8("update_type", tauReq.EPSUpdateType))

	if err := s.sendTAUAcceptForRequest(ue, log, tauReq); err != nil {
		ue.Lock()
		ue.SetEMMState(emm.StateRegistered)
		ue.AttachStep = uecontext.AttachStepNone
		ue.Unlock()
		return err
	}
	ue.Lock()
	step := ue.AttachStep
	ue.Unlock()
	if step == uecontext.AttachStepNone && !releaseWasPending &&
		s.operCfg.EMMInformation.Enabled && s.operCfg.EMMInformation.SendAfterTAU {
		go s.sendEMMInformation(mmeUEID, "tau", log)
	}
	return nil
}

func (s *Server) sendIdleActiveTAUAcceptAndResume(ue *uecontext.Context, log *zap.Logger, req *emm.TAURequest) error {
	opts := s.tauAcceptOptionsForRequest(ue, log, req)
	nasPDU, err := s.buildTAUAcceptNAS(ue, log, opts)
	if err != nil {
		return err
	}
	if err := s.resumeIdleTAUUserPlane(ue, req.EPSBearerStatus, nasPDU, log); err != nil {
		return err
	}
	ue.Lock()
	ue.DLNASCount.Increment()
	ue.SetEMMState(emm.StateRegistered)
	ue.Unlock()
	metrics.NASProceduresTotal.WithLabelValues("TAU", "accept").Inc()
	log.Info("nas: TAU Accept sent",
		zap.Uint32("mme_ue_id", ue.MMEUES1APID),
		zap.Bool("guti_realloc", false),
		zap.Bool("send_success", true),
		zap.String("delivery", "initial_context_setup"))
	return nil
}

func (s *Server) resumeIdleTAUUserPlane(ue *uecontext.Context, requestStatus *emm.EPSBearerContextStatus, nasPDU []byte, log *zap.Logger) error {
	ue.Lock()
	resumeBearers, resumeErr := tauResumeBearersLocked(ue, requestStatus)
	mmeUEID := ue.MMEUES1APID
	defaultEBI := ue.DefaultEBI
	enbUEID := ue.ENBS1APID
	ue.AttachStep = uecontext.AttachStepWaitingICSRespTAU
	if resumeErr == nil && len(resumeBearers) > 0 {
		if err := s.createASSecuritySnapshotLocked(ue, "active_flag_tau"); err != nil {
			ue.AttachStep = uecontext.AttachStepNone
			ue.Unlock()
			log.Warn("nas: idle TAU active-flag AS security snapshot failed",
				zap.Uint32("mme_ue_id", mmeUEID),
				zap.Error(err))
			return err
		}
	}
	ue.Unlock()

	if resumeErr != nil {
		ue.Lock()
		ue.AttachStep = uecontext.AttachStepNone
		ue.Unlock()
		log.Warn("nas: idle TAU active-flag resume skipped due to incomplete retained bearer policy",
			zap.Uint32("mme_ue_id", mmeUEID),
			zap.Error(resumeErr))
		return nil
	}
	if len(resumeBearers) == 0 {
		ue.Lock()
		ue.AttachStep = uecontext.AttachStepNone
		ue.Unlock()
		log.Info("nas: idle TAU active-flag resume skipped because no retained bearers were found",
			zap.Uint32("mme_ue_id", mmeUEID))
		return nil
	}

	log.Info("nas: idle TAU active-flag triggering Initial Context Setup",
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.Uint32("enb_ue_id", enbUEID),
		zap.Uint8("default_ebi", defaultEBI),
		zap.String("ue_eps_bearer_status_hex", tauBearerStatusHex(requestStatus)),
		zap.String("ue_active_ebis", tauBearerStatusEBIString(requestStatus)),
		zap.Int("resume_bearer_count", len(resumeBearers)))

	if err := s.SendInitialContextSetupWithBearers(mmeUEID, nasPDU, resumeBearers); err != nil {
		ue.Lock()
		ue.AttachStep = uecontext.AttachStepNone
		ue.Unlock()
		log.Warn("nas: idle TAU active-flag Initial Context Setup failed",
			zap.Uint32("mme_ue_id", mmeUEID),
			zap.Error(err))
		return err
	}
	return nil
}

func tauResumeBearersLocked(ue *uecontext.Context, requestStatus *emm.EPSBearerContextStatus) ([]BearerInfo, error) {
	resumeBearers, err := retainedResumeBearersLocked(ue, true)
	if err != nil || requestStatus == nil {
		return resumeBearers, err
	}

	filtered := make([]BearerInfo, 0, len(resumeBearers))
	for _, bearer := range resumeBearers {
		if requestStatus.HasEBI(bearer.EBI) {
			filtered = append(filtered, bearer)
		}
	}
	return filtered, nil
}

// processTAUComplete handles a TAU Complete from the UE after GUTI reallocation.
func (s *Server) processTAUComplete(ue *uecontext.Context, log *zap.Logger) error {
	ue.Lock()
	oldGUTI := ue.PendingOldGUTI
	pendingGUTI := ue.PendingGUTI
	reallocPending := ue.GUTIReallocPending
	ue.SetEMMState(emm.StateRegistered)
	ue.AttachStep = uecontext.AttachStepNone
	ue.StopTimer(uecontext.TimerT3450)

	mmeUEID := ue.MMEUES1APID
	imsi := ue.IMSI

	ue.Unlock()

	if reallocPending && pendingGUTI != nil {
		s.ueManager.UpdateGUTI(ue, pendingGUTI)
		s.ueManager.RemoveGUTIAlias(ue, oldGUTI)
		ue.Lock()
		ue.PendingOldGUTI = nil
		ue.PendingGUTI = nil
		ue.GUTIReallocPending = false
		ue.GUTIReallocRetry = 0
		ue.GUTIReallocStartedAt = time.Time{}
		ue.PendingTAUAcceptNAS = nil
		ue.Unlock()
		log.Info("nas: TAU GUTI reallocation committed",
			zap.Uint32("mme_ue_id", mmeUEID),
			zap.String("imsi", imsi),
			zap.String("old_guti", serialiseGUTIForLog(oldGUTI)),
			zap.String("new_guti", serialiseGUTIForLog(pendingGUTI)),
			zap.Bool("database_updated", true))
	}

	metrics.NASProceduresTotal.WithLabelValues("TAU", "complete").Inc()
	s.refreshReachability(ue, "tau-complete")
	log.Info("nas: TAU Complete: UE re-registered",
		zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi))

	s.persistUERecoverySnapshot(ue, models.RecoveryStateActiveSnapshot, "ESTABLISHED")

	if s.operCfg.EMMInformation.Enabled && s.operCfg.EMMInformation.SendAfterTAU {
		go s.sendEMMInformation(mmeUEID, "tau", log)
	}
	ue.Lock()
	releaseAfterComplete := ue.IdleTAUReleaseAfterComplete
	ue.IdleTAUReleaseAfterComplete = false
	ue.Unlock()
	if releaseAfterComplete {
		s.beginIdleTAUPostAcceptRelease(ue, log)
	}

	return nil
}

func (s *Server) beginIdleTAUPostAcceptRelease(ue *uecontext.Context, log *zap.Logger) {
	ue.Lock()
	remote, enbID, pending := ue.ENBGlobalID, ue.ENBS1APID, ue.S1ReleasePending
	ue.Unlock()
	if remote == "" || enbID == 0 || pending {
		return
	}
	log.Info("nas: idle TAU: releasing inactive InitialUE signalling connection", zap.Uint32("enb_ue_id", enbID))
	s.beginPreservedS1Release(ue, remote, enbID, ies.CauseGroupNAS, ies.CauseNASNormalRelease)
}

type tauAcceptOptions struct {
	ReallocateGUTI     bool
	ReallocationReason string
	UpdateResult       uint8
	EPSBearerStatus    *emm.EPSBearerContextStatus
	LAI                *emm.LAI
	AdditionalResult   *uint8
	EMMCause           *uint8
}

// sendTAUAccept builds and sends a security-protected TAU Accept to the UE.
// Same-MME TAU does not reallocate GUTI by default; when no GUTI is included,
// TAU completes when the TAU Accept is sent and no TAU Complete is expected.
func (s *Server) sendTAUAccept(ue *uecontext.Context, log *zap.Logger) error {
	return s.sendTAUAcceptWithOptions(ue, log, tauAcceptOptions{
		ReallocateGUTI:     s.operCfg.TAU.ReallocateGUTI,
		ReallocationReason: "same_mme_policy",
		UpdateResult:       emm.EPSUpdateResultTAUpdated,
	})
}

func (s *Server) sendTAUAcceptWithGUTIReallocation(ue *uecontext.Context, log *zap.Logger, reason string) error {
	if reason == "" {
		reason = "explicit"
	}
	return s.sendTAUAcceptWithOptions(ue, log, tauAcceptOptions{
		ReallocateGUTI:     true,
		ReallocationReason: reason,
		UpdateResult:       emm.EPSUpdateResultTAUpdated,
	})
}

func (s *Server) sendTAUAcceptForRequest(ue *uecontext.Context, log *zap.Logger, req *emm.TAURequest) error {
	return s.sendTAUAcceptWithOptions(ue, log, s.tauAcceptOptionsForRequest(ue, log, req))
}

func (s *Server) tauAcceptOptionsForRequest(ue *uecontext.Context, log *zap.Logger, req *emm.TAURequest) tauAcceptOptions {
	updateResult := emm.EPSUpdateResultTAUpdated
	var nonEPSCause *uint8
	var lai *emm.LAI
	var additionalResult *uint8
	var requestStatus *emm.EPSBearerContextStatus
	reconcileRequestStatus := true
	if req != nil {
		updateResult, nonEPSCause, lai, additionalResult = s.tauAcceptResultForRequest(ue, req.EPSUpdateType)
		requestStatus = req.EPSBearerStatus
		// Reconcile the bearer-status view for active-flag TAU, where the UE is
		// explicitly requesting resume for its currently active bearers, and for
		// periodic TAU, where the bitmap represents the retained context.
		reconcileRequestStatus = req.ActiveFlag || req.EPSUpdateType == emm.EPSUpdateTypePeriodic
	}
	var reconciledDetails string
	if requestStatus != nil && reconcileRequestStatus {
		ue.Lock()
		reconciledDetails = tauReconcileBearerStatusLocked(ue, requestStatus)
		ue.Unlock()
	}
	ue.Lock()
	mmeStatus, activeDetails, skippedDetails := tauMMEBearerContextStatusSnapshotLocked(ue)
	mmeUEID := ue.MMEUES1APID
	imsi := ue.IMSI
	ue.Unlock()

	if requestStatus != nil {
		log.Info("nas: TAU EPS bearer context status evaluated",
			zap.Uint32("mme_ue_id", mmeUEID),
			zap.String("imsi", imsi),
			zap.String("ue_eps_bearer_status_hex", tauBearerStatusHex(requestStatus)),
			zap.String("ue_active_ebis", tauBearerStatusEBIString(requestStatus)),
			zap.String("mme_eps_bearer_status_hex", tauBearerStatusHex(mmeStatus)),
			zap.String("mme_active_ebis", tauBearerStatusEBIString(mmeStatus)),
			zap.String("mme_active_bearer_sources", activeDetails),
			zap.String("mme_skipped_bearers", skippedDetails),
			zap.String("tau_reconciled_bearers", reconciledDetails))
	}

	responseStatus := mmeStatus
	if requestStatus == nil {
		log.Info("nas: TAU Accept including MME EPS bearer context status",
			zap.Uint32("mme_ue_id", mmeUEID),
			zap.String("imsi", imsi),
			zap.String("mme_eps_bearer_status_hex", tauBearerStatusHex(mmeStatus)),
			zap.String("mme_active_ebis", tauBearerStatusEBIString(mmeStatus)),
			zap.String("mme_active_bearer_sources", activeDetails),
			zap.String("mme_skipped_bearers", skippedDetails),
			zap.String("reason", "default_mme_status_sync"))
	} else if !tauBearerStatusesEqual(requestStatus, mmeStatus) {
		if reconcileRequestStatus {
			responseStatus = tauIntersectBearerStatuses(requestStatus, mmeStatus)
			log.Info("nas: TAU EPS bearer context status mismatch",
				zap.Uint32("mme_ue_id", mmeUEID),
				zap.String("ue_eps_bearer_status_hex", tauBearerStatusHex(requestStatus)),
				zap.String("mme_eps_bearer_status_hex", tauBearerStatusHex(mmeStatus)),
				zap.String("tau_accept_eps_bearer_status_hex", tauBearerStatusHex(responseStatus)),
				zap.String("ue_active_ebis", tauBearerStatusEBIString(requestStatus)),
				zap.String("mme_active_ebis", tauBearerStatusEBIString(mmeStatus)),
				zap.String("tau_accept_active_ebis", tauBearerStatusEBIString(responseStatus)),
				zap.String("mme_active_bearer_sources", activeDetails),
				zap.String("mme_skipped_bearers", skippedDetails),
				zap.Bool("tau_accept_eps_bearer_status_included", true),
				zap.String("tau_accept_status_source", "intersection"))
		} else {
			log.Info("nas: TAU EPS bearer context status mismatch",
				zap.Uint32("mme_ue_id", mmeUEID),
				zap.String("ue_eps_bearer_status_hex", tauBearerStatusHex(requestStatus)),
				zap.String("mme_eps_bearer_status_hex", tauBearerStatusHex(mmeStatus)),
				zap.String("tau_accept_eps_bearer_status_hex", tauBearerStatusHex(responseStatus)),
				zap.String("ue_active_ebis", tauBearerStatusEBIString(requestStatus)),
				zap.String("mme_active_ebis", tauBearerStatusEBIString(mmeStatus)),
				zap.String("tau_accept_active_ebis", tauBearerStatusEBIString(responseStatus)),
				zap.String("mme_active_bearer_sources", activeDetails),
				zap.String("mme_skipped_bearers", skippedDetails),
				zap.Bool("tau_accept_eps_bearer_status_included", true),
				zap.String("tau_accept_status_source", "mme-retained"))
		}
	} else {
		log.Info("nas: TAU EPS bearer context status aligned",
			zap.Uint32("mme_ue_id", mmeUEID),
			zap.String("ue_eps_bearer_status_hex", tauBearerStatusHex(requestStatus)),
			zap.String("mme_eps_bearer_status_hex", tauBearerStatusHex(mmeStatus)),
			zap.String("mme_active_ebis", tauBearerStatusEBIString(mmeStatus)),
			zap.Bool("tau_accept_eps_bearer_status_included", true))
	}

	return tauAcceptOptions{
		ReallocateGUTI:     s.operCfg.TAU.ReallocateGUTI,
		ReallocationReason: "same_mme_policy",
		UpdateResult:       updateResult,
		EPSBearerStatus:    responseStatus,
		LAI:                lai,
		AdditionalResult:   additionalResult,
		EMMCause:           nonEPSCause,
	}
}

func (s *Server) buildTAUAcceptNAS(ue *uecontext.Context, log *zap.Logger, opts tauAcceptOptions) ([]byte, error) {
	ue.Lock()
	intAlg := ue.IntAlg
	encAlg := ue.EncAlg
	knasInt := append([]byte(nil), ue.KNASint...)
	knasEnc := append([]byte(nil), ue.KNASenc...)
	tai := ue.TAI
	mmeUEID := ue.MMEUES1APID
	dlCount := uint32(ue.DLNASCount)
	ue.Unlock()

	var taiList []emm.TAI
	for _, item := range s.nfCfg.TAIList {
		plmn, err := encodeNASPLMN(item.MCC, item.MNC)
		if err != nil {
			continue
		}
		taiList = append(taiList, emm.TAI{PLMN: plmn, TAC: item.TAC})
	}
	if len(taiList) == 0 && tai != nil {
		taiList = []emm.TAI{*tai}
	}

	t3412, t3402, t3423, timerErr := s.nasEMMTimers()
	if timerErr != nil {
		return nil, fmt.Errorf("sendTAUAccept: timers: %w", timerErr)
	}
	tauAcceptPDU := emm.EncodeTAUAcceptWithParams(emm.TAUAcceptParams{
		UpdateResult:             opts.UpdateResult,
		T3412:                    t3412,
		T3402:                    t3402,
		T3423:                    t3423,
		TAIList:                  taiList,
		IncludeGUTI:              false,
		EPSBearerStatus:          opts.EPSBearerStatus,
		EPSNetworkFeatureSupport: s.epsNetworkFeatureSupport(),
		LAI:                      opts.LAI,
		AdditionalUpdateResult:   opts.AdditionalResult,
		EMMCause:                 opts.EMMCause,
	})

	toSend := tauAcceptPDU
	if len(knasInt) > 0 {
		var encErr error
		toSend, encErr = nas.EncodeIntegrityAndCiphered(
			tauAcceptPDU, intAlg, encAlg, knasInt, knasEnc, dlCount)
		if encErr != nil {
			return nil, fmt.Errorf("sendTAUAccept: encode: %w", encErr)
		}
	}

	log.Info("nas: TAU Accept encoded",
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.Uint8("update_result", opts.UpdateResult),
		zap.Bool("guti_included", false),
		zap.String("reallocation_reason", opts.ReallocationReason),
		zap.Bool("ims_voice_over_ps_configured", s.nasCfg.EPSNetworkFeatureSupport.IMSVoiceOverPS),
		zap.Bool("ims_voice_over_ps_advertised", s.epsNetworkFeatureSupport() != nil),
		zap.Bool("eps_bearer_status_included", opts.EPSBearerStatus != nil),
		zap.String("eps_bearer_status_hex", tauBearerStatusHex(opts.EPSBearerStatus)),
		zap.String("eps_bearer_status_ebis", tauBearerStatusEBIString(opts.EPSBearerStatus)),
		zap.String("eps_network_feature_support_hex", fmt.Sprintf("%x", encodeFeatureSupportForLog(s.epsNetworkFeatureSupport()))),
		zap.String("plain_tau_accept_hex", fmt.Sprintf("%x", tauAcceptPDU)),
		zap.String("protected_tau_accept_hex", fmt.Sprintf("%x", toSend)),
		zap.Uint32("dl_count", dlCount),
		zap.Bool("t3450_started", false))
	return toSend, nil
}

func tauIntersectBearerStatuses(a, b *emm.EPSBearerContextStatus) *emm.EPSBearerContextStatus {
	if a == nil && b == nil {
		return nil
	}
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	return &emm.EPSBearerContextStatus{Bitmap: a.Bitmap & b.Bitmap}
}

func tauReconcileBearerStatusLocked(ue *uecontext.Context, requestStatus *emm.EPSBearerContextStatus) string {
	if ue == nil || requestStatus == nil {
		return "none"
	}

	changes := make([]string, 0, len(ue.PDNs)+len(ue.DedicatedBearers))

	for _, pdn := range sortedPDNContextsLocked(ue) {
		if pdn == nil || pdn.DefaultEBI == 0 {
			continue
		}
		if requestStatus.HasEBI(pdn.DefaultEBI) {
			continue
		}
		if tauPDNIsInactiveForStatusSync(pdn) {
			continue
		}
		changes = append(changes, fmt.Sprintf("pdn(apn=%s,ebi=%d,state=%s->tau-suspended)", pdn.APN, pdn.DefaultEBI, pdn.State))
		pdn.NASAccepted = false
		pdn.ERABEstablished = false
		pdn.ModifyBearerSent = false
		pdn.ModifyBearerAccepted = false
		pdn.ModifyBearerFailed = false
		pdn.ModifyBearerDeferred = false
		pdn.ModifyBearerFallbackSent = false
		pdn.ENBU_TEID = 0
		pdn.ENBU_IP = nil
		pdn.State = "tau-suspended"
	}

	for _, ebi := range sortedDedicatedBearerEBIsLocked(ue) {
		proc := ue.DedicatedBearers[ebi]
		if proc == nil || proc.AssignedEBI == 0 {
			continue
		}
		if requestStatus.HasEBI(proc.AssignedEBI) {
			continue
		}
		if tauDedicatedBearerInactive(proc) {
			continue
		}
		changes = append(changes, fmt.Sprintf("dedicated(ebi=%d,linked=%d,state=%s->tau-suspended)", proc.AssignedEBI, proc.LinkedEBI, proc.State))
		proc.NASAccepted = false
		proc.ERABEstablished = false
		proc.ERABFailed = false
		proc.ENBS1UTEID = 0
		proc.ENBS1UIP = nil
		proc.State = "tau-suspended"
	}

	if len(changes) == 0 {
		return "none"
	}
	return strings.Join(changes, "; ")
}

func (s *Server) sendTAUAcceptWithOptions(ue *uecontext.Context, log *zap.Logger, opts tauAcceptOptions) error {
	ue.Lock()
	intAlg := ue.IntAlg
	encAlg := ue.EncAlg
	knasInt := append([]byte(nil), ue.KNASint...)
	knasEnc := append([]byte(nil), ue.KNASenc...)
	tai := ue.TAI
	mmeUEID := ue.MMEUES1APID
	oldGUTI := cloneGUTI(ue.GUTI)
	existingPending := cloneGUTI(ue.PendingGUTI)
	reallocPending := ue.GUTIReallocPending
	dlCount := uint32(ue.DLNASCount)
	ue.Unlock()

	hasKeys := len(knasInt) > 0

	// Allocate a new GUTI only when policy/procedure explicitly requests it.
	// A same-MME TAU does not require GUTI reallocation, and forcing it causes
	// unnecessary TAU Complete dependency on ordinary idle returns.
	var newGUTI *emm.GUTI
	if opts.ReallocateGUTI && s.gutiAlloc != nil && hasKeys {
		if existingPending != nil {
			newGUTI = existingPending
		} else {
			allocated, err := s.gutiAlloc.AllocateUnique(func(g *emm.GUTI) bool {
				_, ok := s.ueManager.GetByGUTI(uecontext.SerialiseGUTI(g))
				return ok
			})
			if err != nil {
				return fmt.Errorf("sendTAUAccept: allocate GUTI: %w", err)
			}
			newGUTI = allocated
		}
	}

	// Build TAI list from config (fall back to UE's stored TAI)
	var taiList []emm.TAI
	for _, item := range s.nfCfg.TAIList {
		plmn, err := encodeNASPLMN(item.MCC, item.MNC)
		if err != nil {
			continue
		}
		taiList = append(taiList, emm.TAI{PLMN: plmn, TAC: item.TAC})
	}
	if len(taiList) == 0 && tai != nil {
		taiList = []emm.TAI{*tai}
	}

	t3412, t3402, t3423, timerErr := s.nasEMMTimers()
	if timerErr != nil {
		return fmt.Errorf("sendTAUAccept: timers: %w", timerErr)
	}
	tauAcceptPDU := emm.EncodeTAUAcceptWithParams(emm.TAUAcceptParams{
		UpdateResult:             opts.UpdateResult,
		T3412:                    t3412,
		T3402:                    t3402,
		T3423:                    t3423,
		TAIList:                  taiList,
		IncludeGUTI:              newGUTI != nil,
		GUTI:                     newGUTI,
		EPSBearerStatus:          opts.EPSBearerStatus,
		EPSNetworkFeatureSupport: s.epsNetworkFeatureSupport(),
		LAI:                      opts.LAI,
		AdditionalUpdateResult:   opts.AdditionalResult,
		EMMCause:                 opts.EMMCause,
	})

	var toSend []byte
	var encErr error
	if hasKeys {
		toSend, encErr = nas.EncodeIntegrityAndCiphered(
			tauAcceptPDU, intAlg, encAlg, knasInt, knasEnc, dlCount)
		if encErr != nil {
			return fmt.Errorf("sendTAUAccept: encode: %w", encErr)
		}
	} else {
		toSend = tauAcceptPDU
	}

	log.Info("nas: TAU Accept encoded",
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.Uint8("update_result", opts.UpdateResult),
		zap.Bool("guti_included", newGUTI != nil),
		zap.String("old_guti", serialiseGUTIForLog(oldGUTI)),
		zap.String("pending_new_guti", serialiseGUTIForLog(newGUTI)),
		zap.String("reallocation_reason", opts.ReallocationReason),
		zap.Bool("ims_voice_over_ps_configured", s.nasCfg.EPSNetworkFeatureSupport.IMSVoiceOverPS),
		zap.Bool("ims_voice_over_ps_advertised", s.epsNetworkFeatureSupport() != nil),
		zap.Bool("eps_bearer_status_included", opts.EPSBearerStatus != nil),
		zap.String("eps_bearer_status_hex", tauBearerStatusHex(opts.EPSBearerStatus)),
		zap.String("eps_bearer_status_ebis", tauBearerStatusEBIString(opts.EPSBearerStatus)),
		zap.String("eps_network_feature_support_hex", fmt.Sprintf("%x", encodeFeatureSupportForLog(s.epsNetworkFeatureSupport()))),
		zap.String("plain_tau_accept_hex", fmt.Sprintf("%x", tauAcceptPDU)),
		zap.String("protected_tau_accept_hex", fmt.Sprintf("%x", toSend)),
		zap.Uint32("dl_count", dlCount),
		zap.Bool("t3450_started", false))

	if err := s.SendDownlinkNAS(mmeUEID, toSend); err != nil {
		return fmt.Errorf("sendTAUAccept: send: %w", err)
	}

	var oldAlias *emm.GUTI
	var pendingAlias *emm.GUTI
	var retry int
	ue.Lock()
	ue.DLNASCount.Increment()
	if newGUTI != nil {
		if !reallocPending {
			ue.PendingOldGUTI = cloneGUTI(oldGUTI)
			ue.PendingGUTI = cloneGUTI(newGUTI)
			ue.GUTIReallocPending = true
			ue.GUTIReallocRetry = 0
			ue.GUTIReallocStartedAt = time.Now()
		} else {
			ue.GUTIReallocRetry++
		}
		ue.AttachStep = uecontext.AttachStepWaitingTAUComplete
		ue.PendingTAUAcceptNAS = append(ue.PendingTAUAcceptNAS[:0], toSend...)
		ue.StartTimer(uecontext.TimerT3450, 6*time.Second, func() {
			s.retransmitPendingTAUAccept(ue, log)
		})
		oldAlias = cloneGUTI(ue.PendingOldGUTI)
		pendingAlias = cloneGUTI(ue.PendingGUTI)
		retry = ue.GUTIReallocRetry
	} else {
		ue.SetEMMState(emm.StateRegistered)
		ue.AttachStep = uecontext.AttachStepNone
	}
	ue.Unlock()

	if newGUTI != nil {
		s.ueManager.AddGUTIAlias(ue, oldAlias)
		s.ueManager.AddGUTIAlias(ue, pendingAlias)
		log.Info("nas: TAU GUTI reallocation pending",
			zap.Uint32("mme_ue_id", mmeUEID),
			zap.String("old_guti", serialiseGUTIForLog(oldAlias)),
			zap.String("pending_new_guti", serialiseGUTIForLog(pendingAlias)),
			zap.String("primary_guti", serialiseGUTIForLog(oldAlias)),
			zap.Bool("old_alias_present", s.ueManager.GUTIAliasPresent(ue, oldAlias)),
			zap.Bool("new_alias_present", s.ueManager.GUTIAliasPresent(ue, pendingAlias)),
			zap.String("tau_state", "waiting_tau_complete"),
			zap.Int("t3450_retry_count", retry))
	}

	metrics.NASProceduresTotal.WithLabelValues("TAU", "accept").Inc()
	log.Info("nas: TAU Accept sent",
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.Bool("guti_realloc", newGUTI != nil),
		zap.Bool("send_success", true),
		zap.Bool("t3450_started", newGUTI != nil))
	return nil
}

func (s *Server) tauAcceptResultForRequest(ue *uecontext.Context, updateType uint8) (uint8, *uint8, *emm.LAI, *uint8) {
	// TS 24.301 v16.9.0 §5.5.3.3.4.2 permits combined TAU success for EPS and
	// SMS only.  SGd is not SGs/VLR registration, so this is available only
	// after the actual SMS-in-MME registration outcome is authoritative.
	if updateType == emm.EPSUpdateTypeCombined || updateType == emm.EPSUpdateTypeCombinedIMSIAttach {
		ue.Lock()
		smsRegistered := ue.SMSRegistrationState == uecontext.SMSRegistrationRegistered
		ue.Unlock()
		if s.sgdCfg.Enabled && smsRegistered {
			// Cisco's captured successful SGd flow uses periodic TAU. If a UE
			// does send a combined TAU, keep the result consistent with its
			// successful combined Attach without synthesising LAI/F2/CS state.
			return emm.EPSUpdateResultCombinedTALAUpdated, nil, nil, nil
		}
		// No operational SMS-in-MME outcome exists for this UE.  This remains
		// EPS-only rather than falsely reporting an SGs/VLR registration.
		cause := uint8(emm.CauseCSDomainNotAvailable)
		return emm.EPSUpdateResultTAUpdated, &cause, nil, nil
	}
	return emm.EPSUpdateResultTAUpdated, nil, nil, nil
}

func tauMMEBearerContextStatusLocked(ue *uecontext.Context) *emm.EPSBearerContextStatus {
	status, _, _ := tauMMEBearerContextStatusSnapshotLocked(ue)
	return status
}

func tauMMEBearerContextStatusSnapshotLocked(ue *uecontext.Context) (*emm.EPSBearerContextStatus, string, string) {
	if ue == nil {
		return nil, "", ""
	}
	var bitmap uint16
	active := make([]string, 0, 8)
	skipped := make([]string, 0, 8)
	if ue.DefaultEBI >= 5 && ue.DefaultEBI <= 15 && ue.SGWC_TEID != 0 && ue.SGWU_TEID != 0 {
		bitmap |= 1 << ue.DefaultEBI
		active = append(active, fmt.Sprintf("legacy-default(ebi=%d,sgwc=0x%08x,sgwu=0x%08x)", ue.DefaultEBI, ue.SGWC_TEID, ue.SGWU_TEID))
	} else if ue.DefaultEBI != 0 || ue.SGWC_TEID != 0 || ue.SGWU_TEID != 0 {
		skipped = append(skipped, fmt.Sprintf("legacy-default(ebi=%d,sgwc=0x%08x,sgwu=0x%08x)", ue.DefaultEBI, ue.SGWC_TEID, ue.SGWU_TEID))
	}
	for _, pdn := range sortedPDNContextsLocked(ue) {
		if pdn == nil {
			continue
		}
		if pdn.DefaultEBI < 5 || pdn.DefaultEBI > 15 || tauPDNIsInactiveForStatusSync(pdn) {
			skipped = append(skipped, fmt.Sprintf("pdn(apn=%s,ebi=%d,state=%s,disconnect=%t)", pdn.APN, pdn.DefaultEBI, pdn.State, pdn.DisconnectRequested))
			continue
		}
		if pdn.SGWC_TEID == 0 || pdn.SGWU_TEID == 0 {
			skipped = append(skipped, fmt.Sprintf("pdn(apn=%s,ebi=%d,state=%s,sgwc=0x%08x,sgwu=0x%08x)", pdn.APN, pdn.DefaultEBI, pdn.State, pdn.SGWC_TEID, pdn.SGWU_TEID))
			continue
		}
		bitmap |= 1 << pdn.DefaultEBI
		active = append(active, fmt.Sprintf("pdn(apn=%s,ebi=%d,state=%s,sgwc=0x%08x,sgwu=0x%08x,nas=%t,erab=%t,mbr=%t/%t)",
			pdn.APN, pdn.DefaultEBI, pdn.State, pdn.SGWC_TEID, pdn.SGWU_TEID, pdn.NASAccepted, pdn.ERABEstablished, pdn.ModifyBearerSent, pdn.ModifyBearerAccepted))
	}
	for _, ebi := range sortedDedicatedBearerEBIsLocked(ue) {
		proc := ue.DedicatedBearers[ebi]
		if proc == nil || proc.AssignedEBI < 5 || proc.AssignedEBI > 15 {
			continue
		}
		if tauDedicatedBearerInactive(proc) {
			skipped = append(skipped, fmt.Sprintf("dedicated(ebi=%d,linked=%d,state=%s,nas_accepted=%t,nas_rejected=%t,erab_established=%t,erab_failed=%t)",
				proc.AssignedEBI, proc.LinkedEBI, proc.State, proc.NASAccepted, proc.NASRejected, proc.ERABEstablished, proc.ERABFailed))
			continue
		}
		bitmap |= 1 << proc.AssignedEBI
		active = append(active, fmt.Sprintf("dedicated(ebi=%d,linked=%d,state=%s,qci=%d,nas_accepted=%t,erab_established=%t,sgw_teid=0x%08x,enb_teid=0x%08x)",
			proc.AssignedEBI, proc.LinkedEBI, proc.State, proc.QCI, proc.NASAccepted, proc.ERABEstablished, proc.SGWS1UTEID, proc.ENBS1UTEID))
	}
	return &emm.EPSBearerContextStatus{Bitmap: bitmap}, tauBearerDetailString(active), tauBearerDetailString(skipped)
}

func tauDedicatedBearerInactive(proc *uecontext.DedicatedBearerContext) bool {
	if proc == nil || proc.AssignedEBI == 0 || proc.NASRejected {
		return true
	}
	switch proc.State {
	case "deleting", "erab-setup-failed", "release-failed", "release-missing", "waiting_erab_release", "tau-suspended":
		return true
	default:
		return false
	}
}

func tauPDNIsInactiveForStatusSync(pdn *uecontext.PDNContext) bool {
	if pdn == nil || pdn.DefaultEBI == 0 {
		return true
	}
	if pdn.DisconnectRequested || pdn.DisconnectNASAccepted {
		return true
	}
	switch pdn.State {
	case "", "inactive", "disconnecting", "disconnected", "erab-setup-failed", "tau-suspended":
		return true
	default:
		return !pdn.NASAccepted && !pdn.ERABEstablished && !pdn.ModifyBearerAccepted
	}
}

func tauBearerStatusesEqual(a, b *emm.EPSBearerContextStatus) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Bitmap == b.Bitmap
}

func tauBearerStatusHex(status *emm.EPSBearerContextStatus) string {
	if status == nil {
		return ""
	}
	return fmt.Sprintf("%04x", status.Bitmap)
}

func tauBearerStatusEBIString(status *emm.EPSBearerContextStatus) string {
	if status == nil {
		return ""
	}
	active := status.ActiveEBIs()
	if len(active) == 0 {
		return "none"
	}
	out := make([]string, 0, len(active))
	for _, ebi := range active {
		out = append(out, fmt.Sprintf("%d", ebi))
	}
	return strings.Join(out, ",")
}

func tauBearerDetailString(parts []string) string {
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, "; ")
}

func (s *Server) retransmitPendingTAUAccept(ue *uecontext.Context, log *zap.Logger) {
	ue.Lock()
	if !ue.GUTIReallocPending || len(ue.PendingTAUAcceptNAS) == 0 {
		ue.Unlock()
		return
	}
	mmeUEID := ue.MMEUES1APID
	imsi := ue.IMSI
	enbAddr := ue.ENBGlobalID
	bindingGeneration := ue.S1BindingGeneration
	bindingState := ue.S1BindingState
	if enbAddr == "" {
		oldGUTI := cloneGUTI(ue.PendingOldGUTI)
		pendingGUTI := cloneGUTI(ue.PendingGUTI)
		ue.SetEMMState(emm.StateRegistered)
		ue.AttachStep = uecontext.AttachStepNone
		ue.GUTIReallocPending = false
		ue.GUTIReallocRetry = 0
		ue.GUTIReallocStartedAt = time.Time{}
		ue.PendingOldGUTI = nil
		ue.PendingGUTI = nil
		ue.PendingTAUAcceptNAS = nil
		ue.Unlock()
		s.ueManager.RemoveGUTIAlias(ue, pendingGUTI)
		s.ueManager.AddGUTIAlias(ue, oldGUTI)
		log.Warn("nas: T3450 expired without valid S1 binding; TAU GUTI reallocation rolled back",
			zap.Uint32("mme_ue_id", mmeUEID),
			zap.String("imsi", imsi),
			zap.String("old_guti", serialiseGUTIForLog(oldGUTI)),
			zap.String("pending_new_guti", serialiseGUTIForLog(pendingGUTI)),
			zap.Bool("valid_s1_binding", false),
			zap.Uint64("binding_generation", bindingGeneration),
			zap.String("binding_state", bindingState.String()),
			zap.Bool("retransmission_attempted", false),
			zap.String("rollback_reason", "no_s1_binding"),
			zap.Bool("s11_delete_required", false))
		return
	}
	retry := ue.GUTIReallocRetry + 1
	pdu := append([]byte(nil), ue.PendingTAUAcceptNAS...)
	oldGUTI := cloneGUTI(ue.PendingOldGUTI)
	pendingGUTI := cloneGUTI(ue.PendingGUTI)
	ue.GUTIReallocRetry = retry
	if retry >= 5 {
		ue.SetEMMState(emm.StateRegistered)
		ue.AttachStep = uecontext.AttachStepNone
		ue.GUTIReallocPending = false
		ue.GUTIReallocRetry = 0
		ue.GUTIReallocStartedAt = time.Time{}
		ue.PendingOldGUTI = nil
		ue.PendingGUTI = nil
		ue.PendingTAUAcceptNAS = nil
		ue.Unlock()
		s.ueManager.RemoveGUTIAlias(ue, pendingGUTI)
		s.ueManager.AddGUTIAlias(ue, oldGUTI)
		log.Warn("nas: T3450 retry exhausted; TAU GUTI reallocation rolled back",
			zap.Uint32("mme_ue_id", mmeUEID),
			zap.String("imsi", imsi),
			zap.String("old_guti", serialiseGUTIForLog(oldGUTI)),
			zap.String("pending_new_guti", serialiseGUTIForLog(pendingGUTI)),
			zap.Bool("s11_delete_required", false))
		return
	}
	ue.StartTimer(uecontext.TimerT3450, 6*time.Second, func() {
		s.retransmitPendingTAUAccept(ue, log)
	})
	ue.Unlock()

	if err := s.SendDownlinkNAS(mmeUEID, pdu); err != nil {
		log.Warn("nas: T3450 expired: TAU Accept retransmission failed",
			zap.Uint32("mme_ue_id", mmeUEID),
			zap.String("imsi", imsi),
			zap.Int("t3450_retry_count", retry),
			zap.Error(err))
		return
	}
	log.Warn("nas: T3450 expired: TAU Accept retransmitted",
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.String("imsi", imsi),
		zap.String("old_guti", serialiseGUTIForLog(oldGUTI)),
		zap.String("pending_new_guti", serialiseGUTIForLog(pendingGUTI)),
		zap.Int("t3450_retry_count", retry))
}

func cloneGUTI(g *emm.GUTI) *emm.GUTI {
	if g == nil {
		return nil
	}
	c := *g
	return &c
}

func serialiseGUTIForLog(g *emm.GUTI) string {
	if g == nil {
		return ""
	}
	return uecontext.SerialiseGUTI(g)
}

// sendTAUReject sends a plain TAU Reject to the UE identified by mmeUEID.
func (s *Server) sendTAUReject(mmeUEID uint32, cause uint8) {
	rejectPDU := emm.EncodeTAUReject(cause)
	if err := s.SendDownlinkNAS(mmeUEID, rejectPDU); err != nil {
		s.log.Warn("nas: sendTAUReject: send failed",
			zap.Uint32("mme_ue_id", mmeUEID), zap.Error(err))
	}
	metrics.NASProceduresTotal.WithLabelValues("TAU", "reject").Inc()
}
