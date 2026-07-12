package s1ap

import (
	"fmt"
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
		plmn, err := ies.EncodePLMN(item.MCC, item.MNC)
		if err != nil || len(plmn) != 3 {
			continue
		}
		if plmn[0] == tai.PLMN[0] && plmn[1] == tai.PLMN[1] && plmn[2] == tai.PLMN[2] {
			return true
		}
	}
	return false
}

// taiFromIE converts an S1AP TAI IE to an EMM TAI.
func taiFromIE(t *ies.TAI) *emm.TAI {
	if t == nil {
		return nil
	}
	emmTAI := &emm.TAI{TAC: t.TAC}
	plmn, err := ies.EncodePLMN(t.MCC, t.MNC)
	if err == nil && len(plmn) == 3 {
		copy(emmTAI.PLMN[:], plmn)
	}
	return emmTAI
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

	// Remove temp context before updating the real UE
	s.ueManager.Remove(tempUE)

	// Update UE context with new S1AP IDs, TAI, and state.
	// ECMConnected must be set here: the Initial UE Message opened a new S1 connection
	// so the UE is physically connected even before TAU Accept is sent. Without this,
	// handleDisconnect silently skips the UE (ECMIdle guard) and the S11 session leaks.
	ue.Lock()
	ue.ENBS1APID = enbUEID
	ue.ENBGlobalID = remoteAddr
	ue.S1BindingGeneration++
	ue.S1BindingState = uecontext.S1BindingActive
	ue.S1ReleasePending = false
	if emmTAI := taiFromIE(tai); emmTAI != nil {
		ue.TAI = emmTAI
	}
	ue.SetEMMState(emm.StateTrackingAreaUpdating)
	ue.SetECMState(emm.ECMConnected)
	mmeUEID := ue.MMEUES1APID
	ue.Unlock()

	log.Info("nas: idle TAU: UE found, sending TAU Accept",
		zap.Uint32("mme_ue_id", mmeUEID))

	if err := s.sendTAUAcceptForRequest(ue, log, tauReq); err != nil {
		log.Warn("nas: idle TAU: sendTAUAccept failed", zap.Error(err))
		return
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
	log.Info("nas: TAU Complete: UE re-registered",
		zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi))

	s.persistUERecoverySnapshot(ue, models.RecoveryStateActiveSnapshot, "ESTABLISHED")

	if s.operCfg.EMMInformation.Enabled && s.operCfg.EMMInformation.SendAfterTAU {
		go s.sendEMMInformation(mmeUEID, "tau", log)
	}

	return nil
}

type tauAcceptOptions struct {
	ReallocateGUTI     bool
	ReallocationReason string
	UpdateResult       uint8
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
	updateResult := emm.EPSUpdateResultTAUpdated
	if req != nil {
		updateResult = tauAcceptResultForRequest(req.EPSUpdateType)
	}
	return s.sendTAUAcceptWithOptions(ue, log, tauAcceptOptions{
		ReallocateGUTI:     s.operCfg.TAU.ReallocateGUTI,
		ReallocationReason: "same_mme_policy",
		UpdateResult:       updateResult,
	})
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
		plmn, err := ies.EncodePLMN(item.MCC, item.MNC)
		if err != nil || len(plmn) != 3 {
			continue
		}
		t := emm.TAI{TAC: item.TAC}
		copy(t.PLMN[:], plmn)
		taiList = append(taiList, t)
	}
	if len(taiList) == 0 && tai != nil {
		taiList = []emm.TAI{*tai}
	}

	tauAcceptPDU := emm.EncodeTAUAcceptWithParams(emm.TAUAcceptParams{
		UpdateResult:             opts.UpdateResult,
		T3412:                    0x21,
		TAIList:                  taiList,
		IncludeGUTI:              newGUTI != nil,
		GUTI:                     newGUTI,
		EPSNetworkFeatureSupport: s.epsNetworkFeatureSupport(),
	})

	var toSend []byte
	var encErr error
	if hasKeys {
		if encAlg != security.AlgIDEEA0 {
			toSend, encErr = nas.EncodeIntegrityAndCiphered(
				tauAcceptPDU, intAlg, encAlg, knasInt, knasEnc, dlCount)
		} else {
			toSend, encErr = nas.EncodeIntegrityProtected(
				tauAcceptPDU, intAlg, knasInt, dlCount)
		}
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

func tauAcceptResultForRequest(updateType uint8) uint8 {
	switch updateType {
	case emm.EPSUpdateTypeCombined, emm.EPSUpdateTypeCombinedIMSIAttach:
		return emm.EPSUpdateResultCombinedTALAUpdated
	default:
		return emm.EPSUpdateResultTAUpdated
	}
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
