package s1ap

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	nas "github.com/vectorcore/mme/internal/nas"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/security"
	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/models"
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
	if emmTAI := taiFromIE(tai); emmTAI != nil {
		ue.TAI = emmTAI
	}
	ue.SetEMMState(emm.StateTrackingAreaUpdating)
	ue.SetECMState(emm.ECMConnected)
	mmeUEID := ue.MMEUES1APID
	ue.Unlock()

	log.Info("nas: idle TAU: UE found, sending TAU Accept",
		zap.Uint32("mme_ue_id", mmeUEID))

	if err := s.sendTAUAccept(ue, log); err != nil {
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
	ue.Unlock()

	if tai != nil && !s.validateTAI(tai) {
		log.Warn("nas: connected TAU: TAI not in configured list",
			zap.Uint32("mme_ue_id", mmeUEID))
		s.sendTAUReject(mmeUEID, emm.CauseTrackingAreaNotAllowed)
		return nil
	}

	ue.Lock()
	ue.SetEMMState(emm.StateTrackingAreaUpdating)
	ue.Unlock()

	log.Info("nas: connected TAU: sending TAU Accept",
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.Uint8("update_type", tauReq.EPSUpdateType))

	if err := s.sendTAUAccept(ue, log); err != nil {
		return err
	}
	ue.Lock()
	step := ue.AttachStep
	ue.Unlock()
	if step == uecontext.AttachStepNone &&
		s.operCfg.EMMInformation.Enabled && s.operCfg.EMMInformation.SendAfterTAU {
		go s.sendEMMInformation(mmeUEID, "tau", log)
	}
	return nil
}

// processTAUComplete handles a TAU Complete from the UE after GUTI reallocation.
func (s *Server) processTAUComplete(ue *uecontext.Context, log *zap.Logger) error {
	ue.Lock()
	ue.SetEMMState(emm.StateRegistered)
	ue.AttachStep = uecontext.AttachStepNone
	ue.StopTimer(uecontext.TimerT3450)

	mmeUEID := ue.MMEUES1APID
	imsi := ue.IMSI

	dbCtx := &models.UEContext{
		MMEUES1APID:  ue.MMEUES1APID,
		IMSI:         ue.IMSI,
		EMMState:     ue.EMMState.String(),
		KASME:        append([]byte(nil), ue.KASME...),
		KNASint:      append([]byte(nil), ue.KNASint...),
		KNASenc:      append([]byte(nil), ue.KNASenc...),
		ULNASCount:   uint32(ue.ULNASCount),
		DLNASCount:   uint32(ue.DLNASCount),
		IntAlg:       ue.IntAlg,
		EncAlg:       ue.EncAlg,
		ENBS1APID:    ue.ENBS1APID,
		ENBGlobalID:  ue.ENBGlobalID,
		DefaultEBI:   uint32(ue.DefaultEBI),
		SGWU_TEID:    ue.SGWU_TEID,
		SGWC_TEID:    ue.SGWC_TEID,
		ENBU_TEID:    ue.ENBU_TEID,
		LastModified: time.Now().UTC().Format(time.RFC3339),
	}
	if ue.GUTI != nil {
		gutiStr := uecontext.SerialiseGUTI(ue.GUTI)
		dbCtx.GUTI = &gutiStr
	}
	if ue.TAI != nil {
		dbCtx.TAI = fmt.Sprintf("%02X%02X%02X-%04X",
			ue.TAI.PLMN[0], ue.TAI.PLMN[1], ue.TAI.PLMN[2], ue.TAI.TAC)
	}
	if ue.MSISDN != "" {
		ms := ue.MSISDN
		dbCtx.MSISDN = &ms
	}
	if ue.APN != "" {
		a := ue.APN
		dbCtx.APN = &a
	}
	if ue.UEIPv4 != nil {
		dbCtx.UEIPv4 = ue.UEIPv4.String()
	}
	if ue.SGWU_IP != nil {
		dbCtx.SGWU_IP = ue.SGWU_IP.String()
	}
	if ue.SGWC_IP != nil {
		dbCtx.SGWC_IP = ue.SGWC_IP.String()
	}
	if ue.ENBU_IP != nil {
		dbCtx.ENBU_IP = ue.ENBU_IP.String()
	}
	ue.Unlock()

	metrics.NASProceduresTotal.WithLabelValues("TAU", "complete").Inc()
	log.Info("nas: TAU Complete: UE re-registered",
		zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi))

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.store.UpsertUEContext(ctx, dbCtx); err != nil {
			s.log.Warn("nas: failed to persist UE context after TAU", zap.Error(err))
		}
	}()

	if s.operCfg.EMMInformation.Enabled && s.operCfg.EMMInformation.SendAfterTAU {
		go s.sendEMMInformation(mmeUEID, "tau", log)
	}

	return nil
}

// sendTAUAccept builds and sends a security-protected TAU Accept to the UE.
// If a GUTI allocator is configured, a new GUTI is assigned and the UE is
// moved to AttachStepWaitingTAUComplete (waiting for TAU Complete).
func (s *Server) sendTAUAccept(ue *uecontext.Context, log *zap.Logger) error {
	ue.Lock()
	intAlg := ue.IntAlg
	encAlg := ue.EncAlg
	knasInt := append([]byte(nil), ue.KNASint...)
	knasEnc := append([]byte(nil), ue.KNASenc...)
	tai := ue.TAI
	mmeUEID := ue.MMEUES1APID
	ue.Unlock()

	hasKeys := len(knasInt) > 0

	// Allocate a new GUTI when we have a security context (so the GUTI reallocation
	// is authenticated via TAU Complete).
	var newGUTI *emm.GUTI
	if s.gutiAlloc != nil && hasKeys {
		newGUTI = s.gutiAlloc.Allocate()
	}

	ue.Lock()
	if newGUTI != nil {
		// Don't set ue.GUTI here — UpdateGUTI (called after encoding) sets it
		// and removes the old GUTI index entry atomically.
		ue.AttachStep = uecontext.AttachStepWaitingTAUComplete
	} else {
		ue.SetEMMState(emm.StateRegistered)
		ue.AttachStep = uecontext.AttachStepNone
	}
	dlCount := ue.IncrementDLCount()
	ue.Unlock()

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

	tauAcceptPDU := emm.EncodeTAUAccept(0x00, 0x21, taiList, newGUTI)

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

	if err := s.SendDownlinkNAS(mmeUEID, toSend); err != nil {
		return fmt.Errorf("sendTAUAccept: send: %w", err)
	}

	// Start T3450 when waiting for TAU Complete (GUTI reallocation in progress)
	if newGUTI != nil {
		ue.Lock()
		ue.StartTimer(uecontext.TimerT3450, 6*time.Second, func() {
			log.Warn("nas: T3450 expired: TAU Complete not received",
				zap.Uint32("mme_ue_id", mmeUEID))
		})
		ue.Unlock()

		// Update GUTI index outside the context lock
		s.ueManager.UpdateGUTI(ue, newGUTI)
	}

	metrics.NASProceduresTotal.WithLabelValues("TAU", "accept").Inc()
	log.Info("nas: TAU Accept sent",
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.Bool("guti_realloc", newGUTI != nil))
	return nil
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
