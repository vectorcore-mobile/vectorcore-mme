package s1ap

import (
	"fmt"
	"net"
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/gtpv2"
	"github.com/vectorcore/mme/internal/gtpv2/s10"
	s11teid "github.com/vectorcore/mme/internal/gtpv2/s11"
	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/models"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/security"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/uecontext"
)

// resolveOldMME checks the S10 peer config for a peer whose MMEC matches the GUTI.
// Returns the peer's UDP address ("ip:port") if found.
func (s *Server) resolveOldMME(guti *emm.GUTI) (string, bool) {
	for _, peer := range s.s10Cfg.Peers {
		if peer.MMEC != guti.MMEC {
			continue
		}
		// If MMEGI is configured in the peer entry, verify it matches.
		if peer.MMEGI != 0 && peer.MMEGI != guti.MMEGI {
			continue
		}
		// If MCC/MNC are configured, verify the GUTI PLMN matches.
		if peer.MCC != "" && peer.MNC != "" {
			peerPLMN, err := ies.EncodePLMN(peer.MCC, peer.MNC)
			if err == nil && len(peerPLMN) == 3 {
				if peerPLMN[0] != guti.PLMN[0] || peerPLMN[1] != guti.PLMN[1] || peerPLMN[2] != guti.PLMN[2] {
					continue
				}
			}
		}
		if peer.Address == "" {
			continue
		}
		return peer.Address, true
	}
	return "", false
}

// handleInterMMETAU is the new-MME goroutine for inter-MME TAU. tempUE is the
// freshly allocated context from handleIdleTAUMessage; this goroutine takes ownership.
func (s *Server) handleInterMMETAU(tempUE *uecontext.Context, oldGUTI *emm.GUTI,
	peerAddr string, tai *ies.TAI, nasPDU []byte) {

	metrics.InterMMETAUTotal.WithLabelValues("attempt").Inc()

	tempUE.Lock()
	mmeUEID := tempUE.MMEUES1APID
	tempUE.Unlock()

	log := s.log.With(
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.String("peer_mme", peerAddr),
		zap.String("procedure", "InterMMETAU"),
	)

	// Build Sender F-TEID: IP from our S10 local address; TEID is filled by SendContextRequest.
	localFTEID, err := s10.BuildSenderFTEID(s.s10.LocalAddr(), 0)
	if err != nil {
		log.Warn("s10: cannot build Sender F-TEID", zap.Error(err))
		s.sendTAUReject(mmeUEID, emm.CauseNetworkFailure)
		s.ueManager.Remove(tempUE)
		metrics.InterMMETAUTotal.WithLabelValues("ctx_not_found").Inc()
		return
	}

	req := &s10.ContextRequest{
		SenderFTEID:   localFTEID,
		RawTAURequest: nasPDU,
	}

	ch, err := s.s10.SendContextRequest(peerAddr, req)
	if err != nil {
		log.Warn("s10: SendContextRequest failed", zap.Error(err))
		s.sendTAUReject(mmeUEID, emm.CauseNetworkFailure)
		s.ueManager.Remove(tempUE)
		metrics.InterMMETAUTotal.WithLabelValues("ctx_not_found").Inc()
		return
	}

	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()

	var result s10.ContextResult
	select {
	case result = <-ch:
	case <-timer.C:
		log.Warn("s10: Context Request timed out")
		s.sendTAUReject(mmeUEID, emm.CauseImplicitlyDetached)
		s.ueManager.Remove(tempUE)
		metrics.InterMMETAUTotal.WithLabelValues("ctx_timeout").Inc()
		return
	}

	if result.Err != nil {
		log.Warn("s10: Context Response error", zap.Error(result.Err))
		s.sendTAUReject(mmeUEID, emm.CauseNetworkFailure)
		s.ueManager.Remove(tempUE)
		metrics.InterMMETAUTotal.WithLabelValues("ctx_not_found").Inc()
		return
	}

	resp := result.Resp
	if resp.Cause != gtpv2.CauseRequestAccepted {
		log.Warn("s10: Context Response rejected", zap.Uint8("cause", resp.Cause))
		s.sendTAUReject(mmeUEID, emm.CauseImplicitlyDetached)
		s.ueManager.Remove(tempUE)
		metrics.InterMMETAUTotal.WithLabelValues("ctx_not_found").Inc()
		return
	}

	log.Info("s10: Context Response accepted", zap.String("imsi", resp.IMSI))
	s.importContextAndContinueTAU(tempUE, tai, peerAddr, resp, log)
}

// importContextAndContinueTAU fills tempUE from the Context Response and resumes the TAU flow.
// peerAddr is the old MME's "ip:port" (from peer config), used for the Context Acknowledge.
func (s *Server) importContextAndContinueTAU(tempUE *uecontext.Context, tai *ies.TAI,
	oldMMEAddr string, resp *s10.ContextResponse, log *zap.Logger) {

	mm := resp.MMContext
	pdn := resp.PDNConnection

	// Derive NAS keys from the imported KASME.
	knasInt, knasEnc, err := security.DeriveNASKeys(mm.KASME, mm.IntAlg, mm.EncAlg)
	if err != nil {
		log.Error("s10: DeriveNASKeys failed after context import", zap.Error(err))
		tempUE.Lock()
		mmeUEID := tempUE.MMEUES1APID
		tempUE.Unlock()
		s.sendTAUReject(mmeUEID, emm.CauseNetworkFailure)
		s.ueManager.Remove(tempUE)
		metrics.InterMMETAUTotal.WithLabelValues("ctx_not_found").Inc()
		return
	}

	tempUE.Lock()
	mmeUEID := tempUE.MMEUES1APID

	// Import security context.
	tempUE.KASME = make([]byte, len(mm.KASME))
	copy(tempUE.KASME, mm.KASME)
	tempUE.KNASint = knasInt
	tempUE.KNASenc = knasEnc
	tempUE.IntAlg = mm.IntAlg
	tempUE.EncAlg = mm.EncAlg
	tempUE.ULNASCount = security.NASCount(mm.ULNASCount)
	tempUE.DLNASCount = security.NASCount(mm.DLNASCount)
	if len(mm.NH) == 32 {
		tempUE.NH = make([]byte, 32)
		copy(tempUE.NH, mm.NH)
	}
	tempUE.NCC = mm.NCC
	tempUE.MSISDN = mm.MSISDN
	tempUE.APN = mm.APN

	// Import bearer context.
	tempUE.DefaultEBI = pdn.EBI
	tempUE.SGWC_TEID = pdn.SGWC_FTEID.TEID
	tempUE.SGWC_IP = pdn.SGWC_FTEID.IP
	tempUE.SGWU_TEID = pdn.SGWU_FTEID.TEID
	tempUE.SGWU_IP = pdn.SGWU_FTEID.IP
	tempUE.ENBU_TEID = pdn.ENBU_FTEID.TEID
	tempUE.ENBU_IP = pdn.ENBU_FTEID.IP
	tempUE.UEIPv4 = pdn.UEIPv4
	if pdn.APN != "" && tempUE.APN == "" {
		tempUE.APN = pdn.APN
	}

	// Store S10 transient state for the Context Acknowledge after ULA (if S6a enabled).
	tempUE.S10OldMMEAddr = oldMMEAddr
	tempUE.S10OldMMETEID = resp.SenderFTEID.TEID

	// Update TAI.
	if emmTAI := taiFromIE(tai); emmTAI != nil {
		tempUE.TAI = emmTAI
	}
	tempUE.SetEMMState(emm.StateTrackingAreaUpdating)
	// Mark connected: the Initial UE Message opened an S1 association for this TAU.
	// Without ECMConnected, handleDisconnect skips this UE and leaks the S11 session.
	tempUE.SetECMState(emm.ECMConnected)
	tempUE.Unlock()

	// Register by IMSI.
	s.ueManager.UpdateIMSI(tempUE, resp.IMSI)

	// Allocate a new GUTI for this MME if an allocator is available.
	if s.gutiAlloc != nil {
		newGUTI := s.gutiAlloc.Allocate()
		s.ueManager.UpdateGUTI(tempUE, newGUTI)
		tempUE.Lock()
		tempUE.GUTI = newGUTI
		tempUE.Unlock()
	}

	log.Info("s10: UE context imported", zap.String("imsi", resp.IMSI),
		zap.Uint32("mme_ue_id", mmeUEID))

	// If S6a is a real client, send ULR and wait for ULA before completing TAU.
	_, s6aNoop := s.s6a.(NoopS6aClient)
	if !s6aNoop {
		plmnBytes, err := security.EncodePLMN(s.nfCfg.MCC, s.nfCfg.MNC)
		if err != nil || len(plmnBytes) != 3 {
			log.Error("s10: failed to encode S6a visited PLMN", zap.Error(err))
			s.sendTAUReject(mmeUEID, emm.CauseNetworkFailure)
			return
		}
		var plmn [3]byte
		copy(plmn[:], plmnBytes)
		tempUE.Lock()
		tempUE.AttachStep = uecontext.AttachStepWaitingULAInterMMETAU
		imsi := tempUE.IMSI
		tempUE.Unlock()

		if err := s.s6a.SendULR(imsi, plmn, mmeUEID); err != nil {
			log.Error("s10: SendULR after context import failed", zap.Error(err))
			s.sendTAUReject(mmeUEID, emm.CauseNetworkFailure)
			_ = s.s10.SendContextAcknowledge(oldMMEAddr, resp.SenderFTEID.TEID,
				gtpv2.CauseRequestDenied)
			s.ueManager.Remove(tempUE)
			metrics.InterMMETAUTotal.WithLabelValues("ulr_error").Inc()
		}
		return
	}

	// S6a disabled: complete TAU immediately.
	s.finishInterMMETAU(tempUE, log, oldMMEAddr, resp.SenderFTEID.TEID)
}

// finishInterMMETAU completes the inter-MME TAU after context import (and optional ULA).
// Called directly (S6a disabled) or from HandleULAResult via s10Addr/s10TEID cleared from UE fields.
func (s *Server) finishInterMMETAU(ue *uecontext.Context, log *zap.Logger, s10Addr string, s10TEID uint32) {
	if log == nil {
		log = s.log
	}
	ue.Lock()
	mmeUEID := ue.MMEUES1APID
	ue.S10OldMMEAddr = ""
	ue.S10OldMMETEID = 0
	ue.Unlock()

	// Send TAU Accept with a new local GUTI after inter-MME context import.
	if err := s.sendTAUAcceptWithGUTIReallocation(ue, log, "inter_mme_tau"); err != nil {
		log.Warn("s10: sendTAUAccept failed after context import", zap.Error(err))
	}

	// Count the imported UE. The old MME decremented AttachedUEs in HandleContextAcknowledge;
	// we must increment here so the gauge stays accurate across the transfer.
	metrics.AttachedUEs.Inc()

	// When no GUTI realloc is pending the UE is immediately registered; send EMM Information.
	ue.Lock()
	step := ue.AttachStep
	ue.Unlock()
	if step == uecontext.AttachStepNone &&
		s.operCfg.EMMInformation.Enabled && s.operCfg.EMMInformation.SendAfterTAU {
		go s.sendEMMInformation(mmeUEID, "tau", log)
	}

	// Acknowledge the context transfer to the old MME.
	if s10Addr != "" {
		if err := s.s10.SendContextAcknowledge(s10Addr, s10TEID, gtpv2.CauseRequestAccepted); err != nil {
			log.Warn("s10: SendContextAcknowledge failed", zap.Error(err))
		}
	}

	// Send Modify Bearer Request to update the SGW with the new MME's S11 TEID.
	s.sendInterMMETAUMBR(ue, log)

	s.persistUERecoverySnapshot(ue, models.RecoveryStateActiveSnapshot, "ESTABLISHED")

	metrics.InterMMETAUTotal.WithLabelValues("success").Inc()
	log.Info("s10: inter-MME TAU complete", zap.Uint32("mme_ue_id", mmeUEID))
}

// sendInterMMETAUMBR allocates a new local S11 TEID and sends a Modify Bearer Request
// to notify the SGW of the new MME's control-plane endpoint.
func (s *Server) sendInterMMETAUMBR(ue *uecontext.Context, log *zap.Logger) {
	ue.Lock()
	sgwcTEID := ue.SGWC_TEID
	if sgwcTEID == 0 {
		ue.Unlock()
		return // no S11 session to update
	}
	ebi := ue.DefaultEBI
	sgwAddr := ue.SGWAddress
	enbuTEID := ue.ENBU_TEID
	enbuIP := ue.ENBU_IP
	mmeUEID := ue.MMEUES1APID
	localTEID := s11teid.AllocateTEID()
	ue.LocalS11TEID = localTEID
	ue.Unlock()

	req := &gtpv2.ModifyBearerRequest{
		SGWAddress: sgwAddr,
		SGWC_TEID:  sgwcTEID,
		EBI:        ebi,
		ENBU_TEID:  enbuTEID,
		ENBU_IP:    enbuIP,
		RATType:    gtpv2.RATTypeEUTRAN,
		MMEC_TEID:  localTEID,
		MMEC_IP:    net.IP(s.s11LocalIP),
	}
	if err := s.s11.SendMBR(mmeUEID, req); err != nil {
		log.Warn("s10: inter-MME TAU MBR failed (data path may degrade)",
			zap.Uint32("mme_ue_id", mmeUEID), zap.Error(err))
		metrics.InterMMETAUTotal.WithLabelValues("s11_error").Inc()
	}
}

// --- Old MME role ---

// HandleContextRequest implements ContextRequestHandler (old MME role).
// It finds the UE by the GUTI decoded from the TAU Request and returns the context.
func (s *Server) HandleContextRequest(srcAddr string, req *s10.ContextRequest) (
	*s10.ContextResponse, uint32, bool) {

	log := s.log.With(zap.String("src", srcAddr), zap.String("role", "old_mme"))

	guti, err := s.extractGUTIFromTAURequest(req.RawTAURequest)
	if err != nil {
		log.Warn("s10: cannot extract GUTI from TAU Request", zap.Error(err))
		return &s10.ContextResponse{Cause: gtpv2.CauseContextNotFound}, 0, false
	}

	gutiStr := uecontext.SerialiseGUTI(guti)
	ue, ok := s.ueManager.GetByGUTI(gutiStr)
	if !ok {
		log.Warn("s10: UE not found by GUTI", zap.String("guti", gutiStr))
		return &s10.ContextResponse{Cause: gtpv2.CauseContextNotFound}, 0, false
	}

	ue.Lock()
	mmeUEID := ue.MMEUES1APID
	imsi := ue.IMSI
	resp := &s10.ContextResponse{
		Cause: gtpv2.CauseRequestAccepted,
		IMSI:  imsi,
		MMContext: gtpv2.MMContextParams{
			IntAlg:     ue.IntAlg,
			EncAlg:     ue.EncAlg,
			NCC:        ue.NCC,
			ULNASCount: uint32(ue.ULNASCount),
			DLNASCount: uint32(ue.DLNASCount),
			KASME:      append([]byte(nil), ue.KASME...),
			NH:         append([]byte(nil), ue.NH...),
			MSISDN:     ue.MSISDN,
			APN:        ue.APN,
		},
		PDNConnection: gtpv2.PDNParams{
			EBI: ue.DefaultEBI,
			SGWC_FTEID: gtpv2.FTEID{
				InterfaceType: gtpv2.IFTypeS11S4SGW,
				TEID:          ue.SGWC_TEID,
				IP:            ue.SGWC_IP,
			},
			SGWU_FTEID: gtpv2.FTEID{
				InterfaceType: gtpv2.IFTypeS1USGW,
				TEID:          ue.SGWU_TEID,
				IP:            ue.SGWU_IP,
			},
			ENBU_FTEID: gtpv2.FTEID{
				InterfaceType: gtpv2.IFTypeS1UENB,
				TEID:          ue.ENBU_TEID,
				IP:            ue.ENBU_IP,
			},
			UEIPv4: ue.UEIPv4,
			APN:    ue.APN,
		},
	}
	ue.Unlock()

	log.Info("s10: sending Context Response", zap.String("imsi", imsi), zap.Uint32("mme_ue_id", mmeUEID))
	metrics.S10MessagesTotal.WithLabelValues("ctx_response", "prepared").Inc()
	return resp, mmeUEID, true
}

// HandleContextAcknowledge implements ContextRequestHandler (old MME role).
// On successful acknowledge: release S1 connection if connected and remove the UE locally.
// The S11 bearer is NOT deleted — the new MME now owns it.
func (s *Server) HandleContextAcknowledge(mmeUEID uint32, cause uint8) {
	log := s.log.With(zap.Uint32("mme_ue_id", mmeUEID), zap.Uint8("cause", cause))

	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		log.Warn("s10: HandleContextAcknowledge: UE not found")
		return
	}

	if cause != gtpv2.CauseRequestAccepted {
		// New MME aborted the transfer — leave the UE in place.
		log.Warn("s10: Context Acknowledge denied, keeping local UE context")
		return
	}

	ue.Lock()
	enbAddr := ue.ENBGlobalID
	enbUEID := ue.ENBS1APID
	ecmState := ue.ECMState
	wasAttached := ue.EMMState == emm.StateRegistered
	imsi := ue.IMSI
	ue.StopAllTimers()
	// Zero SGWC_TEID so sendDeleteSession is a no-op if accidentally invoked.
	ue.SGWC_TEID = 0
	ue.Unlock()

	log.Info("s10: context transferred, releasing local S1 context", zap.String("imsi", imsi))

	// Release the S1 signalling connection if the UE was ECM-CONNECTED.
	if ecmState == emm.ECMConnected && enbAddr != "" {
		s.sendUEContextReleaseCommandCause(enbAddr, mmeUEID, enbUEID,
			ies.CauseGroupNAS, ies.CauseNASDetach)
	}

	// Remove from all manager indexes. Do NOT send a Delete Session Request —
	// the S11 bearer is transferred to the new MME, not torn down.
	s.ueManager.Remove(ue)
	if wasAttached {
		metrics.AttachedUEs.Dec()
	}
}

// extractGUTIFromTAURequest decodes the raw NAS PDU (TAU Request) and returns the old GUTI.
func (s *Server) extractGUTIFromTAURequest(nasPDU []byte) (*emm.GUTI, error) {
	if len(nasPDU) < 2 {
		return nil, fmt.Errorf("s10: raw TAU Request too short")
	}
	// The TAU Request may arrive plain or security-protected.
	secHdr := nasPDU[0] & 0x0F // lower nibble is the security header type
	var body []byte
	if secHdr == emm.SecurityHeaderIntegrityProtected || secHdr == emm.SecurityHeaderIntegrityAndCipher {
		if len(nasPDU) < 7 {
			return nil, fmt.Errorf("s10: security-protected TAU Request too short")
		}
		_, _, inner, err := emm.ParseSecurityProtected(nasPDU)
		if err != nil {
			return nil, fmt.Errorf("s10: parse security header: %w", err)
		}
		_, body2, err := emm.ParsePlainNASMessage(inner)
		if err != nil {
			return nil, fmt.Errorf("s10: parse inner NAS: %w", err)
		}
		body = body2
	} else {
		// Plain NAS — skip 2-byte header (security-header-type + message-type).
		body = nasPDU[2:]
	}
	tauReq, err := emm.DecodeTAURequest(body)
	if err != nil {
		return nil, fmt.Errorf("s10: decode TAU Request: %w", err)
	}
	if tauReq.OldGUTI == nil {
		return nil, fmt.Errorf("s10: TAU Request has no GUTI")
	}
	return tauReq.OldGUTI, nil
}
