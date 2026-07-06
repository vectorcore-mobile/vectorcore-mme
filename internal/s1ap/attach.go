package s1ap

import (
	"context"
	"fmt"
	"net"
	"time"

	"go.uber.org/zap"

	nas "github.com/vectorcore/mme/internal/nas"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/esm"
	"github.com/vectorcore/mme/internal/nas/security"
	"github.com/vectorcore/mme/internal/gtpv2"
	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/models"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"github.com/vectorcore/mme/internal/uecontext"
)

// handleInitialUEMessage processes an Initial UE Message from an eNB.
// It creates a UE context, decodes the NAS payload, and triggers the auth flow.
func (s *Server) handleInitialUEMessage(remoteAddr string, p *pdu.PDU, ieList []pdu.ProtocolIE) {
	log := s.log.With(zap.String("remote", remoteAddr), zap.String("procedure", "InitialUE"))

	var enbUEID uint32
	var nasPDU []byte
	var tai *ies.TAI
	var ecgi *ies.ECGI
	var rrcCause uint8
	var mmec uint8
	var mtmsi uint32
	var stmsiPresent bool

	for _, ie := range ieList {
		switch ie.ID {
		case pdu.IEENBS1APID:
			id, err := ies.DecodeENBUEApID(ie.Value)
			if err != nil {
				log.Warn("s1ap: InitialUE: ENB UE S1AP ID decode error", zap.Error(err))
				return
			}
			enbUEID = id
		case pdu.IENAS_PDU:
			nasPDU, _ = ies.DecodeNASPDU(ie.Value)
		case pdu.IETAI:
			t, err := ies.DecodeTAI(ie.Value)
			if err == nil {
				tai = &t
			}
		case pdu.IECGI:
			e, err := ies.DecodeECGI(ie.Value)
			if err == nil {
				ecgi = &e
			}
		case pdu.IERRCEstablishmentCause:
			rrcCause, _ = ies.DecodeRRCEstablishmentCause(ie.Value)
		case pdu.IESTMSI:
			mmec, mtmsi, _ = ies.DecodeSTMSI(ie.Value)
			stmsiPresent = true
		}
	}

	if len(nasPDU) == 0 {
		log.Warn("s1ap: InitialUE: missing NAS PDU")
		return
	}

	_ = rrcCause

	// Allocate UE context
	ue := s.ueManager.Allocate()
	ue.Lock()
	ue.ENBS1APID = enbUEID
	ue.ENBGlobalID = remoteAddr
	if tai != nil {
		plmnBytes, _ := ies.EncodePLMN(tai.MCC, tai.MNC)
		emmTAI := emm.TAI{TAC: tai.TAC}
		if len(plmnBytes) == 3 {
			copy(emmTAI.PLMN[:], plmnBytes)
		}
		ue.TAI = &emmTAI
	}
	if ecgi != nil {
		plmnBytes, _ := ies.EncodePLMN(ecgi.MCC, ecgi.MNC)
		if len(plmnBytes) == 3 {
			copy(ue.ECGIPLMN[:], plmnBytes)
		}
		ue.ECGIECI = ecgi.ECGI
	}
	mmeUEID := ue.MMEUES1APID
	ue.Unlock()

	log = log.With(zap.Uint32("mme_ue_id", mmeUEID), zap.Uint32("enb_ue_id", enbUEID))
	log.Info("s1ap: Initial UE Message")

	// Decode plain NAS — Attach Request must be unprotected; TAU from an idle UE
	// arrives integrity-protected (the UE already has a security context).
	result, err := nas.Decode(nasPDU, 0, 0, nil, nil, 0)
	if err != nil {
		// Decoding failed: check if this is a security-protected TAU Request
		// (MAC verification requires the real UE keys, found only after GUTI lookup).
		secHdr, _, _ := emm.DecodeSecurityHeader(nasPDU)
		if secHdr == emm.SecurityHeaderIntegrityProtected ||
			secHdr == emm.SecurityHeaderIntegrityAndCipher {
			_, _, innerNAS, peekErr := emm.ParseSecurityProtected(nasPDU)
			if peekErr == nil {
				innerMsgType, _, _ := emm.ParsePlainNASMessage(innerNAS)
				if innerMsgType == emm.MsgTrackingAreaUpdateRequest {
					s.handleIdleTAUMessage(ue, tai, nasPDU)
					return
				}
			}
		}
		if secHdr == emm.SecurityHeaderServiceRequest {
			s.handleServiceRequest(ue, mmec, mtmsi, stmsiPresent, tai, nasPDU)
			return
		}
		log.Warn("s1ap: InitialUE: NAS decode error", zap.Error(err))
		s.ueManager.Remove(ue)
		return
	}

	// Plain TAU Request (EIA0 / no security context)
	if result.MsgType == emm.MsgTrackingAreaUpdateRequest {
		s.handleIdleTAUMessage(ue, tai, nasPDU)
		return
	}

	if result.PD != emm.PDEPSMobilityMgmt || result.MsgType != emm.MsgAttachRequest {
		log.Warn("s1ap: InitialUE: unexpected NAS message",
			zap.Uint8("pd", result.PD), zap.Uint8("msg_type", result.MsgType))
		s.ueManager.Remove(ue)
		return
	}

	ar, err := emm.DecodeAttachRequest(result.Inner)
	if err != nil {
		log.Warn("s1ap: InitialUE: Attach Request decode error", zap.Error(err))
		s.ueManager.Remove(ue)
		return
	}

	// Store UE network capability for SMC
	ue.Lock()
	ue.UENetworkCapability = ar.UENetworkCapability
	ue.Unlock()

	// Decode ESM container to get PTI
	if esmMsg, _ := esm.Decode(ar.ESMContainer); esmMsg != nil {
		ue.Lock()
		ue.PDNRequestPTI = esmMsg.Header.ProcedureTransactionID
		ue.Unlock()
	}

	// Resolve IMSI — either directly from Attach Request or via GUTI lookup
	imsi := ar.IMSI
	if imsi == "" && ar.GUTI != nil {
		// Attempt GUTI resolution from local DB
		gutiStr := uecontext.SerialiseGUTI(ar.GUTI)
		existing, ok := s.ueManager.GetByGUTI(gutiStr)
		if ok {
			existing.Lock()
			imsi = existing.IMSI
			existing.Unlock()
		}
	}

	if imsi == "" {
		// Need to send Identity Request
		log.Info("s1ap: InitialUE: no IMSI in Attach Request, requesting identity")
		s.sendIdentityRequest(remoteAddr, ue)
		return
	}

	log = log.With(zap.String("imsi", imsi))
	log.Info("s1ap: Attach Request", zap.Uint8("attach_type", ar.AttachType))

	// Evict stale context with the same IMSI before registering this one.
	if stale, ok := s.ueManager.GetByIMSI(imsi); ok && stale.MMEUES1APID != ue.MMEUES1APID {
		s.log.Warn("s1ap: evicting stale UE context for IMSI", zap.String("imsi", imsi))
		s.sendDeleteSession(stale)
		s.ueManager.Remove(stale)
	}
	// UpdateIMSI acquires ctx.mu internally; caller must NOT hold ctx.mu.
	s.ueManager.UpdateIMSI(ue, imsi)
	ue.Lock()
	ue.SetEMMState(emm.StateRegisteredInitiated)
	ue.AttachStep = uecontext.AttachStepWaitingAIA
	ue.Unlock()

	metrics.NASProceduresTotal.WithLabelValues("Attach", "request").Inc()
	metrics.S1APMessagesTotal.WithLabelValues("InitialUEMessage", "inbound", "ok").Inc()

	// Encode PLMN from config for S6a
	plmn, err := ies.EncodePLMN(s.nfCfg.MCC, s.nfCfg.MNC)
	if err != nil {
		log.Error("s1ap: failed to encode PLMN", zap.Error(err))
		s.ueManager.Remove(ue)
		return
	}
	var plmn3 [3]byte
	copy(plmn3[:], plmn)

	if err := s.s6a.SendAIR(imsi, plmn3, mmeUEID); err != nil {
		log.Error("s1ap: SendAIR failed", zap.Error(err))
		rejectPDU := emm.EncodeAttachReject(emm.CauseNetworkFailure)
		s.sendDownlinkNASTransport(remoteAddr, mmeUEID, enbUEID, rejectPDU)
		s.ueManager.Remove(ue)
	}
}

// sendIdentityRequest sends a NAS Identity Request (IMSI) to the UE.
func (s *Server) sendIdentityRequest(remoteAddr string, ue *uecontext.Context) {
	ue.Lock()
	mmeUEID := ue.MMEUES1APID
	enbUEID := ue.ENBS1APID
	ue.SetEMMState(emm.StateRegisteredInitiated)
	ue.AttachStep = uecontext.AttachStepWaitingAIA // we'll re-use this step; Identity Response precedes AIR
	ue.Unlock()

	idReq := emm.EncodeIdentityRequest(emm.IdentityTypeIMSI)
	s.sendDownlinkNASTransport(remoteAddr, mmeUEID, enbUEID, idReq)
}

// handleUplinkNASTransport processes an Uplink NAS Transport message from an eNB.
func (s *Server) handleUplinkNASTransport(remoteAddr string, p *pdu.PDU, ieList []pdu.ProtocolIE) {
	log := s.log.With(zap.String("remote", remoteAddr), zap.String("procedure", "UplinkNAS"))

	var mmeUEID uint32
	var enbUEID uint32
	var nasPDU []byte

	for _, ie := range ieList {
		switch ie.ID {
		case pdu.IEMMEUES1APID:
			id, err := ies.DecodeMMEUEApID(ie.Value)
			if err != nil {
				log.Warn("s1ap: UplinkNAS: MME UE S1AP ID decode error", zap.Error(err))
				return
			}
			mmeUEID = id
		case pdu.IEENBS1APID:
			id, _ := ies.DecodeENBUEApID(ie.Value)
			enbUEID = id
		case pdu.IENAS_PDU:
			nasPDU, _ = ies.DecodeNASPDU(ie.Value)
		}
	}

	_ = enbUEID

	if len(nasPDU) == 0 {
		log.Warn("s1ap: UplinkNAS: missing NAS PDU")
		return
	}

	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		log.Warn("s1ap: UplinkNAS: unknown MME UE S1AP ID", zap.Uint32("mme_ue_id", mmeUEID))
		return
	}

	metrics.S1APMessagesTotal.WithLabelValues("UplinkNASTransport", "inbound", "ok").Inc()

	if err := s.processNAS(ue, nasPDU); err != nil {
		log.Warn("s1ap: processNAS error", zap.Uint32("mme_ue_id", mmeUEID), zap.Error(err))
	}
}

// processNAS dispatches an uplink NAS PDU through the EMM state machine.
func (s *Server) processNAS(ue *uecontext.Context, raw []byte) error {
	ue.Lock()
	attachStep := ue.AttachStep
	emmState := ue.EMMState
	intAlg := ue.IntAlg
	encAlg := ue.EncAlg
	knasInt := ue.KNASint
	knasEnc := ue.KNASenc
	ulCountVal := uint32(ue.ULNASCount)
	mmeUEID := ue.MMEUES1APID
	ue.Unlock()

	log := s.log.With(zap.Uint32("mme_ue_id", mmeUEID))

	// Decode with appropriate security
	var result *nas.DecodeResult
	var err error

	switch {
	case attachStep == uecontext.AttachStepWaitingAuthResp:
		// Expect plain Auth Response (or Auth Failure)
		result, err = nas.Decode(raw, 0, 0, nil, nil, 0)
	case attachStep == uecontext.AttachStepWaitingSMCCplt:
		// SMC Complete arrives integrity-protected with new EPS security context
		result, err = nas.Decode(raw, intAlg, encAlg, knasInt, knasEnc, ulCountVal)
	case attachStep == uecontext.AttachStepWaitingAttachCplt:
		// Attach Complete arrives integrity-protected (and possibly ciphered)
		result, err = nas.Decode(raw, intAlg, encAlg, knasInt, knasEnc, ulCountVal)
		if err == nil {
			ue.Lock()
			ue.ULNASCount++
			ue.Unlock()
		}
	case attachStep == uecontext.AttachStepWaitingTAUComplete:
		// TAU Complete arrives integrity-protected (and possibly ciphered)
		result, err = nas.Decode(raw, intAlg, encAlg, knasInt, knasEnc, ulCountVal)
		if err == nil {
			ue.Lock()
			ue.ULNASCount++
			ue.Unlock()
		}
	case emmState == emm.StateRegistered:
		// Normal uplink: integrity + possibly ciphered
		ue.Lock()
		newCount := ue.IncrementULCount()
		ue.Unlock()
		result, err = nas.Decode(raw, intAlg, encAlg, knasInt, knasEnc, newCount)
	default:
		// Plain or early messages
		result, err = nas.Decode(raw, 0, 0, nil, nil, 0)
	}

	if err != nil {
		return fmt.Errorf("processNAS: decode: %w", err)
	}

	log.Debug("s1ap: processNAS",
		zap.Uint8("sec_hdr", result.SecHeaderType),
		zap.Uint8("pd", result.PD),
		zap.Uint8("msg_type", result.MsgType))

	switch result.PD {
	case emm.PDEPSMobilityMgmt:
		return s.processEMM(ue, result, attachStep)
	default:
		log.Warn("s1ap: processNAS: unexpected PD", zap.Uint8("pd", result.PD))
	}
	return nil
}

// processEMM handles an EMM message routed through processNAS.
func (s *Server) processEMM(ue *uecontext.Context, result *nas.DecodeResult, attachStep uint8) error {
	ue.Lock()
	mmeUEID := ue.MMEUES1APID
	enbAddr := ue.ENBGlobalID
	enbUEID := ue.ENBS1APID
	imsi := ue.IMSI
	ue.Unlock()

	log := s.log.With(zap.Uint32("mme_ue_id", mmeUEID), zap.Uint8("msg_type", result.MsgType))

	switch result.MsgType {
	case emm.MsgAuthenticationResponse:
		return s.processAuthResponse(ue, result.Inner, log)

	case emm.MsgAuthenticationFailure:
		log.Warn("s1ap: Authentication Failure from UE")
		rejectPDU := emm.EncodeAttachReject(emm.CauseMACFailure)
		s.sendDownlinkNASTransport(enbAddr, mmeUEID, enbUEID, rejectPDU)
		s.ueManager.Remove(ue)
		return nil

	case emm.MsgSecurityModeComplete:
		return s.processSMCComplete(ue, result.Inner, log)

	case emm.MsgSecurityModeReject:
		log.Warn("s1ap: Security Mode Reject from UE")
		rejectPDU := emm.EncodeAttachReject(emm.CauseSecurityModeRejectedUnspecified)
		s.sendDownlinkNASTransport(enbAddr, mmeUEID, enbUEID, rejectPDU)
		s.ueManager.Remove(ue)
		return nil

	case emm.MsgAttachComplete:
		return s.processAttachComplete(ue, log)

	case emm.MsgDetachRequest:
		return s.processDetach(ue, result.Inner, log)

	case emm.MsgIdentityResponse:
		return s.processIdentityResponse(ue, result.Inner, log)

	case emm.MsgTrackingAreaUpdateRequest:
		return s.processTrackingAreaUpdate(ue, result.Inner, log)

	case emm.MsgTrackingAreaUpdateComplete:
		return s.processTAUComplete(ue, log)

	default:
		log.Warn("s1ap: processEMM: unhandled EMM message type", zap.Uint8("msg_type", result.MsgType))
	}
	_ = imsi
	_ = attachStep
	return nil
}

// processAuthResponse verifies the Authentication Response from the UE.
func (s *Server) processAuthResponse(ue *uecontext.Context, body []byte, log *zap.Logger) error {
	ar, err := emm.DecodeAuthenticationResponse(body)
	if err != nil {
		return fmt.Errorf("processAuthResponse: decode: %w", err)
	}

	ue.Lock()
	xres := ue.XRES
	kasme := ue.KASME
	ueCap := ue.UENetworkCapability
	mmeUEID := ue.MMEUES1APID
	enbAddr := ue.ENBGlobalID
	enbUEID := ue.ENBS1APID
	ue.Unlock()

	if !security.VerifyRES(xres, ar.RES) {
		log.Warn("s1ap: Authentication Response: RES mismatch", zap.Uint32("mme_ue_id", mmeUEID))
		rejectPDU := emm.EncodeAttachReject(emm.CauseMACFailure)
		s.sendDownlinkNASTransport(enbAddr, mmeUEID, enbUEID, rejectPDU)
		s.ueManager.Remove(ue)
		return nil
	}

	// Select algorithms based on UE capability and network preference
	cap, capErr := emm.DecodeUENetworkCapability(ueCap)
	intAlg := security.AlgIDEIA0
	encAlg := security.AlgIDEEA0
	if capErr == nil {
		if id, ok := security.PreferredAlgorithm(s.secCfg.IntegrityAlgorithms, cap.SupportedIntegrityAlgs()); ok {
			intAlg = id
		}
		if id, ok := security.PreferredAlgorithm(s.secCfg.CipheringAlgorithms, cap.SupportedCipheringAlgs()); ok {
			encAlg = id
		}
	}

	// Derive NAS keys
	knasInt, knasEnc, err := security.DeriveNASKeys(kasme, intAlg, encAlg)
	if err != nil {
		return fmt.Errorf("processAuthResponse: DeriveNASKeys: %w", err)
	}

	ue.Lock()
	ue.IntAlg = intAlg
	ue.EncAlg = encAlg
	ue.KNASint = knasInt
	ue.KNASenc = knasEnc
	ue.AttachStep = uecontext.AttachStepWaitingSMCCplt
	dlCount := ue.IncrementDLCount()
	ue.Unlock()

	// Encode Security Mode Command (plain, integrity-protected with new KNASint)
	smcPlain := emm.EncodeSecurityModeCommand(intAlg, encAlg, ueCap)
	// SMC is sent integrity-protected with the new keys but NOT ciphered
	smcProtected, err := nas.EncodeIntegrityProtected(smcPlain, intAlg, knasInt, dlCount)
	if err != nil {
		return fmt.Errorf("processAuthResponse: encode SMC: %w", err)
	}

	s.sendDownlinkNASTransport(enbAddr, mmeUEID, enbUEID, smcProtected)
	log.Info("s1ap: Security Mode Command sent",
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.Uint8("int_alg", intAlg), zap.Uint8("enc_alg", encAlg))
	metrics.NASProceduresTotal.WithLabelValues("SecurityMode", "sent").Inc()
	return nil
}

// processSMCComplete handles a Security Mode Complete from the UE.
func (s *Server) processSMCComplete(ue *uecontext.Context, body []byte, log *zap.Logger) error {
	_, _ = emm.DecodeSecurityModeComplete(body) // parse IMEISV if present (ignore for Phase 1)

	ue.Lock()
	imsi := ue.IMSI
	ue.AttachStep = uecontext.AttachStepWaitingULA
	ue.Unlock()

	log.Info("s1ap: Security Mode Complete received, sending ULR")
	metrics.NASProceduresTotal.WithLabelValues("SecurityMode", "complete").Inc()

	plmn, err := ies.EncodePLMN(s.nfCfg.MCC, s.nfCfg.MNC)
	if err != nil {
		return fmt.Errorf("processSMCComplete: EncodePLMN: %w", err)
	}
	var plmn3 [3]byte
	copy(plmn3[:], plmn)

	ue.Lock()
	mmeUEID := ue.MMEUES1APID
	ue.Unlock()

	return s.s6a.SendULR(imsi, plmn3, mmeUEID)
}

// processAttachComplete handles a NAS Attach Complete from the UE.
func (s *Server) processAttachComplete(ue *uecontext.Context, log *zap.Logger) error {
	ue.Lock()
	ue.SetEMMState(emm.StateRegistered)
	ue.SetECMState(emm.ECMConnected)
	ue.AttachStep = uecontext.AttachStepNone
	mmeUEID := ue.MMEUES1APID
	imsi := ue.IMSI

	// Snapshot for MBR (sent after Attach Complete per TS 23.401 step 19)
	mbrENBUTEID := ue.ENBU_TEID
	mbrENBUIP := append(net.IP(nil), ue.ENBU_IP...)
	mbrSGWCTEID := ue.SGWC_TEID
	mbrDefaultEBI := ue.DefaultEBI

	// Snapshot for DB persist
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
	if ue.GUTI != nil {
		gutiStr := uecontext.SerialiseGUTI(ue.GUTI)
		dbCtx.GUTI = &gutiStr
	}
	if ue.TAI != nil {
		dbCtx.TAI = fmt.Sprintf("%02X%02X%02X-%04X", ue.TAI.PLMN[0], ue.TAI.PLMN[1], ue.TAI.PLMN[2], ue.TAI.TAC)
	}
	ue.Unlock()

	metrics.AttachedUEs.Inc()
	metrics.NASProceduresTotal.WithLabelValues("Attach", "complete").Inc()
	log.Info("s1ap: UE attached",
		zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi))

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.store.UpsertUEContext(ctx, dbCtx); err != nil {
			s.log.Warn("s1ap: failed to persist UE context", zap.Error(err))
		}
	}()

	// Send Modify Bearer Request now that UE is registered (TS 23.401 Figure 5.6.1.3-1 step 19).
	if mbrENBUTEID != 0 && mbrSGWCTEID != 0 && mbrDefaultEBI != 0 {
		mbr := &gtpv2.ModifyBearerRequest{
			SGWC_TEID: mbrSGWCTEID,
			EBI:       mbrDefaultEBI,
			ENBU_TEID: mbrENBUTEID,
			ENBU_IP:   mbrENBUIP,
			RATType:   gtpv2.RATTypeEUTRAN,
		}
		go func() {
			if err := s.s11.SendMBR(mmeUEID, mbr); err != nil {
				s.log.Warn("s1ap: SendMBR failed on Attach Complete", zap.Error(err))
			}
		}()
	}

	if s.operCfg.EMMInformation.Enabled && s.operCfg.EMMInformation.SendAfterAttach {
		go s.sendEMMInformation(mmeUEID, "attach", log)
	}

	return nil
}

// processDetach handles a NAS Detach Request from the UE.
func (s *Server) processDetach(ue *uecontext.Context, body []byte, log *zap.Logger) error {
	ue.Lock()
	mmeUEID := ue.MMEUES1APID
	enbAddr := ue.ENBGlobalID
	enbUEID := ue.ENBS1APID
	imsi := ue.IMSI
	ue.SetEMMState(emm.StateDeregisteredInitiated)
	ue.Unlock()

	log.Info("s1ap: Detach Request from UE",
		zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi))

	// Send Detach Accept
	detachAccept := emm.EncodeDetachAccept()
	s.sendDownlinkNASTransport(enbAddr, mmeUEID, enbUEID, detachAccept)

	// Purge UE at HSS
	go s.s6a.SendPUR(imsi)

	// Release S-GW bearer (SGWC_TEID cleared inside to prevent double-send)
	s.sendDeleteSession(ue)

	// Initiate UE context release; metrics.AttachedUEs.Dec() is called in
	// handleUEContextReleaseComplete once the eNB confirms release, guarded by
	// wasAttached — do not decrement here to avoid double-count.
	s.sendUEContextReleaseCommand(enbAddr, mmeUEID, enbUEID)

	metrics.NASProceduresTotal.WithLabelValues("Detach", "request").Inc()
	return nil
}

// processIdentityResponse handles a NAS Identity Response (IMSI).
func (s *Server) processIdentityResponse(ue *uecontext.Context, body []byte, log *zap.Logger) error {
	idResp, err := emm.DecodeIdentityResponse(body)
	if err != nil || idResp.IMSI == "" {
		log.Warn("s1ap: Identity Response: could not extract IMSI", zap.Error(err))
		ue.Lock()
		mmeUEID := ue.MMEUES1APID
		enbAddr := ue.ENBGlobalID
		enbUEID := ue.ENBS1APID
		ue.Unlock()
		rejectPDU := emm.EncodeAttachReject(emm.CauseUEIdentityCannotBeDerived)
		s.sendDownlinkNASTransport(enbAddr, mmeUEID, enbUEID, rejectPDU)
		s.ueManager.Remove(ue)
		return nil
	}

	// Evict stale context with the same IMSI before registering this one.
	if stale, ok := s.ueManager.GetByIMSI(idResp.IMSI); ok && stale.MMEUES1APID != ue.MMEUES1APID {
		s.log.Warn("s1ap: evicting stale UE context for IMSI", zap.String("imsi", idResp.IMSI))
		s.sendDeleteSession(stale)
		s.ueManager.Remove(stale)
	}
	// UpdateIMSI acquires ctx.mu internally; caller must NOT hold ctx.mu.
	s.ueManager.UpdateIMSI(ue, idResp.IMSI)
	ue.Lock()
	ue.AttachStep = uecontext.AttachStepWaitingAIA
	mmeUEID := ue.MMEUES1APID
	ue.Unlock()

	log.Info("s1ap: Identity Response: IMSI obtained", zap.String("imsi", idResp.IMSI))

	plmn, err := ies.EncodePLMN(s.nfCfg.MCC, s.nfCfg.MNC)
	if err != nil {
		return fmt.Errorf("processIdentityResponse: EncodePLMN: %w", err)
	}
	var plmn3 [3]byte
	copy(plmn3[:], plmn)

	return s.s6a.SendAIR(idResp.IMSI, plmn3, mmeUEID)
}
