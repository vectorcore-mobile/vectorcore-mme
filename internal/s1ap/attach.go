package s1ap

import (
	"encoding/hex"
	"fmt"
	"net"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/gtpv2"
	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/models"
	nas "github.com/vectorcore/mme/internal/nas"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/esm"
	"github.com/vectorcore/mme/internal/nas/security"
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
	var stmsiRaw []byte
	var stmsiPresent bool

	for idx, ie := range ieList {
		log.Debug("s1ap: InitialUE IE",
			zap.Int("ie_index", idx),
			zap.Uint16("ie_id", ie.ID),
			zap.String("criticality", ie.Criticality.String()),
			zap.Int("open_type_len", len(ie.Value)),
			zap.String("raw", hex.EncodeToString(ie.Value)))
		switch ie.ID {
		case pdu.IEENBS1APID:
			id, err := ies.DecodeENBUEApID(ie.Value)
			if err != nil {
				log.Warn("s1ap: InitialUE: ENB UE S1AP ID decode error",
					zap.Int("open_type_len", len(ie.Value)),
					zap.String("raw", hex.EncodeToString(ie.Value)),
					zap.Error(err))
				return
			}
			enbUEID = id
			log.Debug("s1ap: InitialUE eNB-UE-S1AP-ID decoded", zap.Uint32("enb_ue_id", enbUEID))
		case pdu.IENAS_PDU:
			nasPDU, _ = ies.DecodeNASPDU(ie.Value)
		case pdu.IETAI:
			taiValue := ie.Value

			// InitialUEMessage TAI open type may include the APER SEQUENCE prefix:
			// ext=0 and iE-Extensions absent=0, aligned to one byte.
			// The semantic TAI value is PLMN[3] + TAC[2].
			if len(taiValue) == 6 && taiValue[0] == 0x00 {
				taiValue = taiValue[1:]
			}

			t, err := ies.DecodeTAI(taiValue)
			if err == nil {
				tai = &t
			} else {
				log.Warn("s1ap: InitialUE: TAI decode error",
					zap.String("raw", hex.EncodeToString(ie.Value)),
					zap.String("tai_value", hex.EncodeToString(taiValue)),
					zap.Error(err),
				)
			}
		case pdu.IECGI:
			e, err := ies.DecodeECGI(ie.Value)
			if err == nil {
				ecgi = &e
			}
		case pdu.IERRCEstablishmentCause:
			rrcCause, _ = ies.DecodeRRCEstablishmentCause(ie.Value)
		case pdu.IESTMSI:
			stmsiRaw = append([]byte(nil), ie.Value...)
			decodedMMEC, decodedMTMSI, err := ies.DecodeSTMSI(ie.Value)
			if err != nil {
				log.Warn("s1ap: ServiceRequest: S-TMSI decode error",
					zap.String("stmsi_raw", hex.EncodeToString(ie.Value)),
					zap.Error(err))
			} else {
				mmec = decodedMMEC
				mtmsi = decodedMTMSI
				log.Info("s1ap: ServiceRequest: S-TMSI decoded from InitialUE",
					zap.String("stmsi_raw", hex.EncodeToString(ie.Value)),
					zap.Uint8("mmec", mmec),
					zap.Uint32("mtmsi", mtmsi),
					zap.String("mtmsi_hex", fmt.Sprintf("0x%08x", mtmsi)))
			}
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
			s.handleServiceRequest(ue, mmec, mtmsi, stmsiRaw, stmsiPresent, tai, nasPDU)
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
	ue.InitialAttachRequestNAS = append([]byte(nil), nasPDU...)
	ue.Unlock()

	// Decode ESM container to get PTI
	if esmMsg, _ := esm.Decode(ar.ESMContainer); esmMsg != nil {
		pdnReq := esm.DecodePDNConnectivityRequest(ar.ESMContainer)
		var pco []byte
		if pdnReq != nil {
			pco = append([]byte(nil), pdnReq.PCO...)
		}
		ue.Lock()
		ue.PDNRequestPTI = esmMsg.Header.ProcedureTransactionID
		ue.ESMContainer = append([]byte(nil), ar.ESMContainer...)
		ue.PDNRequest = append([]byte(nil), ar.ESMContainer...)
		ue.PCO = append([]byte(nil), pco...)
		ue.Unlock()
		log.Debug("s1ap: decoded Attach Request ESM container",
			zap.String("esm_container_hex", hex.EncodeToString(ar.ESMContainer)),
			zap.String("pdn_connectivity_request_hex", hex.EncodeToString(ar.ESMContainer)),
			zap.String("pco_from_ue_hex", hex.EncodeToString(pco)))
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

	// Encode PLMN from config for S6a. Visited-PLMN-Id uses the
	// serving-network format used by KASME derivation, not the S1AP PLMN
	// octet order used inside S1AP IEs.
	plmn, err := security.EncodePLMN(s.nfCfg.MCC, s.nfCfg.MNC)
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
		// SMC Complete arrives integrity-protected and ciphered with the new EPS security context.
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
		zap.String("direction", "uplink"),
		zap.Uint8("sec_hdr", result.SecHeaderType),
		zap.Uint8("pd", result.PD),
		zap.Uint8("msg_type", result.MsgType),
		zap.String("nas_hex", hex.EncodeToString(raw)))

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
		var cause uint8
		if len(result.Inner) > 0 {
			cause = result.Inner[0]
		}
		log.Warn("s1ap: Security Mode Reject from UE",
			zap.Uint8("emm_cause", cause),
			zap.String("emm_cause_name", emm.CauseName(cause)))
		rejectPDU := emm.EncodeAttachReject(emm.CauseSecurityModeRejectedUnspecified)
		s.sendDownlinkNASTransport(enbAddr, mmeUEID, enbUEID, rejectPDU)
		s.ueManager.Remove(ue)
		return nil

	case emm.MsgAttachComplete:
		return s.processAttachComplete(ue, result.Inner, log)

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
	initialAttachRequestNAS := append([]byte(nil), ue.InitialAttachRequestNAS...)
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
	dlCount := uint32(ue.DLNASCount)
	ue.Unlock()

	var hashMME []byte
	if len(initialAttachRequestNAS) > 0 {
		hashMME = security.HashMME(initialAttachRequestNAS)
	}

	// Encode Security Mode Command (plain, integrity-protected with new KNASint)
	smcPlain := emm.EncodeSecurityModeCommandWithHashMME(intAlg, encAlg, ueCap, hashMME)
	// SMC is sent integrity-protected with the new keys but NOT ciphered
	smcProtected, err := nas.EncodeIntegrityProtectedNewEPSSecurityContext(smcPlain, intAlg, knasInt, dlCount)
	if err != nil {
		return fmt.Errorf("processAuthResponse: encode SMC: %w", err)
	}
	smcSeq := uint8(dlCount & 0xff)
	smcMACInput := make([]byte, 1+len(smcPlain))
	smcMACInput[0] = smcSeq
	copy(smcMACInput[1:], smcPlain)
	smcEIA2InputDL := security.EIA2CMACInput(dlCount, 0, 1, smcMACInput)
	smcEIA2InputUL := security.EIA2CMACInput(dlCount, 0, 0, smcMACInput)
	var smcMACDownlinkCandidate, smcMACUplinkCandidate []byte
	var smcMACFirst16Candidate, smcMACLast16Candidate []byte
	var smcEIA2Details *security.EIA2CMACDetails
	var nasKeyMaterial *security.NASKeyMaterial
	if intAlg == security.AlgIDEIA2 {
		smcMACDownlinkCandidate, _ = security.ComputeNASMAC(intAlg, knasInt, dlCount, 0, 1, smcMACInput)
		smcMACUplinkCandidate, _ = security.ComputeNASMAC(intAlg, knasInt, dlCount, 0, 0, smcMACInput)
		smcEIA2Details, _ = security.ComputeEIA2CMACDetails(knasInt, dlCount, 0, 1, smcMACInput)
		nasKeyMaterial, _ = security.DeriveNASKeyMaterial(kasme, intAlg, encAlg)
		if nasKeyMaterial != nil && len(nasKeyMaterial.IntOut) == 32 {
			smcMACFirst16Candidate, _ = security.ComputeNASMAC(intAlg, nasKeyMaterial.IntOut[:16], dlCount, 0, 1, smcMACInput)
			smcMACLast16Candidate, _ = security.ComputeNASMAC(intAlg, nasKeyMaterial.IntOut[16:], dlCount, 0, 1, smcMACInput)
		}
	}
	var intS, encS, intOut, encOut, intFirst16, intLast16, encFirst16, encLast16 []byte
	if nasKeyMaterial != nil {
		intS = nasKeyMaterial.IntS
		encS = nasKeyMaterial.EncS
		intOut = nasKeyMaterial.IntOut
		encOut = nasKeyMaterial.EncOut
		if len(intOut) == 32 {
			intFirst16 = intOut[:16]
			intLast16 = intOut[16:]
		}
		if len(encOut) == 32 {
			encFirst16 = encOut[:16]
			encLast16 = encOut[16:]
		}
	}
	log.Debug("s1ap: Security Mode Command security",
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.Uint32("dl_nas_count", dlCount),
		zap.Uint8("nas_sequence_number", smcSeq),
		zap.Uint8("direction", 1),
		zap.Uint8("bearer", 0),
		zap.Uint8("security_header_type", smcProtected[0]>>4),
		zap.Uint8("protocol_discriminator", smcProtected[0]&0x0f),
		zap.Uint8("selected_int_alg", intAlg),
		zap.Uint8("selected_enc_alg", encAlg),
		zap.Int("kasme_len", len(kasme)),
		zap.String("kasme_hex", hex.EncodeToString(kasme)),
		zap.String("nas_int_kdf_s_hex", hex.EncodeToString(intS)),
		zap.String("nas_enc_kdf_s_hex", hex.EncodeToString(encS)),
		zap.String("nas_int_kdf_out_hex", hex.EncodeToString(intOut)),
		zap.String("nas_int_kdf_first16_hex", hex.EncodeToString(intFirst16)),
		zap.String("nas_int_kdf_last16_hex", hex.EncodeToString(intLast16)),
		zap.String("nas_enc_kdf_out_hex", hex.EncodeToString(encOut)),
		zap.String("nas_enc_kdf_first16_hex", hex.EncodeToString(encFirst16)),
		zap.String("nas_enc_kdf_last16_hex", hex.EncodeToString(encLast16)),
		zap.String("knas_int_hex", hex.EncodeToString(knasInt)),
		zap.String("knas_enc_hex", hex.EncodeToString(knasEnc)),
		zap.String("ue_security_capability_hex", hex.EncodeToString(ueCap)),
		zap.String("initial_nas_attach_request_hex", hex.EncodeToString(initialAttachRequestNAS)),
		zap.String("hash_mme_input_hex", hex.EncodeToString(initialAttachRequestNAS)),
		zap.String("hash_mme_hex", hex.EncodeToString(hashMME)),
		zap.String("plain_smc_hex", hex.EncodeToString(smcPlain)),
		zap.String("plain_smc_hex_with_hash_mme", hex.EncodeToString(smcPlain)),
		zap.String("nas_mac_input_hex", hex.EncodeToString(smcMACInput)),
		zap.String("eia2_cmac_input_downlink_hex", hex.EncodeToString(smcEIA2InputDL)),
		zap.String("eia2_cmac_input_uplink_hex", hex.EncodeToString(smcEIA2InputUL)),
		zap.String("eia2_mac_downlink_candidate_hex", hex.EncodeToString(smcMACDownlinkCandidate)),
		zap.String("eia2_mac_uplink_candidate_hex", hex.EncodeToString(smcMACUplinkCandidate)),
		zap.String("eia2_mac_first16_knasint_candidate_hex", hex.EncodeToString(smcMACFirst16Candidate)),
		zap.String("eia2_mac_last16_knasint_candidate_hex", hex.EncodeToString(smcMACLast16Candidate)),
		zap.String("aes_cmac_full_16_hex", hex.EncodeToString(eia2DetailsFull(smcEIA2Details))),
		zap.String("aes_cmac_first4_hex", hex.EncodeToString(eia2DetailsFirst4(smcEIA2Details))),
		zap.String("aes_cmac_last4_hex", hex.EncodeToString(eia2DetailsLast4(smcEIA2Details))),
		zap.String("aes_cmac_reversed_first4_hex", hex.EncodeToString(eia2DetailsReversedFirst4(smcEIA2Details))),
		zap.String("aes_cmac_reversed_last4_hex", hex.EncodeToString(eia2DetailsReversedLast4(smcEIA2Details))),
		zap.String("computed_mac_hex", hex.EncodeToString(smcProtected[1:5])),
		zap.String("protected_smc_hex", hex.EncodeToString(smcProtected)))

	s.sendDownlinkNASTransport(enbAddr, mmeUEID, enbUEID, smcProtected)
	ue.Lock()
	ue.DLNASCount.Increment()
	ue.Unlock()
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

	plmn, err := security.EncodePLMN(s.nfCfg.MCC, s.nfCfg.MNC)
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
func (s *Server) processAttachComplete(ue *uecontext.Context, body []byte, log *zap.Logger) error {
	ue.Lock()
	expectedEBI := ue.DefaultEBI
	ue.SetEMMState(emm.StateRegistered)
	ue.SetECMState(emm.ECMConnected)
	ue.AttachStep = uecontext.AttachStepNone
	mmeUEID := ue.MMEUES1APID
	imsi := ue.IMSI

	// Snapshot for MBR (sent after Attach Complete per TS 23.401 step 19)
	mbrENBUTEID := ue.ENBU_TEID
	mbrENBUIP := append(net.IP(nil), ue.ENBU_IP...)
	mbrSGWAddr := ue.SGWAddress
	mbrSGWCTEID := ue.SGWC_TEID
	mbrDefaultEBI := ue.DefaultEBI

	ue.Unlock()

	if attachComplete, err := emm.DecodeAttachComplete(body); err != nil {
		log.Warn("s1ap: Attach Complete ESM container decode failed",
			zap.Error(err),
			zap.String("attach_complete_body_hex", hex.EncodeToString(body)))
	} else if accept, err := esm.DecodeActivateDefaultEPSBearerContextAccept(attachComplete.ESMContainer); err != nil {
		log.Warn("s1ap: Attach Complete ESM accept decode failed",
			zap.Error(err),
			zap.String("esm_container_hex", hex.EncodeToString(attachComplete.ESMContainer)))
	} else {
		log.Info("s1ap: Activate Default EPS Bearer Context Accept received",
			zap.Uint8("ebi", accept.EPSBearerID),
			zap.Uint8("expected_ebi", expectedEBI),
			zap.Uint8("procedure_transaction_id", accept.ProcedureTransactionID),
			zap.Int("pco_len", len(accept.PCO)),
			zap.String("pco_hex", hex.EncodeToString(accept.PCO)),
			zap.String("esm_container_hex", hex.EncodeToString(attachComplete.ESMContainer)))
	}

	metrics.AttachedUEs.Inc()
	metrics.NASProceduresTotal.WithLabelValues("Attach", "complete").Inc()
	log.Info("s1ap: UE attached",
		zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi))

	s.persistUERecoverySnapshot(ue, models.RecoveryStateActiveSnapshot, "ESTABLISHED")

	// Send Modify Bearer Request now that UE is registered (TS 23.401 Figure 5.6.1.3-1 step 19).
	if mbrENBUTEID != 0 && mbrSGWCTEID != 0 && mbrDefaultEBI != 0 {
		mbr := &gtpv2.ModifyBearerRequest{
			SGWAddress: mbrSGWAddr,
			SGWC_TEID:  mbrSGWCTEID,
			EBI:        mbrDefaultEBI,
			ENBU_TEID:  mbrENBUTEID,
			ENBU_IP:    mbrENBUIP,
			RATType:    gtpv2.RATTypeEUTRAN,
		}
		s.log.Info("s1ap: sending S11 Modify Bearer Request",
			zap.Uint32("mme_ue_id", mmeUEID),
			zap.Uint8("ebi", mbrDefaultEBI),
			zap.String("sgw_s11_addr", mbrSGWAddr),
			zap.Uint32("sgwc_teid", mbrSGWCTEID),
			zap.String("sgwc_teid_hex", fmt.Sprintf("0x%08x", mbrSGWCTEID)),
			zap.Uint32("enb_s1u_teid", mbrENBUTEID),
			zap.String("enb_s1u_teid_hex", fmt.Sprintf("0x%08x", mbrENBUTEID)),
			zap.String("enb_s1u_ipv4", mbrENBUIP.String()))
		go func() {
			if err := s.s11.SendMBR(mmeUEID, mbr); err != nil {
				s.log.Warn("s1ap: SendMBR failed on Attach Complete", zap.Error(err))
			}
		}()
	} else {
		s.log.Warn("s1ap: skipping S11 Modify Bearer Request after Attach Complete",
			zap.Uint32("mme_ue_id", mmeUEID),
			zap.Uint32("enb_s1u_teid", mbrENBUTEID),
			zap.String("enb_s1u_ipv4", mbrENBUIP.String()),
			zap.Uint32("sgwc_teid", mbrSGWCTEID),
			zap.Uint8("ebi", mbrDefaultEBI))
	}

	if s.operCfg.EMMInformation.Enabled && s.operCfg.EMMInformation.SendAfterAttach {
		s.sendEMMInformation(mmeUEID, "attach", log)
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

	plmn, err := security.EncodePLMN(s.nfCfg.MCC, s.nfCfg.MNC)
	if err != nil {
		return fmt.Errorf("processIdentityResponse: EncodePLMN: %w", err)
	}
	var plmn3 [3]byte
	copy(plmn3[:], plmn)

	return s.s6a.SendAIR(idResp.IMSI, plmn3, mmeUEID)
}

func eia2DetailsFull(d *security.EIA2CMACDetails) []byte {
	if d == nil {
		return nil
	}
	return d.Full
}

func eia2DetailsFirst4(d *security.EIA2CMACDetails) []byte {
	if d == nil {
		return nil
	}
	return d.First4
}

func eia2DetailsLast4(d *security.EIA2CMACDetails) []byte {
	if d == nil {
		return nil
	}
	return d.Last4
}

func eia2DetailsReversedFirst4(d *security.EIA2CMACDetails) []byte {
	if d == nil {
		return nil
	}
	return d.ReversedFirst4
}

func eia2DetailsReversedLast4(d *security.EIA2CMACDetails) []byte {
	if d == nil {
		return nil
	}
	return d.ReversedLast4
}
