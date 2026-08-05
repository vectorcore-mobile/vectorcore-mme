package s1ap

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/gtpv2"
	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/models"
	nas "github.com/vectorcore/mme/internal/nas"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/esm"
	"github.com/vectorcore/mme/internal/nas/security"
	"github.com/vectorcore/mme/internal/plmn"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"github.com/vectorcore/mme/internal/uecontext"
)

func shouldDeferAttachEMMInformation(ue *uecontext.Context) bool {
	ue.Lock()
	defer ue.Unlock()
	if ue.PendingPDN != nil {
		return true
	}
	if strings.EqualFold(ue.APN, "ims") {
		return false
	}
	for _, apn := range ue.SubscriberAPNs {
		if strings.EqualFold(apn, "ims") {
			return true
		}
	}
	return false
}

func applyS1APLocationToUELocked(ue *uecontext.Context, tai *ies.TAI, ecgi *ies.ECGI) {
	if tai != nil {
		ue.TAI = emmTAIFromS1AP(tai)
		// Preserve the selected S1AP TAI PLMN in its typed, explicit-MNC-length
		// form. ue.TAI uses NAS wire ordering and is not re-decoded for roaming.
		if serving, err := plmn.New(tai.MCC, tai.MNC); err == nil {
			ue.Roaming.ServingPLMN = serving
			ue.Roaming.ServingTAI = ue.TAI
		}
	}
	if ecgi != nil {
		if plmn, err := encodeNASPLMN(ecgi.MCC, ecgi.MNC); err == nil {
			ue.ECGIPLMN = plmn
		}
		ue.ECGIECI = ecgi.ECGI
	}
}

func normalizeInitialUEOrUplinkTAIValue(data []byte) []byte {
	// Some eNBs encode TAI as the APER SEQUENCE payload with an extra leading
	// octet for "ext=0, iE-Extensions absent=0" before the semantic PLMN[3]+TAC[2].
	if len(data) == 6 && data[0] == 0x00 {
		return data[1:]
	}
	return data
}

func normalizeInitialUEOrUplinkECGIValue(data []byte) []byte {
	// Some eNBs encode ECGI as the APER SEQUENCE payload with an extra leading
	// octet for "ext=0, iE-Extensions absent=0" before the semantic PLMN[3]+ECGI[4].
	if len(data) == 8 && data[0] == 0x00 {
		return data[1:]
	}
	return data
}

// handleInitialUEMessage processes an Initial UE Message from an eNB.
// It creates a UE context, decodes the NAS payload, and triggers the auth flow.
func (s *Server) handleInitialUEMessage(remoteAddr string, p *pdu.PDU, ieList []pdu.ProtocolIE) {
	log := s.log.With(zap.String("remote", remoteAddr), zap.String("procedure", "InitialUE"))

	var enbUEID uint32
	var nasPDU []byte
	var tai *ies.TAI
	var ecgi *ies.ECGI
	var rrcCause uint8
	var enbUEIDDecodeErr bool
	var taiDecodeErr bool
	var ecgiDecodeErr bool
	var rrcCauseDecodeErr bool
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
				enbUEIDDecodeErr = true
				log.Warn("s1ap: InitialUE: ENB UE S1AP ID decode error",
					zap.Int("open_type_len", len(ie.Value)),
					zap.String("raw", hex.EncodeToString(ie.Value)),
					zap.Error(err))
				s.sendErrorIndication(remoteAddr, p, 0, 0, ies.CauseGroupProtocol, ies.CauseProtocolFalselyConstructedMessage)
				return
			}
			enbUEID = id
			log.Debug("s1ap: InitialUE eNB-UE-S1AP-ID decoded", zap.Uint32("enb_ue_id", enbUEID))
		case pdu.IENAS_PDU:
			nasPDU, _ = ies.DecodeNASPDU(ie.Value)
		case pdu.IETAI:
			taiValue := normalizeInitialUEOrUplinkTAIValue(ie.Value)
			t, err := ies.DecodeTAI(taiValue)
			if err == nil {
				tai = &t
			} else {
				taiDecodeErr = true
				log.Warn("s1ap: InitialUE: TAI decode error",
					zap.String("raw", hex.EncodeToString(ie.Value)),
					zap.String("tai_value", hex.EncodeToString(taiValue)),
					zap.Error(err),
				)
			}
		case pdu.IECGI:
			ecgiValue := normalizeInitialUEOrUplinkECGIValue(ie.Value)
			e, err := ies.DecodeECGI(ecgiValue)
			if err == nil {
				ecgi = &e
			} else {
				ecgiDecodeErr = true
				log.Warn("s1ap: InitialUE: ECGI decode error",
					zap.String("raw", hex.EncodeToString(ie.Value)),
					zap.String("ecgi_value", hex.EncodeToString(ecgiValue)),
					zap.Error(err))
			}
		case pdu.IERRCEstablishmentCause:
			var err error
			rrcCause, err = ies.DecodeRRCEstablishmentCause(ie.Value)
			if err != nil {
				rrcCauseDecodeErr = true
				log.Warn("s1ap: InitialUE: RRC cause decode error",
					zap.String("raw", hex.EncodeToString(ie.Value)),
					zap.Error(err))
			}
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

	if len(nasPDU) == 0 || tai == nil || ecgi == nil || (rrcCause == 0 && rrcCauseDecodeErr) || taiDecodeErr || ecgiDecodeErr || enbUEIDDecodeErr {
		log.Warn("s1ap: InitialUE: mandatory IE validation failed",
			zap.Bool("nas_pdu_present", len(nasPDU) > 0),
			zap.Bool("tai_present", tai != nil),
			zap.Bool("ecgi_present", ecgi != nil),
			zap.Bool("rrc_cause_decode_error", rrcCauseDecodeErr),
			zap.Bool("tai_decode_error", taiDecodeErr),
			zap.Bool("ecgi_decode_error", ecgiDecodeErr))
		s.sendErrorIndication(remoteAddr, p, 0, enbUEID, ies.CauseGroupProtocol, ies.CauseProtocolSemanticError)
		return
	}
	if served, topologyOK := s.validateInitialUETopology(remoteAddr, tai, ecgi); !topologyOK {
		if !served {
			log.Warn("s1ap: InitialUE rejected: unserved TAI/ECGI PLMN",
				zap.String("tai", fmt.Sprintf("%s-%s/%d", tai.MCC, tai.MNC, tai.TAC)),
				zap.String("ecgi_plmn", ecgi.MCC+"-"+ecgi.MNC))
			s.sendErrorIndication(remoteAddr, p, 0, enbUEID, ies.CauseGroupMisc, ies.CauseMiscUnknownPLMN)
			return
		}
		log.Warn("s1ap: InitialUE rejected: TAI/ECGI inconsistent with eNB topology",
			zap.String("tai", fmt.Sprintf("%s-%s/%d", tai.MCC, tai.MNC, tai.TAC)),
			zap.String("ecgi_plmn", ecgi.MCC+"-"+ecgi.MNC))
		// TS 36.413 has no unknown-TAI cause. A served TAI that was not
		// advertised by this association is a protocol semantic error.
		s.sendErrorIndication(remoteAddr, p, 0, enbUEID, ies.CauseGroupProtocol, ies.CauseProtocolSemanticError)
		return
	}

	_ = rrcCause

	// Allocate UE context
	ue := s.ueManager.Allocate()
	ue.Lock()
	ue.ENBS1APID = enbUEID
	ue.ENBGlobalID = remoteAddr
	ue.S1BindingGeneration++
	ue.S1BindingState = uecontext.S1BindingActive
	applyS1APLocationToUELocked(ue, tai, ecgi)
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
		log.Debug("s1ap: InitialUE NAS dispatch fallback",
			zap.Uint8("security_header_type", secHdr),
			zap.String("nas_hex", hex.EncodeToString(nasPDU)),
			zap.Bool("stmsi_present", stmsiPresent),
			zap.Uint8("stmsi_mmec", mmec),
			zap.Uint32("stmsi_mtmsi", mtmsi),
			zap.String("stmsi_mtmsi_hex", fmt.Sprintf("0x%08x", mtmsi)),
			zap.Error(err))
		if secHdr == emm.SecurityHeaderIntegrityProtected ||
			secHdr == emm.SecurityHeaderIntegrityAndCipher {
			_, _, innerNAS, peekErr := emm.ParseSecurityProtected(nasPDU)
			if peekErr == nil {
				innerMsgType, _, _ := emm.ParsePlainNASMessage(innerNAS)
				log.Debug("s1ap: InitialUE protected NAS inner dispatch",
					zap.Uint8("security_header_type", secHdr),
					zap.Uint8("inner_message_type", innerMsgType),
					zap.String("inner_nas_hex", hex.EncodeToString(innerNAS)))
				if innerMsgType == emm.MsgTrackingAreaUpdateRequest {
					log.Debug("s1ap: InitialUE selected idle TAU handler",
						zap.String("selection_reason", "protected_inner_tau_request"))
					s.handleIdleTAUMessage(ue, tai, nasPDU)
					return
				}
			}
		}
		if secHdr == emm.SecurityHeaderServiceRequest {
			log.Debug("s1ap: InitialUE selected Service Request handler",
				zap.String("selection_reason", "service_request_security_header"))
			s.handleServiceRequest(ue, mmec, mtmsi, stmsiRaw, stmsiPresent, tai, nasPDU)
			return
		}
		if secHdr == emm.SecurityHeaderIntegrityProtected ||
			secHdr == emm.SecurityHeaderIntegrityAndCipher {
			s.handleInitialUEDetach(ue, mmec, mtmsi, stmsiRaw, stmsiPresent, tai, nasPDU)
			return
		}
		log.Warn("s1ap: InitialUE: NAS decode error", zap.Error(err))
		s.ueManager.Remove(ue)
		return
	}

	// Plain TAU Request (EIA0 / no security context)
	if result.MsgType == emm.MsgTrackingAreaUpdateRequest {
		log.Debug("s1ap: InitialUE selected idle TAU handler",
			zap.String("selection_reason", "plain_tau_request"),
			zap.Uint8("plain_message_type", result.MsgType))
		s.handleIdleTAUMessage(ue, tai, nasPDU)
		return
	}
	if result.MsgType == emm.MsgExtendedServiceRequest {
		log.Debug("s1ap: InitialUE selected Extended Service Request handler",
			zap.Uint8("plain_message_type", result.MsgType))
		s.handleInitialUEExtendedServiceRequest(ue, tai, result.Inner, nasPDU)
		return
	}
	if result.MsgType == emm.MsgDetachRequest {
		s.handleInitialUEDetach(ue, mmec, mtmsi, stmsiRaw, stmsiPresent, tai, nasPDU)
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
	plainAttachRequestNAS := append([]byte{emm.PDEPSMobilityMgmt, result.MsgType}, result.Inner...)
	var hashMMEInput []byte
	if len(nasPDU) > 0 {
		rawSecHdr, _, _ := emm.DecodeSecurityHeader(nasPDU)
		if rawSecHdr == emm.SecurityHeaderPlain {
			hashMMEInput = plainAttachRequestNAS
		}
	}
	ue.Lock()
	ue.UENetworkCapability = ar.UENetworkCapability
	ue.MSNetworkCapability = ar.MSNetworkCapability
	ue.AttachType = ar.AttachType
	ue.RequestedSMSOnly = ar.AdditionalUpdateType != nil && *ar.AdditionalUpdateType&emm.AdditionalUpdateTypeSMSOnlyBit != 0
	ue.InitialAttachRequestNAS = hashMMEInput
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
			zap.Int("esm_container_len", len(ar.ESMContainer)),
			zap.Int("pco_len", len(pco)))
	}

	// Resolve IMSI only when it is explicitly present. A GUTI match is a
	// candidate lookup, not proof that this radio endpoint owns that context.
	imsi := ar.IMSI
	if imsi == "" && ar.GUTI != nil {
		gutiStr := uecontext.SerialiseGUTI(ar.GUTI)
		var candidateIMSI, candidateEMM, candidateECM string
		var candidateID uint32
		existing, ok := s.ueManager.GetByGUTI(gutiStr)
		if ok {
			existing.Lock()
			candidateIMSI = existing.IMSI
			candidateID = existing.MMEUES1APID
			candidateEMM = existing.EMMState.String()
			candidateECM = existing.ECMState.String()
			existing.Unlock()
		}
		ue.Lock()
		ue.CandidateGUTI = gutiStr
		ue.CandidateIMSI = candidateIMSI
		ue.Unlock()
		log.Info("s1ap: Attach Request GUTI candidate requires identity confirmation",
			zap.String("presented_guti", gutiStr),
			zap.String("candidate_lookup_result", map[bool]string{true: "hit", false: "miss"}[ok]),
			zap.Uint32("candidate_mme_ue_id", candidateID),
			zap.Bool("candidate_imsi_present", candidateIMSI != ""),
			zap.String("candidate_emm_state", candidateEMM),
			zap.String("candidate_ecm_state", candidateECM),
			zap.Bool("destructive_action_deferred", true))
	}

	if imsi == "" {
		// Need to send Identity Request
		log.Info("s1ap: InitialUE: no IMSI in Attach Request, requesting identity")
		s.sendIdentityRequest(remoteAddr, ue)
		return
	}

	log.Info("s1ap: Attach Request", zap.Uint8("attach_type", ar.AttachType))

	ue.Lock()
	ue.IMSI = imsi
	ue.SetEMMState(emm.StateRegisteredInitiated)
	ue.AttachStep = uecontext.AttachStepWaitingAIA
	ue.Unlock()
	if err := s.classifyRoaming(ue, imsi); err != nil {
		cause := emm.CauseUEIdentityCannotBeDerived
		if admission, ok := err.(*roamingAdmissionError); ok {
			cause = admission.cause
		}
		log.Warn("s1ap: roaming admission rejected", zap.String("reason", err.Error()), zap.Uint8("emm_cause", cause))
		s.sendDownlinkNASTransport(remoteAddr, mmeUEID, enbUEID, emm.EncodeAttachReject(cause))
		s.ueManager.Remove(ue)
		return
	}
	if existing, ok := s.ueManager.GetByIMSI(imsi); ok && existing.MMEUES1APID != ue.MMEUES1APID {
		s.log.Info("s1ap: duplicate IMSI attach pending authentication",
			zap.Uint32("new_mme_ue_id", mmeUEID),
			zap.Bool("destructive_action_deferred", true),
			zap.String("eviction_reason", "deferred-until-authentication"))
	}

	metrics.NASProceduresTotal.WithLabelValues("Attach", "request").Inc()
	metrics.S1APMessagesTotal.WithLabelValues("InitialUEMessage", "inbound", "ok").Inc()

	if err := s.sendAIRForUE(ue); err != nil {
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
	var tai *ies.TAI
	var ecgi *ies.ECGI

	for _, ie := range ieList {
		switch ie.ID {
		case pdu.IEMMEUES1APID:
			id, err := ies.DecodeMMEUEApID(ie.Value)
			if err != nil {
				log.Warn("s1ap: UplinkNAS: MME UE S1AP ID decode error", zap.Error(err))
				s.sendErrorIndication(remoteAddr, p, 0, enbUEID, ies.CauseGroupProtocol, ies.CauseProtocolFalselyConstructedMessage)
				return
			}
			mmeUEID = id
		case pdu.IEENBS1APID:
			id, err := ies.DecodeENBUEApID(ie.Value)
			if err != nil {
				log.Warn("s1ap: UplinkNAS: ENB UE S1AP ID decode error", zap.Error(err))
				s.sendErrorIndication(remoteAddr, p, mmeUEID, 0, ies.CauseGroupProtocol, ies.CauseProtocolFalselyConstructedMessage)
				return
			}
			enbUEID = id
		case pdu.IENAS_PDU:
			nasPDU, _ = ies.DecodeNASPDU(ie.Value)
		case pdu.IETAI:
			taiValue := normalizeInitialUEOrUplinkTAIValue(ie.Value)
			decodedTAI, err := ies.DecodeTAI(taiValue)
			if err != nil {
				log.Warn("s1ap: UplinkNAS: TAI decode error",
					zap.String("raw", hex.EncodeToString(ie.Value)),
					zap.String("tai_value", hex.EncodeToString(taiValue)),
					zap.Error(err))
				s.sendErrorIndication(remoteAddr, p, mmeUEID, enbUEID, ies.CauseGroupProtocol, ies.CauseProtocolFalselyConstructedMessage)
				return
			}
			tai = &decodedTAI
		case pdu.IECGI:
			ecgiValue := normalizeInitialUEOrUplinkECGIValue(ie.Value)
			decodedECGI, err := ies.DecodeECGI(ecgiValue)
			if err != nil {
				log.Warn("s1ap: UplinkNAS: ECGI decode error",
					zap.String("raw", hex.EncodeToString(ie.Value)),
					zap.String("ecgi_value", hex.EncodeToString(ecgiValue)),
					zap.Error(err))
				s.sendErrorIndication(remoteAddr, p, mmeUEID, enbUEID, ies.CauseGroupProtocol, ies.CauseProtocolFalselyConstructedMessage)
				return
			}
			ecgi = &decodedECGI
		}
	}

	if len(nasPDU) == 0 || tai == nil || ecgi == nil {
		log.Warn("s1ap: UplinkNAS: mandatory IE validation failed",
			zap.Bool("nas_pdu_present", len(nasPDU) > 0),
			zap.Bool("tai_present", tai != nil),
			zap.Bool("ecgi_present", ecgi != nil))
		s.sendErrorIndication(remoteAddr, p, mmeUEID, enbUEID, ies.CauseGroupProtocol, ies.CauseProtocolSemanticError)
		return
	}

	ue, ok := s.findUEForUEAssociatedMessage(remoteAddr, p, mmeUEID, enbUEID)
	if !ok {
		return
	}

	ue.Lock()
	applyS1APLocationToUELocked(ue, tai, ecgi)
	ue.Unlock()

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
	countUsed := ulCountVal
	commitULCount := false

	switch {
	case attachStep == uecontext.AttachStepWaitingAuthResp:
		// Expect plain Auth Response (or Auth Failure)
		result, err = nas.Decode(raw, 0, 0, nil, nil, 0)
	case attachStep == uecontext.AttachStepWaitingSMCCplt:
		// SMC Complete arrives integrity-protected and ciphered with the new EPS security context.
		countUsed, _, err = reconstructFullULNASCount(raw, ulCountVal)
		if err == nil {
			result, err = nas.Decode(raw, intAlg, encAlg, knasInt, knasEnc, countUsed)
			commitULCount = err == nil
		}
	case attachStep == uecontext.AttachStepWaitingEquipmentIdentity:
		countUsed, _, err = reconstructFullULNASCount(raw, ulCountVal)
		if err == nil {
			result, err = nas.Decode(raw, intAlg, encAlg, knasInt, knasEnc, countUsed)
			commitULCount = err == nil
		}
	case attachStep == uecontext.AttachStepWaitingAttachCplt:
		// Attach Complete arrives integrity-protected (and possibly ciphered)
		countUsed, _, err = reconstructFullULNASCount(raw, ulCountVal)
		if err == nil {
			result, err = nas.Decode(raw, intAlg, encAlg, knasInt, knasEnc, countUsed)
			commitULCount = err == nil
		}
	case attachStep == uecontext.AttachStepWaitingTAUComplete:
		// TAU Complete arrives integrity-protected (and possibly ciphered)
		countUsed, _, err = reconstructFullULNASCount(raw, ulCountVal)
		if err == nil {
			result, err = nas.Decode(raw, intAlg, encAlg, knasInt, knasEnc, countUsed)
			commitULCount = err == nil
		}
	case emmState == emm.StateRegistered:
		// Normal uplink: integrity + possibly ciphered
		countUsed, _, err = reconstructFullULNASCount(raw, ulCountVal)
		if err == nil {
			result, err = nas.Decode(raw, intAlg, encAlg, knasInt, knasEnc, countUsed)
			commitULCount = err == nil
		}
	default:
		// Plain or early messages
		result, err = nas.Decode(raw, 0, 0, nil, nil, 0)
	}

	if err != nil {
		secHdr, _, _ := emm.DecodeSecurityHeader(raw)
		if secHdr == emm.SecurityHeaderIntegrityProtected ||
			secHdr == emm.SecurityHeaderIntegrityAndCipher ||
			secHdr == emm.SecurityHeaderNewEPSSecurityCtx ||
			secHdr == emm.SecurityHeaderCipherNewEPSSecCtx {
			s.logProtectedNASFailure(log, raw, intAlg, encAlg, knasInt, knasEnc, ulCountVal, err)
		}
		return fmt.Errorf("processNAS: decode: %w", err)
	}
	log.Debug("s1ap: processNAS",
		zap.String("direction", "uplink"),
		zap.Uint8("sec_hdr", result.SecHeaderType),
		zap.Uint8("pd", result.PD),
		zap.Uint8("msg_type", result.MsgType),
		zap.Uint32("ul_count_before", ulCountVal),
		zap.Uint32("ul_count_used", countUsed),
		zap.Uint8("sequence_number", result.Sequence),
		zap.String("plain_nas_hex", hex.EncodeToString(result.Plain)),
		zap.Uint8("inner_pd", result.PD),
		zap.Uint8("inner_message_type", result.MsgType),
		zap.String("nas_hex", hex.EncodeToString(raw)))

	switch result.PD {
	case emm.PDEPSMobilityMgmt:
		if !emm.IsKnownEMMMessageType(result.MsgType) {
			log.Warn("s1ap: processNAS: unknown EMM message after security processing",
				zap.Uint8("msg_type", result.MsgType),
				zap.Uint32("ul_count_before", ulCountVal),
				zap.Uint32("ul_count_used", countUsed),
				zap.String("plain_nas_hex", hex.EncodeToString(result.Plain)),
				zap.Bool("ul_count_committed", false))
			return fmt.Errorf("processNAS: unknown EMM message type %#x", result.MsgType)
		}
		if commitULCount {
			ue.Lock()
			ue.ULNASCount = security.NASCount(countUsed)
			ue.Unlock()
		}
		return s.processEMM(ue, result, attachStep)
	case esm.PDEPSSessionMgmt:
		if commitULCount {
			ue.Lock()
			ue.ULNASCount = security.NASCount(countUsed)
			ue.Unlock()
		}
		return s.processESM(ue, result, log)
	default:
		log.Warn("s1ap: processNAS: unexpected PD",
			zap.Uint8("pd", result.PD),
			zap.Uint32("ul_count_before", ulCountVal),
			zap.Uint32("ul_count_used", countUsed),
			zap.String("plain_nas_hex", hex.EncodeToString(result.Plain)),
			zap.Bool("ul_count_committed", commitULCount))
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
	// A successfully verified, protected uplink NAS message proves that an
	// already registered UE has returned. Detach is deliberately excluded: it
	// owns a different cleanup lifecycle.
	if result.SecHeaderType != emm.SecurityHeaderPlain && result.MsgType != emm.MsgDetachRequest {
		s.refreshReachability(ue, "integrity-protected-uplink-nas")
	}

	switch result.MsgType {
	case emm.MsgUplinkNASTransport:
		return s.processUplinkSMS(ue, result.Inner)

	case emm.MsgUplinkGenericNASTransport:
		if result.SecHeaderType == emm.SecurityHeaderPlain {
			return fmt.Errorf("s1ap: unprotected uplink generic NAS transport")
		}
		_, payload, err := emm.DecodeUplinkGenericNASTransport(result.Inner)
		if err != nil {
			return err
		}
		if s.lppSink == nil {
			return fmt.Errorf("s1ap: LPP relay unavailable")
		}
		return s.lppSink.HandleUplinkLPP(mmeUEID, payload)

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

	case emm.MsgEMMStatus:
		return s.processEMMStatus(ue, result, log)

	case emm.MsgTrackingAreaUpdateRequest:
		return s.processTrackingAreaUpdate(ue, result.Inner, log)

	case emm.MsgTrackingAreaUpdateComplete:
		return s.processTAUComplete(ue, log)

	case emm.MsgExtendedServiceRequest:
		return s.processExtendedServiceRequest(ue, result.Inner, log)

	default:
		log.Warn("s1ap: processEMM: unhandled EMM message type", zap.Uint8("msg_type", result.MsgType))
	}
	_ = imsi
	_ = attachStep
	return nil
}

func (s *Server) processExtendedServiceRequest(ue *uecontext.Context, body []byte, log *zap.Logger) error {
	req, err := emm.DecodeExtendedServiceRequest(body)
	if err == nil && req.ServiceType == emm.ServiceTypeMobileTerminatingCSFallback {
		ue.Lock()
		mmeUEID, imsi := ue.MMEUES1APID, ue.IMSI
		ue.Unlock()
		log.Info("s1ap: MT CSFB Extended Service Request received", zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi))
		s.completeSGsPaging(ue)
		metrics.NASProceduresTotal.WithLabelValues("ExtendedServiceRequest", "mt_csfb").Inc()
		return nil
	}
	if err == nil && req.ServiceType == emm.ServiceTypeMobileOriginatingCSFallback {
		ue.Lock()
		sgsAvailable := s.sgsCfg.Enabled && !s.sgsCfg.SMSOnly && ue.SGsState == uecontext.SGsUEAssociated
		ue.Unlock()
		if sgsAvailable {
			s.handleMOCSFBExtendedServiceRequest(ue, log)
			metrics.NASProceduresTotal.WithLabelValues("ExtendedServiceRequest", "mo_csfb").Inc()
			return nil
		}
		// No operational SGs association (disabled, smsonly, or not yet
		// associated - see docs/sgs-ap.md). Complete the unsupported CSFB
		// request without touching any pending EPS procedure.
		ue.Lock()
		mmeUEID := ue.MMEUES1APID
		enbUEID := ue.ENBS1APID
		enbAddr := ue.ENBGlobalID
		ue.Unlock()
		if err := s.sendProtectedServiceRejectForUE(ue, mmeUEID, enbUEID, enbAddr, emm.CauseCSDomainNotAvailable, "MO-CSFB Extended Service Request"); err != nil {
			// A missing S1 route cannot turn the unsupported CSFB request into an
			// EPS failure. The production path logs the send error; pending IMS
			// activation remains untouched either way.
			log.Warn("s1ap: Extended Service Request Service Reject send failed", zap.Error(err))
		}
		metrics.NASProceduresTotal.WithLabelValues("ExtendedServiceRequest", "csfb_reject").Inc()
		return nil
	}
	if err != nil {
		log.Warn("s1ap: Extended Service Request decode error", zap.Error(err))
		return nil
	}

	ue.Lock()
	mmeUEID := ue.MMEUES1APID
	imsi := ue.IMSI

	var pendingPromoted bool
	var pendingAPN string
	var pendingEBI uint8
	if ue.PendingPDN != nil &&
		ue.PendingPDN.APN == "ims" &&
		!ue.PendingPDN.NASAccepted &&
		!ue.PendingPDN.DisconnectRequested {
		pendingPromoted = true
		pendingAPN = ue.PendingPDN.APN
		pendingEBI = ue.PendingPDN.DefaultEBI
	}

	var candidate *uecontext.PDNContext
	candidateCount := 0
	for _, pdn := range ue.PDNs {
		if pdn == nil || pdn.NASAccepted || !pdn.ERABEstablished || pdn.ModifyBearerAccepted || pdn.DisconnectRequested {
			continue
		}
		candidate = pdn
		candidateCount++
	}

	var promotedEBI uint8
	var promotedAPN string
	if candidateCount == 1 && candidate != nil {
		promotedEBI = candidate.DefaultEBI
		promotedAPN = candidate.APN
	}
	ue.Unlock()

	log.Info("s1ap: Extended Service Request received",
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.String("imsi", imsi),
		zap.String("message_body_hex", hex.EncodeToString(body)),
		zap.Bool("pending_default_bearer_promoted", pendingPromoted),
		zap.Uint8("pending_promoted_ebi", pendingEBI),
		zap.String("pending_promoted_apn", pendingAPN),
		zap.Int("default_bearer_candidates", candidateCount),
		zap.Bool("default_bearer_promoted", promotedEBI != 0),
		zap.Uint8("promoted_ebi", promotedEBI),
		zap.String("promoted_apn", promotedAPN))

	return nil
}

func (s *Server) processEMMStatus(ue *uecontext.Context, result *nas.DecodeResult, log *zap.Logger) error {
	status, err := emm.DecodeEMMStatus(result.Inner)
	if err != nil {
		return fmt.Errorf("processEMMStatus: decode: %w", err)
	}
	ue.Lock()
	imsi := ue.IMSI
	mmeUEID := ue.MMEUES1APID
	lastDownlink := ue.LastDownlinkNASMessage
	ue.Unlock()

	log.Warn("s1ap: EMM Status received",
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.String("imsi", imsi),
		zap.Uint8("security_header_type", result.SecHeaderType),
		zap.Uint32("uplink_nas_count", result.Count),
		zap.Uint8("sequence_number", result.Sequence),
		zap.String("received_mac", hex.EncodeToString(result.MAC)),
		zap.String("deciphered_plain_nas", hex.EncodeToString(result.Plain)),
		zap.Uint8("message_type", result.MsgType),
		zap.Uint8("emm_cause", status.Cause),
		zap.String("emm_cause_name", emm.CauseName(status.Cause)),
		zap.String("triggering_last_downlink_message", lastDownlink))
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
	msCap := ue.MSNetworkCapability
	mmeUEID := ue.MMEUES1APID
	enbAddr := ue.ENBGlobalID
	enbUEID := ue.ENBS1APID
	nasKSI := ue.NASKSI
	ue.Unlock()
	if nasKSI > 6 {
		nasKSI = 0
	}

	if !security.VerifyRES(xres, ar.RES) {
		log.Warn("s1ap: Authentication Response: RES mismatch", zap.Uint32("mme_ue_id", mmeUEID))
		rejectPDU := emm.EncodeAttachReject(emm.CauseMACFailure)
		s.sendDownlinkNASTransport(enbAddr, mmeUEID, enbUEID, rejectPDU)
		s.ueManager.Remove(ue)
		return nil
	}
	s.confirmAuthenticatedIdentityOwnership(ue, log)

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

	replayedUECap := emm.ReplayedUESecurityCapability(ueCap, msCap)

	// Encode Security Mode Command (plain, integrity-protected with new KNASint)
	requestIMEISV := false
	if checker, ok := s.s6a.(interface{ S13Enabled() bool }); ok {
		requestIMEISV = checker.S13Enabled()
	}
	smcPlain := emm.EncodeSecurityModeCommandWithKSIHashAndIMEISVRequest(intAlg, encAlg, nasKSI, replayedUECap, nil, requestIMEISV)
	// SMC is sent integrity-protected with the new keys but NOT ciphered
	smcProtected, err := nas.EncodeIntegrityProtectedNewEPSSecurityContext(smcPlain, intAlg, knasInt, dlCount)
	if err != nil {
		return fmt.Errorf("processAuthResponse: encode SMC: %w", err)
	}
	smcSeq := uint8(dlCount & 0xff)
	var nasKeyMaterial *security.NASKeyMaterial
	if intAlg == security.AlgIDEIA2 {
		nasKeyMaterial, _ = security.DeriveNASKeyMaterial(kasme, intAlg, encAlg)
	}
	var intOut, encOut, intFirst16, intLast16, encFirst16, encLast16 []byte
	if nasKeyMaterial != nil {
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
		zap.Uint8("nas_ksi", nasKSI),
		zap.Int("kasme_len", len(kasme)),
		zap.String("kasme_sha256_prefix", keyFingerprint(kasme)),
		zap.String("nas_int_kdf_out_sha256_prefix", keyFingerprint(intOut)),
		zap.String("nas_int_kdf_first16_sha256_prefix", keyFingerprint(intFirst16)),
		zap.String("nas_int_kdf_last16_sha256_prefix", keyFingerprint(intLast16)),
		zap.String("nas_enc_kdf_out_sha256_prefix", keyFingerprint(encOut)),
		zap.String("nas_enc_kdf_first16_sha256_prefix", keyFingerprint(encFirst16)),
		zap.String("nas_enc_kdf_last16_sha256_prefix", keyFingerprint(encLast16)),
		zap.String("knas_int_sha256_prefix", keyFingerprint(knasInt)),
		zap.String("knas_enc_sha256_prefix", keyFingerprint(knasEnc)),
		zap.Int("ue_security_capability_len", len(ueCap)),
		zap.Int("ms_network_capability_len", len(msCap)),
		zap.Int("protected_smc_len", len(smcProtected)))

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
	smc, _ := emm.DecodeSecurityModeComplete(body)
	if smc != nil && len(smc.IMEISV) > 0 {
		if identity, err := emm.DecodeEquipmentIdentity(smc.IMEISV); err == nil {
			ue.Lock()
			ue.IMEISV = identity
			ue.Unlock()
		} else {
			log.Warn("s1ap: invalid IMEISV in Security Mode Complete", zap.Error(err))
		}
	}

	ue.Lock()
	imsi := ue.IMSI
	identity := ue.IMEISV
	if identity == "" {
		identity = ue.IMEI
	}
	mmeUEID := ue.MMEUES1APID
	ue.AttachStep = uecontext.AttachStepWaitingULA
	ue.Unlock()
	if checker, ok := s.s6a.(interface {
		S13Enabled() bool
		SendEquipmentCheck(string, string, uint32) error
	}); ok && checker.S13Enabled() {
		if identity != "" {
			ue.Lock()
			ue.AttachStep = uecontext.AttachStepWaitingS13ECA
			ue.Unlock()
			if err := checker.SendEquipmentCheck(imsi, identity, mmeUEID); err == nil {
				log.Info("s1ap: Security Mode Complete received, waiting for S13 ECA")
				return nil
			} else {
				log.Warn("s1ap: S13 ECR could not be sent", zap.Error(err))
				return s.handleEquipmentIdentityFailure(ue, log, err.Error())
			}
		}
		// TS 24.301 identity acquisition fallback: a UE is not required to
		// include IMEISV in Security Mode Complete. Request it under the newly
		// established NAS security context instead of silently bypassing S13.
		ue.Lock()
		ue.AttachStep = uecontext.AttachStepWaitingEquipmentIdentity
		ue.PendingIdentityType = emm.IdentityTypeIMEISV
		ue.Unlock()
		if err := s.sendProtectedNAS(ue, emm.EncodeIdentityRequest(emm.IdentityTypeIMEISV), "S13 IMEISV Identity Request"); err == nil {
			log.Info("s13: requesting UE equipment identity", zap.Uint32("mme_ue_id", mmeUEID), zap.String("identity_type", "imeisv"))
			return nil
		}
		ue.Lock()
		ue.AttachStep = uecontext.AttachStepWaitingULA
		ue.PendingIdentityType = 0
		ue.Unlock()
	}

	log.Info("s1ap: Security Mode Complete received, sending ULR")
	metrics.NASProceduresTotal.WithLabelValues("SecurityMode", "complete").Inc()

	_ = imsi
	_ = mmeUEID
	return s.sendULRForUE(ue)
}

// processAttachComplete handles a NAS Attach Complete from the UE.
func (s *Server) processAttachComplete(ue *uecontext.Context, body []byte, log *zap.Logger) error {
	ue.Lock()
	expectedEBI := ue.DefaultEBI
	for _, pdn := range ue.PDNs {
		if pdn == nil || pdn.DefaultEBI != expectedEBI {
			continue
		}
		pdn.NASAccepted = true
		if pdn.ERABEstablished {
			if pdn.ModifyBearerAccepted {
				pdn.State = "active"
			} else {
				pdn.State = "access-established"
			}
		}
	}
	ue.SetEMMState(emm.StateRegistered)
	ue.SetECMState(emm.ECMConnected)
	ue.AttachStep = uecontext.AttachStepNone
	mmeUEID := ue.MMEUES1APID
	imsi := ue.IMSI

	ue.Unlock()

	if attachComplete, err := emm.DecodeAttachComplete(body); err != nil {
		log.Warn("s1ap: Attach Complete ESM container decode failed",
			zap.Error(err),
			zap.String("attach_complete_body_hex", hex.EncodeToString(body)))
	} else if accept, err := esm.DecodeActivateDefaultEPSBearerContextAccept(attachComplete.ESMContainer); err != nil {
		log.Warn("s1ap: Attach Complete ESM accept decode failed",
			zap.Error(err))
	} else {
		log.Info("s1ap: Activate Default EPS Bearer Context Accept received",
			zap.Uint8("ebi", accept.EPSBearerID),
			zap.Uint8("expected_ebi", expectedEBI),
			zap.Uint8("procedure_transaction_id", accept.ProcedureTransactionID),
			zap.Int("pco_len", len(accept.PCO)),
			zap.Int("esm_container_len", len(attachComplete.ESMContainer)))
	}

	metrics.AttachedUEs.Inc()
	s.refreshReachability(ue, "attach-complete")
	s.completeSGsTMSIReallocation(ue)
	metrics.NASProceduresTotal.WithLabelValues("Attach", "complete").Inc()
	log.Info("s1ap: UE attached",
		zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi))

	s.persistUERecoverySnapshot(ue, models.RecoveryStateActiveSnapshot, "ESTABLISHED")

	// TS 23.401 Figure 5.6.1.3-1 step 19. The ICS response and Attach
	// Complete can arrive in either order, so this only starts the procedure
	// once both independently-recorded prerequisites are present.
	s.tryStartInitialAccessModifyBearer(ue, "attach-complete")

	if s.operCfg.EMMInformation.Enabled && s.operCfg.EMMInformation.SendAfterAttach {
		if shouldDeferAttachEMMInformation(ue) {
			log.Info("s1ap: deferring EMM Information after Attach",
				zap.Uint32("mme_ue_id", mmeUEID),
				zap.String("reason", "secondary-ims-expected"))
		} else {
			s.sendEMMInformation(mmeUEID, "attach", log)
		}
	}

	return nil
}

// tryStartInitialAccessModifyBearer atomically starts the initial default-bearer
// S11 Modify Bearer procedure once NAS activation and the ICS E-RAB result are
// both available. Call it after either event; the PDN transaction flags make it
// safe for duplicate or concurrent notifications.
func (s *Server) tryStartInitialAccessModifyBearer(ue *uecontext.Context, trigger string) {
	ue.Lock()
	mmeUEID := ue.MMEUES1APID
	bindingGeneration := ue.S1BindingGeneration
	defaultEBI := ue.DefaultEBI
	var pdn *uecontext.PDNContext
	for _, candidate := range ue.PDNs {
		if candidate != nil && candidate.DefaultEBI == defaultEBI {
			pdn = candidate
			break
		}
	}

	if pdn == nil || !pdn.NASAccepted || !pdn.ERABEstablished ||
		pdn.SGWAddress == "" || pdn.SGWC_TEID == 0 || pdn.SGWU_TEID == 0 || len(pdn.SGWU_IP) == 0 ||
		pdn.ENBU_TEID == 0 || len(pdn.ENBU_IP) == 0 ||
		!hasActiveS1BindingLocked(ue) {
		fields := []zap.Field{
			zap.Uint32("mme_ue_id", mmeUEID),
			zap.String("trigger", trigger),
			zap.Uint8("ebi", defaultEBI),
			zap.Uint64("s1_binding_generation", bindingGeneration),
		}
		if pdn != nil {
			fields = append(fields,
				zap.Bool("nas_accepted", pdn.NASAccepted),
				zap.Bool("erab_established", pdn.ERABEstablished),
				zap.Uint32("enb_s1u_teid", pdn.ENBU_TEID),
				zap.String("enb_s1u_address", pdn.ENBU_IP.String()))
		}
		ue.Unlock()
		s.log.Debug("s1ap: initial access Modify Bearer deferred; waiting for prerequisites", fields...)
		return
	}
	if pdn.ModifyBearerSent || pdn.ModifyBearerAccepted || pdn.ModifyBearerFailed {
		ue.Unlock()
		return
	}

	pdn.ModifyBearerSent = true
	pdn.ModifyBearerAccepted = false
	pdn.ModifyBearerFailed = false
	pdn.State = "modify-bearer-pending"
	mbr := &gtpv2.ModifyBearerRequest{
		SGWAddress:            pdn.SGWAddress,
		SGWC_TEID:             pdn.SGWC_TEID,
		EBI:                   pdn.DefaultEBI,
		ENBU_TEID:             pdn.ENBU_TEID,
		ENBU_IP:               append([]byte(nil), pdn.ENBU_IP...),
		RATType:               gtpv2.RATTypeEUTRAN,
		IncludeIndicationCRSI: true,
		OmitRATType:           true,
	}
	sgwS1UIP := append([]byte(nil), pdn.SGWU_IP...)
	sgwS1UTEID := pdn.SGWU_TEID
	ue.Unlock()

	s.log.Info("s1ap: sending initial access S11 Modify Bearer Request",
		zap.String("trigger", trigger),
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.Uint8("ebi", mbr.EBI),
		zap.String("sgw_s11_addr", mbr.SGWAddress),
		zap.Uint32("sgwc_teid", mbr.SGWC_TEID),
		zap.String("sgw_s1u_address", net.IP(sgwS1UIP).String()),
		zap.Uint32("sgw_s1u_teid", sgwS1UTEID),
		zap.String("enb_s1u_address", mbr.ENBU_IP.String()),
		zap.Uint32("enb_s1u_teid", mbr.ENBU_TEID),
		zap.String("transaction_state", "modify-bearer-pending"),
		zap.Uint64("s1_binding_generation", bindingGeneration))
	go func() {
		if err := s.s11.SendMBR(mmeUEID, mbr); err != nil {
			s.log.Warn("s1ap: SendMBR failed for initial access", zap.Uint32("mme_ue_id", mmeUEID), zap.Error(err))
		}
	}()
}

func (s *Server) confirmAuthenticatedIdentityOwnership(ue *uecontext.Context, log *zap.Logger) {
	ue.Lock()
	imsi := ue.IMSI
	mmeUEID := ue.MMEUES1APID
	candidateGUTI := ue.CandidateGUTI
	candidateIMSI := ue.CandidateIMSI
	ue.CandidateGUTI = ""
	ue.CandidateIMSI = ""
	ue.Unlock()
	if imsi == "" {
		return
	}

	if existing, ok := s.ueManager.GetByIMSI(imsi); ok && existing.MMEUES1APID != mmeUEID {
		existing.Lock()
		oldMMEID := existing.MMEUES1APID
		oldGUTI := ""
		if existing.GUTI != nil {
			oldGUTI = uecontext.SerialiseGUTI(existing.GUTI)
		}
		existingEMM := existing.EMMState.String()
		existingECM := existing.ECMState.String()
		existing.Unlock()

		log.Warn("s1ap: evicting UE context after authenticated IMSI ownership",
			zap.String("imsi", imsi),
			zap.Uint32("old_mme_ue_id", oldMMEID),
			zap.Uint32("new_mme_ue_id", mmeUEID),
			zap.String("old_guti", oldGUTI),
			zap.String("candidate_guti", candidateGUTI),
			zap.String("candidate_imsi", candidateIMSI),
			zap.String("candidate_emm_state", existingEMM),
			zap.String("candidate_ecm_state", existingECM),
			zap.String("eviction_reason", "authenticated-imsi-reattach"),
			zap.Bool("ownership_confirmed", true),
			zap.Bool("context_replacement_authorized", true),
			zap.Bool("s11_delete_required", true))
		s.sendDeleteSession(existing)
		s.ueManager.Remove(existing)
	}

	s.ueManager.UpdateIMSI(ue, imsi)
}

// processDetach handles a NAS Detach Request from the UE.
func (s *Server) processDetach(ue *uecontext.Context, body []byte, log *zap.Logger) error {
	dr, err := emm.DecodeDetachRequest(body)
	if err != nil {
		return fmt.Errorf("processDetach: decode detach request: %w", err)
	}
	s.cancelReachabilityForDetach(ue)

	ue.Lock()
	mmeUEID := ue.MMEUES1APID
	enbAddr := ue.ENBGlobalID
	enbUEID := ue.ENBS1APID
	imsi := ue.IMSI
	intAlg := ue.IntAlg
	encAlg := ue.EncAlg
	knasInt := append([]byte(nil), ue.KNASint...)
	knasEnc := append([]byte(nil), ue.KNASenc...)
	dlCount := uint32(ue.DLNASCount)
	sgsState := ue.SGsState
	sgsVLRName := ue.SGsVLRName
	ue.SetEMMState(emm.StateDeregisteredInitiated)
	ue.Unlock()

	log.Info("s1ap: Detach Request from UE",
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.String("imsi", imsi),
		zap.Uint8("detach_type", dr.DetachType),
		zap.String("detach_type_name", emm.DetachTypeName(dr.DetachType)),
		zap.Bool("switch_off", dr.SwitchOff),
		zap.Uint8("ksi", dr.NASKeySetIdentifier),
		zap.String("eps_mobile_identity_hex", hex.EncodeToString(dr.EPSMobileIdentity)))

	// SGsAP EPS/IMSI Detach Indication (TS 29.118 §5.4/§5.5): only applies to
	// a UE that isn't already SGs-NULL. An IMSI or combined EPS/IMSI detach
	// not due to switch-off must hold back the Detach Accept (and, with it,
	// the S1 context release) until SGsAP-IMSI-DETACH-ACK arrives.
	waitForIMSIDetachAck := false
	if s.sgsCfg.Enabled && sgsState != uecontext.SGsUENull {
		sentIMSIDetach := s.sendSGsDetachIndicationForUE(ue, sgsVLRName, imsi, dr.DetachType, log)
		waitForIMSIDetachAck = sentIMSIDetach && !dr.SwitchOff
	}

	if !dr.SwitchOff {
		detachAccept := emm.EncodeDetachAccept()
		protected, encErr := nas.EncodeIntegrityAndCiphered(detachAccept, intAlg, encAlg, knasInt, knasEnc, dlCount)
		if encErr != nil {
			return fmt.Errorf("processDetach: encode detach accept: %w", encErr)
		}
		if waitForIMSIDetachAck {
			s.deferDetachAcceptForIMSIDetachAck(ue, mmeUEID, enbUEID, enbAddr, protected, log)
			log.Info("s1ap: Detach Accept withheld pending SGsAP-IMSI-DETACH-ACK",
				zap.Uint32("mme_ue_id", mmeUEID), zap.Uint32("dl_nas_count", dlCount))
		} else {
			s.sendDownlinkNASTransport(enbAddr, mmeUEID, enbUEID, protected)
			ue.Lock()
			ue.DLNASCount.Increment()
			ue.Unlock()
			log.Info("s1ap: Detach Accept sent",
				zap.Uint32("mme_ue_id", mmeUEID),
				zap.Uint32("dl_nas_count", dlCount),
				zap.Uint8("security_header_type", protected[0]>>4))
		}
	} else {
		log.Info("s1ap: Detach Accept suppressed for switch-off detach",
			zap.Uint32("mme_ue_id", mmeUEID))
	}

	// Purge UE at HSS
	if imsi != "" && s.s6a != nil {
		s.sendPURForUE(ue)
	}

	// Release all active PDN sessions. Detach can arrive with multiple active
	// PDNs (for example internet + IMS), so a single UE-level DSR is not enough.
	s.sendDeleteSessionsForDetach(ue)

	// Initiate UE context release; metrics.AttachedUEs.Dec() is called in
	// handleUEContextReleaseComplete once the eNB confirms release, guarded by
	// wasAttached — do not decrement here to avoid double-count. Deferred
	// until the withheld Detach Accept above actually goes out, since the S1
	// signalling connection is needed to deliver it.
	if !waitForIMSIDetachAck {
		s.sendUEContextReleaseCommand(enbAddr, mmeUEID, enbUEID)
	}

	metrics.NASProceduresTotal.WithLabelValues("Detach", "request").Inc()
	return nil
}

// processIdentityResponse handles a NAS Identity Response (IMSI).
func (s *Server) processIdentityResponse(ue *uecontext.Context, body []byte, log *zap.Logger) error {
	idResp, err := emm.DecodeIdentityResponse(body)
	ue.Lock()
	pendingType := ue.PendingIdentityType
	step := ue.AttachStep
	ue.Unlock()
	if step == uecontext.AttachStepWaitingEquipmentIdentity {
		if err != nil || idResp.IMEI == "" || idResp.IdentityType != pendingType {
			return s.handleEquipmentIdentityFailure(ue, log, "invalid or mismatched equipment Identity Response")
		}
		ue.Lock()
		if idResp.IdentityType == emm.IdentityTypeIMEISV {
			ue.IMEISV = idResp.IMEI
		} else {
			ue.IMEI = idResp.IMEI
		}
		ue.PendingIdentityType = 0
		imsi, mmeUEID := ue.IMSI, ue.MMEUES1APID
		ue.AttachStep = uecontext.AttachStepWaitingS13ECA
		ue.Unlock()
		checker, ok := s.s6a.(interface {
			SendEquipmentCheck(string, string, uint32) error
		})
		if !ok {
			return s.handleEquipmentIdentityFailure(ue, log, "S13 client unavailable")
		}
		if err := checker.SendEquipmentCheck(imsi, idResp.IMEI, mmeUEID); err != nil {
			return s.handleEquipmentIdentityFailure(ue, log, err.Error())
		}
		log.Info("s13: equipment Identity Response received; ECR sent", zap.Uint32("mme_ue_id", mmeUEID), zap.String("identity_type", "imeisv"))
		return nil
	}
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

	ue.Lock()
	candidateGUTI := ue.CandidateGUTI
	candidateIMSI := ue.CandidateIMSI
	ue.Unlock()
	if candidateGUTI != "" {
		if candidateIMSI != "" && candidateIMSI != idResp.IMSI {
			log.Warn("s1ap: GUTI collision detected",
				zap.String("presented_guti", candidateGUTI),
				zap.String("candidate_imsi", candidateIMSI),
				zap.String("confirmed_imsi", idResp.IMSI),
				zap.Bool("candidate_context_preserved", true),
				zap.Bool("destructive_action_deferred", true))
		} else {
			log.Info("s1ap: GUTI candidate identity resolved",
				zap.String("presented_guti", candidateGUTI),
				zap.String("candidate_imsi", candidateIMSI),
				zap.String("confirmed_imsi", idResp.IMSI),
				zap.Bool("identity_match", candidateIMSI == idResp.IMSI))
		}
	}

	ue.Lock()
	ue.IMSI = idResp.IMSI
	ue.AttachStep = uecontext.AttachStepWaitingAIA
	mmeUEID := ue.MMEUES1APID
	ue.Unlock()
	if err := s.classifyRoaming(ue, idResp.IMSI); err != nil {
		cause := emm.CauseUEIdentityCannotBeDerived
		if admission, ok := err.(*roamingAdmissionError); ok {
			cause = admission.cause
		}
		ue.Lock()
		enbAddr, enbUEID := ue.ENBGlobalID, ue.ENBS1APID
		ue.Unlock()
		log.Warn("s1ap: roaming admission rejected", zap.String("reason", err.Error()), zap.Uint8("emm_cause", cause))
		s.sendDownlinkNASTransport(enbAddr, mmeUEID, enbUEID, emm.EncodeAttachReject(cause))
		s.ueManager.Remove(ue)
		return nil
	}
	if existing, ok := s.ueManager.GetByIMSI(idResp.IMSI); ok && existing.MMEUES1APID != ue.MMEUES1APID {
		s.log.Info("s1ap: duplicate IMSI identity pending authentication",
			zap.Uint32("new_mme_ue_id", mmeUEID),
			zap.Bool("destructive_action_deferred", true),
			zap.String("eviction_reason", "deferred-until-authentication"))
	}

	log.Info("s1ap: Identity Response: IMSI obtained")
	return s.sendAIRForUE(ue)
}

func (s *Server) handleEquipmentIdentityFailure(ue *uecontext.Context, log *zap.Logger, reason string) error {
	ue.Lock()
	mmeUEID, remote, enbID, imsi := ue.MMEUES1APID, ue.ENBGlobalID, ue.ENBS1APID, ue.IMSI
	ue.PendingIdentityType = 0
	ue.AttachStep = uecontext.AttachStepWaitingULA
	ue.Unlock()
	log.Warn("s13: equipment identity unavailable", zap.String("reason", reason))
	// The current S13 client exposes fail-open through the absence of an ECA;
	// a fail-closed deployment rejects here rather than creating a session.
	if policy, ok := s.s6a.(interface{ S13FailurePolicy() string }); ok && policy.S13FailurePolicy() == "reject" {
		s.sendDownlinkNASTransport(remote, mmeUEID, enbID, emm.EncodeAttachReject(emm.CauseNetworkFailure))
		s.ueManager.Remove(ue)
		return nil
	}
	_ = imsi
	_ = mmeUEID
	return s.sendULRForUE(ue)
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
