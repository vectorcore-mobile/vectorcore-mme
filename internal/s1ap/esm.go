package s1ap

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/gateway"
	"github.com/vectorcore/mme/internal/gtpv2"
	s11teid "github.com/vectorcore/mme/internal/gtpv2/s11"
	nas "github.com/vectorcore/mme/internal/nas"
	"github.com/vectorcore/mme/internal/nas/esm"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/uecontext"
)

func canonicalizeRequestedAPN(requestedAPN string, ue *uecontext.Context) (canonical string, cfg uecontext.SubscriberAPNConfig, authorized bool) {
	if requestedAPN == "" {
		return "", uecontext.SubscriberAPNConfig{}, false
	}
	if ue.SubscriberAPNConfigs == nil {
		if strings.EqualFold(requestedAPN, ue.APN) {
			return ue.APN, uecontext.SubscriberAPNConfig{ServiceSelection: ue.APN}, true
		}
		return requestedAPN, uecontext.SubscriberAPNConfig{}, false
	}
	if cfg, ok := ue.SubscriberAPNConfigs[requestedAPN]; ok {
		return requestedAPN, cfg, true
	}
	for apn, cfg := range ue.SubscriberAPNConfigs {
		if strings.EqualFold(apn, requestedAPN) {
			return apn, cfg, true
		}
	}
	return requestedAPN, uecontext.SubscriberAPNConfig{}, false
}

// negotiatedPDNTypeCause derives the optional ESM negotiation cause from all
// inputs to the PDN-type decision. Subscriber and network types use the 3GPP
// PDN-type values (IPv4=1, IPv6=2, IPv4v6=3); PAA is authoritative for the
// actual network selection when present.
func selectedPDNTypeForRequest(policy, configuredType, requested uint8) uint8 {
	switch policy {
	case 0:
		return esm.PDNTypeIPv4
	case 1:
		return esm.PDNTypeIPv6
	case 2:
		return esm.PDNTypeIPv4v6
	case 3: // IPv4-or-IPv6: the UE's single-family request selects the family.
		if requested == esm.PDNTypeIPv4 || requested == esm.PDNTypeIPv6 {
			return requested
		}
		return esm.PDNTypeIPv4
	default:
		return configuredType
	}
}

func negotiatedPDNTypeCause(requested, subscribedPolicy, networkSelected uint8, paa net.IP) uint8 {
	granted := networkSelected
	if granted == 0 && paa.To4() != nil {
		granted = esm.PDNTypeIPv4
	}
	if requested != esm.PDNTypeIPv4v6 || granted == 0 {
		return 0
	}
	switch {
	case subscribedPolicy == 0 && granted == esm.PDNTypeIPv4:
		return esm.ESMCausePDNTypeIPv4OnlyAllowed
	case subscribedPolicy == 1 && granted == esm.PDNTypeIPv6:
		return esm.ESMCausePDNTypeIPv6OnlyAllowed
	case subscribedPolicy == 2 && (granted == esm.PDNTypeIPv4 || granted == esm.PDNTypeIPv6):
		// A dual-stack subscription with a single selected address needs the
		// explicit single-address-bearer indication.
		return esm.ESMCauseSingleAddressBearerOnly
	default:
		return 0
	}
}

// imsDefaultBearerOptionalIEs selects the legacy inter-system mobility
// parameters only for the IMS signalling APN with its standardized QCI 5.
// This is APN/bearer policy, not a handset compatibility condition; all other
// PDNs retain their existing activation encoding unless their policy later
// explicitly selects such parameters.
func imsDefaultBearerOptionalIEs(apn string, qci uint8, apnAMBRUpBps, apnAMBRDownBps uint32) esm.ActivateDefaultBearerOptionalIEs {
	if !strings.EqualFold(apn, "ims") || qci != 5 {
		return esm.ActivateDefaultBearerOptionalIEs{}
	}
	return esm.IMSDefaultBearerInterworkingOptions(apnAMBRUpBps, apnAMBRDownBps)
}

func (s *Server) processESM(ue *uecontext.Context, result *nas.DecodeResult, log *zap.Logger) error {
	msg, err := esm.Decode(result.Plain)
	if err != nil || msg == nil {
		log.Warn("s1ap: malformed ESM message",
			zap.Error(err),
			zap.String("plain_nas_hex", hex.EncodeToString(result.Plain)))
		return nil
	}

	esmLog := log.With(
		zap.String("nas_family", "ESM"),
		zap.Uint8("ebi", msg.Header.EPSBearerID),
		zap.Uint8("pti", msg.Header.ProcedureTransactionID),
		zap.Uint8("esm_message_type", msg.Header.MessageType),
		zap.String("esm_message_name", esm.MessageTypeName(msg.Header.MessageType)),
		zap.String("plain_nas_hex", hex.EncodeToString(result.Plain)),
	)
	esmLog.Info("s1ap: decoded ESM message")

	switch msg.Header.MessageType {
	case esm.MsgPDNConnectivityRequest:
		req := esm.DecodePDNConnectivityRequest(result.Plain)
		if req == nil {
			esmLog.Warn("s1ap: malformed PDN Connectivity Request")
			return s.sendESMReject(ue, msg.Header.ProcedureTransactionID, esm.ESMCauseProtocolError, esmLog)
		}
		return s.handlePDNConnectivityRequest(ue, req, esmLog)
	case esm.MsgESMInformationResponse:
		resp, err := esm.DecodeESMInformationResponse(result.Plain)
		if err != nil {
			esmLog.Warn("s1ap: malformed ESM Information Response", zap.Error(err))
			return nil
		}
		return s.handleESMInformationResponse(ue, resp, esmLog)
	case esm.MsgPDNDisconnectRequest:
		req, err := esm.DecodePDNDisconnectRequest(result.Plain)
		if err != nil {
			esmLog.Warn("s1ap: malformed PDN Disconnect Request", zap.Error(err))
			return nil
		}
		esmLog.Info("s1ap: decoded PDN Disconnect Request",
			zap.Uint8("request_ebi", req.EPSBearerID),
			zap.Uint8("linked_ebi", req.LinkedEPSBearerID),
			zap.Uint8("pti", req.ProcedureTransactionID),
			zap.String("pco_hex", hex.EncodeToString(req.PCO)))
		return s.handlePDNDisconnectRequest(ue, req, esmLog)
	case esm.MsgBearerResourceModificationRequest:
		req, err := esm.DecodeBearerResourceModificationRequest(result.Plain)
		if err != nil {
			esmLog.Warn("s1ap: malformed Bearer Resource Modification Request", zap.Error(err))
			return nil
		}
		esmLog.Info("s1ap: decoded Bearer Resource Modification Request",
			zap.Uint8("linked_ebi", req.LinkedEPSBearerID),
			zap.String("tfa_hex", hex.EncodeToString(req.TFA)))
		return s.handleBearerResourceModificationRequest(ue, req, esmLog)
	case esm.MsgESMStatus:
		status, err := esm.DecodeESMStatus(result.Plain)
		if err != nil {
			esmLog.Warn("s1ap: malformed ESM Status", zap.Error(err))
			return nil
		}
		return s.handleESMStatus(ue, result, status, esmLog)
	case esm.MsgActivateDefaultEPSBearerContextAccept:
		accept, err := esm.DecodeActivateDefaultEPSBearerContextAccept(result.Plain)
		if err != nil {
			esmLog.Warn("s1ap: malformed Activate Default EPS Bearer Context Accept", zap.Error(err))
			return nil
		}
		return s.handleStandaloneBearerAccept(ue, accept, esmLog)
	case esm.MsgActivateDefaultEPSBearerContextReject:
		resp, err := esm.DecodeBearerProcedureResponse(result.Plain)
		if err != nil {
			esmLog.Warn("s1ap: malformed Activate Default EPS Bearer Context Reject", zap.Error(err))
			return nil
		}
		return s.handleStandaloneBearerReject(ue, resp, esmLog)
	case esm.MsgActivateDedicatedEPSBearerContextAccept,
		esm.MsgActivateDedicatedEPSBearerContextReject,
		esm.MsgModifyEPSBearerContextAccept,
		esm.MsgModifyEPSBearerContextReject,
		esm.MsgDeactivateEPSBearerContextAccept:
		resp, err := esm.DecodeBearerProcedureResponse(result.Plain)
		if err != nil {
			esmLog.Warn("s1ap: malformed bearer procedure response", zap.Error(err))
			return nil
		}
		esmLog.Info("s1ap: decoded bearer procedure response",
			zap.String("response_message_name", esm.MessageTypeName(resp.MessageType)),
			zap.Uint8("response_ebi", resp.EPSBearerID),
			zap.Uint8("pti", resp.ProcedureTransactionID),
			zap.Uint8("cause", resp.Cause),
			zap.String("pco_hex", hex.EncodeToString(resp.PCO)))
		if s.handlePDNDisconnectBearerResponse(ue, resp, esmLog) {
			return nil
		}
		s.handleDedicatedBearerNASResponse(ue, resp, esmLog)
		return nil
	default:
		esmLog.Warn("s1ap: unsupported ESM message")
		return nil
	}
}

func (s *Server) handleStandaloneBearerReject(ue *uecontext.Context, resp *esm.BearerProcedureResponse, log *zap.Logger) error {
	if resp == nil {
		return nil
	}
	ue.Lock()
	pdn := findPDNByLinkedEBILocked(ue, resp.EPSBearerID)
	if pdn == nil {
		ue.Unlock()
		log.Warn("s1ap: Activate Default EPS Bearer Context Reject for unknown bearer", zap.Uint8("ebi", resp.EPSBearerID))
		return nil
	}
	stopDefaultT3485Locked(ue, pdn)
	pdn.State = "activation-rejected"
	ue.Unlock()
	log.Info("s1ap: Activate Default EPS Bearer Context Reject received", zap.Uint8("ebi", resp.EPSBearerID), zap.Uint8("cause", resp.Cause))
	s.failLinkedCreateBearerTransactions(ue, resp.EPSBearerID, gtpv2.CauseUERefuses)
	s.sendDeleteSessionForPDN(ue, resp.EPSBearerID, log)
	return nil
}

func (s *Server) handleESMStatus(ue *uecontext.Context, result *nas.DecodeResult, status *esm.ESMStatus, log *zap.Logger) error {
	ue.Lock()
	imsi := ue.IMSI
	mmeUEID := ue.MMEUES1APID
	lastDownlink := ue.LastDownlinkNASMessage
	ue.Unlock()

	log.Warn("s1ap: ESM Status received",
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.String("imsi", imsi),
		zap.Uint8("security_header_type", result.SecHeaderType),
		zap.Uint32("uplink_nas_count", result.Count),
		zap.Uint8("sequence_number", result.Sequence),
		zap.String("received_mac", hex.EncodeToString(result.MAC)),
		zap.String("deciphered_plain_nas", hex.EncodeToString(result.Plain)),
		zap.Uint8("message_type", result.MsgType),
		zap.Uint8("esm_cause", status.Cause),
		zap.String("esm_cause_name", esm.CauseName(status.Cause)),
		zap.String("triggering_last_downlink_message", lastDownlink))
	return nil
}

func (s *Server) handlePDNConnectivityRequest(ue *uecontext.Context, req *esm.PDNConnectivityRequest, log *zap.Logger) error {
	requestedAPN := req.APN
	ue.Lock()
	if req.ESMInformationRequired {
		if ue.PendingPDN != nil {
			pendingAPN := ue.PendingPDN.APN
			ue.Unlock()
			log.Warn("s1ap: rejecting ESM information transfer while another PDN is pending",
				zap.String("pending_apn", pendingAPN),
				zap.Uint8("pti", req.ProcedureTransactionID))
			return s.sendESMReject(ue, req.ProcedureTransactionID, esm.ESMCauseInsufficientResources, log)
		}
		ue.PendingPDN = &uecontext.PDNContext{
			APN:                    requestedAPN,
			ProcedureTransactionID: req.ProcedureTransactionID,
			PDNType:                req.PDNType,
			UEPCO:                  append([]byte(nil), req.PCO...),
			State:                  "esm-information-pending",
		}
		ue.Unlock()
		if err := s.sendProtectedNAS(ue, esm.EncodeESMInformationRequest(req.ProcedureTransactionID), "ESM Information Request"); err != nil {
			ue.Lock()
			if ue.PendingPDN != nil && ue.PendingPDN.ProcedureTransactionID == req.ProcedureTransactionID && ue.PendingPDN.State == "esm-information-pending" {
				ue.PendingPDN = nil
			}
			ue.Unlock()
			log.Warn("s1ap: failed to send ESM Information Request",
				zap.Uint8("pti", req.ProcedureTransactionID),
				zap.Error(err))
			return err
		}
		log.Info("s1ap: ESM Information Request sent",
			zap.Uint8("pti", req.ProcedureTransactionID),
			zap.Uint8("requested_pdn_type", req.PDNType),
			zap.String("pco_hex", hex.EncodeToString(req.PCO)))
		return nil
	}
	if requestedAPN == "" {
		requestedAPN = ue.APN
	}
	requestedAPN, apnCfg, authorized := canonicalizeRequestedAPN(requestedAPN, ue)
	if ue.SubscriberAPNConfigs == nil && authorized && apnCfg.ServiceSelection == "" {
		apnCfg = uecontext.SubscriberAPNConfig{ServiceSelection: requestedAPN}
	}
	mmeID := ue.MMEUES1APID
	imsi := ue.IMSI
	msisdn := ue.MSISDN
	subscribedAPNs := append([]string(nil), ue.SubscriberAPNs...)
	ecgieci := ue.ECGIECI
	var ulitac uint16
	if ue.TAI != nil {
		ulitac = ue.TAI.TAC
	}
	if ue.PDNs == nil {
		ue.PDNs = make(map[string]*uecontext.PDNContext)
	}
	if _, exists := ue.PDNs[requestedAPN]; exists {
		ue.Unlock()
		log.Info("s1ap: PDN Connectivity Request for already active APN",
			zap.String("requested_apn", requestedAPN),
			zap.Uint8("pti", req.ProcedureTransactionID))
		return s.sendESMReject(ue, req.ProcedureTransactionID, esm.ESMCauseRequestRejectedUnspecified, log)
	}
	if ue.PendingPDN != nil {
		ue.Unlock()
		log.Warn("s1ap: rejecting PDN Connectivity Request while another PDN is pending",
			zap.String("requested_apn", requestedAPN),
			zap.String("pending_apn", ue.PendingPDN.APN))
		return s.sendESMReject(ue, req.ProcedureTransactionID, esm.ESMCauseInsufficientResources, log)
	}
	ebi := allocateDefaultBearerIDLocked(ue)
	pendingReservationID := pendingPDNReservationID(ue, req.ProcedureTransactionID, requestedAPN)
	if ebi != 0 {
		if ue.EBIReservations == nil {
			ue.EBIReservations = make(map[uint8]uecontext.EBIReservation)
		}
		ue.EBIReservations[ebi] = uecontext.EBIReservation{
			EBI:           ebi,
			TransactionID: pendingReservationID,
			ReservedAt:    time.Now(),
		}
	}
	ue.Unlock()

	log.Info("s1ap: PDN Connectivity Request received",
		zap.String("requested_apn", requestedAPN),
		zap.Uint8("requested_pdn_type", req.PDNType),
		zap.Uint8("request_type", req.RequestType),
		zap.Uint8("pti", req.ProcedureTransactionID),
		zap.Uint8("request_ebi", req.EPSBearerID),
		zap.Strings("subscribed_apns", subscribedAPNs),
		zap.Bool("authorized", authorized),
		zap.String("pco_hex", hex.EncodeToString(req.PCO)))

	if !authorized || requestedAPN == "" {
		return s.sendESMReject(ue, req.ProcedureTransactionID, esm.ESMCauseMissingOrUnknownAPN, log)
	}
	if missing := validateSubscriberAPNPolicy(&apnCfg); len(missing) != 0 {
		log.Warn("s1ap: incomplete subscriber APN policy, rejecting PDN Connectivity Request",
			zap.String("requested_apn", requestedAPN),
			zap.Uint8("pti", req.ProcedureTransactionID),
			zap.Strings("missing_fields", missing))
		return s.sendESMReject(ue, req.ProcedureTransactionID, esm.ESMCauseRequestRejectedUnspecified, log)
	}
	if ebi == 0 {
		return s.sendESMReject(ue, req.ProcedureTransactionID, esm.ESMCauseInsufficientResources, log)
	}

	localTEID := s11teid.AllocateTEID()
	plmn := s.buildPLMN()
	localIP := net.IP(s.s11LocalIP)
	sgwAddr := ""
	pgwIP := net.IP(s.pgwIP)
	if s.gatewaySel != nil {
		selCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		sgwSel, err := s.gatewaySel.SelectSGW(selCtx, ulitac)
		if err != nil {
			log.Warn("s1ap: SGW selection failed for PDN request", zap.Error(err))
			return s.sendESMReject(ue, req.ProcedureTransactionID, esm.ESMCauseRequestRejectedUnspecified, log)
		}
		gtwCfg := gateway.APNConfiguration{
			ContextIdentifier:   apnCfg.ContextIdentifier,
			ServiceSelection:    requestedAPN,
			MIPHomeAgentAddress: apnCfg.MIPHomeAgentAddress,
			MIPHomeAgentHost:    apnCfg.MIPHomeAgentHost,
			PDNGWAllocationType: apnCfg.PDNGWAllocationType,
		}
		pgwSel, err := s.gatewaySel.SelectPGW(selCtx, requestedAPN, &gtwCfg)
		if err != nil {
			log.Warn("s1ap: PGW selection failed for PDN request", zap.Error(err))
			return s.sendESMReject(ue, req.ProcedureTransactionID, esm.ESMCauseMissingOrUnknownAPN, log)
		}
		sgwAddr = sgwSel.UDPAddr()
		pgwIP = pgwSel.Address
	}

	pdn := &uecontext.PDNContext{
		APN:                     requestedAPN,
		ProcedureTransactionID:  req.ProcedureTransactionID,
		PDNType:                 selectedPDNTypeForRequest(apnCfg.PDNTypePolicy, apnCfg.PDNType, req.PDNType),
		RequestedPDNType:        req.PDNType,
		SubscribedPDNType:       apnCfg.PDNType,
		SubscribedPDNTypePolicy: apnCfg.PDNTypePolicy,
		DefaultEBI:              ebi,
		QCI:                     apnCfg.QCI,
		ARPPriority:             apnCfg.ARPPriority,
		PreemptionCapability:    apnCfg.PreemptionCapability,
		PreemptionVulnerability: apnCfg.PreemptionVulnerability,
		APNAMBRDown:             apnCfg.APNAMBRDown,
		APNAMBRUp:               apnCfg.APNAMBRUp,
		LocalS11TEID:            localTEID,
		SGWAddress:              sgwAddr,
		UEPCO:                   append([]byte(nil), req.PCO...),
		State:                   "csr-sent",
	}
	ue.Lock()
	ue.PendingPDN = pdn
	ue.Unlock()

	csr := &gtpv2.CreateSessionRequest{
		SGWAddress:              sgwAddr,
		IMSI:                    imsi,
		MSISDN:                  msisdn,
		APN:                     requestedAPN,
		RATType:                 gtpv2.RATTypeEUTRAN,
		ServingNetwork:          plmn,
		LocalS11TEID:            localTEID,
		LocalS11IP:              localIP,
		PGWIP:                   pgwIP,
		ULIPLMN:                 plmn,
		ULITAC:                  ulitac,
		ULIECI:                  ecgieci,
		PCO:                     req.PCO,
		PDNType:                 pdn.PDNType,
		DefaultEBI:              ebi,
		BearerQCI:               apnCfg.QCI,
		BearerPriorityLevel:     apnCfg.ARPPriority,
		PreemptionCapability:    apnCfg.PreemptionCapability,
		PreemptionVulnerability: apnCfg.PreemptionVulnerability,
		UplinkAMBRKbps:          apnCfg.APNAMBRUp,
		DownlinkAMBRKbps:        apnCfg.APNAMBRDown,
	}
	if err := s.s11.SendCSR(mmeID, csr); err != nil {
		ue.Lock()
		if ue.PendingPDN == pdn {
			ue.PendingPDN = nil
		}
		releasePendingPDNReservationLocked(ue, pdn)
		ue.Unlock()
		log.Warn("s1ap: IMS PDN SendCSR failed", zap.Error(err))
		return s.sendESMReject(ue, req.ProcedureTransactionID, esm.ESMCauseRequestRejectedUnspecified, log)
	}
	log.Info("s1ap: IMS PDN Create Session Request sent",
		zap.String("apn", requestedAPN),
		zap.Uint8("default_ebi", ebi),
		zap.Uint32("local_teid", localTEID),
		zap.String("selected_pgw", pgwIP.String()))
	return nil
}

func (s *Server) handleESMInformationResponse(ue *uecontext.Context, resp *esm.ESMInformationResponse, log *zap.Logger) error {
	ue.Lock()
	pending := ue.PendingPDN
	if pending == nil || pending.State != "esm-information-pending" {
		ue.Unlock()
		log.Warn("s1ap: ESM Information Response without pending PDN",
			zap.Uint8("pti", resp.ProcedureTransactionID),
			zap.String("apn", resp.APN))
		return nil
	}
	if pending.ProcedureTransactionID != resp.ProcedureTransactionID {
		pendingPTI := pending.ProcedureTransactionID
		ue.Unlock()
		log.Warn("s1ap: ESM Information Response PTI mismatch",
			zap.Uint8("pti", resp.ProcedureTransactionID),
			zap.Uint8("pending_pti", pendingPTI),
			zap.String("apn", resp.APN))
		return nil
	}
	req := &esm.PDNConnectivityRequest{
		EPSBearerID:            resp.EPSBearerID,
		ProcedureTransactionID: resp.ProcedureTransactionID,
		PDNType:                pending.PDNType,
		RequestType:            1,
		APN:                    resp.APN,
		PCO:                    append([]byte(nil), pending.UEPCO...),
	}
	if len(resp.PCO) > 0 {
		req.PCO = append([]byte(nil), resp.PCO...)
	}
	ue.PendingPDN = nil
	releasePendingPDNReservationLocked(ue, pending)
	ue.Unlock()

	log.Info("s1ap: ESM Information Response received; resuming PDN Connectivity",
		zap.Uint8("pti", resp.ProcedureTransactionID),
		zap.String("apn", resp.APN),
		zap.String("pco_hex", hex.EncodeToString(req.PCO)))
	return s.handlePDNConnectivityRequest(ue, req, log)
}

func (s *Server) handleStandaloneBearerAccept(ue *uecontext.Context, accept *esm.ActivateDefaultEPSBearerContextAccept, log *zap.Logger) error {
	ue.Lock()
	for _, pdn := range ue.PDNs {
		if pdn.DefaultEBI == accept.EPSBearerID {
			stopDefaultT3485Locked(ue, pdn)
			pdn.NASAccepted = true
			if pdn.ERABEstablished && pdn.ModifyBearerAccepted {
				pdn.State = "active"
			} else if pdn.ERABEstablished && !pdn.ModifyBearerSent {
				pdn.State = "access-established"
			}
			log.Info("s1ap: Activate Default EPS Bearer Context Accept received",
				zap.String("apn", pdn.APN),
				zap.Uint8("ebi", accept.EPSBearerID),
				zap.Uint8("pti", accept.ProcedureTransactionID),
				zap.Bool("erab_established", pdn.ERABEstablished),
				zap.Bool("modify_bearer_sent", pdn.ModifyBearerSent),
				zap.Bool("modify_bearer_accepted", pdn.ModifyBearerAccepted),
				zap.String("pco_hex", hex.EncodeToString(accept.PCO)))
			ue.Unlock()
			s.maybeAdvanceDefaultBearer(ue, accept.EPSBearerID, "nas-accept", log)
			return nil
		}
	}
	ue.Unlock()
	log.Warn("s1ap: Activate Default EPS Bearer Context Accept for unknown bearer",
		zap.Uint8("ebi", accept.EPSBearerID),
		zap.Uint8("pti", accept.ProcedureTransactionID))
	return nil
}

func (s *Server) handlePDNDisconnectRequest(ue *uecontext.Context, req *esm.PDNDisconnectRequest, log *zap.Logger) error {
	ue.Lock()
	target := findPDNByLinkedEBILocked(ue, req.LinkedEPSBearerID)
	if target == nil {
		ue.Unlock()
		log.Warn("s1ap: PDN Disconnect Request for unknown linked bearer",
			zap.Uint8("linked_ebi", req.LinkedEPSBearerID),
			zap.Uint8("pti", req.ProcedureTransactionID))
		return s.sendPDNDisconnectReject(ue, req.ProcedureTransactionID, esm.ESMCauseProtocolError, log)
	}
	if target.DisconnectRequested {
		ue.Unlock()
		log.Warn("s1ap: PDN Disconnect Request while disconnect already pending",
			zap.Uint8("linked_ebi", req.LinkedEPSBearerID),
			zap.Uint8("pti", req.ProcedureTransactionID))
		return s.sendPDNDisconnectReject(ue, req.ProcedureTransactionID, esm.ESMCauseRequestRejectedUnspecified, log)
	}
	target.DisconnectPTI = req.ProcedureTransactionID
	target.DisconnectRequested = true
	target.DisconnectNASAccepted = false
	target.State = "pdn-disconnect-requested"
	apn := target.APN
	defaultEBI := target.DefaultEBI
	ue.Unlock()

	log.Info("s1ap: PDN Disconnect Request received",
		zap.String("apn", apn),
		zap.Uint8("linked_ebi", req.LinkedEPSBearerID),
		zap.Uint8("default_ebi", defaultEBI),
		zap.Uint8("pti", req.ProcedureTransactionID),
		zap.String("pco_hex", hex.EncodeToString(req.PCO)))
	if err := s.sendProtectedNAS(ue, esm.EncodeDeactivateEPSBearerContextRequest(defaultEBI, req.ProcedureTransactionID, esm.ESMCauseRegularDeactivation), "Deactivate EPS Bearer Context Request"); err != nil {
		ue.Lock()
		if current := findPDNByLinkedEBILocked(ue, req.LinkedEPSBearerID); current != nil && current.DisconnectPTI == req.ProcedureTransactionID {
			current.DisconnectRequested = false
			current.State = "active"
		}
		ue.Unlock()
		log.Warn("s1ap: failed to send PDN Disconnect deactivation request",
			zap.String("apn", apn),
			zap.Uint8("default_ebi", defaultEBI),
			zap.Error(err))
		return err
	}
	ue.Lock()
	if current := findPDNByLinkedEBILocked(ue, req.LinkedEPSBearerID); current != nil && current.DisconnectPTI == req.ProcedureTransactionID {
		current.State = "pdn-disconnect-deactivate-sent"
	}
	ue.Unlock()
	log.Info("s1ap: PDN Disconnect deactivation started",
		zap.String("apn", apn),
		zap.Uint8("default_ebi", defaultEBI),
		zap.Uint8("pti", req.ProcedureTransactionID))
	return nil
}

func (s *Server) handleBearerResourceModificationRequest(ue *uecontext.Context, req *esm.BearerResourceModificationRequest, log *zap.Logger) error {
	ue.Lock()
	linkedPDN := findPDNByLinkedEBILocked(ue, req.LinkedEPSBearerID)
	dedicated := ue.DedicatedBearers[req.LinkedEPSBearerID]
	ue.Unlock()

	if linkedPDN == nil && dedicated == nil {
		log.Warn("s1ap: Bearer Resource Modification Request for unknown bearer",
			zap.Uint8("linked_ebi", req.LinkedEPSBearerID))
		return s.sendBearerResourceModificationReject(ue, req.ProcedureTransactionID, esm.ESMCauseProtocolError, log)
	}

	if dedicated == nil {
		log.Info("s1ap: Bearer Resource Modification Request unsupported for default bearer",
			zap.Uint8("linked_ebi", req.LinkedEPSBearerID),
			zap.Bool("matched_default_bearer", linkedPDN != nil),
			zap.Bool("matched_dedicated_bearer", false))
		return s.sendBearerResourceModificationReject(ue, req.ProcedureTransactionID, esm.ESMCauseServiceOptionNotSupported, log)
	}

	log.Info("s1ap: Bearer Resource Modification Request received",
		zap.Uint8("linked_ebi", req.LinkedEPSBearerID),
		zap.Bool("matched_default_bearer", linkedPDN != nil),
		zap.Bool("matched_dedicated_bearer", dedicated != nil),
		zap.String("tfa_hex", hex.EncodeToString(req.TFA)))
	if err := s.HandleLocalBearerResourceModification(ue, req); err != nil {
		log.Warn("s1ap: Bearer Resource Modification Request handling failed",
			zap.Uint8("linked_ebi", req.LinkedEPSBearerID),
			zap.Error(err))
		return s.sendBearerResourceModificationReject(ue, req.ProcedureTransactionID, esm.ESMCauseRequestRejectedUnspecified, log)
	}
	return nil
}

func (s *Server) handlePDNDisconnectBearerResponse(ue *uecontext.Context, resp *esm.BearerProcedureResponse, log *zap.Logger) bool {
	if resp.MessageType != esm.MsgDeactivateEPSBearerContextAccept {
		return false
	}
	var matched *uecontext.PDNContext
	ue.Lock()
	for _, pdn := range ue.PDNs {
		if pdn == nil || !pdn.DisconnectRequested || pdn.DefaultEBI != resp.EPSBearerID {
			continue
		}
		if resp.ProcedureTransactionID != 0 && pdn.DisconnectPTI != resp.ProcedureTransactionID {
			continue
		}
		pdn.DisconnectNASAccepted = true
		pdn.State = "pdn-disconnect-deactivate-accepted"
		matched = pdn
		break
	}
	ue.Unlock()
	if matched == nil {
		return false
	}
	log.Info("s1ap: PDN Disconnect deactivate accept received",
		zap.String("apn", matched.APN),
		zap.Uint8("default_ebi", matched.DefaultEBI),
		zap.Uint8("pti", resp.ProcedureTransactionID))
	s.advancePDNDisconnectCleanup(ue, matched.DefaultEBI, log)
	return true
}

func (s *Server) handlePendingPDNCSRResult(ue *uecontext.Context, resp *gtpv2.CreateSessionResponse, err error, log *zap.Logger) {
	ue.Lock()
	pdn := ue.PendingPDN
	if pdn == nil {
		ue.Unlock()
		return
	}
	pti := pdn.ProcedureTransactionID
	apn := pdn.APN
	ue.Unlock()

	if err != nil {
		log.Warn("s1ap: IMS CSRsp error",
			zap.String("apn", apn),
			zap.Error(err))
		ue.Lock()
		if ue.PendingPDN == pdn {
			ue.PendingPDN = nil
		}
		releasePendingPDNReservationLocked(ue, pdn)
		ue.Unlock()
		_ = s.sendESMReject(ue, pti, esm.ESMCauseRequestRejectedUnspecified, log)
		return
	}
	if !gtpv2.IsAcceptedCause(resp.Cause) {
		log.Warn("s1ap: IMS CSRsp rejected",
			zap.String("apn", apn),
			zap.Uint8("cause", resp.Cause),
			zap.String("cause_name", gtpv2.CauseName(resp.Cause)))
		ue.Lock()
		if ue.PendingPDN == pdn {
			ue.PendingPDN = nil
		}
		releasePendingPDNReservationLocked(ue, pdn)
		ue.Unlock()
		_ = s.sendESMReject(ue, pti, esm.ESMCauseRequestRejectedBySGW, log)
		return
	}
	if resp.EBI == 0 {
		log.Warn("s1ap: IMS CSRsp accepted without valid bearer EBI",
			zap.String("apn", apn))
		ue.Lock()
		if ue.PendingPDN == pdn {
			ue.PendingPDN = nil
		}
		releasePendingPDNReservationLocked(ue, pdn)
		ue.Unlock()
		_ = s.sendESMReject(ue, pti, esm.ESMCauseRequestRejectedUnspecified, log)
		return
	}

	ue.Lock()
	if pdn.DefaultEBI != resp.EBI {
		releasePendingPDNReservationLocked(ue, pdn)
		if ue.EBIReservations == nil {
			ue.EBIReservations = make(map[uint8]uecontext.EBIReservation)
		}
		ue.EBIReservations[resp.EBI] = uecontext.EBIReservation{
			EBI:           resp.EBI,
			TransactionID: pendingPDNReservationID(ue, pdn.ProcedureTransactionID, pdn.APN),
			ReservedAt:    time.Now(),
		}
	}
	pdn.DefaultEBI = resp.EBI
	pdn.SGWC_TEID = resp.SGWC_TEID
	pdn.SGWC_IP = append(net.IP(nil), resp.SGWC_IP...)
	pdn.SGWU_TEID = resp.SGWU_TEID
	pdn.SGWU_IP = append(net.IP(nil), resp.SGWU_IP...)
	pdn.UEIPv4 = append(net.IP(nil), resp.UEIPv4...)
	pdn.NetworkPDNType = resp.PDNType
	pdn.PGWPCO = append([]byte(nil), resp.PCO...)
	pdn.State = "activating"
	pdn.SessionCreatedAt = time.Now()
	pdn.LastSuccessfulS11Procedure = "create-session-response"
	if ue.PDNs == nil {
		ue.PDNs = make(map[string]*uecontext.PDNContext)
	}
	ue.PDNs[pdn.APN] = pdn
	ue.PendingPDN = nil
	releasePendingPDNReservationLocked(ue, pdn)
	ue.Unlock()

	esmAPN := s.apnForIMSDefaultBearerNAS(pdn.APN)
	if pdn.QCI == 0 {
		log.Error("s1ap: refusing default bearer activation without subscribed QCI", zap.String("apn", pdn.APN), zap.Uint8("ebi", pdn.DefaultEBI))
		return
	}
	downgradeCause := negotiatedPDNTypeCause(pdn.RequestedPDNType, pdn.SubscribedPDNTypePolicy, pdn.NetworkPDNType, pdn.UEIPv4)
	optionalIEs := imsDefaultBearerOptionalIEs(pdn.APN, pdn.QCI, pdn.APNAMBRUp, pdn.APNAMBRDown)
	activate := esm.EncodePDNConnectivityAcceptWithQoSAndCauseAndOptionalIEs(pti, esmAPN, pdn.DefaultEBI, pdn.UEIPv4, pdn.QCI, pdn.APNAMBRUp, pdn.APNAMBRDown, downgradeCause, pdn.PGWPCO, optionalIEs)
	protected, _, err := s.protectNAS(ue, activate)
	if err != nil {
		log.Warn("s1ap: failed to protect IMS Activate Default EPS Bearer Context Request",
			zap.String("apn", pdn.APN),
			zap.Uint8("ebi", pdn.DefaultEBI),
			zap.Error(err))
		return
	}
	s.stageInitialIMSDefaultERABActivation(ue, pdn, activate, protected, log)
	log.Info("s1ap: IMS Activate Default EPS Bearer Context Request constructed and queued for E-RAB setup",
		zap.String("apn", pdn.APN),
		zap.String("canonical_apn", esmAPN),
		zap.Uint8("pti", pti),
		zap.Uint8("default_ebi", pdn.DefaultEBI),
		zap.Uint8("nas_qci", pdn.QCI),
		zap.Uint8("s1ap_qci", pdn.QCI),
		zap.Uint8("s11_qci", pdn.QCI),
		zap.Uint8("arp_priority", pdn.ARPPriority),
		zap.Uint32("apn_ambr_dl", pdn.APNAMBRDown),
		zap.Uint32("apn_ambr_ul", pdn.APNAMBRUp),
		zap.String("plain_nas_hex", hex.EncodeToString(activate)),
		zap.String("paa_ipv4", pdn.UEIPv4.String()),
		zap.Uint32("sgwc_teid", pdn.SGWC_TEID),
		zap.Uint32("sgwu_teid", pdn.SGWU_TEID),
		zap.String("pgw_pco_hex", hex.EncodeToString(pdn.PGWPCO)))
}

func (s *Server) sendESMReject(ue *uecontext.Context, pti uint8, cause uint8, log *zap.Logger) error {
	reject := esm.EncodePDNConnectivityReject(pti, cause)
	if err := s.sendProtectedNAS(ue, reject, "PDN Connectivity Reject"); err != nil {
		log.Warn("s1ap: failed to send PDN Connectivity Reject", zap.Error(err), zap.Uint8("esm_cause", cause))
		return err
	}
	log.Info("s1ap: PDN Connectivity Reject sent",
		zap.Uint8("pti", pti),
		zap.Uint8("esm_cause", cause))
	return nil
}

func (s *Server) sendPDNDisconnectReject(ue *uecontext.Context, pti uint8, cause uint8, log *zap.Logger) error {
	reject := esm.EncodePDNDisconnectReject(pti, cause)
	if err := s.sendProtectedNAS(ue, reject, "PDN Disconnect Reject"); err != nil {
		log.Warn("s1ap: failed to send PDN Disconnect Reject", zap.Error(err), zap.Uint8("esm_cause", cause))
		return err
	}
	log.Info("s1ap: PDN Disconnect Reject sent",
		zap.Uint8("pti", pti),
		zap.Uint8("esm_cause", cause))
	return nil
}

func (s *Server) sendBearerResourceModificationReject(ue *uecontext.Context, pti uint8, cause uint8, log *zap.Logger) error {
	reject := esm.EncodeBearerResourceModificationReject(pti, cause)
	if err := s.sendProtectedNAS(ue, reject, "Bearer Resource Modification Reject"); err != nil {
		log.Warn("s1ap: failed to send Bearer Resource Modification Reject", zap.Error(err), zap.Uint8("esm_cause", cause))
		return err
	}
	log.Info("s1ap: Bearer Resource Modification Reject sent",
		zap.Uint8("pti", pti),
		zap.Uint8("esm_cause", cause))
	return nil
}

func (s *Server) sendProtectedNAS(ue *uecontext.Context, plain []byte, name string) error {
	mmeID := ue.MMEUES1APID
	protected, _, err := s.protectNAS(ue, plain)
	if err != nil {
		return err
	}
	if err := s.SendDownlinkNAS(mmeID, protected); err != nil {
		return err
	}
	ue.Lock()
	ue.DLNASCount.Increment()
	ue.LastDownlinkNASMessage = name
	ue.Unlock()
	return nil
}

func (s *Server) protectNAS(ue *uecontext.Context, plain []byte) ([]byte, uint32, error) {
	ue.Lock()
	intAlg := ue.IntAlg
	encAlg := ue.EncAlg
	knasInt := append([]byte(nil), ue.KNASint...)
	knasEnc := append([]byte(nil), ue.KNASenc...)
	dlCount := uint32(ue.DLNASCount)
	ue.Unlock()

	protected, err := nas.EncodeIntegrityAndCiphered(plain, intAlg, encAlg, knasInt, knasEnc, dlCount)
	if err != nil {
		return nil, dlCount, fmt.Errorf("protect NAS: %w", err)
	}
	return protected, dlCount, nil
}

func allocateDefaultBearerIDLocked(ue *uecontext.Context) uint8 {
	used := map[uint8]bool{}
	if ue.DefaultEBI != 0 {
		used[ue.DefaultEBI] = true
	}
	for _, pdn := range ue.PDNs {
		if pdn.DefaultEBI != 0 {
			used[pdn.DefaultEBI] = true
		}
	}
	if ue.PendingPDN != nil && ue.PendingPDN.DefaultEBI != 0 {
		used[ue.PendingPDN.DefaultEBI] = true
	}
	for ebi := range ue.DedicatedBearers {
		if ebi != 0 {
			used[ebi] = true
		}
	}
	for ebi := range ue.EBIReservations {
		if ebi != 0 {
			used[ebi] = true
		}
	}
	for _, tx := range ue.PendingBearerTransactions {
		for ebi := range tx.Bearers {
			if ebi != 0 {
				used[ebi] = true
			}
		}
	}
	for ebi := uint8(5); ebi <= 15; ebi++ {
		if !used[ebi] {
			return ebi
		}
	}
	return 0
}

func pendingPDNReservationID(ue *uecontext.Context, pti uint8, apn string) string {
	return fmt.Sprintf("pending-pdn-%d-%d-%s", ue.MMEUES1APID, pti, apn)
}

func releasePendingPDNReservationLocked(ue *uecontext.Context, pdn *uecontext.PDNContext) {
	if ue == nil || pdn == nil || pdn.DefaultEBI == 0 {
		return
	}
	res, ok := ue.EBIReservations[pdn.DefaultEBI]
	if !ok {
		return
	}
	if res.TransactionID != pendingPDNReservationID(ue, pdn.ProcedureTransactionID, pdn.APN) {
		return
	}
	delete(ue.EBIReservations, pdn.DefaultEBI)
}

func findPDNByLinkedEBILocked(ue *uecontext.Context, linkedEBI uint8) *uecontext.PDNContext {
	if linkedEBI == 0 {
		return nil
	}
	for _, pdn := range ue.PDNs {
		if pdn != nil && pdn.DefaultEBI == linkedEBI {
			return pdn
		}
	}
	if ue.DefaultEBI == linkedEBI && ue.APN != "" {
		if ue.PDNs == nil {
			ue.PDNs = make(map[string]*uecontext.PDNContext)
		}
		pdn := ue.PDNs[ue.APN]
		if pdn == nil {
			pdn = &uecontext.PDNContext{
				APN:          ue.APN,
				DefaultEBI:   ue.DefaultEBI,
				LocalS11TEID: ue.LocalS11TEID,
				SGWAddress:   ue.SGWAddress,
				SGWC_TEID:    ue.SGWC_TEID,
				SGWC_IP:      append([]byte(nil), ue.SGWC_IP...),
				SGWU_TEID:    ue.SGWU_TEID,
				SGWU_IP:      append([]byte(nil), ue.SGWU_IP...),
				ENBU_TEID:    ue.ENBU_TEID,
				ENBU_IP:      append([]byte(nil), ue.ENBU_IP...),
				UEIPv4:       append([]byte(nil), ue.UEIPv4...),
				State:        "legacy-default-bearer",
			}
			ue.PDNs[ue.APN] = pdn
		}
		return pdn
	}
	return nil
}

func (s *Server) advancePDNDisconnectCleanup(ue *uecontext.Context, linkedEBI uint8, log *zap.Logger) {
	ue.Lock()
	pdn := findPDNByLinkedEBILocked(ue, linkedEBI)
	if pdn == nil || !pdn.DisconnectRequested || !pdn.DisconnectNASAccepted {
		ue.Unlock()
		return
	}
	linkedDedicated := collectLinkedDedicatedBearersLocked(ue, linkedEBI)
	mmeUEID := ue.MMEUES1APID
	txID := fmt.Sprintf("pdn-disc-%d-%d", mmeUEID, linkedEBI)
	if len(linkedDedicated) == 0 {
		ue.Unlock()
		s.sendDeleteSessionForPDN(ue, linkedEBI, log)
		return
	}
	if !hasActiveS1BindingLocked(ue) {
		for _, ebi := range linkedDedicated {
			delete(ue.DedicatedBearers, ebi)
		}
		ue.Unlock()
		s.sendDeleteSessionForPDN(ue, linkedEBI, log)
		return
	}
	items := make([]ERABReleaseItem, 0, len(linkedDedicated))
	for _, ebi := range linkedDedicated {
		items = append(items, ERABReleaseItem{
			EBI:        ebi,
			CauseGroup: ies.CauseGroupNAS,
			Cause:      ies.CauseNASNormalRelease,
		})
	}
	pdn.State = "pdn-disconnect-erab-release-pending"
	ue.Unlock()
	if err := s.SendERABReleaseRequestTracked(mmeUEID, items, "pdn_disconnect_bearers", txID); err != nil {
		log.Warn("s1ap: failed to send PDN disconnect E-RAB Release Request",
			zap.Uint32("mme_ue_id", mmeUEID),
			zap.Uint8("linked_ebi", linkedEBI),
			zap.Error(err))
		ue.Lock()
		for _, ebi := range linkedDedicated {
			delete(ue.DedicatedBearers, ebi)
		}
		ue.Unlock()
		s.sendDeleteSessionForPDN(ue, linkedEBI, log)
		return
	}
	log.Info("s1ap: PDN disconnect E-RAB Release Request sent",
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.Uint8("linked_ebi", linkedEBI),
		zap.Uint8s("dedicated_ebis", linkedDedicated))
}

func collectLinkedDedicatedBearersLocked(ue *uecontext.Context, linkedEBI uint8) []uint8 {
	out := make([]uint8, 0, len(ue.DedicatedBearers))
	for ebi, proc := range ue.DedicatedBearers {
		if proc == nil || proc.LinkedEBI != linkedEBI {
			continue
		}
		out = append(out, ebi)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func pdnDisconnectInProgress(pdn *uecontext.PDNContext) bool {
	if pdn == nil {
		return false
	}
	if pdn.DisconnectRequested || pdn.DisconnectNASAccepted {
		return true
	}
	switch pdn.State {
	case "pdn-disconnect-requested",
		"pdn-disconnect-deactivate-sent",
		"pdn-disconnect-deactivate-accepted",
		"pdn-disconnect-erab-release-pending",
		"pdn-disconnect-erab-release-complete",
		"pdn-disconnect-delete-session-pending":
		return true
	default:
		return false
	}
}
