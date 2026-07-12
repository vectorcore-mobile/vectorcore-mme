package s1ap

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/gateway"
	"github.com/vectorcore/mme/internal/gtpv2"
	s11teid "github.com/vectorcore/mme/internal/gtpv2/s11"
	nas "github.com/vectorcore/mme/internal/nas"
	"github.com/vectorcore/mme/internal/nas/esm"
	"github.com/vectorcore/mme/internal/nas/security"
	"github.com/vectorcore/mme/internal/uecontext"
)

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
		zap.String("plain_nas_hex", hex.EncodeToString(result.Plain)),
	)

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
	case esm.MsgActivateDefaultEPSBearerContextAccept:
		accept, err := esm.DecodeActivateDefaultEPSBearerContextAccept(result.Plain)
		if err != nil {
			esmLog.Warn("s1ap: malformed Activate Default EPS Bearer Context Accept", zap.Error(err))
			return nil
		}
		return s.handleStandaloneBearerAccept(ue, accept, esmLog)
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
		s.handleDedicatedBearerNASResponse(ue, resp, esmLog)
		return nil
	default:
		esmLog.Warn("s1ap: unsupported ESM message")
		return nil
	}
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
	apnCfg, authorized := ue.SubscriberAPNConfigs[requestedAPN]
	if ue.SubscriberAPNConfigs == nil {
		authorized = requestedAPN == ue.APN
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
		return nil
	}
	if ue.PendingPDN != nil {
		ue.Unlock()
		log.Warn("s1ap: rejecting PDN Connectivity Request while another PDN is pending",
			zap.String("requested_apn", requestedAPN),
			zap.String("pending_apn", ue.PendingPDN.APN))
		return s.sendESMReject(ue, req.ProcedureTransactionID, esm.ESMCauseInsufficientResources, log)
	}
	ebi := allocateDefaultBearerIDLocked(ue)
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
		APN:                    requestedAPN,
		ProcedureTransactionID: req.ProcedureTransactionID,
		PDNType:                req.PDNType,
		DefaultEBI:             ebi,
		LocalS11TEID:           localTEID,
		SGWAddress:             sgwAddr,
		UEPCO:                  append([]byte(nil), req.PCO...),
		State:                  "csr-sent",
	}
	ue.Lock()
	ue.PendingPDN = pdn
	ue.Unlock()

	csr := &gtpv2.CreateSessionRequest{
		SGWAddress:       sgwAddr,
		IMSI:             imsi,
		MSISDN:           msisdn,
		APN:              requestedAPN,
		RATType:          gtpv2.RATTypeEUTRAN,
		ServingNetwork:   plmn,
		LocalS11TEID:     localTEID,
		LocalS11IP:       localIP,
		PGWIP:            pgwIP,
		ULIPLMN:          plmn,
		ULITAC:           ulitac,
		ULIECI:           ecgieci,
		PCO:              req.PCO,
		PDNType:          gtpv2.PDNTypeIPv4,
		DefaultEBI:       ebi,
		BearerQCI:        5,
		UplinkAMBRKbps:   100_000,
		DownlinkAMBRKbps: 100_000,
	}
	if err := s.s11.SendCSR(mmeID, csr); err != nil {
		ue.Lock()
		if ue.PendingPDN == pdn {
			ue.PendingPDN = nil
		}
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
	ue.Unlock()

	log.Info("s1ap: ESM Information Response received; resuming PDN Connectivity",
		zap.Uint8("pti", resp.ProcedureTransactionID),
		zap.String("apn", resp.APN),
		zap.String("pco_hex", hex.EncodeToString(req.PCO)))
	return s.handlePDNConnectivityRequest(ue, req, log)
}

func (s *Server) handleStandaloneBearerAccept(ue *uecontext.Context, accept *esm.ActivateDefaultEPSBearerContextAccept, log *zap.Logger) error {
	ue.Lock()
	defer ue.Unlock()
	for _, pdn := range ue.PDNs {
		if pdn.DefaultEBI == accept.EPSBearerID {
			pdn.NASAccepted = true
			if pdn.ERABEstablished && pdn.ModifyBearerAccepted {
				pdn.State = "active"
			}
			log.Info("s1ap: Activate Default EPS Bearer Context Accept received",
				zap.String("apn", pdn.APN),
				zap.Uint8("ebi", accept.EPSBearerID),
				zap.Uint8("pti", accept.ProcedureTransactionID),
				zap.Bool("erab_established", pdn.ERABEstablished),
				zap.Bool("modify_bearer_accepted", pdn.ModifyBearerAccepted),
				zap.String("pco_hex", hex.EncodeToString(accept.PCO)))
			return nil
		}
	}
	log.Warn("s1ap: Activate Default EPS Bearer Context Accept for unknown bearer",
		zap.Uint8("ebi", accept.EPSBearerID),
		zap.Uint8("pti", accept.ProcedureTransactionID))
	return nil
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
		ue.Unlock()
		_ = s.sendESMReject(ue, pti, esm.ESMCauseRequestRejectedUnspecified, log)
		return
	}
	if resp.Cause != gtpv2.CauseRequestAccepted {
		log.Warn("s1ap: IMS CSRsp rejected",
			zap.String("apn", apn),
			zap.Uint8("cause", resp.Cause),
			zap.String("cause_name", gtpv2.CauseName(resp.Cause)))
		ue.Lock()
		if ue.PendingPDN == pdn {
			ue.PendingPDN = nil
		}
		ue.Unlock()
		_ = s.sendESMReject(ue, pti, esm.ESMCauseRequestRejectedBySGW, log)
		return
	}

	ue.Lock()
	if resp.EBI != 0 {
		pdn.DefaultEBI = resp.EBI
	}
	pdn.SGWC_TEID = resp.SGWC_TEID
	pdn.SGWC_IP = append(net.IP(nil), resp.SGWC_IP...)
	pdn.SGWU_TEID = resp.SGWU_TEID
	pdn.SGWU_IP = append(net.IP(nil), resp.SGWU_IP...)
	pdn.UEIPv4 = append(net.IP(nil), resp.UEIPv4...)
	pdn.PGWPCO = append([]byte(nil), resp.PCO...)
	pdn.State = "activating"
	if ue.PDNs == nil {
		ue.PDNs = make(map[string]*uecontext.PDNContext)
	}
	ue.PDNs[pdn.APN] = pdn
	ue.PendingPDN = nil
	ue.Unlock()

	activate := esm.EncodePDNConnectivityAcceptWithPCO(pti, pdn.APN, pdn.DefaultEBI, pdn.UEIPv4, pdn.PGWPCO)
	protected, _, err := s.protectNAS(ue, activate)
	if err != nil {
		log.Warn("s1ap: failed to protect IMS Activate Default EPS Bearer Context Request",
			zap.String("apn", pdn.APN),
			zap.Uint8("ebi", pdn.DefaultEBI),
			zap.Error(err))
		return
	}
	if err := s.SendERABSetupRequest(ue.MMEUES1APID, []ERABSetupItem{{
		EBI:                     pdn.DefaultEBI,
		QCI:                     5,
		ARPPriority:             8,
		PreemptionCapability:    false,
		PreemptionVulnerability: true,
		SGWS1UIPv4:              pdn.SGWU_IP,
		SGWS1UTEID:              pdn.SGWU_TEID,
		NASPDU:                  protected,
	}}); err != nil {
		log.Warn("s1ap: failed to send IMS E-RAB Setup Request",
			zap.String("apn", pdn.APN),
			zap.Uint8("ebi", pdn.DefaultEBI),
			zap.Error(err))
		return
	}
	ue.Lock()
	ue.DLNASCount.Increment()
	ue.LastDownlinkNASMessage = "Activate Default EPS Bearer Context Request"
	pdn.State = "erab-setup-pending"
	ue.Unlock()
	log.Info("s1ap: IMS Activate Default EPS Bearer Context Request sent",
		zap.String("apn", pdn.APN),
		zap.Uint8("pti", pti),
		zap.Uint8("default_ebi", pdn.DefaultEBI),
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

	var protected []byte
	var err error
	if encAlg != security.AlgIDEEA0 {
		protected, err = nas.EncodeIntegrityAndCiphered(plain, intAlg, encAlg, knasInt, knasEnc, dlCount)
	} else {
		protected, err = nas.EncodeIntegrityProtected(plain, intAlg, knasInt, dlCount)
	}
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
	for ebi := uint8(5); ebi <= 15; ebi++ {
		if !used[ebi] {
			return ebi
		}
	}
	return 0
}
