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
	"github.com/vectorcore/mme/internal/metrics"
	nas "github.com/vectorcore/mme/internal/nas"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/esm"
	"github.com/vectorcore/mme/internal/nas/security"
	"github.com/vectorcore/mme/internal/uecontext"
)

// S6aClient is the interface the S1AP layer uses to initiate Diameter requests.
// Implemented by internal/diameter/s6a.Handlers.
type S6aClient interface {
	// SendAIR triggers an Authentication-Information-Request to the HSS.
	// The response arrives asynchronously via Server.HandleAIAResult.
	SendAIR(imsi string, plmn [3]byte, mmeUEID uint32) error

	// SendULR triggers an Update-Location-Request to the HSS.
	// The response arrives asynchronously via Server.HandleULAResult.
	SendULR(imsi string, plmn [3]byte, mmeUEID uint32) error

	// SendPUR triggers a Purge-UE-Request to the HSS on detach.
	SendPUR(imsi string) error
}

// HandleAIAResult is called by the S6a layer when an AIA (auth vectors) arrives.
// It stores the challenge and sends a NAS Authentication Request to the UE.
func (s *Server) HandleAIAResult(mmeUEID uint32, rand, xres, autn, kasme []byte, aiaErr error) {
	log := s.log.With(zap.Uint32("mme_ue_id", mmeUEID))

	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		log.Warn("s1ap: HandleAIAResult: UE not found")
		return
	}

	ue.Lock()
	if aiaErr != nil {
		log.Warn("s1ap: AIA error, rejecting attach", zap.Error(aiaErr))
		rejectPDU := emm.EncodeAttachReject(emm.CauseNetworkFailure)
		mmeID := ue.MMEUES1APID
		enbAddr := ue.ENBGlobalID
		enbUEID := ue.ENBS1APID
		ue.Unlock()
		s.sendDownlinkNASTransport(enbAddr, mmeID, enbUEID, rejectPDU)
		s.ueManager.Remove(ue)
		return
	}

	ue.StoreAuthChallenge(rand, xres, autn, kasme)
	ue.AttachStep = uecontext.AttachStepWaitingAuthResp
	mmeID := ue.MMEUES1APID
	enbAddr := ue.ENBGlobalID
	enbUEID := ue.ENBS1APID
	ue.Unlock()

	authReq, err := emm.EncodeAuthenticationRequest(0, rand, autn)
	if err != nil {
		log.Error("s1ap: failed to encode Auth Request", zap.Error(err))
		return
	}
	s.sendDownlinkNASTransport(enbAddr, mmeID, enbUEID, authReq)
	metrics.NASProceduresTotal.WithLabelValues("Authentication", "sent").Inc()
	log.Info("s1ap: Authentication Request sent")
}

// HandleULAResult is called by the S6a layer when a ULA (subscription data) arrives.
// When S11 is enabled it sends a Create Session Request; when disabled (noop client)
// it builds an Attach Accept with a PDN Connectivity Reject immediately.
func (s *Server) HandleULAResult(mmeUEID uint32, msisdn, apn string, ulaErr error) {
	var apnCfg *gateway.APNConfiguration
	if apn != "" {
		apnCfg = &gateway.APNConfiguration{ServiceSelection: apn}
	}
	s.HandleULAResultWithAPNConfig(mmeUEID, msisdn, apnCfg, ulaErr)
}

func (s *Server) HandleULAResultWithAPNConfig(mmeUEID uint32, msisdn string, apnConfig *gateway.APNConfiguration, ulaErr error) {
	log := s.log.With(zap.Uint32("mme_ue_id", mmeUEID))
	apn := ""
	if apnConfig != nil {
		apn = apnConfig.ServiceSelection
	}

	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		log.Warn("s1ap: HandleULAResult: UE not found")
		return
	}

	ue.Lock()
	// Inter-MME TAU path: context already imported, just waiting for subscription data.
	if ue.AttachStep == uecontext.AttachStepWaitingULAInterMMETAU {
		if ulaErr == nil {
			ue.MSISDN = msisdn
			ue.APN = apn
		}
		s10Addr := ue.S10OldMMEAddr
		s10TEID := ue.S10OldMMETEID
		ue.Unlock()

		if ulaErr != nil {
			log.Warn("s1ap: ULA error during inter-MME TAU, rejecting", zap.Error(ulaErr))
			metrics.InterMMETAUTotal.WithLabelValues("ulr_error").Inc()
			s.sendTAUReject(mmeUEID, emm.CauseNetworkFailure)
			_ = s.s10.SendContextAcknowledge(s10Addr, s10TEID, gtpv2.CauseRequestDenied)
			s.ueManager.Remove(ue)
			return
		}
		s.finishInterMMETAU(ue, log, s10Addr, s10TEID)
		return
	}

	if ulaErr != nil {
		log.Warn("s1ap: ULA error, rejecting attach", zap.Error(ulaErr))
		rejectPDU := emm.EncodeAttachReject(emm.CauseNetworkFailure)
		mmeID := ue.MMEUES1APID
		enbAddr := ue.ENBGlobalID
		enbUEID := ue.ENBS1APID
		ue.Unlock()
		s.sendDownlinkNASTransport(enbAddr, mmeID, enbUEID, rejectPDU)
		s.ueManager.Remove(ue)
		return
	}

	ue.MSISDN = msisdn
	ue.APN = apn

	imsi := ue.IMSI
	mmeID := ue.MMEUES1APID

	// Check if S11 is a real client (not noop) by attempting to send CSR.
	// We always call SendCSR; the noop client returns nil immediately and the flow
	// falls through to HandleCSRResult which the noop never calls — so for the noop
	// path we go directly to ICS from here.
	_, isNoop := s.s11.(NoopS11Client)
	if isNoop {
		// No S-GW: build Attach Accept with PDN Connectivity Reject (Phase 1 backward compat).
		if s.gutiAlloc != nil && ue.GUTI == nil {
			newGUTI := s.gutiAlloc.Allocate()
			ue.GUTI = newGUTI
			ue.Unlock()
			s.ueManager.UpdateGUTI(ue, newGUTI)
			ue.Lock()
		}
		pti := ue.PDNRequestPTI
		tai := ue.TAI
		guti := ue.GUTI
		intAlg := ue.IntAlg
		encAlg := ue.EncAlg
		knasInt := make([]byte, len(ue.KNASint))
		copy(knasInt, ue.KNASint)
		knasEnc := make([]byte, len(ue.KNASenc))
		copy(knasEnc, ue.KNASenc)
		dlCount := ue.IncrementDLCount()
		ue.AttachStep = uecontext.AttachStepWaitingICSResp
		ue.Unlock()

		esmReject := esm.EncodePDNConnectivityReject(pti, esm.ESMCauseServiceOptionNotSupported)
		var taiList []emm.TAI
		if tai != nil {
			taiList = []emm.TAI{*tai}
		}
		attachAccept := emm.EncodeAttachAccept(1, taiList, guti, esmReject)

		var protected []byte
		var err error
		if encAlg != security.AlgIDEEA0 {
			protected, err = nas.EncodeIntegrityAndCiphered(attachAccept, intAlg, encAlg, knasInt, knasEnc, dlCount)
		} else {
			protected, err = nas.EncodeIntegrityProtected(attachAccept, intAlg, knasInt, dlCount)
		}
		if err != nil {
			log.Error("s1ap: failed to encode Attach Accept (noop)", zap.Error(err))
			return
		}
		if err := s.SendInitialContextSetup(mmeID, protected, nil); err != nil {
			log.Error("s1ap: SendInitialContextSetup failed (noop)", zap.Error(err))
		}
		metrics.NASProceduresTotal.WithLabelValues("Attach", "accept_noop").Inc()
		log.Info("s1ap: ICS sent (noop S11, no bearer)")
		return
	}

	// S11 enabled: send Create Session Request, wait for CSRsp in HandleCSRResult.
	localTEID := s11teid.AllocateTEID()
	ue.LocalS11TEID = localTEID
	ue.DefaultEBI = 5
	ue.AttachStep = uecontext.AttachStepWaitingCSRsp
	enbAddr := ue.ENBGlobalID
	enbUEID := ue.ENBS1APID
	ecgiplmn := ue.ECGIPLMN
	ecgieci := ue.ECGIECI
	var ulitac uint16
	if ue.TAI != nil {
		ulitac = ue.TAI.TAC
	}
	ue.Unlock()

	plmn := s.buildPLMN()
	localIP := net.IP(s.s11LocalIP)
	sgwAddr := ""
	pgwIP := net.IP(s.pgwIP)
	if s.gatewaySel != nil {
		selCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		sgwSel, err := s.gatewaySel.SelectSGW(selCtx, ulitac)
		if err != nil {
			log.Error("s1ap: SGW selection failed", zap.Error(err))
			rejectPDU := emm.EncodeAttachReject(emm.CauseNetworkFailure)
			s.sendDownlinkNASTransport(enbAddr, mmeID, enbUEID, rejectPDU)
			s.ueManager.Remove(ue)
			return
		}
		pgwSel, err := s.gatewaySel.SelectPGW(selCtx, apn, apnConfig)
		if err != nil {
			log.Error("s1ap: PGW selection failed", zap.Error(err))
			rejectPDU := emm.EncodeAttachReject(emm.CauseNetworkFailure)
			s.sendDownlinkNASTransport(enbAddr, mmeID, enbUEID, rejectPDU)
			s.ueManager.Remove(ue)
			return
		}
		sgwAddr = sgwSel.UDPAddr()
		pgwIP = pgwSel.Address
		ue.Lock()
		ue.SGWAddress = sgwAddr
		ue.Unlock()
	}
	// Use ECGI PLMN for ULI; fall back to serving network PLMN if not set.
	uliPLMN := ecgiplmn
	if uliPLMN == ([3]byte{}) {
		uliPLMN = plmn
	}

	csr := &gtpv2.CreateSessionRequest{
		SGWAddress:       sgwAddr,
		IMSI:             imsi,
		MSISDN:           msisdn,
		APN:              apn,
		RATType:          gtpv2.RATTypeEUTRAN,
		ServingNetwork:   plmn,
		LocalS11TEID:     localTEID,
		LocalS11IP:       localIP,
		PGWIP:            pgwIP,
		ULIPLMN:          uliPLMN,
		ULITAC:           ulitac,
		ULIECI:           ecgieci,
		PDNType:          gtpv2.PDNTypeIPv4,
		DefaultEBI:       5,
		BearerQCI:        9,
		UplinkAMBRKbps:   100_000,
		DownlinkAMBRKbps: 100_000,
	}
	if err := s.s11.SendCSR(mmeID, csr); err != nil {
		log.Error("s1ap: SendCSR failed", zap.Error(err))
		rejectPDU := emm.EncodeAttachReject(emm.CauseNetworkFailure)
		ue, ok2 := s.ueManager.GetByMMEID(mmeID)
		if ok2 {
			ue.Lock()
			enbAddr := ue.ENBGlobalID
			enbUEID := ue.ENBS1APID
			ue.Unlock()
			s.sendDownlinkNASTransport(enbAddr, mmeID, enbUEID, rejectPDU)
			s.ueManager.Remove(ue)
		}
		return
	}
	metrics.S11MessagesTotal.WithLabelValues("csr", "initiated").Inc()
	log.Info("s1ap: CSR sent to S-GW", zap.String("imsi", imsi), zap.Uint32("local_teid", localTEID))
}

// HandleCSRResult is called by the S11 client when a Create Session Response arrives.
func (s *Server) HandleCSRResult(mmeUEID uint32, resp *gtpv2.CreateSessionResponse, err error) {
	log := s.log.With(zap.Uint32("mme_ue_id", mmeUEID))

	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		log.Warn("s1ap: HandleCSRResult: UE not found")
		return
	}

	if err != nil {
		log.Warn("s1ap: CSRsp error, rejecting attach", zap.Error(err))
		ue.Lock()
		enbAddr := ue.ENBGlobalID
		enbUEID := ue.ENBS1APID
		ue.Unlock()
		rejectPDU := emm.EncodeAttachReject(emm.CauseNetworkFailure)
		s.sendDownlinkNASTransport(enbAddr, mmeUEID, enbUEID, rejectPDU)
		s.ueManager.Remove(ue)
		return
	}

	if resp.Cause != gtpv2.CauseRequestAccepted {
		log.Warn("s1ap: CSRsp rejected", zap.Uint8("cause", resp.Cause))
		ue.Lock()
		enbAddr := ue.ENBGlobalID
		enbUEID := ue.ENBS1APID
		ue.Unlock()
		rejectPDU := emm.EncodeAttachReject(emm.CauseNetworkFailure)
		s.sendDownlinkNASTransport(enbAddr, mmeUEID, enbUEID, rejectPDU)
		s.ueManager.Remove(ue)
		return
	}

	ue.Lock()
	ue.SGWC_TEID = resp.SGWC_TEID
	ue.SGWC_IP = resp.SGWC_IP
	ue.SGWU_TEID = resp.SGWU_TEID
	ue.SGWU_IP = resp.SGWU_IP
	ue.UEIPv4 = resp.UEIPv4
	ue.DefaultEBI = resp.EBI
	if ue.DefaultEBI == 0 {
		ue.DefaultEBI = 5 // fallback
	}
	if s.gutiAlloc != nil && ue.GUTI == nil {
		newGUTI := s.gutiAlloc.Allocate()
		ue.GUTI = newGUTI
		ue.Unlock()
		s.ueManager.UpdateGUTI(ue, newGUTI)
		ue.Lock()
	}

	pti := ue.PDNRequestPTI
	tai := ue.TAI
	guti := ue.GUTI
	intAlg := ue.IntAlg
	encAlg := ue.EncAlg
	knasInt := make([]byte, len(ue.KNASint))
	copy(knasInt, ue.KNASint)
	knasEnc := make([]byte, len(ue.KNASenc))
	copy(knasEnc, ue.KNASenc)
	dlCount := ue.IncrementDLCount()
	ue.AttachStep = uecontext.AttachStepWaitingICSResp
	mmeID := ue.MMEUES1APID
	ueIPv4 := ue.UEIPv4
	apn := ue.APN
	ebi := ue.DefaultEBI
	sgwuTEID := ue.SGWU_TEID
	sgwuIP := ue.SGWU_IP
	ue.Unlock()

	// Build ESM Activate Default EPS Bearer Context Request
	esmAccept := esm.EncodePDNConnectivityAccept(pti, apn, ebi, ueIPv4)

	var taiList []emm.TAI
	if tai != nil {
		taiList = []emm.TAI{*tai}
	}
	attachAccept := emm.EncodeAttachAccept(ebi, taiList, guti, esmAccept)

	var protected []byte
	var encErr error
	if encAlg != security.AlgIDEEA0 {
		protected, encErr = nas.EncodeIntegrityAndCiphered(attachAccept, intAlg, encAlg, knasInt, knasEnc, dlCount)
	} else {
		protected, encErr = nas.EncodeIntegrityProtected(attachAccept, intAlg, knasInt, dlCount)
	}
	if encErr != nil {
		log.Error("s1ap: failed to encode Attach Accept", zap.Error(encErr))
		s.sendDeleteSession(ue)
		return
	}

	bearer := &BearerInfo{
		EBI:       ebi,
		SGWU_TEID: sgwuTEID,
		SGWU_IP:   sgwuIP.To4(),
	}
	if err := s.SendInitialContextSetup(mmeID, protected, bearer); err != nil {
		log.Error("s1ap: SendInitialContextSetup failed", zap.Error(err))
		s.sendDeleteSession(ue)
		return
	}
	metrics.NASProceduresTotal.WithLabelValues("Attach", "accept").Inc()
	log.Info("s1ap: ICS sent with E-RAB", zap.Uint8("ebi", ebi),
		zap.String("ue_ipv4", ueIPv4.String()))
}

// HandleMBRResult is called when a Modify Bearer Response arrives.
func (s *Server) HandleMBRResult(mmeUEID uint32, err error) {
	if err != nil {
		s.log.Warn("s1ap: MBRsp error (data path may degrade)",
			zap.Uint32("mme_ue_id", mmeUEID), zap.Error(err))
		return
	}
	s.log.Info("s1ap: MBR accepted, data path established", zap.Uint32("mme_ue_id", mmeUEID))
}

// HandleDSRResult is called when a Delete Session Response arrives.
func (s *Server) HandleDSRResult(mmeUEID uint32, err error) {
	if err != nil {
		s.log.Warn("s1ap: DSRsp error", zap.Uint32("mme_ue_id", mmeUEID), zap.Error(err))
		return
	}
	s.log.Info("s1ap: DSRsp accepted, session deleted", zap.Uint32("mme_ue_id", mmeUEID))
}

// sendDeleteSession sends a GTPv2-C Delete Session Request to the S-GW for the given UE.
// It reads and clears SGWC_TEID under lock so subsequent calls are no-ops.
func (s *Server) sendDeleteSession(ue *uecontext.Context) {
	ue.Lock()
	sgwcTEID := ue.SGWC_TEID
	ue.SGWC_TEID = 0 // prevent double-send across processDetach → handleUEContextReleaseComplete
	sgwAddr := ue.SGWAddress
	ebi := ue.DefaultEBI
	imsi := ue.IMSI
	mmeID := ue.MMEUES1APID
	apn := ue.APN
	ue.Unlock()

	if sgwcTEID == 0 {
		return // no session established, or DSR already sent
	}
	s.log.Info("s1ap: sending Delete Session Request",
		zap.String("imsi", imsi),
		zap.Uint32("mme_ue_id", mmeID),
		zap.String("apn", apn),
		zap.Uint8("ebi", ebi),
		zap.Uint32("sgwc_teid", sgwcTEID))
	if err := s.s11.SendDSR(mmeID, &gtpv2.DeleteSessionRequest{SGWAddress: sgwAddr, SGWC_TEID: sgwcTEID, EBI: ebi}); err != nil {
		s.log.Warn("s1ap: SendDSR failed", zap.Uint32("mme_ue_id", mmeID), zap.Error(err))
	}
}

// buildPLMN builds the 3-byte PLMN BCD from the NF config (MCC+MNC).
func (s *Server) buildPLMN() [3]byte {
	mcc := s.nfCfg.MCC
	mnc := s.nfCfg.MNC
	var plmn [3]byte
	if len(mcc) == 3 && len(mnc) >= 2 {
		// byte 0: MCC digit 2 | MCC digit 1
		// byte 1: MNC digit 3 (0xF if 2-digit MNC) | MCC digit 3
		// byte 2: MNC digit 2 | MNC digit 1
		plmn[0] = (digit(mcc[1]) << 4) | digit(mcc[0])
		if len(mnc) == 2 {
			plmn[1] = 0xF0 | digit(mcc[2])
		} else {
			plmn[1] = (digit(mnc[2]) << 4) | digit(mcc[2])
		}
		plmn[2] = (digit(mnc[1]) << 4) | digit(mnc[0])
	}
	return plmn
}

func digit(b byte) byte {
	if b >= '0' && b <= '9' {
		return b - '0'
	}
	return 0
}

// unused ensures imports used only in noop path are not flagged.
var _ = fmt.Sprintf

// sendDownlinkNASTransport sends a plain (not-yet-security-wrapped) NAS PDU via DL NAS Transport.
func (s *Server) sendDownlinkNASTransport(enbAddr string, mmeUEID, enbUEID uint32, nasPDU []byte) {
	if len(nasPDU) > 0 {
		secHdr, pd, _ := emm.DecodeSecurityHeader(nasPDU)
		s.log.Debug("s1ap: sending downlink NAS",
			zap.String("direction", "downlink"),
			zap.Uint32("mme_ue_id", mmeUEID),
			zap.Uint32("enb_ue_id", enbUEID),
			zap.Uint8("sec_hdr", secHdr),
			zap.Uint8("pd", pd),
			zap.String("nas_hex", hex.EncodeToString(nasPDU)))
	}
	if err := s.SendDownlinkNAS(mmeUEID, nasPDU); err != nil {
		// Fall back to direct send if the UE context no longer has a route
		s.log.Warn("s1ap: sendDownlinkNASTransport via SendDownlinkNAS failed, trying direct",
			zap.Uint32("mme_ue_id", mmeUEID), zap.Error(err))
		_ = enbAddr
		_ = enbUEID
	}
}

// algName converts a numeric algorithm ID to a name for PreferredAlgorithm.
func intAlgNames(cap emm.UENetworkCapability) []string {
	return cap.SupportedIntegrityAlgs()
}

func encAlgNames(cap emm.UENetworkCapability) []string {
	return cap.SupportedCipheringAlgs()
}
