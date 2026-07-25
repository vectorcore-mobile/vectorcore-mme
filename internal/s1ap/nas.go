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

	"github.com/vectorcore/mme/internal/diameter/s13"
	"github.com/vectorcore/mme/internal/gateway"
	"github.com/vectorcore/mme/internal/gtpv2"
	s11teid "github.com/vectorcore/mme/internal/gtpv2/s11"
	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/models"
	nas "github.com/vectorcore/mme/internal/nas"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/esm"
	"github.com/vectorcore/mme/internal/nas/security"
	nastimer "github.com/vectorcore/mme/internal/nas/timer"
	"github.com/vectorcore/mme/internal/uecontext"
)

// HandleS13Result resumes a per-UE attach after the asynchronous EIR check.
func (s *Server) HandleS13Result(mmeUEID uint32, result s13.Result) {
	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		return
	}
	ue.Lock()
	if ue.AttachStep != uecontext.AttachStepWaitingS13ECA {
		ue.Unlock()
		return
	}
	imsi, remote, enbID := ue.IMSI, ue.ENBGlobalID, ue.ENBS1APID
	ue.AttachStep = uecontext.AttachStepWaitingULA
	ue.Unlock()
	if !result.Allowed {
		cause := emm.CauseNetworkFailure
		reason := "s13-check-failed"
		if result.Verified && result.Status == s13.Blacklisted {
			// TS 24.301 §9.9.3.9 cause #5 is the explicit equipment rejection.
			cause = emm.CauseIMEINotAccepted
			reason = "s13-equipment-blacklisted"
			s.log.Warn("s13: equipment blacklisted", zap.Uint32("mme_ue_id", mmeUEID), zap.Uint32("enb_ue_id", enbID), zap.Uint32("equipment_status", uint32(result.Status)), zap.String("masked_imei", s13.MaskIMEI(result.IMEI)))
			s.log.Debug("s13: blacklist identity", zap.Uint32("mme_ue_id", mmeUEID), zap.String("imei", result.IMEI), zap.String("imeisv", result.IMEISV))
		}
		s.log.Info("s1ap: Attach Reject sent", zap.Uint32("mme_ue_id", mmeUEID), zap.Uint32("enb_ue_id", enbID), zap.Uint8("emm_cause", cause), zap.String("emm_cause_name", emm.CauseName(cause)), zap.String("reason", reason), zap.Uint8("security_header_type", emm.SecurityHeaderPlain))
		metrics.S13AttachRejectsTotal.WithLabelValues(reason).Inc()
		s.sendDownlinkNASTransport(remote, mmeUEID, enbID, emm.EncodeAttachReject(cause))
		s.ueManager.Remove(ue)
		return
	}
	plmn, err := security.EncodePLMN(s.nfCfg.MCC, s.nfCfg.MNC)
	if err != nil {
		s.ueManager.Remove(ue)
		return
	}
	var plmn3 [3]byte
	copy(plmn3[:], plmn)
	if err := s.s6a.SendULR(imsi, plmn3, mmeUEID); err != nil {
		s.sendDownlinkNASTransport(remote, mmeUEID, enbID, emm.EncodeAttachReject(emm.CauseNetworkFailure))
		s.ueManager.Remove(ue)
	}
}

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

// HandleSMSRegistrationPending records that the normal ULR is also carrying
// an SMS-in-MME registration request. It never changes EPS attach outcome.
func (s *Server) HandleSMSRegistrationPending(mmeUEID uint32) {
	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		return
	}
	ue.Lock()
	ue.SMSRegistrationState = uecontext.SMSRegistrationPending
	ue.SMSRegistrationCause = ""
	ue.SMSRegistrationAt = time.Now().UTC()
	ue.Unlock()
	s.log.Info("sms: registration requested", zap.Uint32("mme_ue_id", mmeUEID))
	metrics.SMSRegistrationRequestsTotal.Inc()
}

// HandleSMSRegistrationResult records the SMS-specific ULA outcome without
// turning a valid EPS ULA into an attach failure.
func (s *Server) HandleSMSRegistrationResult(mmeUEID uint32, registered bool, cause string) {
	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		return
	}
	ue.Lock()
	if registered {
		ue.SMSRegistrationState = uecontext.SMSRegistrationRegistered
		ue.SMSRegistrationCause = ""
	} else {
		ue.SMSRegistrationState = uecontext.SMSRegistrationRejected
		ue.SMSRegistrationCause = cause
	}
	ue.SMSRegistrationAt = time.Now().UTC()
	ue.Unlock()
	if registered {
		metrics.SMSRegistrationSuccessTotal.Inc()
		s.log.Info("sms: registration accepted", zap.Uint32("mme_ue_id", mmeUEID))
		return
	}
	metrics.SMSRegistrationFailuresTotal.WithLabelValues("hss").Inc()
	s.log.Warn("sms: registration rejected", zap.Uint32("mme_ue_id", mmeUEID), zap.String("cause", cause))
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

	if len(ue.KeNB) > 0 {
		s.invalidateASSecuritySnapshotLoggedLocked(ue, "security-context-replaced")
	}
	ue.StoreAuthChallenge(rand, xres, autn, kasme)
	ue.AttachStep = uecontext.AttachStepWaitingAuthResp
	mmeID := ue.MMEUES1APID
	enbAddr := ue.ENBGlobalID
	enbUEID := ue.ENBS1APID
	nasKSI := ue.NASKSI
	ue.Unlock()
	if nasKSI > 6 {
		nasKSI = 0
	}

	authReq, err := emm.EncodeAuthenticationRequest(nasKSI, rand, autn)
	if err != nil {
		log.Error("s1ap: failed to encode Auth Request", zap.Error(err))
		return
	}
	s.sendDownlinkNASTransport(enbAddr, mmeID, enbUEID, authReq)
	metrics.NASProceduresTotal.WithLabelValues("Authentication", "sent").Inc()
	log.Info("s1ap: Authentication Request sent")
}

// HandleULAResult is called by the S6a layer when a ULA (subscription data) arrives.
// Runtime MME sends a Create Session Request over S11. A no-op S11 path remains
// only for unit tests that exercise NAS/S1AP without a GTPv2-C client.
func (s *Server) HandleULAResult(mmeUEID uint32, msisdn, apn string, ulaErr error) {
	var apnCfg *gateway.APNConfiguration
	if apn != "" {
		apnCfg = &gateway.APNConfiguration{ServiceSelection: apn}
	}
	s.HandleULAResultWithAPNConfig(mmeUEID, msisdn, apnCfg, ulaErr)
}

func (s *Server) HandleULAResultWithAPNConfig(mmeUEID uint32, msisdn string, apnConfig *gateway.APNConfiguration, ulaErr error) {
	var profile *gateway.SubscriberProfile
	if apnConfig != nil && apnConfig.ServiceSelection != "" {
		profile = &gateway.SubscriberProfile{
			DefaultContextID: apnConfig.ContextIdentifier,
			APNs: map[string]gateway.APNConfiguration{
				apnConfig.ServiceSelection: *apnConfig,
			},
		}
	}
	s.HandleULAResultWithSubscriberProfile(mmeUEID, msisdn, profile, ulaErr)
}

func (s *Server) HandleULAResultWithSubscriberProfile(mmeUEID uint32, msisdn string, profile *gateway.SubscriberProfile, ulaErr error) {
	log := s.log.With(zap.Uint32("mme_ue_id", mmeUEID))
	apnConfig := profile.DefaultAPNConfiguration()
	apn := ""
	if apnConfig != nil {
		apn = apnConfig.ServiceSelection
	}
	subscribedAPNs := subscriberAPNNames(profile)

	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		log.Warn("s1ap: HandleULAResult: UE not found")
		return
	}

	ue.Lock()
	// Inter-MME TAU path: context already imported, just waiting for subscription data.
	if ue.AttachStep == uecontext.AttachStepWaitingULAInterMMETAU {
		if ulaErr == nil {
			if missing := validateDefaultSubscriberPolicy(profile); len(missing) != 0 {
				s10Addr := ue.S10OldMMEAddr
				s10TEID := ue.S10OldMMETEID
				ue.Unlock()
				log.Warn("s1ap: incomplete subscriber policy during inter-MME TAU, rejecting",
					zap.Strings("missing_fields", missing))
				metrics.InterMMETAUTotal.WithLabelValues("subscriber_policy_missing").Inc()
				s.sendTAUReject(mmeUEID, emm.CauseNetworkFailure)
				_ = s.s10.SendContextAcknowledge(s10Addr, s10TEID, gtpv2.CauseRequestDenied)
				s.ueManager.Remove(ue)
				return
			}
			ue.MSISDN = msisdn
			ue.APN = apn
			ue.UEAMBRDown = profile.UEAMBRDown
			ue.UEAMBRUp = profile.UEAMBRUp
			ue.SubscriberAPNs = subscribedAPNs
			ue.SubscriberAPNConfigs = cloneSubscriberAPNConfigs(profile)
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
	ue.UEAMBRDown = profile.UEAMBRDown
	ue.UEAMBRUp = profile.UEAMBRUp
	ue.SubscriberAPNs = subscribedAPNs
	ue.SubscriberAPNConfigs = cloneSubscriberAPNConfigs(profile)

	imsi := ue.IMSI
	mmeID := ue.MMEUES1APID
	if missing := validateDefaultSubscriberPolicy(profile); len(missing) != 0 {
		enbAddr := ue.ENBGlobalID
		enbUEID := ue.ENBS1APID
		ue.Unlock()
		log.Warn("s1ap: incomplete subscriber policy, rejecting attach",
			zap.String("imsi", imsi),
			zap.String("default_apn", apn),
			zap.Strings("missing_fields", missing))
		rejectPDU := emm.EncodeAttachReject(emm.CauseNetworkFailure)
		s.sendDownlinkNASTransport(enbAddr, mmeID, enbUEID, rejectPDU)
		s.ueManager.Remove(ue)
		return
	}

	// Unit-test no-op path: build Attach Accept with PDN Connectivity Reject
	// directly when tests construct the server without a GTPv2-C client.
	_, isNoop := s.s11.(NoopS11Client)
	if isNoop {
		// No S-GW: build Attach Accept with PDN Connectivity Reject (Phase 1 backward compat).
		if s.gutiAlloc != nil && ue.GUTI == nil {
			newGUTI, err := s.allocateAttachGUTI(log)
			if err != nil {
				enbAddr := ue.ENBGlobalID
				enbUEID := ue.ENBS1APID
				ue.Unlock()
				rejectPDU := emm.EncodeAttachReject(emm.CauseNetworkFailure)
				s.sendDownlinkNASTransport(enbAddr, mmeID, enbUEID, rejectPDU)
				s.ueManager.Remove(ue)
				return
			}
			ue.GUTI = newGUTI
			ue.Unlock()
			s.ueManager.UpdateGUTI(ue, newGUTI)
			logAssignedGUTI(log, "s1ap: assigned GUTI", mmeID, imsi, newGUTI)
			ue.Lock()
		}
		pti := ue.PDNRequestPTI
		tai := ue.TAI
		guti := ue.GUTI
		attachType := ue.AttachType
		smsRegistrationState := ue.SMSRegistrationState
		intAlg := ue.IntAlg
		encAlg := ue.EncAlg
		knasInt := make([]byte, len(ue.KNASint))
		copy(knasInt, ue.KNASint)
		knasEnc := make([]byte, len(ue.KNASenc))
		copy(knasEnc, ue.KNASenc)
		dlCount := uint32(ue.DLNASCount)
		ue.AttachStep = uecontext.AttachStepWaitingICSResp
		ue.Unlock()

		t3396, timerErr := s.esmBackoffTimer()
		if timerErr != nil {
			log.Error("s1ap: failed to derive PDN Connectivity Reject T3396", zap.Error(timerErr))
			s.sendDeleteSession(ue)
			return
		}
		esmReject := esm.EncodePDNConnectivityRejectWithBackoff(pti, esm.ESMCauseServiceOptionNotSupported, t3396)
		var taiList []emm.TAI
		if tai != nil {
			taiList = []emm.TAI{*tai}
		}
		attachResult, additionalResult := s.attachAcceptRegistration(attachType, smsRegistrationState)
		featureSupport := s.epsNetworkFeatureSupport()
		t3412, t3402, t3423, timerErr := s.nasEMMTimers()
		if timerErr != nil {
			log.Error("s1ap: failed to derive Attach Accept timers", zap.Error(timerErr))
			s.sendDeleteSession(ue)
			return
		}
		attachAccept := emm.EncodeAttachAcceptWithParams(emm.AttachAcceptParams{
			AttachResult:             attachResult,
			T3412:                    t3412,
			T3402:                    t3402,
			T3423:                    t3423,
			TAIList:                  taiList,
			GUTI:                     guti,
			ESMContainer:             esmReject,
			EPSNetworkFeatureSupport: featureSupport,
			AdditionalUpdateResult:   additionalResult,
		})

		// TS 24.301 §4.4.5 and TS 33.401 §8.2 regard EEA0 as ciphering.
		// The null cipher leaves the payload unchanged, but the NAS security header
		// must still indicate integrity protected and ciphered (type 2).
		protected, err := nas.EncodeIntegrityAndCiphered(attachAccept, intAlg, encAlg, knasInt, knasEnc, dlCount)
		if err != nil {
			log.Error("s1ap: failed to encode Attach Accept (noop)", zap.Error(err))
			return
		}
		ue.Lock()
		enbAddr := ue.ENBGlobalID
		enbUEID := ue.ENBS1APID
		ue.DLNASCount.Increment()
		ue.Unlock()
		s.sendDownlinkNASTransport(enbAddr, mmeID, enbUEID, protected)
		metrics.NASProceduresTotal.WithLabelValues("Attach", "accept_noop").Inc()
		log.Info("s1ap: Attach Accept sent without ICS (noop S11, no bearer)")
		return
	}

	// S11 enabled: send Create Session Request, wait for CSRsp in HandleCSRResult.
	localTEID := s11teid.AllocateTEID()
	ue.LocalS11TEID = localTEID
	ue.DefaultEBI = 5
	ue.AttachStep = uecontext.AttachStepWaitingCSRsp
	enbAddr := ue.ENBGlobalID
	enbUEID := ue.ENBS1APID
	ecgieci := ue.ECGIECI
	pco := append([]byte(nil), ue.PCO...)
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
	// GTPv2-C ULI TAI/ECGI PLMN uses the TS 29.274 digit layout
	// MCC2|MCC1, MNC3|MCC3, MNC2|MNC1. S1AP stores PLMN bytes in a
	// different layout, so use the serving PLMN built from MME config here.
	uliPLMN := plmn
	cfg := uecontext.SubscriberAPNConfig{
		PDNType:                 apnConfig.PDNType,
		PDNTypePolicy:           apnConfig.PDNTypePolicy,
		QCI:                     apnConfig.QCI,
		ARPPriority:             apnConfig.ARPPriority,
		PreemptionCapability:    apnConfig.PreemptionCapability,
		PreemptionVulnerability: apnConfig.PreemptionVulnerability,
		APNAMBRUp:               apnConfig.APNAMBRUp,
		APNAMBRDown:             apnConfig.APNAMBRDown,
	}

	csr := &gtpv2.CreateSessionRequest{
		SGWAddress:              sgwAddr,
		IMSI:                    imsi,
		MSISDN:                  msisdn,
		APN:                     apn,
		RATType:                 gtpv2.RATTypeEUTRAN,
		ServingNetwork:          plmn,
		LocalS11TEID:            localTEID,
		LocalS11IP:              localIP,
		PGWIP:                   pgwIP,
		ULIPLMN:                 uliPLMN,
		ULITAC:                  ulitac,
		ULIECI:                  ecgieci,
		PCO:                     pco,
		PDNType:                 cfg.PDNType,
		DefaultEBI:              5,
		BearerQCI:               cfg.QCI,
		BearerPriorityLevel:     cfg.ARPPriority,
		PreemptionCapability:    cfg.PreemptionCapability,
		PreemptionVulnerability: cfg.PreemptionVulnerability,
		UplinkAMBRKbps:          cfg.APNAMBRUp,
		DownlinkAMBRKbps:        cfg.APNAMBRDown,
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
	log.Info("s1ap: CSR sent to S-GW",
		zap.String("imsi", imsi),
		zap.String("default_apn", apn),
		zap.Strings("subscribed_apns", subscribedAPNs),
		zap.Uint32("local_teid", localTEID),
		zap.String("serving_network_hex", hex.EncodeToString(plmn[:])),
		zap.String("uli_plmn_hex", hex.EncodeToString(uliPLMN[:])),
		zap.Uint16("uli_tac", ulitac),
		zap.Uint32("uli_eci", ecgieci),
		zap.String("csr_pco_hex", hex.EncodeToString(pco)))
}

// HandleCSRResult is called by the S11 client when a Create Session Response arrives.
func (s *Server) HandleCSRResult(mmeUEID uint32, resp *gtpv2.CreateSessionResponse, err error) {
	log := s.log.With(zap.Uint32("mme_ue_id", mmeUEID))

	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		log.Warn("s1ap: HandleCSRResult: UE not found")
		return
	}

	ue.Lock()
	hasPendingPDN := ue.PendingPDN != nil
	ue.Unlock()
	if hasPendingPDN {
		s.handlePendingPDNCSRResult(ue, resp, err, log)
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

	if !gtpv2.IsAcceptedCause(resp.Cause) {
		log.Warn("s1ap: CSRsp rejected",
			zap.Uint8("cause", resp.Cause),
			zap.String("cause_name", gtpv2.CauseName(resp.Cause)))
		ue.Lock()
		enbAddr := ue.ENBGlobalID
		enbUEID := ue.ENBS1APID
		ue.Unlock()
		rejectPDU := emm.EncodeAttachReject(emm.CauseNetworkFailure)
		s.sendDownlinkNASTransport(enbAddr, mmeUEID, enbUEID, rejectPDU)
		s.ueManager.Remove(ue)
		return
	}
	if resp.EBI == 0 {
		log.Warn("s1ap: CSRsp accepted without valid bearer EBI, rejecting attach")
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
	imsi := ue.IMSI
	ue.SGWC_TEID = resp.SGWC_TEID
	ue.SGWC_IP = resp.SGWC_IP
	ue.SGWU_TEID = resp.SGWU_TEID
	ue.SGWU_IP = resp.SGWU_IP
	ue.UEIPv4 = resp.UEIPv4
	ue.DefaultEBI = resp.EBI
	ue.PGWPCO = append(ue.PGWPCO[:0], resp.PCO...)
	if s.gutiAlloc != nil && ue.GUTI == nil {
		newGUTI, err := s.allocateAttachGUTI(log)
		if err != nil {
			ue.Unlock()
			s.sendDeleteSession(ue)
			s.ueManager.Remove(ue)
			return
		}
		ue.GUTI = newGUTI
		ue.Unlock()
		s.ueManager.UpdateGUTI(ue, newGUTI)
		logAssignedGUTI(log, "s1ap: assigned GUTI", mmeUEID, imsi, newGUTI)
		ue.Lock()
	}

	pti := ue.PDNRequestPTI
	tai := ue.TAI
	guti := ue.GUTI
	attachType := ue.AttachType
	smsRegistrationState := ue.SMSRegistrationState
	intAlg := ue.IntAlg
	encAlg := ue.EncAlg
	knasInt := make([]byte, len(ue.KNASint))
	copy(knasInt, ue.KNASint)
	knasEnc := make([]byte, len(ue.KNASenc))
	copy(knasEnc, ue.KNASenc)
	dlCount := uint32(ue.DLNASCount)
	ue.AttachStep = uecontext.AttachStepWaitingICSResp
	mmeID := ue.MMEUES1APID
	ueIPv4 := ue.UEIPv4
	apn := ue.APN
	ebi := ue.DefaultEBI
	sgwuTEID := ue.SGWU_TEID
	sgwuIP := ue.SGWU_IP
	pgwPCO := append([]byte(nil), ue.PGWPCO...)
	apnPolicy := uecontext.SubscriberAPNConfig{QCI: 9}
	if cfg, ok := ue.SubscriberAPNConfigs[apn]; ok {
		apnPolicy = cfg
	} else {
		for configuredAPN, cfg := range ue.SubscriberAPNConfigs {
			if strings.EqualFold(configuredAPN, apn) {
				apnPolicy = cfg
				break
			}
		}
	}
	if ue.PDNs == nil {
		ue.PDNs = make(map[string]*uecontext.PDNContext)
	}
	ue.PDNs[apn] = &uecontext.PDNContext{
		APN:                        apn,
		ProcedureTransactionID:     pti,
		PDNType:                    gtpv2.PDNTypeIPv4,
		DefaultEBI:                 ebi,
		QCI:                        apnPolicy.QCI,
		ARPPriority:                apnPolicy.ARPPriority,
		PreemptionCapability:       apnPolicy.PreemptionCapability,
		PreemptionVulnerability:    apnPolicy.PreemptionVulnerability,
		APNAMBRDown:                apnPolicy.APNAMBRDown,
		APNAMBRUp:                  apnPolicy.APNAMBRUp,
		LocalS11TEID:               ue.LocalS11TEID,
		SGWAddress:                 ue.SGWAddress,
		SGWC_TEID:                  ue.SGWC_TEID,
		SGWC_IP:                    append(net.IP(nil), ue.SGWC_IP...),
		SGWU_TEID:                  ue.SGWU_TEID,
		SGWU_IP:                    append(net.IP(nil), ue.SGWU_IP...),
		UEIPv4:                     append(net.IP(nil), ue.UEIPv4...),
		UEPCO:                      append([]byte(nil), ue.PCO...),
		PGWPCO:                     append([]byte(nil), ue.PGWPCO...),
		State:                      "activating",
		SessionCreatedAt:           time.Now(),
		LastSuccessfulS11Procedure: "create-session-response",
	}
	ue.Unlock()

	// Build ESM Activate Default EPS Bearer Context Request
	esmAPN := s.apnForNAS(apn)
	esmAccept := esm.EncodePDNConnectivityAcceptWithQoS(pti, esmAPN, ebi, ueIPv4, apnPolicy.QCI, apnPolicy.APNAMBRUp, apnPolicy.APNAMBRDown, pgwPCO)

	var taiList []emm.TAI
	if tai != nil {
		taiList = []emm.TAI{*tai}
	}
	attachResult, additionalResult := s.attachAcceptRegistration(attachType, smsRegistrationState)
	featureSupport := s.epsNetworkFeatureSupport()
	t3412, t3402, t3423, timerErr := s.nasEMMTimers()
	if timerErr != nil {
		log.Error("s1ap: failed to derive Attach Accept timers", zap.Error(timerErr))
		s.sendDeleteSession(ue)
		return
	}
	attachAccept := emm.EncodeAttachAcceptWithParams(emm.AttachAcceptParams{
		AttachResult:             attachResult,
		T3412:                    t3412,
		T3402:                    t3402,
		T3423:                    t3423,
		TAIList:                  taiList,
		GUTI:                     guti,
		ESMContainer:             esmAccept,
		EPSNetworkFeatureSupport: featureSupport,
		AdditionalUpdateResult:   additionalResult,
	})

	// EEA0 is a null cipher, not an integrity-only procedure. It uses header type 2.
	protected, encErr := nas.EncodeIntegrityAndCiphered(attachAccept, intAlg, encAlg, knasInt, knasEnc, dlCount)
	if encErr != nil {
		log.Error("s1ap: failed to encode Attach Accept", zap.Error(encErr))
		s.sendDeleteSession(ue)
		return
	}
	ue.Lock()
	ue.DLNASCount.Increment()
	ue.Unlock()

	t3412ConfiguredSeconds := s.nasCfg.Timers.T3412
	if t3412ConfiguredSeconds <= 0 {
		t3412ConfiguredSeconds = nastimer.DefaultT3412
	}
	log.Debug("s1ap: Attach Accept NAS constructed",
		zap.String("nas_message", "AttachAccept"),
		zap.Uint32("mme_ue_id", mmeID),
		zap.Uint8("ebi", ebi),
		zap.Uint8("attach_result", attachResult),
		zap.String("apn", apn),
		zap.String("paa_ipv4", ueIPv4.String()),
		zap.Bool("ims_voice_over_ps_configured", s.nasCfg.EPSNetworkFeatureSupport.IMSVoiceOverPS),
		zap.Bool("ims_voice_over_ps_advertised", featureSupport != nil && featureSupport.IMSVoiceOverPSSessionInS1Mode),
		zap.String("eps_network_feature_support_hex", hex.EncodeToString(encodeFeatureSupportForLog(featureSupport))),
		zap.String("integrity_algorithm", nasIntegrityAlgorithmName(intAlg)),
		zap.String("ciphering_algorithm", nasCipheringAlgorithmName(encAlg)),
		zap.Bool("eea0_null_cipher", encAlg == security.AlgIDEEA0),
		zap.Uint32("dl_nas_count", dlCount),
		zap.Uint8("nas_sequence_number", protected[5]),
		zap.Uint8("security_header_type", protected[0]>>4),
		zap.String("security_header_name", nasSecurityHeaderName(protected[0]>>4)),
		zap.Uint8("protocol_discriminator", protected[0]&0x0f),
		zap.String("esm_apn", esmAPN),
		zap.Int("esm_container_len", len(esmAccept)),
		zap.Int("attach_accept_len", len(attachAccept)),
		zap.Int("protected_nas_pdu_len", len(protected)),
		zap.String("plain_nas_hex", hex.EncodeToString(attachAccept)),
		zap.String("protected_nas_hex", hex.EncodeToString(protected)),
		zap.Int("t3412_configured_seconds", t3412ConfiguredSeconds),
		zap.String("t3412_encoded_octet", fmt.Sprintf("0x%02x", t3412)),
		zap.Int("t3412_effective_seconds", nastimer.DecodeGPRSTimer(t3412)))

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
func (s *Server) HandleMBRResult(mmeUEID uint32, correlationID string, resp *gtpv2.ModifyBearerResponse, err error) {
	if correlationID != "" {
		if s.handlePendingERABModificationMBRResult(mmeUEID, correlationID, resp, err) {
			return
		}
	}
	if ue, ok := s.ueManager.GetByMMEID(mmeUEID); ok {
		ue.Lock()
		for _, pdn := range ue.PDNs {
			if pdn.State != "modify-bearer-pending" {
				continue
			}
			if err == nil && resp != nil && !gtpv2.IsAcceptedCause(resp.Cause) {
				canRetry := resp.Cause == gtpv2.CauseRequestRejected &&
					pdn.NASAccepted && pdn.ERABEstablished &&
					pdn.ModifyBearerRetryAttempts < 2 &&
					!hasPendingCreateBearerForLinkedEBILocked(ue, pdn.DefaultEBI)
				if canRetry {
					ebi := pdn.DefaultEBI
					apn := pdn.APN
					pdn.ModifyBearerRetryAttempts++
					pdn.ModifyBearerSent = false
					pdn.ModifyBearerDeferred = true
					pdn.State = "access-established"
					attempt := pdn.ModifyBearerRetryAttempts
					ue.Unlock()
					s.log.Warn("s1ap: transient IMS Modify Bearer rejection; scheduling retry",
						zap.String("apn", apn), zap.Uint8("ebi", ebi), zap.Uint8("cause", resp.Cause), zap.Uint8("attempt", attempt))
					time.AfterFunc(40*time.Millisecond, func() {
						if currentUE, ok := s.ueManager.GetByMMEID(mmeUEID); ok {
							s.maybeAdvanceDefaultBearer(currentUE, ebi, "modify-bearer-cause-94-retry", s.log)
						}
					})
					return
				}
				err = fmt.Errorf("S11 Modify Bearer rejected: cause=%d (%s)", resp.Cause, gtpv2.CauseName(resp.Cause))
			}
			if err != nil {
				pdn.ModifyBearerAccepted = false
				pdn.ModifyBearerFailed = true
				pdn.ModifyBearerDeferred = false
				pdn.ModifyBearerFallbackSent = false
				pdn.State = "modify-bearer-failed"
				apn := pdn.APN
				ebi := pdn.DefaultEBI
				nasAccepted := pdn.NASAccepted
				erabEstablished := pdn.ERABEstablished
				ue.StopTimer(imsModifyBearerSettleTimerName(ebi))
				ue.StopTimer(imsModifyBearerTimerName(ebi))
				ue.Unlock()
				s.log.Warn("s1ap: PDN Modify Bearer failed",
					zap.Uint32("mme_ue_id", mmeUEID),
					zap.String("apn", apn),
					zap.Uint8("ebi", ebi),
					zap.Bool("nas_accepted", nasAccepted),
					zap.Bool("erab_established", erabEstablished),
					zap.Error(err))
				s.logPostICSDebugWindow(ue, "modify_bearer_failed",
					zap.String("apn", apn),
					zap.Uint8("ebi", ebi))
				s.failDDNPagingIfPending(ue, "modify_bearer_failed")
				s.failPendingCreateBearersForLinkedEBI(ue, ebi, gtpv2.CauseRequestRejected, "modify_bearer_failed")
				return
			}
			pdn.ModifyBearerAccepted = true
			pdn.ModifyBearerFailed = false
			pdn.ModifyBearerDeferred = false
			pdn.ModifyBearerFallbackSent = false
			pdn.LastSuccessfulS11Procedure = "modify-bearer-response"
			if pdn.NASAccepted && pdn.ERABEstablished {
				pdn.State = "active"
			} else {
				pdn.State = "access-established"
			}
			apn := pdn.APN
			ebi := pdn.DefaultEBI
			nasAccepted := pdn.NASAccepted
			erabEstablished := pdn.ERABEstablished
			ue.StopTimer(imsModifyBearerSettleTimerName(ebi))
			ue.StopTimer(imsModifyBearerTimerName(ebi))
			ue.Unlock()
			s.log.Info("s1ap: PDN Modify Bearer accepted",
				zap.Uint32("mme_ue_id", mmeUEID),
				zap.String("apn", apn),
				zap.Uint8("ebi", ebi),
				zap.Bool("nas_accepted", nasAccepted),
				zap.Bool("erab_established", erabEstablished))
			s.logPostICSDebugWindow(ue, "modify_bearer_accepted",
				zap.String("apn", apn),
				zap.Uint8("ebi", ebi))
			s.completeDDNPagingIfPending(ue, "modify_bearer_accepted", []uint8{ebi})
			s.maybeAdvanceDefaultBearer(ue, ebi, "modify-bearer-accepted", s.log)
			return
		}
		ue.Unlock()
	}
	if err != nil {
		s.log.Warn("s1ap: MBRsp error (data path may degrade)",
			zap.Uint32("mme_ue_id", mmeUEID), zap.Error(err))
		return
	}
	s.log.Info("s1ap: MBR accepted, data path established", zap.Uint32("mme_ue_id", mmeUEID))
	if ue, ok := s.ueManager.GetByMMEID(mmeUEID); ok {
		s.logPostICSDebugWindow(ue, "mbr_accepted_generic")
	}
}

// HandleDSRResult is called when a Delete Session Response arrives.
func (s *Server) HandleDSRResult(mmeUEID uint32, linkedEBI uint8, err error) {
	if err != nil {
		s.log.Warn("s1ap: DSRsp error",
			zap.Uint32("mme_ue_id", mmeUEID),
			zap.Uint8("linked_ebi", linkedEBI),
			zap.Error(err))
		// Terminal implicit detach is a local ownership boundary. A rejected
		// DSR is recorded and that PDN is completed locally; the overall
		// cleanup deadline remains the safety net for missing responses.
		if ue, ok := s.ueManager.GetByMMEID(mmeUEID); ok {
			metrics.ImplicitDetachCleanupFailuresTotal.Inc()
			ue.Lock()
			terminal := ue.ImplicitDetachCleanupStarted
			ue.Unlock()
			if terminal && s.cleanupDisconnectedPDN(mmeUEID, linkedEBI, "s11-delete-session-failed") {
				if s.detachedUEDeleteSessionsComplete(mmeUEID) {
					s.cleanupDetachedUE(mmeUEID, "implicit-detach-dsr-failed")
				}
			}
		}
		return
	}
	s.log.Info("s1ap: DSRsp accepted, session deleted",
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.Uint8("linked_ebi", linkedEBI))
	if s.cleanupDisconnectedPDN(mmeUEID, linkedEBI, "s11-delete-session") {
		if s.detachedUEDeleteSessionsComplete(mmeUEID) {
			s.cleanupDetachedUE(mmeUEID, "s11-delete-session")
		}
		return
	}
	s.cleanupDetachedUE(mmeUEID, "s11-delete-session")
}

func (s *Server) cleanupDisconnectedPDN(mmeUEID uint32, linkedEBI uint8, reason string) bool {
	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		return false
	}
	ue.Lock()
	var targetAPN string
	var removedLinkedEBI uint8
	for apn, pdn := range ue.PDNs {
		if pdn == nil || pdn.State != "pdn-disconnect-delete-session-pending" {
			continue
		}
		if linkedEBI != 0 && pdn.DefaultEBI != linkedEBI {
			continue
		}
		targetAPN = apn
		removedLinkedEBI = pdn.DefaultEBI
		stopDefaultT3485Locked(ue, pdn)
		delete(ue.PDNs, apn)
		break
	}
	if targetAPN == "" {
		ue.Unlock()
		return false
	}
	for ebi, proc := range ue.DedicatedBearers {
		if proc != nil && proc.LinkedEBI == removedLinkedEBI {
			delete(ue.DedicatedBearers, ebi)
		}
	}
	for key, tx := range ue.PendingBearerTransactions {
		if tx == nil || tx.LinkedEBI != removedLinkedEBI {
			continue
		}
		for _, proc := range tx.Bearers {
			stopDedicatedT3485Locked(ue, proc)
		}
		delete(ue.PendingERABProcedures, tx.ID)
		delete(ue.PendingBearerTransactions, key)
	}
	imsi := ue.IMSI
	ue.Unlock()
	s.log.Info("s1ap: PDN context removed after DSRsp",
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.String("imsi", imsi),
		zap.String("apn", targetAPN),
		zap.Uint8("linked_ebi", removedLinkedEBI),
		zap.String("reason", reason))
	return true
}

func (s *Server) cleanupDetachedUE(mmeUEID uint32, reason string) {
	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		s.log.Debug("s1ap: detached UE cleanup skipped, context already removed",
			zap.Uint32("mme_ue_id", mmeUEID),
			zap.String("reason", reason))
		return
	}

	ue.Lock()
	emmState := ue.EMMState
	imsi := ue.IMSI
	ue.ImplicitDetachCleanupGeneration++
	ue.ImplicitDetachCleanupTimerActive = false
	ue.ImplicitDetachCleanupDeadline = time.Time{}
	ue.StopTimer(uecontext.TimerImplicitDetachCleanup)
	ue.Unlock()
	if emmState != emm.StateDeregisteredInitiated {
		s.log.Debug("s1ap: DSRsp cleanup skipped, UE is not detaching",
			zap.Uint32("mme_ue_id", mmeUEID),
			zap.String("imsi", imsi),
			zap.String("emm_state", emmState.String()),
			zap.String("reason", reason))
		return
	}

	s.cleanupUEOwnedSMS(ue)
	s.ueManager.Remove(ue)
	metrics.AttachedUEs.Dec()
	s.persistUERecoverySnapshot(ue, models.RecoveryStateDetached, "DELETED")
	s.log.Info("s1ap: detached UE context removed",
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.String("imsi", imsi),
		zap.String("reason", reason))
}

func (s *Server) detachedUEDeleteSessionsComplete(mmeUEID uint32) bool {
	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		return false
	}
	ue.Lock()
	defer ue.Unlock()
	if ue.EMMState != emm.StateDeregisteredInitiated {
		return false
	}
	if ue.SGWC_TEID != 0 {
		return false
	}
	for _, pdn := range ue.PDNs {
		if pdn == nil {
			continue
		}
		if pdn.State == "pdn-disconnect-delete-session-pending" || pdn.SGWC_TEID != 0 {
			return false
		}
	}
	return true
}

// sendDeleteSession sends a GTPv2-C Delete Session Request to the S-GW for the given UE.
// It resolves the linked default bearer from the authoritative PDN context when
// present and clears the selected control-plane TEID under lock so repeated calls
// stay idempotent across detach and UE context release cleanup.
func (s *Server) sendDeleteSession(ue *uecontext.Context) {
	ue.Lock()
	sgwcTEID, sgwAddr, ebi, imsi, mmeID, apn := resolveDeleteSessionTargetLocked(ue)
	localS11TEID := ue.LocalS11TEID
	ecgieci := ue.ECGIECI
	var ulitac uint16
	if ue.TAI != nil {
		ulitac = ue.TAI.TAC
	}
	ue.Unlock()

	if sgwcTEID == 0 {
		return // no session established, or DSR already sent
	}
	req := s.buildDeleteSessionRequest(sgwAddr, sgwcTEID, ebi, localS11TEID, ulitac, ecgieci)
	s.log.Info("s1ap: sending Delete Session Request",
		zap.String("imsi", imsi),
		zap.Uint32("mme_ue_id", mmeID),
		zap.String("apn", apn),
		zap.Uint8("ebi", ebi),
		zap.Uint32("sgwc_teid", sgwcTEID))
	if err := s.s11.SendDSR(mmeID, req); err != nil {
		s.log.Warn("s1ap: SendDSR failed", zap.Uint32("mme_ue_id", mmeID), zap.Error(err))
	}
}

func (s *Server) sendDeleteSessionsForDetach(ue *uecontext.Context) {
	ue.Lock()
	if ue.DefaultEBI != 0 && ue.APN != "" {
		_ = findPDNByLinkedEBILocked(ue, ue.DefaultEBI)
	}
	linkedEBIs := make([]uint8, 0, len(ue.PDNs))
	seen := make(map[uint8]struct{}, len(ue.PDNs))
	for _, pdn := range ue.PDNs {
		if pdn == nil || pdn.DefaultEBI == 0 || pdn.SGWC_TEID == 0 {
			continue
		}
		if _, ok := seen[pdn.DefaultEBI]; ok {
			continue
		}
		seen[pdn.DefaultEBI] = struct{}{}
		linkedEBIs = append(linkedEBIs, pdn.DefaultEBI)
	}
	legacyPending := ue.SGWC_TEID != 0
	ue.Unlock()

	if len(linkedEBIs) == 0 {
		if legacyPending {
			s.sendDeleteSession(ue)
		}
		return
	}
	for _, linkedEBI := range linkedEBIs {
		s.sendDeleteSessionForPDN(ue, linkedEBI, s.log)
	}
}

func resolveDeleteSessionTargetLocked(ue *uecontext.Context) (uint32, string, uint8, string, uint32, string) {
	sgwcTEID := ue.SGWC_TEID
	sgwAddr := ue.SGWAddress
	ebi := ue.DefaultEBI
	imsi := ue.IMSI
	mmeID := ue.MMEUES1APID
	apn := ue.APN
	if sgwcTEID == 0 {
		return 0, sgwAddr, ebi, imsi, mmeID, apn
	}
	if pdn := resolvePDNForDeleteSessionLocked(ue, sgwcTEID); pdn != nil {
		if pdn.DefaultEBI != 0 {
			ebi = pdn.DefaultEBI
		}
		if pdn.SGWAddress != "" {
			sgwAddr = pdn.SGWAddress
		}
		if pdn.APN != "" {
			apn = pdn.APN
		}
		pdn.SGWC_TEID = 0
	}
	ue.SGWC_TEID = 0
	return sgwcTEID, sgwAddr, ebi, imsi, mmeID, apn
}

func resolvePDNForDeleteSessionLocked(ue *uecontext.Context, sgwcTEID uint32) *uecontext.PDNContext {
	if ue == nil || sgwcTEID == 0 {
		return nil
	}
	for _, pdn := range ue.PDNs {
		if pdn == nil {
			continue
		}
		if pdn.SGWC_TEID == sgwcTEID {
			return pdn
		}
	}
	if ue.APN != "" {
		if pdn := ue.PDNs[ue.APN]; pdn != nil && pdn.SGWC_TEID != 0 {
			return pdn
		}
	}
	for _, pdn := range ue.PDNs {
		if pdn == nil || pdn.SGWC_TEID == 0 {
			continue
		}
		return pdn
	}
	return nil
}

func (s *Server) sendDeleteSessionForPDN(ue *uecontext.Context, linkedEBI uint8, log *zap.Logger) {
	ue.Lock()
	pdn := findPDNByLinkedEBILocked(ue, linkedEBI)
	if pdn == nil {
		ue.Unlock()
		return
	}
	sgwcTEID := pdn.SGWC_TEID
	sgwAddr := pdn.SGWAddress
	apn := pdn.APN
	mmeID := ue.MMEUES1APID
	imsi := ue.IMSI
	localS11TEID := pdn.LocalS11TEID
	if localS11TEID == 0 {
		localS11TEID = ue.LocalS11TEID
	}
	ecgieci := ue.ECGIECI
	var ulitac uint16
	if ue.TAI != nil {
		ulitac = ue.TAI.TAC
	}
	pdn.SGWC_TEID = 0
	pdn.State = "pdn-disconnect-delete-session-pending"
	if ue.DefaultEBI == linkedEBI || ue.SGWC_TEID == sgwcTEID {
		ue.SGWC_TEID = 0
	}
	ue.Unlock()

	if sgwcTEID == 0 {
		log.Info("s1ap: PDN disconnect completed without DSR",
			zap.Uint32("mme_ue_id", mmeID),
			zap.String("imsi", imsi),
			zap.String("apn", apn),
			zap.Uint8("linked_ebi", linkedEBI))
		s.cleanupDisconnectedPDN(mmeID, linkedEBI, "no-s11-session")
		return
	}
	log.Info("s1ap: sending PDN Delete Session Request",
		zap.Uint32("mme_ue_id", mmeID),
		zap.String("imsi", imsi),
		zap.String("apn", apn),
		zap.Uint8("linked_ebi", linkedEBI),
		zap.Uint32("sgwc_teid", sgwcTEID))
	req := s.buildDeleteSessionRequest(sgwAddr, sgwcTEID, linkedEBI, localS11TEID, ulitac, ecgieci)
	if err := s.s11.SendDSR(mmeID, req); err != nil {
		log.Warn("s1ap: PDN SendDSR failed",
			zap.Uint32("mme_ue_id", mmeID),
			zap.String("apn", apn),
			zap.Error(err))
	}
}

func (s *Server) buildDeleteSessionRequest(sgwAddr string, sgwcTEID uint32, ebi uint8, localS11TEID uint32, ulitac uint16, ecgieci uint32) *gtpv2.DeleteSessionRequest {
	req := &gtpv2.DeleteSessionRequest{
		SGWAddress:          sgwAddr,
		SGWC_TEID:           sgwcTEID,
		EBI:                 ebi,
		LocalS11TEID:        localS11TEID,
		LocalS11IP:          net.IP(s.s11LocalIP),
		IncludeIndicationOI: true,
	}
	if ulitac != 0 || ecgieci != 0 {
		req.IncludeULI = true
		req.ULIPLMN = s.buildPLMN()
		req.ULITAC = ulitac
		req.ULIECI = ecgieci
		req.IncludeULITimestamp = true
		req.ULITimestamp = uint32(time.Now().UTC().Unix()) + 2208988800
	}
	return req
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

func (s *Server) apnForNAS(apn string) string {
	apn = strings.TrimSpace(apn)
	if apn == "" {
		return apn
	}
	apn = strings.TrimSuffix(apn, ".")
	// A short IMS service selection is encoded as its canonical network APN.
	// Keep already-qualified APNs intact and derive the PLMN from configuration.
	if strings.EqualFold(apn, "ims") && s.nfCfg.MCC != "" && s.nfCfg.MNC != "" {
		mnc := strings.TrimSpace(s.nfCfg.MNC)
		mcc := strings.TrimSpace(s.nfCfg.MCC)
		for len(mnc) < 3 {
			mnc = "0" + mnc
		}
		for len(mcc) < 3 {
			mcc = "0" + mcc
		}
		return "ims.mnc" + mnc + ".mcc" + mcc + ".gprs"
	}
	return apn
}

// apnForIMSDefaultBearerNAS is presentation-only. Internal APN state remains
// normalized ("ims") for subscription, DNS, and session correlation, while
// the default IMS bearer APN IE retains the Cisco-compatible label case.
func (s *Server) apnForIMSDefaultBearerNAS(apn string) string {
	canonical := s.apnForNAS(apn)
	if strings.EqualFold(strings.TrimSpace(apn), "ims") && strings.HasPrefix(strings.ToLower(canonical), "ims.") {
		return "IMS" + canonical[3:]
	}
	return canonical
}

func logAssignedGUTI(log *zap.Logger, msg string, mmeUEID uint32, imsi string, guti *emm.GUTI) {
	if guti == nil {
		return
	}
	log.Info(msg,
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.String("imsi", imsi),
		zap.String("guti_plmn_hex", hex.EncodeToString(guti.PLMN[:])),
		zap.Uint16("mmegi", guti.MMEGI),
		zap.Uint8("mmec", guti.MMEC),
		zap.Uint32("mtmsi", guti.MTMSI),
		zap.String("full_guti_lookup_key", uecontext.SerialiseGUTI(guti)))
}

// attachAcceptRegistration uses the completed, per-UE SMS-in-MME registration
// outcome rather than temporary Diameter peer state. The Cisco SGd-only
// reference responds to successful combined Attach with result 2 and explicit
// Additional Update Result F0, without SGs, CS service, LAI, or CS TMSI.
func (s *Server) attachAcceptRegistration(attachType uint8, smsState uecontext.SMSRegistrationState) (uint8, *uint8) {
	if attachType != emm.AttachTypeCombinedEPSAndIMSI || !s.sgdCfg.Enabled || smsState != uecontext.SMSRegistrationRegistered {
		return emm.AttachTypeEPSOnly, nil
	}
	noAdditionalInfo := uint8(0)
	return emm.AttachTypeCombinedEPSAndIMSI, &noAdditionalInfo
}

func (s *Server) epsNetworkFeatureSupport() *emm.EPSNetworkFeatureSupport {
	if !s.nasCfg.EPSNetworkFeatureSupport.IMSVoiceOverPS {
		return nil
	}
	return &emm.EPSNetworkFeatureSupport{IMSVoiceOverPSSessionInS1Mode: true}
}

func encodeFeatureSupportForLog(support *emm.EPSNetworkFeatureSupport) []byte {
	if support == nil {
		return nil
	}
	return emm.EncodeEPSNetworkFeatureSupport(*support)
}

func (s *Server) nasEMMTimers() (t3412 uint8, t3402 *uint8, t3423 *uint8, err error) {
	timers := s.nasCfg.Timers
	if timers.T3412 <= 0 {
		timers.T3402 = nastimer.DefaultT3402
		timers.T3396 = nastimer.DefaultT3396
		timers.T3412 = nastimer.DefaultT3412
		timers.T3423 = nastimer.DefaultT3423
	}
	t3412, err = nastimer.EncodeGPRSTimer(timers.T3412)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("t3412: %w", err)
	}
	if timers.T3402 > 0 {
		value, convErr := nastimer.EncodeGPRSTimer(timers.T3402)
		if convErr != nil {
			return 0, nil, nil, fmt.Errorf("t3402: %w", convErr)
		}
		t3402 = &value
	}
	if timers.T3423 > 0 {
		value, convErr := nastimer.EncodeGPRSTimer(timers.T3423)
		if convErr != nil {
			return 0, nil, nil, fmt.Errorf("t3423: %w", convErr)
		}
		t3423 = &value
	}
	return t3412, t3402, t3423, nil
}

func (s *Server) esmBackoffTimer() (*uint8, error) {
	t3396 := s.nasCfg.Timers.T3396
	if s.nasCfg.Timers.T3412 <= 0 {
		t3396 = nastimer.DefaultT3396
	}
	if t3396 <= 0 {
		return nil, nil
	}
	value, err := nastimer.EncodeGPRSTimer3(t3396)
	if err != nil {
		return nil, fmt.Errorf("t3396: %w", err)
	}
	return &value, nil
}

func subscriberAPNNames(profile *gateway.SubscriberProfile) []string {
	if profile == nil || len(profile.APNs) == 0 {
		return nil
	}
	names := make([]string, 0, len(profile.APNs))
	for name := range profile.APNs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func cloneSubscriberAPNConfigs(profile *gateway.SubscriberProfile) map[string]uecontext.SubscriberAPNConfig {
	if profile == nil || len(profile.APNs) == 0 {
		return nil
	}
	out := make(map[string]uecontext.SubscriberAPNConfig, len(profile.APNs))
	for name, cfg := range profile.APNs {
		out[name] = uecontext.SubscriberAPNConfig{
			ContextIdentifier:       cfg.ContextIdentifier,
			ServiceSelection:        cfg.ServiceSelection,
			MIPHomeAgentAddress:     append(net.IP(nil), cfg.MIPHomeAgentAddress...),
			MIPHomeAgentHost:        cfg.MIPHomeAgentHost,
			PDNGWAllocationType:     cloneInt32Ptr(cfg.PDNGWAllocationType),
			PDNType:                 cfg.PDNType,
			PDNTypePolicy:           cfg.PDNTypePolicy,
			QCI:                     cfg.QCI,
			ARPPriority:             cfg.ARPPriority,
			PreemptionCapability:    cfg.PreemptionCapability,
			PreemptionVulnerability: cfg.PreemptionVulnerability,
			APNAMBRDown:             cfg.APNAMBRDown,
			APNAMBRUp:               cfg.APNAMBRUp,
		}
	}
	return out
}

func validateDefaultSubscriberPolicy(profile *gateway.SubscriberProfile) []string {
	if profile == nil {
		return []string{"subscriber_profile", "default_apn"}
	}
	cfg := profile.DefaultAPNConfiguration()
	missing := validateSubscriberAPNPolicyConfig(cfg)
	if cfg == nil || strings.TrimSpace(cfg.ServiceSelection) == "" {
		missing = appendMissingField(missing, "default_apn")
	}
	if profile.UEAMBRUp == 0 {
		missing = appendMissingField(missing, "ue_ambr_ul")
	}
	if profile.UEAMBRDown == 0 {
		missing = appendMissingField(missing, "ue_ambr_dl")
	}
	return missing
}

func validateSubscriberAPNPolicy(cfg *uecontext.SubscriberAPNConfig) []string {
	if cfg == nil {
		return []string{"pdn_type", "qci", "arp_priority", "apn_ambr_ul", "apn_ambr_dl"}
	}
	var missing []string
	if cfg.PDNType == 0 {
		missing = append(missing, "pdn_type")
	}
	if cfg.QCI == 0 {
		missing = append(missing, "qci")
	}
	if cfg.ARPPriority == 0 {
		missing = append(missing, "arp_priority")
	}
	if cfg.APNAMBRUp == 0 {
		missing = append(missing, "apn_ambr_ul")
	}
	if cfg.APNAMBRDown == 0 {
		missing = append(missing, "apn_ambr_dl")
	}
	return missing
}

func validateSubscriberAPNPolicyConfig(cfg *gateway.APNConfiguration) []string {
	if cfg == nil {
		return validateSubscriberAPNPolicy(nil)
	}
	apnCfg := uecontext.SubscriberAPNConfig{
		ServiceSelection:        cfg.ServiceSelection,
		PDNType:                 cfg.PDNType,
		PDNTypePolicy:           cfg.PDNTypePolicy,
		QCI:                     cfg.QCI,
		ARPPriority:             cfg.ARPPriority,
		PreemptionCapability:    cfg.PreemptionCapability,
		PreemptionVulnerability: cfg.PreemptionVulnerability,
		APNAMBRDown:             cfg.APNAMBRDown,
		APNAMBRUp:               cfg.APNAMBRUp,
	}
	return validateSubscriberAPNPolicy(&apnCfg)
}

func appendMissingField(fields []string, field string) []string {
	for _, existing := range fields {
		if existing == field {
			return fields
		}
	}
	return append(fields, field)
}

func subscriberPDNType(cfg *uecontext.SubscriberAPNConfig, fallback uint8) uint8 {
	if cfg != nil && cfg.PDNType != 0 {
		return cfg.PDNType
	}
	if fallback != 0 {
		return fallback
	}
	return gtpv2.PDNTypeIPv4
}

func subscriberBearerQCI(cfg *uecontext.SubscriberAPNConfig, apn string) uint8 {
	if cfg != nil && cfg.QCI != 0 {
		return cfg.QCI
	}
	return 0
}

func subscriberARPProfile(cfg *uecontext.SubscriberAPNConfig) (uint8, bool, bool) {
	if cfg != nil && cfg.ARPPriority != 0 {
		return cfg.ARPPriority, cfg.PreemptionCapability, cfg.PreemptionVulnerability
	}
	return 8, false, true
}

func subscriberAPNAMBR(cfg *uecontext.SubscriberAPNConfig) (uint32, uint32) {
	if cfg != nil && (cfg.APNAMBRUp != 0 || cfg.APNAMBRDown != 0) {
		return cfg.APNAMBRUp, cfg.APNAMBRDown
	}
	return 100_000, 100_000
}

func subscriberUEAMBR(ue *uecontext.Context) (uint64, uint64, error) {
	if ue == nil {
		return 0, 0, fmt.Errorf("s1ap: missing UE context for UE AMBR")
	}
	effective := effectiveUEAMBR(ue)
	downlink := effective.Downlink
	uplink := effective.Uplink
	if downlink == 0 || uplink == 0 {
		return 0, 0, fmt.Errorf("s1ap: missing UE AMBR in UE context (down=%d up=%d)", downlink, uplink)
	}
	return downlink, uplink, nil
}

func cloneInt32Ptr(v *int32) *int32 {
	if v == nil {
		return nil
	}
	c := *v
	return &c
}

func (s *Server) allocateAttachGUTI(log *zap.Logger) (*emm.GUTI, error) {
	if s.gutiAlloc == nil {
		return nil, fmt.Errorf("s1ap: GUTI allocator unavailable")
	}
	guti, err := s.gutiAlloc.AllocateUnique(func(g *emm.GUTI) bool {
		_, ok := s.ueManager.GetByGUTI(uecontext.SerialiseGUTI(g))
		return ok
	})
	if err != nil {
		log.Warn("s1ap: GUTI allocation failed",
			zap.Error(err),
			zap.String("allocation_source", "random-unique"))
		return nil, err
	}
	log.Debug("s1ap: GUTI allocated",
		zap.String("allocated_guti", uecontext.SerialiseGUTI(guti)),
		zap.Uint32("mtmsi", guti.MTMSI),
		zap.String("allocation_source", "random-unique"),
		zap.String("collision_checks", "active-guti-index"))
	return guti, nil
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
func (s *Server) sendDownlinkNASTransport(enbAddr string, mmeUEID, enbUEID uint32, nasPDU []byte) error {
	if len(nasPDU) > 0 {
		secHdr, pd, _ := emm.DecodeSecurityHeader(nasPDU)
		s.log.Debug("s1ap: sending downlink NAS",
			zap.String("direction", "downlink"),
			zap.Uint32("mme_ue_id", mmeUEID),
			zap.Uint32("enb_ue_id", enbUEID),
			zap.Uint8("sec_hdr", secHdr),
			zap.Uint8("pd", pd),
			zap.Int("nas_len", len(nasPDU)))
	}
	if err := s.SendDownlinkNAS(mmeUEID, nasPDU); err != nil {
		// Fall back to direct send if the UE context no longer has a route
		s.log.Warn("s1ap: sendDownlinkNASTransport via SendDownlinkNAS failed, trying direct",
			zap.Uint32("mme_ue_id", mmeUEID), zap.Error(err))
		_ = enbAddr
		_ = enbUEID
		return err
	}
	return nil
}

// algName converts a numeric algorithm ID to a name for PreferredAlgorithm.
func intAlgNames(cap emm.UENetworkCapability) []string {
	return cap.SupportedIntegrityAlgs()
}

func encAlgNames(cap emm.UENetworkCapability) []string {
	return cap.SupportedCipheringAlgs()
}
