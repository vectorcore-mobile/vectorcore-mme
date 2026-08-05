package s1ap

import (
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/gtpv2"
	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/models"
	nas "github.com/vectorcore/mme/internal/nas"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/security"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/uecontext"
)

const serviceRequestReleaseWaitTimeout = 500 * time.Millisecond

type resumeBearerSelectionRecord struct {
	EBI                    uint8  `json:"ebi"`
	BearerType             string `json:"bearer_type"`
	LinkedEBI              uint8  `json:"linked_ebi"`
	APN                    string `json:"apn"`
	QCI                    uint8  `json:"qci"`
	ARPPriority            uint8  `json:"arp"`
	State                  string `json:"state"`
	NASAccepted            bool   `json:"nas_accepted"`
	ERABEstablished        bool   `json:"erab_established"`
	ModifyBearerSent       bool   `json:"modify_bearer_sent"`
	ModifyBearerAccepted   bool   `json:"modify_bearer_accepted"`
	SGWS1UIP               string `json:"sgw_s1u_ip"`
	SGWS1UTEID             uint32 `json:"sgw_s1u_teid"`
	PreviousENBS1UTEID     uint32 `json:"previous_enb_s1u_teid"`
	PendingTransactionType string `json:"pending_transaction_type"`
	PendingTransactionID   string `json:"pending_transaction_id"`
	SelectedForResume      bool   `json:"selected_for_resume"`
	SelectionReason        string `json:"selection_reason"`
}

// handleServiceRequest handles a NAS Service Request arriving via Initial UE Message
// (ECM-IDLE UE re-establishing S1 connectivity).
//
// tempUE is the freshly allocated context from handleInitialUEMessage; it holds
// the new S1AP IDs and TAI from the Initial UE Message.  The real UE context is
// found by constructing a GUTI from the S-TMSI carried in the S1AP message.
func (s *Server) handleServiceRequest(
	tempUE *uecontext.Context,
	mmec uint8, mtmsi uint32, stmsiRaw []byte, stmsiPresent bool,
	tai *ies.TAI, nasPDU []byte,
) {
	tempUE.Lock()
	enbUEID := tempUE.ENBS1APID
	enbAddr := tempUE.ENBGlobalID
	tempMmeUEID := tempUE.MMEUES1APID
	tempUE.Unlock()

	log := s.log.With(
		zap.String("remote", enbAddr),
		zap.String("procedure", "ServiceRequest"),
		zap.Uint32("tmp_mme_ue_id", tempMmeUEID),
		zap.Uint32("enb_ue_id", enbUEID),
	)
	log.Info("s1ap: ServiceRequest received",
		zap.String("nas_hex", hex.EncodeToString(nasPDU)),
		zap.String("stmsi_raw", hex.EncodeToString(stmsiRaw)),
		zap.Bool("stmsi_present", stmsiPresent),
		zap.Uint8("decoded_mmec", mmec),
		zap.Uint32("decoded_mtmsi", mtmsi),
		zap.String("decoded_mtmsi_hex", fmt.Sprintf("0x%08x", mtmsi)))

	reject := func(cause uint8) {
		log.Warn("s1ap: ServiceRequest rejected",
			zap.Uint8("emm_cause", cause),
			zap.String("nas_hex", hex.EncodeToString(nasPDU)),
			zap.String("stmsi_raw", hex.EncodeToString(stmsiRaw)),
			zap.Uint8("decoded_mmec", mmec),
			zap.Uint32("decoded_mtmsi", mtmsi))
		s.sendServiceReject(tempMmeUEID, enbUEID, enbAddr, cause)
		s.ueManager.Remove(tempUE)
		metrics.NASProceduresTotal.WithLabelValues("ServiceRequest", "reject").Inc()
	}

	if !stmsiPresent {
		log.Warn("s1ap: ServiceRequest: no S-TMSI in Initial UE Message")
		reject(emm.CauseImplicitlyDetached)
		return
	}

	// Construct GUTI from S-TMSI + our own PLMN + MMEGI. GUTI uses the NAS/EMM
	// TBCD PLMN layout, not the S1AP PLMNIdentity helper.
	plmn, err := security.EncodePLMN(s.nfCfg.MCC, s.nfCfg.MNC)
	if err != nil {
		log.Error("s1ap: ServiceRequest: failed to encode PLMN", zap.Error(err))
		reject(emm.CauseNetworkFailure)
		return
	}
	lookupGUTI := &emm.GUTI{
		MMEGI: s.nfCfg.MMEGI,
		MMEC:  mmec,
		MTMSI: mtmsi,
	}
	copy(lookupGUTI.PLMN[:], plmn)
	gutiStr := uecontext.SerialiseGUTI(lookupGUTI)

	realUE, ok := s.ueManager.GetByGUTI(gutiStr)
	if !ok {
		log.Warn("s1ap: ServiceRequest: GUTI not found",
			zap.String("lookup_result", "miss"),
			zap.String("lookup_guti", gutiStr),
			zap.Uint8("mmec", mmec),
			zap.Uint32("mtmsi", mtmsi),
			zap.String("mtmsi_hex", fmt.Sprintf("0x%08x", mtmsi)))
		reject(emm.CauseImplicitlyDetached)
		return
	}
	// Snapshot fields under the real UE lock.
	realUE.Lock()
	intAlg := realUE.IntAlg
	knasInt := append([]byte(nil), realUE.KNASint...)
	ulCount := uint32(realUE.ULNASCount)
	defaultEBI := realUE.DefaultEBI
	sgwUTEID := realUE.SGWU_TEID
	sgwUIP := append(net.IP(nil), realUE.SGWU_IP...)
	emmState := realUE.EMMState
	ecmState := realUE.ECMState
	releasePending := realUE.S1ReleasePending
	releaseENBID := realUE.S1ReleaseENBID
	boundENBUEID := realUE.ENBS1APID
	boundENBAddr := realUE.ENBGlobalID
	bindingGeneration := realUE.S1BindingGeneration
	realMmeUEID := realUE.MMEUES1APID
	imsi := realUE.IMSI
	attachStep := realUE.AttachStep
	realUE.Unlock()

	log = log.With(zap.Uint32("mme_ue_id", realMmeUEID))
	log.Info("s1ap: ServiceRequest lookup result",
		zap.String("lookup_result", "hit"),
		zap.String("lookup_guti", gutiStr),
		zap.String("imsi", imsi),
		zap.Stringer("emm_state", emmState),
		zap.Stringer("ecm_state", ecmState),
		zap.Uint8("default_ebi", defaultEBI),
		zap.Uint32("sgw_s1u_teid", sgwUTEID),
		zap.String("sgw_s1u_teid_hex", fmt.Sprintf("0x%08x", sgwUTEID)),
		zap.String("sgw_s1u_ipv4", sgwUIP.String()),
		zap.Uint32("ul_nas_count", ulCount),
		zap.Uint8("attach_step", attachStep),
		zap.Bool("s1_release_pending", releasePending),
		zap.Uint32("s1_release_enb_ue_id", releaseENBID))

	resumePending := attachStep == uecontext.AttachStepWaitingICSRespSR
	incomingDifferentBinding := boundENBUEID != enbUEID || boundENBAddr != enbAddr

	// Validate UE state.
	if emmState != emm.StateRegistered && !resumePending {
		log.Warn("s1ap: ServiceRequest: UE not in Registered state", zap.Stringer("state", emmState))
		reject(emm.CauseImplicitlyDetached)
		return
	}
	if ecmState != emm.ECMIdle && !resumePending && !incomingDifferentBinding {
		log.Warn("s1ap: ServiceRequest: UE already ECM-Connected on current S1 binding")
		// The S-TMSI was resolved above, so cause 9 (identity cannot be
		// derived) is not valid for a same-binding duplicate.
		reject(emm.CauseNetworkFailure)
		return
	}
	if ecmState == emm.ECMConnected && incomingDifferentBinding {
		log.Info("s1ap: ServiceRequest arrived on different S1 binding",
			zap.Uint32("old_enb_ue_id", boundENBUEID),
			zap.Uint32("new_enb_ue_id", enbUEID),
			zap.String("old_remote", boundENBAddr),
			zap.String("new_remote", enbAddr),
			zap.Uint64("old_binding_generation", bindingGeneration))
	}
	if defaultEBI == 0 || sgwUTEID == 0 {
		log.Warn("s1ap: ServiceRequest: no active bearer")
		reject(emm.CauseNoEPSBearerContextActivated)
		return
	}

	// Verify short MAC.
	ok, macDetails := emm.VerifyShortMACDetailed(nasPDU, intAlg, knasInt, ulCount)
	var reconstructedCount uint32
	if macDetails != nil {
		reconstructedCount = macDetails.ReconstructedCount
	}
	if !ok {
		log.Warn("s1ap: ServiceRequest: short MAC verification failed",
			zap.Uint32("stored_ul_nas_count", ulCount),
			zap.String("nas_hex_full", hex.EncodeToString(nasPDU)),
			zap.String("nas_hex_used_for_mac", serviceRequestMACInputHex(macDetails)),
			zap.String("extracted_short_mac_hex", serviceRequestExpectedShortMACHex(macDetails)),
			zap.Uint8("ksi", serviceRequestKSI(macDetails)),
			zap.Uint8("sequence_number_raw", serviceRequestSequenceNumber(macDetails)),
			zap.Uint32("reconstructed_count", reconstructedCount),
			zap.Uint32("overflow", serviceRequestOverflow(macDetails)),
			zap.Uint8("bearer", serviceRequestBearer(macDetails)),
			zap.Uint8("direction", serviceRequestDirection(macDetails)),
			zap.String("knas_int_prefix_hex", truncateHex(knasInt, 8)),
			zap.String("computed_mac_hex", serviceRequestComputedMACHex(macDetails)),
			zap.String("computed_short_mac_hex", serviceRequestComputedShortMACHex(macDetails)),
			zap.String("expected_short_mac_hex", serviceRequestExpectedShortMACHex(macDetails)))
		reject(emm.CauseUEIdentityCannotBeDerived)
		return
	}
	log.Info("s1ap: ServiceRequest short MAC verified",
		zap.Uint32("stored_ul_nas_count", ulCount),
		zap.Uint32("reconstructed_ul_nas_count", reconstructedCount),
		zap.String("nas_hex_used_for_mac", serviceRequestMACInputHex(macDetails)),
		zap.String("computed_short_mac_hex", serviceRequestComputedShortMACHex(macDetails)),
		zap.String("expected_short_mac_hex", serviceRequestExpectedShortMACHex(macDetails)))
	// Short-MAC verification binds this return to the retained EPS context; a
	// bare Initial UE Message must never cancel implicit detach.
	s.refreshReachability(realUE, "service-request-short-mac")

	if resumePending {
		realUE.Lock()
		currentENBUEID := realUE.ENBS1APID
		currentENBAddr := realUE.ENBGlobalID
		currentGeneration := realUE.S1BindingGeneration
		realUE.Unlock()
		s.ueManager.Remove(tempUE)
		if currentENBUEID != enbUEID || currentENBAddr != enbAddr {
			log.Warn("s1ap: ServiceRequest ignored; another binding resume is already in progress",
				zap.Uint32("winning_enb_ue_id", currentENBUEID),
				zap.String("winning_remote", currentENBAddr),
				zap.Uint64("winning_binding_generation", currentGeneration))
			s.sendServiceReject(realMmeUEID, enbUEID, enbAddr, emm.CauseNetworkFailure)
			metrics.NASProceduresTotal.WithLabelValues("ServiceRequest", "reject").Inc()
			return
		}
		log.Info("s1ap: duplicate ServiceRequest ignored; ICS resume already pending",
			zap.Uint64("binding_generation", currentGeneration))
		return
	}

	// Transfer S1AP context from tempUE to the real UE.
	realUE.Lock()
	realUE.StopTimer(uecontext.TimerT3413)
	oldENBUEID := realUE.ENBS1APID
	oldENBAddr := realUE.ENBGlobalID
	oldBindingGeneration := realUE.S1BindingGeneration
	obsoleteRelease := oldENBUEID != 0 && oldENBAddr != "" &&
		(oldENBUEID != enbUEID || oldENBAddr != enbAddr)
	if obsoleteRelease {
		// A UE that reconnects faster than the eNB acknowledges a release can
		// leave more than one superseded binding outstanding at once; each is
		// tracked and retired independently as its own Release Complete arrives.
		realUE.AddObsoleteS1Release(&uecontext.ObsoleteS1BindingRelease{
			MMEUES1APID:       realUE.MMEUES1APID,
			ENBS1APID:         oldENBUEID,
			ENBAddr:           oldENBAddr,
			BindingGeneration: oldBindingGeneration,
			CleanupGeneration: oldBindingGeneration + 1,
			Deadline:          time.Now().Add(30 * time.Second),
		})
	}
	// PagingAttempts is NOT cleared here — handleServiceRequestReestablished reads it
	// to increment the paging-success metric, then clears it.
	realUE.ENBS1APID = enbUEID
	realUE.ENBGlobalID = enbAddr
	realUE.S1BindingGeneration++
	realUE.S1BindingState = uecontext.S1BindingActive
	if obsoleteRelease {
		// A release that belongs to the superseded access context must not
		// delay or mutate this authenticated replacement binding.
		realUE.S1ReleasePending = false
		realUE.S1ReleaseENBID = 0
		realUE.S1ReleaseENBAddr = ""
		realUE.S1ReleaseGeneration = 0
	}
	if tai != nil {
		realUE.TAI = emmTAIFromS1AP(tai)
	}
	realUE.ULNASCount = security.NASCount(reconstructedCount)
	realUE.SetEMMState(emm.StateServiceRequestInitiated)
	realUE.AttachStep = uecontext.AttachStepWaitingICSRespSR
	resumeBearers, resumeErr := s.serviceRequestResumeBearersLocked(realUE)
	if resumeErr == nil && len(resumeBearers) > 0 {
		if err := s.createASSecuritySnapshotLocked(realUE, "service_request"); err != nil {
			realUE.AttachStep = uecontext.AttachStepNone
			realUE.Unlock()
			log.Warn("s1ap: Service Request AS security snapshot failed", zap.Error(err))
			s.sendServiceReject(realMmeUEID, enbUEID, enbAddr, emm.CauseNetworkFailure)
			metrics.NASProceduresTotal.WithLabelValues("ServiceRequest", "reject").Inc()
			return
		}
	}
	if resumeErr == nil {
		s.logServiceRequestResumeSelectionLocked(realUE, "accepted_resume", resumeBearers)
	}
	newBindingGeneration := realUE.S1BindingGeneration
	realUE.Unlock()
	s.noteDDNServiceRequest(realUE, enbUEID, newBindingGeneration)
	if obsoleteRelease {
		log.Info("s1ap: authenticated S1 binding replacement reserved",
			zap.Uint32("old_enb_ue_id", oldENBUEID), zap.Uint32("new_enb_ue_id", enbUEID),
			zap.String("old_remote", oldENBAddr), zap.String("new_remote", enbAddr),
			zap.Uint64("old_binding_generation", oldBindingGeneration),
			zap.Uint64("new_binding_generation", newBindingGeneration))
		s.sendUEContextReleaseCommand(oldENBAddr, realMmeUEID, oldENBUEID)
		s.scheduleObsoleteS1BindingCleanup(realUE, oldBindingGeneration)
		releasePending = false
	}

	// Remove the temporary UE — its only purpose was to carry the S1AP IDs.
	s.ueManager.Remove(tempUE)
	if resumeErr != nil {
		log.Warn("s1ap: Service Request rejected due to incomplete retained bearer policy", zap.Error(resumeErr))
		realUE.Lock()
		realUE.SetEMMState(emm.StateRegistered)
		realUE.SetECMState(emm.ECMIdle)
		realUE.AttachStep = uecontext.AttachStepNone
		realUE.Unlock()
		s.sendServiceReject(realMmeUEID, enbUEID, enbAddr, emm.CauseNetworkFailure)
		metrics.NASProceduresTotal.WithLabelValues("ServiceRequest", "reject").Inc()
		return
	}

	metrics.NASProceduresTotal.WithLabelValues("ServiceRequest", "attempt").Inc()
	log.Info("s1ap: Service Request accepted, sending ICS resume",
		zap.Uint8("ebi", defaultEBI),
		zap.Int("resume_bearer_count", len(resumeBearers)),
		zap.Uint32("sgw_s1u_teid", sgwUTEID),
		zap.String("sgw_s1u_teid_hex", fmt.Sprintf("0x%08x", sgwUTEID)),
		zap.String("sgw_s1u_ipv4", sgwUIP.String()),
		zap.Bool("s1_release_pending", releasePending))

	sendResumeICS := func() {
		if err := s.SendInitialContextSetupWithBearers(realMmeUEID, nil, resumeBearers); err != nil {
			log.Error("s1ap: ServiceRequest: SendInitialContextSetup failed", zap.Error(err))
			realUE.Lock()
			realUE.SetEMMState(emm.StateRegistered)
			realUE.SetECMState(emm.ECMIdle)
			realUE.AttachStep = uecontext.AttachStepNone
			realUE.Unlock()
			metrics.NASProceduresTotal.WithLabelValues("ServiceRequest", "reject").Inc()
			return
		}
		log.Info("s1ap: ServiceRequest ICS resume sent",
			zap.Uint32("mme_ue_id", realMmeUEID),
			zap.Uint32("enb_ue_id", enbUEID),
			zap.Uint8("ebi", defaultEBI),
			zap.Bool("delayed_for_release_complete", releasePending))
	}

	// EPS has no NAS Service Accept message. Open5GS accepts a normal LTE
	// Service Request by sending InitialContextSetupRequest without NAS-PDU.
	// If a previous UE Context Release is still pending, wait for the release
	// to clear rather than relying on a fixed sleep.
	s.sendResumeICSWhenReleaseClears(realUE, releasePending, releaseENBID, enbUEID, newBindingGeneration, sendResumeICS, log)
}

func (s *Server) handleInitialUEExtendedServiceRequest(
	tempUE *uecontext.Context,
	tai *ies.TAI,
	body []byte,
	nasPDU []byte,
) {
	tempUE.Lock()
	enbUEID := tempUE.ENBS1APID
	enbAddr := tempUE.ENBGlobalID
	tempMmeUEID := tempUE.MMEUES1APID
	tempUE.Unlock()

	log := s.log.With(
		zap.String("remote", enbAddr),
		zap.String("procedure", "ExtendedServiceRequest"),
		zap.Uint32("tmp_mme_ue_id", tempMmeUEID),
		zap.Uint32("enb_ue_id", enbUEID),
	)

	reject := func(cause uint8) {
		log.Warn("s1ap: Extended Service Request rejected",
			zap.Uint8("emm_cause", cause),
			zap.String("nas_hex", hex.EncodeToString(nasPDU)))
		s.sendServiceReject(tempMmeUEID, enbUEID, enbAddr, cause)
		s.ueManager.Remove(tempUE)
		metrics.NASProceduresTotal.WithLabelValues("ExtendedServiceRequest", "reject").Inc()
	}

	req, err := emm.DecodeExtendedServiceRequest(body)
	if err != nil {
		log.Warn("s1ap: Extended Service Request decode error",
			zap.String("message_body_hex", hex.EncodeToString(body)),
			zap.Error(err))
		reject(emm.CauseUEIdentityCannotBeDerived)
		return
	}

	var lookupGUTI *emm.GUTI
	if req.GUTI != nil {
		lookupGUTI = req.GUTI
	} else {
		plmn, err := security.EncodePLMN(s.nfCfg.MCC, s.nfCfg.MNC)
		if err != nil {
			log.Error("s1ap: Extended Service Request: failed to encode PLMN", zap.Error(err))
			reject(emm.CauseNetworkFailure)
			return
		}
		lookupGUTI = &emm.GUTI{
			MMEGI: s.nfCfg.MMEGI,
			MMEC:  s.nfCfg.MMEC,
			MTMSI: req.MTMSI,
		}
		copy(lookupGUTI.PLMN[:], plmn)
	}
	gutiStr := uecontext.SerialiseGUTI(lookupGUTI)

	log.Info("s1ap: Extended Service Request received",
		zap.String("nas_hex", hex.EncodeToString(nasPDU)),
		zap.String("message_body_hex", hex.EncodeToString(body)),
		zap.Uint8("service_type", req.ServiceType),
		zap.Uint8("identity_type", req.IdentityType),
		zap.Uint32("mtmsi", req.MTMSI),
		zap.String("mtmsi_hex", fmt.Sprintf("0x%08x", req.MTMSI)),
		zap.String("lookup_guti", gutiStr))

	realUE, ok := s.ueManager.GetByGUTI(gutiStr)
	if !ok {
		log.Warn("s1ap: Extended Service Request: GUTI not found",
			zap.String("lookup_result", "miss"),
			zap.String("lookup_guti", gutiStr))
		reject(emm.CauseImplicitlyDetached)
		return
	}
	if req.ServiceType == emm.ServiceTypeMobileOriginatingCSFallback {
		if err := s.sendProtectedServiceRejectForUE(realUE, tempMmeUEID, enbUEID, enbAddr, emm.CauseCSDomainNotAvailable, "idle MO-CSFB Extended Service Request"); err != nil {
			log.Warn("s1ap: Extended Service Request CSFB reject send failed", zap.Error(err))
		}
		// The temporary InitialUE context has served only as the current S1
		// route. The authoritative EPS context and all PDNs remain untouched.
		s.ueManager.Remove(tempUE)
		metrics.NASProceduresTotal.WithLabelValues("ExtendedServiceRequest", "csfb_reject").Inc()
		return
	}

	realUE.Lock()
	defaultEBI := realUE.DefaultEBI
	sgwUTEID := realUE.SGWU_TEID
	emmState := realUE.EMMState
	ecmState := realUE.ECMState
	imsi := realUE.IMSI
	attachStep := realUE.AttachStep
	realUE.Unlock()

	log = log.With(zap.Uint32("mme_ue_id", realUE.MMEUES1APID))
	log.Info("s1ap: Extended Service Request lookup result",
		zap.String("lookup_result", "hit"),
		zap.String("lookup_guti", gutiStr),
		zap.String("imsi", imsi),
		zap.Stringer("emm_state", emmState),
		zap.Stringer("ecm_state", ecmState),
		zap.Uint8("attach_step", attachStep),
		zap.Uint8("default_ebi", defaultEBI),
		zap.Uint32("sgw_s1u_teid", sgwUTEID))

	resumePending := attachStep == uecontext.AttachStepWaitingICSRespSR
	if emmState != emm.StateRegistered && !resumePending {
		log.Warn("s1ap: Extended Service Request: UE not in Registered state", zap.Stringer("state", emmState))
		reject(emm.CauseImplicitlyDetached)
		return
	}
	if ecmState != emm.ECMIdle && !resumePending {
		log.Warn("s1ap: Extended Service Request: UE already ECM-Connected")
		reject(emm.CauseUEIdentityCannotBeDerived)
		return
	}
	if defaultEBI == 0 || sgwUTEID == 0 {
		log.Warn("s1ap: Extended Service Request: no active bearer")
		reject(emm.CauseNoEPSBearerContextActivated)
		return
	}

	s.resumeIdleUEFromInitialUE(tempUE, realUE, tai, log)
	metrics.NASProceduresTotal.WithLabelValues("ExtendedServiceRequest", "attempt").Inc()
}

func (s *Server) resumeIdleUEFromInitialUE(
	tempUE *uecontext.Context,
	realUE *uecontext.Context,
	tai *ies.TAI,
	log *zap.Logger,
) {
	tempUE.Lock()
	enbUEID := tempUE.ENBS1APID
	enbAddr := tempUE.ENBGlobalID
	tempUE.Unlock()

	realUE.Lock()
	realUE.StopTimer(uecontext.TimerT3413)
	releasePending := realUE.S1ReleasePending
	releaseENBID := realUE.S1ReleaseENBID
	realUE.ENBS1APID = enbUEID
	realUE.ENBGlobalID = enbAddr
	realUE.S1BindingGeneration++
	realUE.S1BindingState = uecontext.S1BindingActive
	if tai != nil {
		realUE.TAI = emmTAIFromS1AP(tai)
	}
	realUE.SetEMMState(emm.StateServiceRequestInitiated)
	realUE.AttachStep = uecontext.AttachStepWaitingICSRespSR
	realMmeUEID := realUE.MMEUES1APID
	defaultEBI := realUE.DefaultEBI
	resumeBearers, resumeErr := s.serviceRequestResumeBearersLocked(realUE)
	if resumeErr == nil && len(resumeBearers) > 0 {
		if err := s.createASSecuritySnapshotLocked(realUE, "service_request"); err != nil {
			realUE.AttachStep = uecontext.AttachStepNone
			realUE.Unlock()
			s.ueManager.Remove(tempUE)
			log.Warn("s1ap: resume AS security snapshot failed", zap.Error(err))
			s.sendServiceReject(realMmeUEID, enbUEID, enbAddr, emm.CauseNetworkFailure)
			metrics.NASProceduresTotal.WithLabelValues("ExtendedServiceRequest", "reject").Inc()
			return
		}
	}
	newBindingGeneration := realUE.S1BindingGeneration
	realUE.Unlock()
	s.noteDDNServiceRequest(realUE, enbUEID, newBindingGeneration)

	s.ueManager.Remove(tempUE)
	if resumeErr != nil {
		log.Warn("s1ap: resume rejected due to incomplete retained bearer policy", zap.Error(resumeErr))
		realUE.Lock()
		realUE.SetEMMState(emm.StateRegistered)
		realUE.SetECMState(emm.ECMIdle)
		realUE.AttachStep = uecontext.AttachStepNone
		realUE.Unlock()
		s.sendServiceReject(realMmeUEID, enbUEID, enbAddr, emm.CauseNetworkFailure)
		metrics.NASProceduresTotal.WithLabelValues("ExtendedServiceRequest", "reject").Inc()
		return
	}

	sendResumeICS := func() {
		if err := s.SendInitialContextSetupWithBearers(realMmeUEID, nil, resumeBearers); err != nil {
			log.Error("s1ap: resume InitialContextSetup failed", zap.Error(err))
			realUE.Lock()
			realUE.SetEMMState(emm.StateRegistered)
			realUE.SetECMState(emm.ECMIdle)
			realUE.AttachStep = uecontext.AttachStepNone
			realUE.Unlock()
			return
		}
		log.Info("s1ap: resume ICS sent",
			zap.Uint32("mme_ue_id", realMmeUEID),
			zap.Uint32("enb_ue_id", enbUEID),
			zap.Uint8("ebi", defaultEBI),
			zap.Bool("delayed_for_release_complete", releasePending))
	}

	log.Info("s1ap: resume accepted, sending ICS resume",
		zap.Uint8("ebi", defaultEBI),
		zap.Int("resume_bearer_count", len(resumeBearers)),
		zap.Bool("s1_release_pending", releasePending))

	s.sendResumeICSWhenReleaseClears(realUE, releasePending, releaseENBID, enbUEID, newBindingGeneration, sendResumeICS, log)
}

func (s *Server) serviceRequestResumeBearersLocked(ue *uecontext.Context) ([]BearerInfo, error) {
	return retainedResumeBearersLocked(ue, true)
}

func retainedResumeBearersLocked(ue *uecontext.Context, includeDedicated bool) ([]BearerInfo, error) {
	defaultsByEBI := make(map[uint8]BearerInfo, len(ue.PDNs)+1)
	dedicatedByLinkedEBI := make(map[uint8][]BearerInfo, len(ue.DedicatedBearers))
	if includeDedicated {
		for _, ebi := range sortedDedicatedBearerEBIsLocked(ue) {
			proc := ue.DedicatedBearers[ebi]
			if proc == nil || proc.SGWS1UTEID == 0 || len(proc.SGWS1UIP) == 0 {
				continue
			}
			if tauDedicatedBearerInactive(proc) {
				continue
			}
			if dedicatedBearerHasPendingResumeBlockingTransactionLocked(ue, proc.AssignedEBI) {
				continue
			}
			if !proc.NASAccepted && !proc.ERABEstablished {
				continue
			}
			item := BearerInfo{
				EBI:                     proc.AssignedEBI,
				QCI:                     proc.QCI,
				ARPPriority:             arpPriority(proc.ARP),
				PreemptionCapability:    preemptionCapability(proc.ARP),
				PreemptionVulnerability: preemptionVulnerability(proc.ARP),
				BearerQoS:               append([]byte(nil), proc.BearerQoS...),
				SGWU_TEID:               proc.SGWS1UTEID,
				SGWU_IP:                 append([]byte(nil), proc.SGWS1UIP.To4()...),
			}
			if proc.LinkedEBI == 0 {
				continue
			}
			dedicatedByLinkedEBI[proc.LinkedEBI] = append(dedicatedByLinkedEBI[proc.LinkedEBI], item)
		}
	}

	pdns := sortedPDNContextsLocked(ue)
	for _, pdn := range pdns {
		if pdn == nil || pdn.DefaultEBI == 0 || pdn.SGWU_TEID == 0 || len(pdn.SGWU_IP) == 0 {
			continue
		}
		if pdnDisconnectInProgress(pdn) {
			continue
		}
		if tauPDNIsInactiveForStatusSync(pdn) || pdn.ModifyBearerFailed {
			continue
		}
		cfg, ok := subscriberAPNConfigForResumeLocked(ue, pdn.APN)
		if !ok {
			return nil, fmt.Errorf("s1ap: missing subscriber APN policy for resumed PDN %q", pdn.APN)
		}
		if missing := validateSubscriberAPNPolicy(&cfg); len(missing) != 0 {
			return nil, fmt.Errorf("s1ap: incomplete subscriber APN policy for resumed PDN %q: %s", pdn.APN, strings.Join(missing, ","))
		}
		defaultsByEBI[pdn.DefaultEBI] = BearerInfo{
			EBI:                     pdn.DefaultEBI,
			QCI:                     cfg.QCI,
			ARPPriority:             cfg.ARPPriority,
			PreemptionCapability:    cfg.PreemptionCapability,
			PreemptionVulnerability: cfg.PreemptionVulnerability,
			SGWU_TEID:               pdn.SGWU_TEID,
			SGWU_IP:                 append([]byte(nil), pdn.SGWU_IP.To4()...),
		}
	}

	if ue.DefaultEBI != 0 && ue.SGWU_TEID != 0 && len(ue.SGWU_IP) != 0 {
		if _, ok := defaultsByEBI[ue.DefaultEBI]; !ok {
			cfg, ok := subscriberAPNConfigForResumeLocked(ue, ue.APN)
			if !ok {
				return nil, fmt.Errorf("s1ap: missing subscriber APN policy for retained default bearer %q", ue.APN)
			}
			if missing := validateSubscriberAPNPolicy(&cfg); len(missing) != 0 {
				return nil, fmt.Errorf("s1ap: incomplete subscriber APN policy for retained default bearer %q: %s", ue.APN, strings.Join(missing, ","))
			}
			defaultsByEBI[ue.DefaultEBI] = BearerInfo{
				EBI:                     ue.DefaultEBI,
				QCI:                     cfg.QCI,
				ARPPriority:             cfg.ARPPriority,
				PreemptionCapability:    cfg.PreemptionCapability,
				PreemptionVulnerability: cfg.PreemptionVulnerability,
				SGWU_TEID:               ue.SGWU_TEID,
				SGWU_IP:                 append([]byte(nil), ue.SGWU_IP.To4()...),
			}
		}
	}

	appendLinked := func(out []BearerInfo, linkedEBI uint8) []BearerInfo {
		items := dedicatedByLinkedEBI[linkedEBI]
		sort.Slice(items, func(i, j int) bool { return items[i].EBI < items[j].EBI })
		out = append(out, items...)
		delete(dedicatedByLinkedEBI, linkedEBI)
		return out
	}

	legacyDefaultEBI := ue.DefaultEBI
	nonLegacyDefaultEBIs := make([]uint8, 0, len(defaultsByEBI))
	for ebi := range defaultsByEBI {
		if ebi == legacyDefaultEBI {
			continue
		}
		nonLegacyDefaultEBIs = append(nonLegacyDefaultEBIs, ebi)
	}
	sort.Slice(nonLegacyDefaultEBIs, func(i, j int) bool { return nonLegacyDefaultEBIs[i] < nonLegacyDefaultEBIs[j] })

	out := make([]BearerInfo, 0, len(defaultsByEBI)+len(ue.DedicatedBearers))
	for _, ebi := range nonLegacyDefaultEBIs {
		out = append(out, defaultsByEBI[ebi])
		out = appendLinked(out, ebi)
	}

	if legacy, ok := defaultsByEBI[legacyDefaultEBI]; ok {
		if len(nonLegacyDefaultEBIs) == 0 {
			out = append(out, legacy)
			out = appendLinked(out, legacyDefaultEBI)
		} else {
			out = appendLinked(out, legacyDefaultEBI)
			out = append(out, legacy)
		}
		delete(defaultsByEBI, legacyDefaultEBI)
	}

	return out, nil
}

func dedicatedBearerHasPendingResumeBlockingTransactionLocked(ue *uecontext.Context, assignedEBI uint8) bool {
	for _, tx := range ue.PendingBearerTransactions {
		if tx == nil {
			continue
		}
		switch tx.Kind {
		case bearerTxDelete, bearerTxUpdate, bearerTxLocalUpdate:
			if _, ok := tx.Bearers[assignedEBI]; ok {
				return true
			}
		}
	}
	return false
}

func (s *Server) logServiceRequestResumeSelectionLocked(ue *uecontext.Context, phase string, selected []BearerInfo) {
	selectedByEBI := make(map[uint8]struct{}, len(selected))
	selectedEBIs := make([]uint8, 0, len(selected))
	for _, bearer := range selected {
		selectedByEBI[bearer.EBI] = struct{}{}
		selectedEBIs = append(selectedEBIs, bearer.EBI)
	}

	records := make([]resumeBearerSelectionRecord, 0, len(ue.PDNs)+len(ue.DedicatedBearers))
	skippedEBIs := make([]uint8, 0, len(ue.PDNs)+len(ue.DedicatedBearers))

	for _, pdn := range sortedPDNContextsLocked(ue) {
		if pdn == nil || pdn.DefaultEBI == 0 {
			continue
		}
		_, isSelected := selectedByEBI[pdn.DefaultEBI]
		reason := "selected_default_bearer"
		if !isSelected {
			reason = defaultResumeSkipReasonLocked(ue, pdn)
			skippedEBIs = append(skippedEBIs, pdn.DefaultEBI)
		}
		records = append(records, resumeBearerSelectionRecord{
			EBI:                  pdn.DefaultEBI,
			BearerType:           "default",
			APN:                  pdn.APN,
			QCI:                  pdnQCIForResumeLocked(ue, pdn),
			ARPPriority:          pdnARPPriorityForResumeLocked(ue, pdn),
			State:                pdn.State,
			NASAccepted:          pdn.NASAccepted,
			ERABEstablished:      pdn.ERABEstablished,
			ModifyBearerSent:     pdn.ModifyBearerSent,
			ModifyBearerAccepted: pdn.ModifyBearerAccepted,
			SGWS1UIP:             ipString(pdn.SGWU_IP),
			SGWS1UTEID:           pdn.SGWU_TEID,
			PreviousENBS1UTEID:   pdn.ENBU_TEID,
			SelectedForResume:    isSelected,
			SelectionReason:      reason,
		})
	}

	for _, ebi := range sortedDedicatedBearerEBIsLocked(ue) {
		proc := ue.DedicatedBearers[ebi]
		if proc == nil {
			continue
		}
		pendingType, pendingID := dedicatedBearerResumeBlockingTransactionLocked(ue, ebi)
		_, isSelected := selectedByEBI[ebi]
		reason := "selected_dedicated_bearer"
		if !isSelected {
			reason = dedicatedResumeSkipReasonLocked(proc, pendingType, true)
			skippedEBIs = append(skippedEBIs, ebi)
		}
		records = append(records, resumeBearerSelectionRecord{
			EBI:                    proc.AssignedEBI,
			BearerType:             "dedicated",
			LinkedEBI:              proc.LinkedEBI,
			APN:                    apnForLinkedEBILocked(ue, proc.LinkedEBI),
			QCI:                    proc.QCI,
			ARPPriority:            arpPriority(proc.ARP),
			State:                  proc.State,
			NASAccepted:            proc.NASAccepted,
			ERABEstablished:        proc.ERABEstablished,
			SGWS1UIP:               ipString(proc.SGWS1UIP),
			SGWS1UTEID:             proc.SGWS1UTEID,
			PreviousENBS1UTEID:     proc.ENBS1UTEID,
			PendingTransactionType: pendingType,
			PendingTransactionID:   pendingID,
			SelectedForResume:      isSelected,
			SelectionReason:        reason,
		})
	}

	sort.Slice(records, func(i, j int) bool { return records[i].EBI < records[j].EBI })
	sort.Slice(skippedEBIs, func(i, j int) bool { return skippedEBIs[i] < skippedEBIs[j] })

	s.log.Info("s1ap: ServiceRequest resume bearer selection",
		zap.Uint32("mme_ue_id", ue.MMEUES1APID),
		zap.Uint32("enb_ue_id", ue.ENBS1APID),
		zap.String("imsi", ue.IMSI),
		zap.String("phase", phase),
		zap.Uint8s("resume_ics_ebis", selectedEBIs),
		zap.Uint8s("resume_skipped_ebis", skippedEBIs),
		zap.Any("resume_selection_records", records))
}

func defaultResumeSkipReasonLocked(ue *uecontext.Context, pdn *uecontext.PDNContext) string {
	if pdn == nil {
		return "missing_pdn_context"
	}
	if pdn.DefaultEBI == 0 {
		return "missing_default_ebi"
	}
	if pdn.SGWU_TEID == 0 || len(pdn.SGWU_IP) == 0 {
		return "missing_sgw_s1u_transport"
	}
	if pdnDisconnectInProgress(pdn) {
		return "pdn_disconnect_in_progress"
	}
	if tauPDNIsInactiveForStatusSync(pdn) {
		return "inactive_pdn_state"
	}
	if pdn.ModifyBearerFailed {
		return "modify_bearer_failed"
	}
	return "not_selected"
}

func dedicatedResumeSkipReasonLocked(proc *uecontext.DedicatedBearerContext, pendingType string, defaultOnly bool) string {
	if proc == nil {
		return "missing_dedicated_bearer"
	}
	if defaultOnly {
		return "default_only_resume_policy"
	}
	if proc.SGWS1UTEID == 0 || len(proc.SGWS1UIP) == 0 {
		return "missing_sgw_s1u_transport"
	}
	if tauDedicatedBearerInactive(proc) {
		return "inactive_dedicated_state"
	}
	if pendingType != "" {
		return "pending_transaction_" + pendingType
	}
	if !proc.NASAccepted && !proc.ERABEstablished {
		return "nas_and_erab_not_accepted"
	}
	return "not_selected"
}

func dedicatedBearerResumeBlockingTransactionLocked(ue *uecontext.Context, assignedEBI uint8) (string, string) {
	for _, tx := range ue.PendingBearerTransactions {
		if tx == nil {
			continue
		}
		switch tx.Kind {
		case bearerTxDelete, bearerTxUpdate, bearerTxLocalUpdate:
			if _, ok := tx.Bearers[assignedEBI]; ok {
				return tx.Kind, tx.ID
			}
		}
	}
	return "", ""
}

func apnForLinkedEBILocked(ue *uecontext.Context, linkedEBI uint8) string {
	for _, pdn := range ue.PDNs {
		if pdn != nil && pdn.DefaultEBI == linkedEBI {
			return pdn.APN
		}
	}
	if ue.DefaultEBI == linkedEBI {
		return ue.APN
	}
	return ""
}

func pdnQCIForResumeLocked(ue *uecontext.Context, pdn *uecontext.PDNContext) uint8 {
	if pdn == nil {
		return 0
	}
	if cfg, ok := subscriberAPNConfigForResumeLocked(ue, pdn.APN); ok {
		return cfg.QCI
	}
	if pdn.DefaultEBI == ue.DefaultEBI {
		if cfg, ok := subscriberAPNConfigForResumeLocked(ue, ue.APN); ok {
			return cfg.QCI
		}
	}
	return 0
}

func pdnARPPriorityForResumeLocked(ue *uecontext.Context, pdn *uecontext.PDNContext) uint8 {
	if pdn == nil {
		return 0
	}
	if cfg, ok := subscriberAPNConfigForResumeLocked(ue, pdn.APN); ok {
		return cfg.ARPPriority
	}
	if pdn.DefaultEBI == ue.DefaultEBI {
		if cfg, ok := subscriberAPNConfigForResumeLocked(ue, ue.APN); ok {
			return cfg.ARPPriority
		}
	}
	return 0
}

type serviceRequestMBRGroup struct {
	sgwAddr  string
	sgwcTEID uint32
	bearers  []gtpv2.ModifyBearer
}

func serviceRequestMBRGroupsLocked(ue *uecontext.Context) []serviceRequestMBRGroup {
	type groupKey struct {
		legacyDefault bool
		sgwAddr       string
		sgwcTEID      uint32
	}

	groups := make(map[groupKey]*serviceRequestMBRGroup, len(ue.PDNs)+1)
	seen := make(map[uint8]struct{}, len(ue.PDNs)+len(ue.DedicatedBearers)+1)

	ensureGroup := func(legacyDefault bool, sgwAddr string, sgwcTEID uint32) *serviceRequestMBRGroup {
		key := groupKey{legacyDefault: legacyDefault, sgwAddr: sgwAddr, sgwcTEID: sgwcTEID}
		if grp, ok := groups[key]; ok {
			return grp
		}
		grp := &serviceRequestMBRGroup{sgwAddr: sgwAddr, sgwcTEID: sgwcTEID}
		groups[key] = grp
		return grp
	}

	pdnByDefaultEBI := make(map[uint8]*uecontext.PDNContext, len(ue.PDNs))
	for _, pdn := range ue.PDNs {
		if pdn == nil || pdn.DefaultEBI == 0 {
			continue
		}
		pdnByDefaultEBI[pdn.DefaultEBI] = pdn
	}

	for _, ebi := range sortedDedicatedBearerEBIsLocked(ue) {
		proc := ue.DedicatedBearers[ebi]
		if proc == nil || !proc.ERABEstablished || proc.SGWS1UTEID == 0 || len(proc.SGWS1UIP) == 0 || proc.ENBS1UTEID == 0 || len(proc.ENBS1UIP) == 0 {
			continue
		}

		legacyDefault := proc.LinkedEBI == ue.DefaultEBI
		sgwAddr := ue.SGWAddress
		sgwcTEID := ue.SGWC_TEID
		if pdn := pdnByDefaultEBI[proc.LinkedEBI]; pdn != nil {
			sgwAddr = pdn.SGWAddress
			sgwcTEID = pdn.SGWC_TEID
			legacyDefault = pdn.DefaultEBI == ue.DefaultEBI
		}
		if sgwcTEID == 0 {
			continue
		}

		seen[ebi] = struct{}{}
		grp := ensureGroup(legacyDefault, sgwAddr, sgwcTEID)
		grp.bearers = append(grp.bearers, gtpv2.ModifyBearer{
			EBI:       proc.AssignedEBI,
			ENBU_TEID: proc.ENBS1UTEID,
			ENBU_IP:   append(net.IP(nil), proc.ENBS1UIP...),
		})
	}

	for _, pdn := range sortedPDNContextsLocked(ue) {
		if pdn == nil || pdn.DefaultEBI == 0 || !pdn.ERABEstablished || pdn.ModifyBearerFailed || pdnDisconnectInProgress(pdn) {
			continue
		}
		if pdn.SGWC_TEID == 0 || pdn.ENBU_TEID == 0 || len(pdn.ENBU_IP) == 0 {
			continue
		}
		if _, ok := seen[pdn.DefaultEBI]; ok {
			continue
		}
		seen[pdn.DefaultEBI] = struct{}{}
		grp := ensureGroup(pdn.DefaultEBI == ue.DefaultEBI, pdn.SGWAddress, pdn.SGWC_TEID)
		grp.bearers = append(grp.bearers, gtpv2.ModifyBearer{
			EBI:       pdn.DefaultEBI,
			ENBU_TEID: pdn.ENBU_TEID,
			ENBU_IP:   append(net.IP(nil), pdn.ENBU_IP...),
		})
	}

	if ue.DefaultEBI != 0 {
		if _, ok := seen[ue.DefaultEBI]; !ok && ue.SGWC_TEID != 0 && ue.ENBU_TEID != 0 && len(ue.ENBU_IP) != 0 {
			grp := ensureGroup(true, ue.SGWAddress, ue.SGWC_TEID)
			grp.bearers = append(grp.bearers, gtpv2.ModifyBearer{
				EBI:       ue.DefaultEBI,
				ENBU_TEID: ue.ENBU_TEID,
				ENBU_IP:   append(net.IP(nil), ue.ENBU_IP...),
			})
		}
	}

	out := make([]serviceRequestMBRGroup, 0, len(groups))
	for _, grp := range groups {
		sort.Slice(grp.bearers, func(i, j int) bool { return grp.bearers[i].EBI < grp.bearers[j].EBI })
		if len(grp.bearers) == 0 {
			continue
		}
		out = append(out, *grp)
	}
	sort.Slice(out, func(i, j int) bool {
		leftLegacy := false
		rightLegacy := false
		if len(out[i].bearers) != 0 {
			leftLegacy = out[i].bearers[0].EBI == ue.DefaultEBI
		}
		if len(out[j].bearers) != 0 {
			rightLegacy = out[j].bearers[0].EBI == ue.DefaultEBI
		}
		if leftLegacy != rightLegacy {
			return !leftLegacy && rightLegacy
		}
		return out[i].bearers[0].EBI < out[j].bearers[0].EBI
	})
	return out
}

func (s *Server) sendResumeICSWhenReleaseClears(
	ue *uecontext.Context,
	releasePending bool,
	oldENBUEID uint32,
	newENBUEID uint32,
	expectedGeneration uint64,
	send func(),
	log *zap.Logger,
) {
	if !releasePending {
		send()
		return
	}
	log.Info("s1ap: resume ICS waiting for UE Context Release Complete",
		zap.Uint32("old_enb_ue_id", oldENBUEID),
		zap.Uint32("new_enb_ue_id", newENBUEID),
		zap.Duration("timeout", serviceRequestReleaseWaitTimeout))
	go func() {
		deadline := time.Now().Add(serviceRequestReleaseWaitTimeout)
		ticker := time.NewTicker(25 * time.Millisecond)
		defer ticker.Stop()
		for {
			ue.Lock()
			stillPending := ue.S1ReleasePending
			attachStep := ue.AttachStep
			currentGeneration := ue.S1BindingGeneration
			ue.Unlock()

			// attachStep alone can't distinguish "this resume is still
			// pending" from "a newer resume has since taken its place" —
			// both look identical (WaitingICSRespSR). A UE that reconnects
			// faster than this wait's timeout would otherwise cause this
			// stale goroutine to fire an ICS built from this resume's own
			// captured (and by now outdated) bearer snapshot on top of the
			// newer, current binding. The generation check closes that gap.
			if attachStep != uecontext.AttachStepWaitingICSRespSR || currentGeneration != expectedGeneration {
				log.Info("s1ap: resume ICS cancelled before release cleared",
					zap.Uint32("old_enb_ue_id", oldENBUEID),
					zap.Uint32("new_enb_ue_id", newENBUEID),
					zap.Uint8("attach_step", attachStep),
					zap.Uint64("expected_binding_generation", expectedGeneration),
					zap.Uint64("current_binding_generation", currentGeneration))
				return
			}
			if !stillPending {
				break
			}
			if time.Now().After(deadline) {
				log.Warn("s1ap: resume ICS proceeding after release wait timeout",
					zap.Uint32("old_enb_ue_id", oldENBUEID),
					zap.Uint32("new_enb_ue_id", newENBUEID),
					zap.Duration("timeout", serviceRequestReleaseWaitTimeout))
				break
			}
			<-ticker.C
		}
		send()
	}()
}

func sortedDedicatedBearerEBIsLocked(ue *uecontext.Context) []uint8 {
	out := make([]uint8, 0, len(ue.DedicatedBearers))
	for ebi := range ue.DedicatedBearers {
		out = append(out, ebi)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedPDNContextsLocked(ue *uecontext.Context) []*uecontext.PDNContext {
	out := make([]*uecontext.PDNContext, 0, len(ue.PDNs))
	keys := make([]string, 0, len(ue.PDNs))
	for apn := range ue.PDNs {
		keys = append(keys, apn)
	}
	sort.Strings(keys)
	for _, apn := range keys {
		out = append(out, ue.PDNs[apn])
	}
	return out
}

func subscriberAPNConfigForResumeLocked(ue *uecontext.Context, apn string) (uecontext.SubscriberAPNConfig, bool) {
	if ue.SubscriberAPNConfigs == nil {
		return uecontext.SubscriberAPNConfig{}, false
	}
	if cfg, ok := ue.SubscriberAPNConfigs[apn]; ok {
		return cfg, true
	}
	for candidateAPN, cfg := range ue.SubscriberAPNConfigs {
		if strings.EqualFold(candidateAPN, apn) {
			return cfg, true
		}
	}
	return uecontext.SubscriberAPNConfig{}, false
}

func serviceRequestKSI(d *emm.ServiceRequestMACDetails) uint8 {
	if d == nil {
		return 0
	}
	return d.KSI
}

func serviceRequestSequenceNumber(d *emm.ServiceRequestMACDetails) uint8 {
	if d == nil {
		return 0
	}
	return d.SequenceNumber
}

func serviceRequestOverflow(d *emm.ServiceRequestMACDetails) uint32 {
	if d == nil {
		return 0
	}
	return d.Overflow
}

func serviceRequestBearer(d *emm.ServiceRequestMACDetails) uint8 {
	if d == nil {
		return 0
	}
	return d.Bearer
}

func serviceRequestDirection(d *emm.ServiceRequestMACDetails) uint8 {
	if d == nil {
		return 0
	}
	return d.Direction
}

func serviceRequestMACInputHex(d *emm.ServiceRequestMACDetails) string {
	if d == nil {
		return ""
	}
	return hex.EncodeToString(d.MessageForMAC)
}

func serviceRequestComputedMACHex(d *emm.ServiceRequestMACDetails) string {
	if d == nil {
		return ""
	}
	return hex.EncodeToString(d.ComputedMAC)
}

func serviceRequestComputedShortMACHex(d *emm.ServiceRequestMACDetails) string {
	if d == nil {
		return ""
	}
	return hex.EncodeToString(d.ComputedShortMAC)
}

func isServiceRequestResumeStep(step uint8) bool {
	return step == uecontext.AttachStepWaitingICSRespSR
}

func isTAUActiveResumeStep(step uint8) bool {
	return step == uecontext.AttachStepWaitingICSRespTAU
}

func isResumeICSAttachStep(step uint8) bool {
	return isServiceRequestResumeStep(step) || isTAUActiveResumeStep(step)
}

func serviceRequestExpectedShortMACHex(d *emm.ServiceRequestMACDetails) string {
	if d == nil {
		return ""
	}
	return hex.EncodeToString(d.ExpectedShortMAC)
}

// handleServiceRequestReestablished is called from handleInitialContextSetupResponse
// when the ICS was triggered by a Service Request (attachStep == WaitingICSRespSR).
// It sends a Modify Bearer Request and persists the updated UE context.
func (s *Server) handleServiceRequestReestablished(ue *uecontext.Context, log *zap.Logger) {
	ue.Lock()
	ue.SetEMMState(emm.StateRegistered)
	ue.AttachStep = uecontext.AttachStepNone
	wasPaging := ue.PagingAttempts > 0
	ue.PagingAttempts = 0

	mmeUEID := ue.MMEUES1APID
	imsi := ue.IMSI
	mbrGroups := serviceRequestMBRGroupsLocked(ue)

	ue.Unlock()

	metrics.NASProceduresTotal.WithLabelValues("ServiceRequest", "accept").Inc()
	if wasPaging {
		metrics.PagingTotal.WithLabelValues("success").Inc()
	}
	log.Info("s1ap: Service Request re-established", zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi))
	s.noteDDNResumeInProgress(ue)
	s.logPostICSDebugWindow(ue, "service_request_reestablished")

	s.persistUERecoverySnapshot(ue, models.RecoveryStateRecovered, "ESTABLISHED")
	s.ResumePendingNetworkBearerProcedures(ue)
	s.deliverPendingMTSMS(ue)
	s.deliverPendingSGsMT(ue)
	// Fallback completion for an SGs paging cycle answered by a plain
	// Service Request rather than an MT CSFB Extended Service Request (e.g.
	// paging for an SMS-indicator, not a CS call). completeSGsPaging is a
	// no-op if processExtendedServiceRequest already completed it.
	s.completeSGsPaging(ue)

	for _, group := range mbrGroups {
		if group.sgwcTEID == 0 || len(group.bearers) == 0 {
			continue
		}
		mbr := &gtpv2.ModifyBearerRequest{
			SGWAddress: group.sgwAddr,
			SGWC_TEID:  group.sgwcTEID,
			Bearers:    append([]gtpv2.ModifyBearer(nil), group.bearers...),
			RATType:    gtpv2.RATTypeEUTRAN,
		}
		if err := s.s11.SendMBR(mmeUEID, mbr); err != nil {
			s.log.Warn("s1ap: ServiceRequest: SendMBR failed", zap.Error(err))
		}
	}
}

func (s *Server) handleActiveTAUReestablished(ue *uecontext.Context, log *zap.Logger) {
	ue.Lock()
	ue.SetEMMState(emm.StateRegistered)
	ue.AttachStep = uecontext.AttachStepNone

	mmeUEID := ue.MMEUES1APID
	imsi := ue.IMSI
	mbrGroups := serviceRequestMBRGroupsLocked(ue)

	ue.Unlock()

	log.Info("s1ap: Active-flag TAU access re-established", zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi))
	s.logPostICSDebugWindow(ue, "tau_active_reestablished")

	for _, group := range mbrGroups {
		if group.sgwcTEID == 0 || len(group.bearers) == 0 {
			continue
		}
		mbr := &gtpv2.ModifyBearerRequest{
			SGWAddress: group.sgwAddr,
			SGWC_TEID:  group.sgwcTEID,
			Bearers:    append([]gtpv2.ModifyBearer(nil), group.bearers...),
			RATType:    gtpv2.RATTypeEUTRAN,
		}
		if err := s.s11.SendMBR(mmeUEID, mbr); err != nil {
			s.log.Warn("s1ap: ActiveTAU: SendMBR failed", zap.Error(err))
		}
	}
}

// sendServiceReject sends a plain NAS Service Reject via Downlink NAS Transport.
func (s *Server) sendServiceReject(mmeUEID, enbUEID uint32, enbAddr string, cause uint8) {
	reject := emm.EncodeServiceReject(cause)
	s.log.Info("s1ap: Service Reject sent",
		zap.Uint32("route_mme_ue_id", mmeUEID),
		zap.Uint32("route_enb_ue_id", enbUEID),
		zap.Uint8("emm_message_type", reject[1]),
		zap.Uint8("emm_cause", cause))
	s.sendDownlinkNASTransport(enbAddr, mmeUEID, enbUEID, reject)
}

// sendProtectedServiceRejectForUE completes an ESR using the authoritative
// UE NAS security context while allowing InitialUE ESR to route over its
// temporary S1 context. Reserving the DL COUNT under the UE lock prevents a
// concurrent ESM activation from reusing the Service Reject sequence number.
func (s *Server) sendProtectedServiceRejectForUE(ue *uecontext.Context, routeMMEID, routeENBID uint32, routeENBAddr string, cause uint8, name string) error {
	plain := emm.EncodeServiceReject(cause)
	ue.Lock()
	dlCount := uint32(ue.DLNASCount)
	protected, err := nas.EncodeIntegrityAndCiphered(plain, ue.IntAlg, ue.EncAlg, ue.KNASint, ue.KNASenc, dlCount)
	if err == nil {
		ue.DLNASCount.Increment()
		ue.LastDownlinkNASMessage = name
	}
	ue.Unlock()
	if err != nil {
		return fmt.Errorf("protect Service Reject: %w", err)
	}
	if err := s.sendDownlinkNASTransport(routeENBAddr, routeMMEID, routeENBID, protected); err != nil {
		return fmt.Errorf("send Service Reject: %w", err)
	}
	s.log.Info("s1ap: protected Service Reject sent",
		zap.Uint32("route_mme_ue_id", routeMMEID),
		zap.Uint32("route_enb_ue_id", routeENBID),
		zap.Uint8("emm_message_type", plain[1]),
		zap.Uint8("emm_cause", cause),
		zap.Uint32("dl_nas_count", dlCount),
		zap.String("message", name))
	return nil
}
