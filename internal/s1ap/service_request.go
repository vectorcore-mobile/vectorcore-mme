package s1ap

import (
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/gtpv2"
	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/models"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/security"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/uecontext"
)

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
	realMmeUEID := realUE.MMEUES1APID
	imsi := realUE.IMSI
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
		zap.Bool("s1_release_pending", releasePending),
		zap.Uint32("s1_release_enb_ue_id", releaseENBID))

	// Validate UE state.
	if emmState != emm.StateRegistered {
		log.Warn("s1ap: ServiceRequest: UE not in Registered state", zap.Stringer("state", emmState))
		reject(emm.CauseImplicitlyDetached)
		return
	}
	if ecmState != emm.ECMIdle {
		log.Warn("s1ap: ServiceRequest: UE already ECM-Connected")
		reject(emm.CauseUEIdentityCannotBeDerived)
		return
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

	// Transfer S1AP context from tempUE to the real UE.
	realUE.Lock()
	realUE.StopTimer(uecontext.TimerT3413)
	// PagingAttempts is NOT cleared here — handleServiceRequestReestablished reads it
	// to increment the paging-success metric, then clears it.
	realUE.ENBS1APID = enbUEID
	realUE.ENBGlobalID = enbAddr
	realUE.S1BindingGeneration++
	realUE.S1BindingState = uecontext.S1BindingActive
	realUE.S1ReleasePending = false
	if tai != nil {
		plmnBytes, _ := ies.EncodePLMN(tai.MCC, tai.MNC)
		t := emm.TAI{TAC: tai.TAC}
		if len(plmnBytes) == 3 {
			copy(t.PLMN[:], plmnBytes)
		}
		realUE.TAI = &t
	}
	realUE.ULNASCount = security.NASCount(reconstructedCount)
	realUE.SetEMMState(emm.StateServiceRequestInitiated)
	realUE.AttachStep = uecontext.AttachStepWaitingICSRespSR
	realUE.Unlock()

	// Remove the temporary UE — its only purpose was to carry the S1AP IDs.
	s.ueManager.Remove(tempUE)

	metrics.NASProceduresTotal.WithLabelValues("ServiceRequest", "attempt").Inc()
	log.Info("s1ap: Service Request accepted, sending ICS resume",
		zap.Uint8("ebi", defaultEBI),
		zap.Uint32("sgw_s1u_teid", sgwUTEID),
		zap.String("sgw_s1u_teid_hex", fmt.Sprintf("0x%08x", sgwUTEID)),
		zap.String("sgw_s1u_ipv4", sgwUIP.String()),
		zap.Bool("s1_release_pending", releasePending))

	sendResumeICS := func() {
		if err := s.SendInitialContextSetup(realMmeUEID, nil, &BearerInfo{
			EBI:       defaultEBI,
			SGWU_TEID: sgwUTEID,
			SGWU_IP:   sgwUIP.To4(),
		}); err != nil {
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
	// If the previous UE Context Release is still pending, defer slightly so
	// srsENB can finish cleaning up the old RRC/E-RAB context before resume ICS.
	if releasePending {
		log.Info("s1ap: ServiceRequest resume ICS delayed pending UE Context Release Complete",
			zap.Uint32("old_enb_ue_id", releaseENBID),
			zap.Uint32("new_enb_ue_id", enbUEID),
			zap.Duration("delay", 150*time.Millisecond))
		go func() {
			time.Sleep(150 * time.Millisecond)
			sendResumeICS()
		}()
		return
	}
	sendResumeICS()
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

	mbrSGWCTEID := ue.SGWC_TEID
	mbrSGWAddr := ue.SGWAddress
	mbrEBI := ue.DefaultEBI
	mbrENBUTEID := ue.ENBU_TEID
	mbrENBUIP := append(net.IP(nil), ue.ENBU_IP...)

	ue.Unlock()

	metrics.NASProceduresTotal.WithLabelValues("ServiceRequest", "accept").Inc()
	if wasPaging {
		metrics.PagingTotal.WithLabelValues("success").Inc()
	}
	log.Info("s1ap: Service Request re-established", zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi))

	s.persistUERecoverySnapshot(ue, models.RecoveryStateRecovered, "ESTABLISHED")
	s.ResumePendingNetworkBearerProcedures(ue)

	if mbrSGWCTEID != 0 && mbrEBI != 0 && mbrENBUTEID != 0 {
		mbr := &gtpv2.ModifyBearerRequest{
			SGWAddress: mbrSGWAddr,
			SGWC_TEID:  mbrSGWCTEID,
			EBI:        mbrEBI,
			ENBU_TEID:  mbrENBUTEID,
			ENBU_IP:    mbrENBUIP,
			RATType:    gtpv2.RATTypeEUTRAN,
		}
		go func() {
			if err := s.s11.SendMBR(mmeUEID, mbr); err != nil {
				s.log.Warn("s1ap: ServiceRequest: SendMBR failed", zap.Error(err))
			}
		}()
	}
}

// sendServiceReject sends a plain NAS Service Reject via Downlink NAS Transport.
func (s *Server) sendServiceReject(mmeUEID, enbUEID uint32, enbAddr string, cause uint8) {
	reject := emm.EncodeServiceReject(cause)
	s.sendDownlinkNASTransport(enbAddr, mmeUEID, enbUEID, reject)
}
