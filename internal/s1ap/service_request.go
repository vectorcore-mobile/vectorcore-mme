package s1ap

import (
	"context"
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
	mmec uint8, mtmsi uint32, stmsiPresent bool,
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
	)

	reject := func(cause uint8) {
		s.sendServiceReject(tempMmeUEID, enbUEID, enbAddr, cause)
		s.ueManager.Remove(tempUE)
		metrics.NASProceduresTotal.WithLabelValues("ServiceRequest", "reject").Inc()
	}

	if !stmsiPresent {
		log.Warn("s1ap: ServiceRequest: no S-TMSI in Initial UE Message")
		reject(emm.CauseImplicitlyDetached)
		return
	}

	// Construct GUTI from S-TMSI + our own PLMN + MMEGI.
	plmn, err := ies.EncodePLMN(s.nfCfg.MCC, s.nfCfg.MNC)
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
			zap.Uint8("mmec", mmec), zap.Uint32("mtmsi", mtmsi))
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
	realMmeUEID := realUE.MMEUES1APID
	realUE.Unlock()

	log = log.With(zap.Uint32("mme_ue_id", realMmeUEID))

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
	ok, reconstructedCount := emm.VerifyShortMAC(nasPDU, intAlg, knasInt, ulCount)
	if !ok {
		log.Warn("s1ap: ServiceRequest: short MAC verification failed")
		reject(emm.CauseUEIdentityCannotBeDerived)
		return
	}

	// Transfer S1AP context from tempUE to the real UE.
	realUE.Lock()
	realUE.StopTimer(uecontext.TimerT3413)
	// PagingAttempts is NOT cleared here — handleServiceRequestReestablished reads it
	// to increment the paging-success metric, then clears it.
	realUE.ENBS1APID = enbUEID
	realUE.ENBGlobalID = enbAddr
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
	log.Info("s1ap: Service Request accepted, sending ICS")

	// Send ICS Request with the existing default bearer.  No NAS PDU for Service Request.
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
	}
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
	mbrEBI := ue.DefaultEBI
	mbrENBUTEID := ue.ENBU_TEID
	mbrENBUIP := append(net.IP(nil), ue.ENBU_IP...)

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
		g := uecontext.SerialiseGUTI(ue.GUTI)
		dbCtx.GUTI = &g
	}
	if ue.TAI != nil {
		dbCtx.TAI = fmt.Sprintf("%02X%02X%02X-%04X",
			ue.TAI.PLMN[0], ue.TAI.PLMN[1], ue.TAI.PLMN[2], ue.TAI.TAC)
	}
	ue.Unlock()

	metrics.NASProceduresTotal.WithLabelValues("ServiceRequest", "accept").Inc()
	if wasPaging {
		metrics.PagingTotal.WithLabelValues("success").Inc()
	}
	log.Info("s1ap: Service Request re-established", zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi))

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.store.UpsertUEContext(ctx, dbCtx); err != nil {
			s.log.Warn("s1ap: ServiceRequest: failed to persist UE context", zap.Error(err))
		}
	}()

	if mbrSGWCTEID != 0 && mbrEBI != 0 && mbrENBUTEID != 0 {
		mbr := &gtpv2.ModifyBearerRequest{
			SGWC_TEID: mbrSGWCTEID,
			EBI:       mbrEBI,
			ENBU_TEID: mbrENBUTEID,
			ENBU_IP:   mbrENBUIP,
			RATType:   gtpv2.RATTypeEUTRAN,
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
