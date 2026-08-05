package s1ap

import (
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/metrics"
	nas "github.com/vectorcore/mme/internal/nas"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/sgsap"
	"github.com/vectorcore/mme/internal/uecontext"
)

// decodeNASPLMN decodes a PLMN in NAS TBCD digit order (the order ue.TAI.PLMN
// and every other NAS-layer PLMN in this MME is stored in - see
// security.EncodePLMN, the encoder for this same order). This is
// deliberately distinct from internal/s1ap/ies.DecodePLMN, which models one
// specific eNB vendor's different S1AP-wire byte order (see the comment on
// pagingS1APPLMN) and must never be used on a NAS-order PLMN like this one.
func decodeNASPLMN(plmn [3]byte) (mcc, mnc string, err error) {
	d1, d2 := plmn[0]&0x0f, plmn[0]>>4
	d3, d4 := plmn[1]&0x0f, plmn[1]>>4
	d5, d6 := plmn[2]&0x0f, plmn[2]>>4
	valid := func(d byte) bool { return d <= 9 }
	if !valid(d1) || !valid(d2) || !valid(d3) || !valid(d5) || !valid(d6) || (d4 != 0x0f && !valid(d4)) {
		return "", "", fmt.Errorf("s1ap: invalid NAS PLMN digit encoding %02x%02x%02x", plmn[0], plmn[1], plmn[2])
	}
	mcc = fmt.Sprintf("%d%d%d", d1, d2, d3)
	if d4 == 0x0f {
		mnc = fmt.Sprintf("%d%d", d5, d6)
	} else {
		mnc = fmt.Sprintf("%d%d%d", d5, d6, d4)
	}
	return mcc, mnc, nil
}

// MMEFQDNForSGs derives the canonical MME FQDN (TS 23.003 §19.4.2.1) used as
// the MME name IE in SGsAP Location Update Request / Reset Indication /
// detach indications. It is independent of nf.mme_name, which is a
// free-text S1AP display string rather than this canonical DNS-label
// identity, and matches the FQDN convention open5gs builds from the same
// MMEC/MMEGI/MCC/MNC fields.
func (s *Server) MMEFQDNForSGs() string {
	mnc := s.nfCfg.MNC
	if len(mnc) == 2 {
		mnc = "0" + mnc
	}
	return fmt.Sprintf("mmec%02d.mmegi%04d.mme.epc.mnc%s.mcc%s.3gppnetwork.org",
		s.nfCfg.MMEC, s.nfCfg.MMEGI, mnc, s.nfCfg.MCC)
}

// maybeSendSGsLocationUpdateRequest fires the SGs Location Update
// asynchronously after the EPS attach/TAU procedure has already completed
// (Attach/TAU Accept already sent). It never blocks or affects the EPS
// outcome: a rejection or timeout only ever leaves the UE's SGs state at
// SGsUENull, recorded via HandleLocationUpdateReject/the request timeout,
// for the UE's next combined TAU to retry (see attachAcceptRegistration and
// tauAcceptResultForRequest, which report a genuine combined result with a
// real LAI only once this succeeds).
func (s *Server) maybeSendSGsLocationUpdateRequest(ue *uecontext.Context, combinedRequested, smsOnlyRequested bool, updateType sgsap.EPSLocationUpdateType) {
	if !s.sgsCfg.Enabled || (!combinedRequested && !smsOnlyRequested) {
		return
	}
	ue.Lock()
	imsi := ue.IMSI
	tai := ue.TAI
	imeisv := ue.IMEISV
	notIdle := ue.SGsState == uecontext.SGsUEAssociated || ue.SGsState == uecontext.SGsUELAUpdateRequested
	mmeUEID := ue.MMEUES1APID
	ue.Unlock()
	if imsi == "" || tai == nil || notIdle {
		return
	}

	mcc, mnc, err := decodeNASPLMN(tai.PLMN)
	if err != nil {
		s.log.Warn("sgs: cannot derive PLMN for Location Update", zap.Uint32("mme_ue_id", mmeUEID), zap.Error(err))
		return
	}
	mapping, ok := s.vlr.LookupVLR(mcc, mnc, tai.TAC)
	if !ok {
		s.log.Debug("sgs: no VLR mapped for TAI, skipping Location Update",
			zap.Uint32("mme_ue_id", mmeUEID), zap.String("mcc", mcc), zap.String("mnc", mnc), zap.Uint16("tac", tai.TAC))
		return
	}
	if !s.vlr.Available(mapping.VLR) {
		s.log.Debug("sgs: VLR association not yet up, skipping Location Update",
			zap.Uint32("mme_ue_id", mmeUEID), zap.String("vlr_name", mapping.VLR))
		return
	}

	laiPLMN, err := sgsap.EncodePLMN(mapping.LAI.MCC, mapping.LAI.MNC)
	if err != nil {
		s.log.Warn("sgs: invalid configured LAI PLMN", zap.String("vlr_name", mapping.VLR), zap.Error(err))
		return
	}
	req := sgsap.LocationUpdateRequest{
		IMSI:       imsi,
		MMEName:    s.MMEFQDNForSGs(),
		UpdateType: updateType,
		NewLAI:     sgsap.LAI{PLMN: laiPLMN, LAC: mapping.LAI.LAC},
		TAI:        &sgsap.TAI{PLMN: tai.PLMN, TAC: tai.TAC},
	}
	if imeisv != "" {
		req.IMEISV = imeisv
	}

	ue.Lock()
	ue.SGsState = uecontext.SGsUELAUpdateRequested
	ue.SGsVLRName = mapping.VLR
	ue.Unlock()

	if err := s.vlr.SendLocationUpdateRequest(mapping.VLR, req); err != nil {
		s.log.Warn("sgs: Location Update Request failed to send", zap.Uint32("mme_ue_id", mmeUEID), zap.String("vlr_name", mapping.VLR), zap.Error(err))
		ue.Lock()
		ue.SGsState = uecontext.SGsUENull
		ue.Unlock()
		return
	}
	metrics.SGsLocationUpdateRequestsTotal.WithLabelValues("sent").Inc()
	s.log.Info("sgs: Location Update Request sent", zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi), zap.String("vlr_name", mapping.VLR))

	timeout := s.sgsCfg.RequestTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	time.AfterFunc(timeout, func() { s.expireSGsLocationUpdate(mmeUEID, mapping.VLR) })
}

// expireSGsLocationUpdate reverts a UE to SGs-NULL if no Location Update
// Accept/Reject arrived within the configured timeout. It never touches EMM
// or ECM state - the EPS attach/TAU this LU rode in on already completed.
func (s *Server) expireSGsLocationUpdate(mmeUEID uint32, vlrName string) {
	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		return
	}
	ue.Lock()
	if ue.SGsState != uecontext.SGsUELAUpdateRequested || ue.SGsVLRName != vlrName {
		ue.Unlock()
		return
	}
	ue.SGsState = uecontext.SGsUENull
	ue.SGsRejectCause = 0
	ue.SGsRejectAt = time.Now().UTC()
	imsi := ue.IMSI
	ue.Unlock()
	metrics.SGsLocationUpdateRequestsTotal.WithLabelValues("timeout").Inc()
	s.log.Warn("sgs: Location Update timed out", zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi), zap.String("vlr_name", vlrName))
}

// sendSGsDetachIndicationForUE sends the SGsAP EPS or IMSI Detach
// Indication matching a UE-initiated NAS Detach Request's detach type (TS
// 29.118 §5.4.2.1/§5.5.2.1), then immediately reverts the UE's SGs
// association to SGs-NULL - both procedures require this "after sending"
// regardless of any acknowledgement, and this MME does not implement the
// Ts8/Ns8/Ts9/Ns9 retransmission timers. Returns true only if an IMSI (or
// combined EPS/IMSI) Detach Indication was sent successfully, telling the
// caller it must hold the Detach Accept for SGsAP-IMSI-DETACH-ACK per
// §5.5.2.2.
func (s *Server) sendSGsDetachIndicationForUE(ue *uecontext.Context, vlrName, imsi string, detachType uint8, log *zap.Logger) (sentIMSIDetach bool) {
	mmeName := s.MMEFQDNForSGs()
	switch detachType {
	case emm.DetachTypeNormal:
		if err := s.vlr.SendEPSDetachIndication(vlrName, sgsap.EPSDetachIndication{
			IMSI: imsi, MMEName: mmeName, DetachType: sgsap.EPSDetachUEInitiated,
		}); err != nil {
			log.Warn("sgs: failed to send EPS-DETACH-INDICATION", zap.String("imsi", imsi), zap.String("vlr_name", vlrName), zap.Error(err))
		}
	case emm.DetachTypeIMSIDetach:
		if err := s.vlr.SendIMSIDetachIndication(vlrName, sgsap.IMSIDetachIndication{
			IMSI: imsi, MMEName: mmeName, DetachType: sgsap.NonEPSDetachExplicitUEInitiated,
		}); err != nil {
			log.Warn("sgs: failed to send IMSI-DETACH-INDICATION", zap.String("imsi", imsi), zap.String("vlr_name", vlrName), zap.Error(err))
		} else {
			sentIMSIDetach = true
		}
	case emm.DetachTypeEPSAndIMSI:
		if err := s.vlr.SendIMSIDetachIndication(vlrName, sgsap.IMSIDetachIndication{
			IMSI: imsi, MMEName: mmeName, DetachType: sgsap.NonEPSDetachCombinedUEInitiated,
		}); err != nil {
			log.Warn("sgs: failed to send IMSI-DETACH-INDICATION", zap.String("imsi", imsi), zap.String("vlr_name", vlrName), zap.Error(err))
		} else {
			sentIMSIDetach = true
		}
	default:
		return false
	}

	ue.Lock()
	ue.SGsState = uecontext.SGsUENull
	ue.SGsVLRName = ""
	ue.SGsLAI = nil
	ue.Unlock()
	return sentIMSIDetach
}

// deferDetachAcceptForIMSIDetachAck holds an already-encoded Detach Accept
// back until SGsAP-IMSI-DETACH-ACK arrives (HandleIMSIDetachAck) or the SGs
// request timeout elapses, whichever comes first (TS 29.118 §5.5.2.2/
// §5.5.2.3(ii): if no ack arrives, send the confirmation anyway).
func (s *Server) deferDetachAcceptForIMSIDetachAck(ue *uecontext.Context, mmeUEID, enbUEID uint32, enbAddr string, payload []byte, log *zap.Logger) {
	ue.Lock()
	ue.SGsPendingDetachAccept = &uecontext.SGsPendingDetachAccept{
		MMEUEID: mmeUEID, ENBUEID: enbUEID, ENBAddr: enbAddr, Payload: payload,
	}
	ue.Unlock()

	timeout := s.sgsCfg.RequestTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	time.AfterFunc(timeout, func() { s.completeDeferredDetach(mmeUEID, "timeout", log) })
}

// completeDeferredDetach sends a withheld Detach Accept and releases the S1
// context. A no-op if nothing is pending (already completed by the other of
// the ack/timeout race).
func (s *Server) completeDeferredDetach(mmeUEID uint32, reason string, log *zap.Logger) {
	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		return
	}
	ue.Lock()
	pending := ue.SGsPendingDetachAccept
	ue.SGsPendingDetachAccept = nil
	ue.Unlock()
	if pending == nil {
		return
	}
	s.sendDownlinkNASTransport(pending.ENBAddr, pending.MMEUEID, pending.ENBUEID, pending.Payload)
	ue.Lock()
	ue.DLNASCount.Increment()
	ue.Unlock()
	log.Info("s1ap: Detach Accept sent (deferred SGsAP-IMSI-DETACH-ACK wait completed)",
		zap.Uint32("mme_ue_id", mmeUEID), zap.String("reason", reason))
	s.sendUEContextReleaseCommand(pending.ENBAddr, pending.MMEUEID, pending.ENBUEID)
}

// --- vlr.Handler implementation ---
//
// vlr.Manager depends on this interface structurally (Go interfaces are
// implicit); *Server is passed as the handler in cmd/mme/main.go, avoiding a
// direct import of internal/vlr from this package.

func (s *Server) HandleLocationUpdateAccept(vlrName string, a *sgsap.LocationUpdateAccept) {
	if a == nil {
		return
	}
	ue, ok := s.ueManager.GetByIMSI(a.IMSI)
	if !ok {
		s.log.Warn("sgs: LOCATION-UPDATE-ACCEPT for unknown IMSI", zap.String("vlr_name", vlrName))
		return
	}
	lai := a.LAI
	ue.Lock()
	ue.SGsState = uecontext.SGsUEAssociated
	ue.SGsVLRName = vlrName
	ue.SGsLAI = &lai
	ue.SGsAssociatedAt = time.Now().UTC()
	// TS 29.118 §5.2.2.3: a new TMSI in the Mobile identity IE means the UE
	// must perform a TMSI reallocation; relay it via the next Attach/TAU
	// Accept (attachAcceptRegistration/tauAcceptResultForRequest), which is
	// also when this UE's next real LAI first becomes available (see
	// maybeSendSGsLocationUpdateRequest). An IMSI in that IE instead (TMSI
	// deallocation) needs no NAS relay or SGsAP completion message, so it is
	// intentionally not modeled here, matching open5gs's own scope.
	if a.NewIdentity != nil && a.NewIdentity.Kind == sgsap.MobileIdentityTMSI {
		tmsi := a.NewIdentity.TMSI
		ue.SGsPendingNewTMSI = &tmsi
	}
	mmeUEID := ue.MMEUES1APID
	ue.Unlock()
	metrics.SGsLocationUpdateRequestsTotal.WithLabelValues("accepted").Inc()
	s.log.Info("sgs: Location Update accepted", zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", a.IMSI), zap.String("vlr_name", vlrName))
}

// completeSGsTMSIReallocation sends SGsAP-TMSI-REALLOCATION-COMPLETE for a
// TMSI just confirmed delivered to the UE (TS 29.118 §5.2.2.3: "when the
// MME receives the ATTACH COMPLETE or the TRACKING AREA UPDATE COMPLETE
// message"), and clears the pending state. A no-op if nothing is pending.
func (s *Server) completeSGsTMSIReallocation(ue *uecontext.Context) {
	ue.Lock()
	pending := ue.SGsSentNewTMSI
	ue.SGsSentNewTMSI = nil
	vlrName := ue.SGsVLRName
	imsi := ue.IMSI
	mmeUEID := ue.MMEUES1APID
	ue.Unlock()
	if pending == nil {
		return
	}
	if err := s.vlr.SendTMSIReallocationComplete(vlrName, imsi); err != nil {
		s.log.Warn("sgs: failed to send TMSI-REALLOCATION-COMPLETE",
			zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi), zap.String("vlr_name", vlrName), zap.Error(err))
		return
	}
	s.log.Info("sgs: TMSI-REALLOCATION-COMPLETE sent",
		zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi), zap.String("vlr_name", vlrName))
}

func (s *Server) HandleLocationUpdateReject(vlrName string, r *sgsap.LocationUpdateReject) {
	if r == nil {
		return
	}
	ue, ok := s.ueManager.GetByIMSI(r.IMSI)
	if !ok {
		s.log.Warn("sgs: LOCATION-UPDATE-REJECT for unknown IMSI", zap.String("vlr_name", vlrName))
		return
	}
	ue.Lock()
	ue.SGsState = uecontext.SGsUENull
	ue.SGsRejectCause = r.Cause
	ue.SGsRejectAt = time.Now().UTC()
	mmeUEID := ue.MMEUES1APID
	ue.Unlock()
	metrics.SGsLocationUpdateRequestsTotal.WithLabelValues("rejected").Inc()
	s.log.Warn("sgs: Location Update rejected", zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", r.IMSI), zap.String("vlr_name", vlrName), zap.Uint8("cause", r.Cause))
}

// HandlePagingRequest implements the MME side of TS 29.118 §5.1.3: if a NAS
// signalling connection already exists, the SGsAP-SERVICE-REQUEST answer is
// sent immediately (§5.1.3.3); otherwise the UE is paged with CN Domain=CS
// (§5.1.3.2) and the answer is sent once completeSGsPaging runs, from
// either the plain Service Request path (service_request.go) or a mobile
// terminating CS Fallback Extended Service Request (attach.go).
func (s *Server) HandlePagingRequest(vlrName string, r *sgsap.PagingRequest) {
	if r == nil {
		return
	}
	ue, ok := s.ueManager.GetByIMSI(r.IMSI)
	if !ok {
		s.log.Warn("sgs: PAGING-REQUEST for unknown IMSI", zap.String("vlr_name", vlrName), zap.String("imsi", r.IMSI))
		if err := s.vlr.SendPagingReject(vlrName, r.IMSI, sgsap.CauseIMSIUnknown); err != nil {
			s.log.Warn("sgs: failed to send PAGING-REJECT", zap.String("imsi", r.IMSI), zap.Error(err))
		}
		return
	}

	ue.Lock()
	connected := ue.ECMState == emm.ECMConnected
	ue.SGsPendingPaging = &uecontext.SGsPagingContext{
		VLRName:          vlrName,
		ServiceIndicator: uint8(r.ServiceIndicator),
		StartedAt:        time.Now().UTC(),
	}
	mmeUEID := ue.MMEUES1APID
	ue.Unlock()

	if connected {
		s.completeSGsPaging(ue)
		return
	}

	if err := s.PageUEForCSFB(r.IMSI); err != nil {
		ue.Lock()
		ue.SGsPendingPaging = nil
		ue.Unlock()
		s.log.Warn("sgs: CSFB paging failed", zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", r.IMSI), zap.Error(err))
		if sendErr := s.vlr.SendPagingReject(vlrName, r.IMSI, sgsap.CauseUEUnreachable); sendErr != nil {
			s.log.Warn("sgs: failed to send PAGING-REJECT", zap.String("imsi", r.IMSI), zap.Error(sendErr))
		}
		return
	}
	s.log.Info("sgs: CSFB paging started", zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", r.IMSI),
		zap.Uint8("service_indicator", uint8(r.ServiceIndicator)))
}

// completeSGsPaging sends SGsAP-SERVICE-REQUEST to the VLR once a NAS
// signalling connection exists for a UE with an outstanding SGs paging
// request, and clears the pending state. A no-op if nothing is pending.
func (s *Server) completeSGsPaging(ue *uecontext.Context) {
	ue.Lock()
	pending := ue.SGsPendingPaging
	ue.SGsPendingPaging = nil
	ue.PagingAttempts = 0
	imsi := ue.IMSI
	imeisv := ue.IMEISV
	tai := ue.TAI
	mmeUEID := ue.MMEUES1APID
	ue.Unlock()
	if pending == nil {
		return
	}

	req := sgsap.ServiceRequest{
		IMSI:             imsi,
		ServiceIndicator: sgsap.ServiceIndicator(pending.ServiceIndicator),
		UEEMMMode:        sgsap.UEEMMModeConnected,
		TAI:              tai,
	}
	if imeisv != "" {
		req.IMEISV = imeisv
	}
	if err := s.vlr.SendServiceRequest(pending.VLRName, req); err != nil {
		s.log.Warn("sgs: failed to send SERVICE-REQUEST to VLR",
			zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi), zap.String("vlr_name", pending.VLRName), zap.Error(err))
		return
	}
	s.log.Info("sgs: SERVICE-REQUEST sent to VLR",
		zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi), zap.String("vlr_name", pending.VLRName))
}

// handleMOCSFBExtendedServiceRequest implements the UE-initiated half of TS
// 29.118's CS Fallback support (§5.2.1): a UE with an established SGs
// association that requests mobile originating CSFB gets a
// SGsAP-SERVICE-REQUEST (so the VLR treats the subscriber as reachable/using
// the CS domain, mirroring completeSGsPaging's MT-side send) followed by
// SGsAP-MO-CSFB-INDICATION (§8.25, informing the VLR this service request was
// for an MO CS call rather than a resumed MT one), then the S1AP CS Fallback
// Indicator via SendUEContextModificationForCSFB so the eNB redirects the UE
// to 2G/3G. Callers must already have confirmed s.sgsCfg is enabled,
// non-smsonly, and ue.SGsState is SGsUEAssociated.
func (s *Server) handleMOCSFBExtendedServiceRequest(ue *uecontext.Context, log *zap.Logger) {
	ue.Lock()
	imsi := ue.IMSI
	imeisv := ue.IMEISV
	tai := ue.TAI
	vlrName := ue.SGsVLRName
	mmeUEID := ue.MMEUES1APID
	ue.Unlock()

	req := sgsap.ServiceRequest{
		IMSI:             imsi,
		ServiceIndicator: sgsap.ServiceIndicatorCSCall,
		UEEMMMode:        sgsap.UEEMMModeConnected,
		TAI:              tai,
	}
	if imeisv != "" {
		req.IMEISV = imeisv
	}
	if err := s.vlr.SendServiceRequest(vlrName, req); err != nil {
		log.Warn("sgs: failed to send SERVICE-REQUEST to VLR for MO CSFB",
			zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi), zap.String("vlr_name", vlrName), zap.Error(err))
		return
	}
	if err := s.vlr.SendMOCSFBIndication(vlrName, sgsap.MOCSFBIndication{IMSI: imsi, TAI: tai}); err != nil {
		log.Warn("sgs: failed to send MO-CSFB-INDICATION to VLR",
			zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi), zap.String("vlr_name", vlrName), zap.Error(err))
		return
	}
	log.Info("sgs: MO CSFB SERVICE-REQUEST/MO-CSFB-INDICATION sent to VLR",
		zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi), zap.String("vlr_name", vlrName))

	if err := s.SendUEContextModificationForCSFB(mmeUEID); err != nil {
		log.Warn("sgs: UE Context Modification (MO CSFB) send failed", zap.Uint32("mme_ue_id", mmeUEID), zap.Error(err))
	}
}

// reportSGsUEUnreachable notifies the VLR that a CSFB paging attempt timed
// out (TS 29.118 §5.1.2.5 / SGs cause "UE unreachable").
func (s *Server) reportSGsUEUnreachable(vlrName, imsi string) {
	if err := s.vlr.SendUEUnreachable(vlrName, sgsap.UEUnreachable{IMSI: imsi, Cause: sgsap.CauseUEUnreachable}); err != nil {
		s.log.Warn("sgs: failed to send UE-UNREACHABLE to VLR", zap.String("imsi", imsi), zap.String("vlr_name", vlrName), zap.Error(err))
	}
}

// HandleDownlinkUnitdata is implemented in sgs_sms.go, alongside the rest of
// the SMS-over-SGs relay.

// HandleEPSDetachAck acknowledges an SGsAP-EPS-DETACH-INDICATION (TS 29.118
// §5.4.2.2). Unlike the IMSI/combined case, an EPS-only detach never holds
// the Detach Accept back for this ack, so there is nothing further to
// complete - the MME does not implement the Ts8 retransmission timer this
// otherwise stops.
func (s *Server) HandleEPSDetachAck(vlrName string, imsi string) {
	s.log.Info("sgs: EPS-DETACH-ACK received", zap.String("vlr_name", vlrName), zap.String("imsi", imsi))
}

// HandleIMSIDetachAck completes a Detach Accept withheld by
// deferDetachAcceptForIMSIDetachAck (TS 29.118 §5.5.2.2).
func (s *Server) HandleIMSIDetachAck(vlrName string, imsi string) {
	ue, ok := s.ueManager.GetByIMSI(imsi)
	if !ok {
		s.log.Warn("sgs: IMSI-DETACH-ACK for unknown IMSI", zap.String("vlr_name", vlrName), zap.String("imsi", imsi))
		return
	}
	ue.Lock()
	mmeUEID := ue.MMEUES1APID
	ue.Unlock()
	s.completeDeferredDetach(mmeUEID, "ack", s.log)
}

// HandleReleaseRequest implements TS 29.118 §5.11.4: a cause of "IMSI
// unknown" or "IMSI detached for non-EPS services" means the VLR considers
// the SGs association gone, so the MME resets its own side to SGs-NULL
// (equivalent to clearing the "VLR-Reliable" MM context variable - the next
// combined TAU's maybeSendSGsLocationUpdateRequest will re-establish it, the
// same effective "request the UE to re-attach for non-EPS services" this
// section calls for). Any other cause just means the VLR has nothing more
// to tunnel right now; there is no MME-side resource to release for that.
func (s *Server) HandleReleaseRequest(vlrName string, imsi string, cause *sgsap.Cause) {
	ue, ok := s.ueManager.GetByIMSI(imsi)
	if !ok {
		s.log.Info("sgs: RELEASE-REQUEST for unknown IMSI", zap.String("vlr_name", vlrName), zap.String("imsi", imsi))
		return
	}
	if cause != nil && (*cause == sgsap.CauseIMSIUnknown || *cause == sgsap.CauseIMSIDetachedForNonEPS) {
		ue.Lock()
		ue.SGsState = uecontext.SGsUENull
		ue.SGsVLRName = ""
		ue.SGsLAI = nil
		ue.Unlock()
		s.log.Warn("sgs: RELEASE-REQUEST reset SGs association to SGs-NULL",
			zap.String("vlr_name", vlrName), zap.String("imsi", imsi), zap.Uint8("cause", uint8(*cause)))
		return
	}
	s.log.Info("sgs: RELEASE-REQUEST received", zap.String("vlr_name", vlrName), zap.String("imsi", imsi))
}

// HandleAlertRequest implements TS 29.118 §5.3.3.1/§5.3.3.2: acknowledge if
// the IMSI is known, otherwise reject with "IMSI unknown". NEAF-triggered
// SGsAP-UE-ACTIVITY-INDICATION (§5.3.3.3) is not implemented: it requires
// instrumenting every E-UTRAN signalling/data-activity detection point in
// this server to notice activity that does *not* already lead to some other
// SGs procedure, which is unrelated in scope to the rest of this handler.
func (s *Server) HandleAlertRequest(vlrName string, imsi string) {
	if _, ok := s.ueManager.GetByIMSI(imsi); !ok {
		s.log.Warn("sgs: ALERT-REQUEST for unknown IMSI", zap.String("vlr_name", vlrName), zap.String("imsi", imsi))
		if err := s.vlr.SendAlertReject(vlrName, imsi, sgsap.CauseIMSIUnknown); err != nil {
			s.log.Warn("sgs: failed to send ALERT-REJECT", zap.String("vlr_name", vlrName), zap.String("imsi", imsi), zap.Error(err))
		}
		return
	}
	if err := s.vlr.SendAlertAck(vlrName, imsi); err != nil {
		s.log.Warn("sgs: failed to send ALERT-ACK", zap.String("vlr_name", vlrName), zap.String("imsi", imsi), zap.Error(err))
		return
	}
	s.log.Info("sgs: ALERT-REQUEST acknowledged", zap.String("vlr_name", vlrName), zap.String("imsi", imsi))
}

// HandleMMInformationRequest relays a VLR-originated MM Information message
// to the UE. See relayMMInformationToUE for how the relay works.
func (s *Server) HandleMMInformationRequest(vlrName string, r *sgsap.MMInformationRequest) {
	if r == nil {
		return
	}
	ue, ok := s.ueManager.GetByIMSI(r.IMSI)
	if !ok {
		s.log.Warn("sgs: MM-INFORMATION-REQUEST for unknown IMSI", zap.String("vlr_name", vlrName), zap.String("imsi", r.IMSI))
		return
	}
	s.relayMMInformationToUE(ue, r.MMInformation)
}

// relayMMInformationToUE relays an SGsAP-MM-INFORMATION-REQUEST to the UE as
// an EMM INFORMATION NAS message (TS 24.301 §8.2.9/9.9.4). The TS 24.008 MM
// Information message's IEs (Full/Short Name for Network, Local Time Zone,
// Universal Time and Local Time Zone, Network Daylight Saving Time -
// TS 24.008 §10.5.3.5a/8/9/12) are the exact same IEs EMM Information reuses
// by reference at TS 24.301 §9.9.3.16/17/24/25/29, and internal/sgsap
// already stripped the SGsAP MM Information IE down to just this content
// (no 24.008 PD/skip/message-type octets) - so it can be relayed verbatim as
// the EMM Information message body, the same transparent-relay approach
// sgs_sms.go uses for SMS.
func (s *Server) relayMMInformationToUE(ue *uecontext.Context, mmInformation []byte) {
	ue.Lock()
	mmeUEID := ue.MMEUES1APID
	imsi := ue.IMSI
	enbUEID := ue.ENBS1APID
	enbAddr := ue.ENBGlobalID
	intAlg := ue.IntAlg
	encAlg := ue.EncAlg
	knasInt := append([]byte(nil), ue.KNASint...)
	knasEnc := append([]byte(nil), ue.KNASenc...)
	dlCount := uint32(ue.DLNASCount)
	ue.Unlock()
	if len(knasInt) == 0 {
		s.log.Warn("sgs: cannot relay MM Information, NAS security unavailable", zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi))
		return
	}

	body := append([]byte{emm.PDEPSMobilityMgmt | emm.SecurityHeaderPlain<<4, emm.MsgEMMInformation}, mmInformation...)
	wrapped, err := nas.EncodeIntegrityAndCiphered(body, intAlg, encAlg, knasInt, knasEnc, dlCount)
	if err != nil {
		s.log.Warn("sgs: MM Information encode failed", zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi), zap.Error(err))
		return
	}
	s.sendDownlinkNASTransport(enbAddr, mmeUEID, enbUEID, wrapped)
	ue.Lock()
	ue.DLNASCount.Increment()
	ue.Unlock()
	s.log.Info("sgs: MM Information relayed to UE", zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi))
}

// HandleServiceAbortRequest implements TS 29.118 §5.9: the VLR is
// withdrawing an in-progress CS Fallback paging attempt (for example, a call
// was cancelled before the UE responded). Abort our own paging cycle for it
// without reporting SGsAP-UE-UNREACHABLE - the VLR itself asked us to stop,
// this isn't a paging failure.
func (s *Server) HandleServiceAbortRequest(vlrName string, imsi string) {
	ue, ok := s.ueManager.GetByIMSI(imsi)
	if !ok {
		s.log.Warn("sgs: SERVICE-ABORT-REQUEST for unknown IMSI", zap.String("vlr_name", vlrName), zap.String("imsi", imsi))
		return
	}
	ue.Lock()
	hadPaging := ue.SGsPendingPaging != nil
	ue.SGsPendingPaging = nil
	ue.PagingAttempts = 0
	ue.StopTimer(uecontext.TimerT3413)
	ue.Unlock()
	s.log.Info("sgs: SERVICE-ABORT-REQUEST received, aborted pending CSFB paging",
		zap.String("vlr_name", vlrName), zap.String("imsi", imsi), zap.Bool("had_pending_paging", hadPaging))
}

func (s *Server) HandleStatus(vlrName string, st *sgsap.Status) {
	if st == nil {
		return
	}
	s.log.Warn("sgs: STATUS received from VLR", zap.String("vlr_name", vlrName), zap.String("imsi", st.IMSI), zap.Uint8("cause", uint8(st.Cause)))
}

// OnVLRReset reverts every UE associated with vlrName back to SGs-NULL: the
// VLR just restarted and has forgotten every SGs association (TS 29.118
// §4.2.2 note, §5.8.3). It never touches EMM/ECM state.
func (s *Server) OnVLRReset(vlrName string) {
	affected := 0
	s.ueManager.Range(func(ue *uecontext.Context) bool {
		ue.Lock()
		if ue.SGsVLRName == vlrName && ue.SGsState != uecontext.SGsUENull {
			ue.SGsState = uecontext.SGsUENull
			ue.SGsLAI = nil
			affected++
		}
		ue.Unlock()
		return true
	})
	s.log.Warn("sgs: VLR reset, cleared UE associations", zap.String("vlr_name", vlrName), zap.Int("affected_ues", affected))
}

// OnVLRAssociationUp logs the node-level Reset procedure completing. Phase 1
// relies on the next Attach/TAU to (re)trigger any UE-level Location Update;
// there is no queued-request backlog to retry here yet.
func (s *Server) OnVLRAssociationUp(vlrName string) {
	s.log.Info("sgs: VLR association up", zap.String("vlr_name", vlrName))
}
