package s1ap

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/lcsnotify"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"github.com/vectorcore/mme/internal/uecontext"
	"go.uber.org/zap"
)

// pendingGenericNAS is one queued ECM-IDLE downlink Generic NAS Transport
// message. LPP and the LCS location-notification procedure (TS 24.171
// §5.2.1.1) share the same queue and page-then-deliver behavior — they
// differ only in Generic-message-container-type, routing (nil for LCS
// notification; see EncodeDownlinkGenericNASTransport), and payload.
type pendingGenericNAS struct {
	containerType uint8
	routing       []byte
	payload       []byte
}

// pendingLPPa is one queued ECM-IDLE downlink LPPa Initiation Request,
// mirroring pendingGenericNAS for the S1AP (not NAS) delivery path — see
// SendDownlinkLPPa.
type pendingLPPa struct {
	routing uint8
	payload []byte
}

func (s *Server) SetLPPaSink(v LPPaSink) { s.lppaSink = v }
func (s *Server) SetLPPSink(v LPPSink)   { s.lppSink = v }

// SendDownlinkLPP relays an LPP payload to the UE over NAS. routing is the
// SLs Correlation ID (TS 29.171) for the positioning transaction this
// payload belongs to; TS 24.171 §5.3.2.1.1 requires the MME to carry it as
// the Routing Identifier in the Additional Information IE so a later Uplink
// Generic NAS Transport response can be mapped back to the right SLs
// transaction.
func (s *Server) SendDownlinkLPP(mme uint32, routing []byte, payload []byte) error {
	return s.sendOrQueueGenericNAS(mme, emm.GenericMessageContainerTypeLPP, routing, payload, "Downlink Generic NAS Transport (LPP)", "lpp")
}

// sendOrQueueGenericNAS delivers a Generic NAS Transport payload immediately
// if the UE is ECM-CONNECTED, or queues it (bounded, FIFO) and pages the UE
// otherwise. label is used for logging; metricLabel identifies the traffic
// kind ("lpp" or "lcs_notify") in logs. The mme_lpp_* metrics themselves stay
// LPP-only (their names are not generic), so they are only incremented for
// GenericMessageContainerTypeLPP — LCS-notification traffic is logged but
// does not inflate LPP-named series. routing is passed straight through to
// EncodeDownlinkGenericNASTransport (nil for LCS notification).
func (s *Server) sendOrQueueGenericNAS(mme uint32, containerType uint8, routing, payload []byte, label, metricLabel string) error {
	plain, err := emm.EncodeDownlinkGenericNASTransport(containerType, routing, payload)
	if err != nil {
		return err
	}
	ue, ok := s.ueManager.GetByMMEID(mme)
	if !ok {
		return fmt.Errorf("s1ap: %s UE not found", label)
	}
	isLPP := containerType == emm.GenericMessageContainerTypeLPP
	ue.Lock()
	idle := ue.ECMState == emm.ECMIdle
	imsi := ue.IMSI
	ue.Unlock()
	if idle {
		s.lppPendingMu.Lock()
		q := s.lppPending[mme]
		if len(q) >= 4 {
			s.lppPendingMu.Unlock()
			if isLPP {
				metrics.PositioningQueueRejectTotal.Inc()
			}
			return fmt.Errorf("s1ap: %s pending queue full", label)
		}
		s.lppPending[mme] = append(q, pendingGenericNAS{containerType: containerType, routing: append([]byte(nil), routing...), payload: append([]byte(nil), payload...)})
		if isLPP {
			metrics.PositioningPendingLPPMessages.Inc()
		}
		s.lppPendingMu.Unlock()
		s.log.Info("positioning.generic.deferred", zap.Uint32("mme_ue_id", mme), zap.String("kind", metricLabel), zap.Int("payload_len", len(payload)), zap.Int("pending_queue_depth", len(q)+1), zap.String("ecm_state", emm.ECMIdle.String()))
		pageErr := s.PageUE(imsi)
		if pageErr != nil && pageErr != ErrAlreadyPaging && pageErr != ErrAlreadyConnected {
			metrics.PositioningPagingTotal.WithLabelValues("failure").Inc()
			return pageErr
		}
		if pageErr == ErrAlreadyPaging {
			metrics.PositioningPagingTotal.WithLabelValues("already_active").Inc()
		} else {
			metrics.PositioningPagingTotal.WithLabelValues("requested").Inc()
		}
		return nil
	}
	if isLPP {
		metrics.PositioningLPPDownlinkTotal.WithLabelValues("connected").Inc()
	}
	s.log.Info("positioning.generic.connected_delivery", zap.Uint32("mme_ue_id", mme), zap.String("kind", metricLabel), zap.Int("payload_len", len(payload)), zap.String("ecm_state", emm.ECMConnected.String()))
	return s.sendProtectedNAS(ue, plain, label)
}

// lcsNotifyResult is delivered on the per-UE channel registered by
// SendLocationNotification when the matching RELEASE COMPLETE arrives (see
// handleUplinkLCSNotification).
type lcsNotifyResult struct {
	granted bool
	err     error
}

// SendLocationNotification sends a TS 24.080 LCS location-notification
// REGISTER (TS 23.271 §9.1.15 step 4) to the UE identified by mme, over the
// same Generic NAS Transport delivery path SendDownlinkLPP uses (queue and
// page if ECM-IDLE, direct send if ECM-CONNECTED).
//
// If wait is false (LCS-Privacy-Check = ALLOWED_WITH_NOTIFICATION: the UE is
// informed but its response does not gate positioning), it returns as soon
// as the message is sent or queued, with granted always true.
//
// If wait is true (ALLOWED_IF_NO_RESPONSE / RESTRICTED_IF_NO_RESPONSE), it
// blocks for the UE's RELEASE COMPLETE, bounded by timeout — a short window
// distinct from the full positioning timeout, since this is only the
// consent step, not positioning itself. A timeout is reported through err
// so the caller can apply TS 23.271 step 5's differing no-response
// semantics for the two privacy-check values.
func (s *Server) SendLocationNotification(mme uint32, notificationType lcsnotify.NotificationType, wait bool, timeout time.Duration) (granted bool, err error) {
	payload, err := lcsnotify.EncodeRegister(notificationType)
	if err != nil {
		return false, err
	}
	var resultCh chan lcsNotifyResult
	if wait {
		resultCh = make(chan lcsNotifyResult, 1)
		s.lcsNotifyMu.Lock()
		if s.lcsNotifyPending == nil {
			s.lcsNotifyPending = make(map[uint32]chan lcsNotifyResult)
		}
		s.lcsNotifyPending[mme] = resultCh
		s.lcsNotifyMu.Unlock()
		defer func() {
			s.lcsNotifyMu.Lock()
			if s.lcsNotifyPending[mme] == resultCh {
				delete(s.lcsNotifyPending, mme)
			}
			s.lcsNotifyMu.Unlock()
		}()
	}
	if err := s.sendOrQueueGenericNAS(mme, emm.GenericMessageContainerTypeLCS, nil, payload, "Downlink Generic NAS Transport (LCS Notification)", "lcs_notify"); err != nil {
		return false, err
	}
	if !wait {
		return true, nil
	}
	select {
	case r := <-resultCh:
		return r.granted, r.err
	case <-time.After(timeout):
		return false, context.DeadlineExceeded
	}
}

// handleUplinkLCSNotification parses a RELEASE COMPLETE carrying the UE's
// response to a pending lcs-LocationNotification Invoke and delivers it to
// the matching SendLocationNotification waiter, if one is still pending. A
// response with no waiter (already timed out, or the notification was
// sent without wait) is dropped rather than treated as an error.
func (s *Server) handleUplinkLCSNotification(mme uint32, payload []byte) error {
	granted, err := lcsnotify.DecodeReleaseComplete(payload)
	s.lcsNotifyMu.Lock()
	ch := s.lcsNotifyPending[mme]
	s.lcsNotifyMu.Unlock()
	if ch == nil {
		return nil
	}
	select {
	case ch <- lcsNotifyResult{granted: granted, err: err}:
	default:
	}
	return nil
}

// ResumePendingLPP is called after the existing service-resumption path has
// restored an active S1 binding. The queue is bounded and FIFO; failed sends
// retain the undelivered head for the normal SLs timeout/association cleanup.
func (s *Server) ResumePendingLPP(ue *uecontext.Context) {
	if ue == nil {
		return
	}
	ue.Lock()
	mme := ue.MMEUES1APID
	connected := ue.ECMState == emm.ECMConnected
	ue.Unlock()
	if !connected {
		return
	}
	for {
		s.lppPendingMu.Lock()
		q := s.lppPending[mme]
		if len(q) == 0 {
			s.lppPendingMu.Unlock()
			return
		}
		b := q[0]
		// Keep the queue mutex through the send. ClearPendingLPP therefore
		// linearizes terminal cleanup with delivery: whichever wins first
		// determines whether an old payload can be transmitted.
		plain, e := emm.EncodeDownlinkGenericNASTransport(b.containerType, b.routing, b.payload)
		if e != nil || s.sendProtectedNAS(ue, plain, "Downlink Generic NAS Transport (resumed)") != nil {
			s.lppPendingMu.Unlock()
			return
		}
		s.lppPending[mme] = q[1:]
		if len(q) == 1 {
			delete(s.lppPending, mme)
		}
		if b.containerType == emm.GenericMessageContainerTypeLPP {
			metrics.PositioningPendingLPPMessages.Dec()
			metrics.PositioningLPPDownlinkTotal.WithLabelValues("resumed").Inc()
		}
		s.log.Info("positioning.generic.delivered", zap.Uint32("mme_ue_id", mme), zap.Int("payload_len", len(b.payload)), zap.Int("pending_queue_depth", len(q)-1))
		s.lppPendingMu.Unlock()
	}
}

// ClearPendingLPP is called by the owning SLs transaction on every terminal
// path. It invalidates any queued idle-mode NAS delivery before a later
// Service Request can observe it. The queue is LPP-specific in practice (the
// LCS-notification path does not register an SLs transaction), but this
// still only counts LPP-typed entries against the LPP gauge for correctness.
func (s *Server) ClearPendingLPP(mme uint32) {
	s.lppPendingMu.Lock()
	q := s.lppPending[mme]
	count := len(q)
	lppCount := 0
	for _, entry := range q {
		if entry.containerType == emm.GenericMessageContainerTypeLPP {
			lppCount++
		}
	}
	delete(s.lppPending, mme)
	if lppCount > 0 {
		metrics.PositioningPendingLPPMessages.Sub(float64(lppCount))
	}
	if count > 0 {
		s.log.Info("positioning.lpp.cleanup", zap.Uint32("mme_ue_id", mme), zap.Int("pending_queue_depth", count))
	}
	s.lppPendingMu.Unlock()
}

// SendDownlinkLPPa sends an LPPa Initiation Request over Downlink UE
// Associated LPPa Transport if the UE currently has an active S1 binding,
// or queues it (bounded, FIFO) and pages the UE otherwise — mirroring
// sendOrQueueGenericNAS's ECM-IDLE handling for the LPP path. A target UE
// being ECM-IDLE is the ordinary case, not an error: SendDownlinkLPPa's
// caller (the SLs positioning relay) expects an eventual delivery or its
// own timeout, not an immediate synchronous failure just because the UE
// happened to be idle at the moment the request arrived.
func (s *Server) SendDownlinkLPPa(mme uint32, routing uint8, payload []byte) error {
	if len(payload) == 0 {
		return fmt.Errorf("s1ap: empty LPPa PDU")
	}
	ue, ok := s.ueManager.GetByMMEID(mme)
	if !ok {
		return fmt.Errorf("s1ap: positioning UE not found")
	}
	ue.Lock()
	remote, enb := ue.ENBGlobalID, ue.ENBS1APID
	imsi := ue.IMSI
	ue.Unlock()
	if remote == "" {
		s.lppPendingMu.Lock()
		q := s.lppaPending[mme]
		if len(q) >= 4 {
			s.lppPendingMu.Unlock()
			return fmt.Errorf("s1ap: LPPa pending queue full")
		}
		s.lppaPending[mme] = append(q, pendingLPPa{routing: routing, payload: append([]byte(nil), payload...)})
		s.lppPendingMu.Unlock()
		s.log.Info("positioning.lppa.deferred", zap.Uint32("mme_ue_id", mme), zap.Int("payload_len", len(payload)), zap.Int("pending_queue_depth", len(q)+1), zap.String("ecm_state", emm.ECMIdle.String()))
		pageErr := s.PageUE(imsi)
		if pageErr != nil && pageErr != ErrAlreadyPaging && pageErr != ErrAlreadyConnected {
			metrics.PositioningPagingTotal.WithLabelValues("failure").Inc()
			return pageErr
		}
		if pageErr == ErrAlreadyPaging {
			metrics.PositioningPagingTotal.WithLabelValues("already_active").Inc()
		} else {
			metrics.PositioningPagingTotal.WithLabelValues("requested").Inc()
		}
		return nil
	}
	list := []pdu.ProtocolIE{{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeMMEUEApID(mme)}, {ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(enb)}, {ID: pdu.IERoutingID, Criticality: aper.CriticalityReject, Value: []byte{routing}}, {ID: pdu.IELPPaPDU, Criticality: aper.CriticalityReject, Value: append([]byte(nil), payload...)}}
	s.log.Info("positioning.lppa.sent", zap.Uint32("mme_ue_id", mme), zap.String("remote", remote), zap.Uint32("enb_ue_id", enb), zap.Uint8("routing_id", routing), zap.Int("payload_len", len(payload)), zap.String("lppa_apdu_hex", hex.EncodeToString(payload)))
	return s.sendToAddr(remote, pdu.BuildInitiatingMessage(pdu.ProcDownlinkUEAssociatedLPPaTransport, aper.CriticalityIgnore, list))
}

// ResumePendingLPPa is ResumePendingLPP's counterpart for the LPPa/S1AP
// delivery path, called from the same S1-binding-restoration point (see
// ResumePendingNetworkBearerProcedures) once ue.ENBGlobalID/ENBS1APID are
// populated again.
func (s *Server) ResumePendingLPPa(ue *uecontext.Context) {
	if ue == nil {
		return
	}
	ue.Lock()
	mme := ue.MMEUES1APID
	remote, enb := ue.ENBGlobalID, ue.ENBS1APID
	ue.Unlock()
	if remote == "" {
		return
	}
	for {
		s.lppPendingMu.Lock()
		q := s.lppaPending[mme]
		if len(q) == 0 {
			s.lppPendingMu.Unlock()
			return
		}
		b := q[0]
		list := []pdu.ProtocolIE{{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeMMEUEApID(mme)}, {ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(enb)}, {ID: pdu.IERoutingID, Criticality: aper.CriticalityReject, Value: []byte{b.routing}}, {ID: pdu.IELPPaPDU, Criticality: aper.CriticalityReject, Value: b.payload}}
		s.log.Info("positioning.lppa.sent", zap.Uint32("mme_ue_id", mme), zap.String("remote", remote), zap.Uint32("enb_ue_id", enb), zap.Uint8("routing_id", b.routing), zap.Int("payload_len", len(b.payload)), zap.String("lppa_apdu_hex", hex.EncodeToString(b.payload)), zap.Bool("resumed", true))
		// Keep the queue mutex through the send, symmetric with
		// ResumePendingLPP: ClearPendingLPPa linearizes terminal cleanup
		// with delivery this way too.
		if err := s.sendToAddr(remote, pdu.BuildInitiatingMessage(pdu.ProcDownlinkUEAssociatedLPPaTransport, aper.CriticalityIgnore, list)); err != nil {
			s.lppPendingMu.Unlock()
			return
		}
		s.lppaPending[mme] = q[1:]
		if len(q) == 1 {
			delete(s.lppaPending, mme)
		}
		s.log.Info("positioning.lppa.delivered", zap.Uint32("mme_ue_id", mme), zap.Int("payload_len", len(b.payload)), zap.Int("pending_queue_depth", len(q)-1))
		s.lppPendingMu.Unlock()
	}
}

// ClearPendingLPPa is ClearPendingLPP's counterpart for the LPPa queue,
// called from the same terminal SLs-transaction paths.
func (s *Server) ClearPendingLPPa(mme uint32) {
	s.lppPendingMu.Lock()
	q := s.lppaPending[mme]
	count := len(q)
	delete(s.lppaPending, mme)
	if count > 0 {
		s.log.Info("positioning.lppa.cleanup", zap.Uint32("mme_ue_id", mme), zap.Int("pending_queue_depth", count))
	}
	s.lppPendingMu.Unlock()
}
func (s *Server) handleUplinkLPPa(remote string, list []pdu.ProtocolIE) {
	var mme, enb uint32
	var route uint8
	var payload []byte
	seen := map[uint16]bool{}
	for _, x := range list {
		if seen[x.ID] {
			return
		}
		seen[x.ID] = true
		switch x.ID {
		case pdu.IEMMEUES1APID:
			v, e := ies.DecodeMMEUEApID(x.Value)
			if e != nil {
				return
			}
			mme = v
		case pdu.IEENBS1APID:
			v, e := ies.DecodeENBUEApID(x.Value)
			if e != nil {
				return
			}
			enb = v
		case pdu.IERoutingID:
			if len(x.Value) != 1 {
				return
			}
			route = x.Value[0]
		case pdu.IELPPaPDU:
			if len(x.Value) == 0 {
				return
			}
			payload = append([]byte(nil), x.Value...)
		}
	}
	if mme == 0 || len(payload) == 0 {
		return
	}
	ue, ok := s.ueManager.GetByMMEID(mme)
	if !ok {
		return
	}
	ue.Lock()
	valid := ue.ENBGlobalID == remote && ue.ENBS1APID == enb
	ue.Unlock()
	if !valid {
		return
	}
	if s.lppaSink != nil {
		_ = s.lppaSink.HandleUplinkLPPa(mme, route, payload)
	}
}
