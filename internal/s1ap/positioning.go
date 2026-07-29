package s1ap

import (
	"fmt"
	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"github.com/vectorcore/mme/internal/uecontext"
	"go.uber.org/zap"
)

func (s *Server) SetLPPaSink(v LPPaSink) { s.lppaSink = v }
func (s *Server) SetLPPSink(v LPPSink)   { s.lppSink = v }
func (s *Server) SendDownlinkLPP(mme uint32, payload []byte) error {
	plain, err := emm.EncodeDownlinkGenericNASTransport(emm.GenericMessageContainerTypeLPP, payload)
	if err != nil {
		return err
	}
	ue, ok := s.ueManager.GetByMMEID(mme)
	if !ok {
		return fmt.Errorf("s1ap: LPP UE not found")
	}
	ue.Lock()
	idle := ue.ECMState == emm.ECMIdle
	imsi := ue.IMSI
	ue.Unlock()
	if idle {
		s.lppPendingMu.Lock()
		q := s.lppPending[mme]
		if len(q) >= 4 {
			s.lppPendingMu.Unlock()
			metrics.PositioningQueueRejectTotal.Inc()
			return fmt.Errorf("s1ap: LPP pending queue full")
		}
		s.lppPending[mme] = append(q, append([]byte(nil), payload...))
		metrics.PositioningPendingLPPMessages.Inc()
		s.lppPendingMu.Unlock()
		s.log.Info("positioning.lpp.deferred", zap.Uint32("mme_ue_id", mme), zap.Int("payload_len", len(payload)), zap.Int("pending_queue_depth", len(q)+1), zap.String("ecm_state", emm.ECMIdle.String()))
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
	metrics.PositioningLPPDownlinkTotal.WithLabelValues("connected").Inc()
	s.log.Info("positioning.lpp.connected_delivery", zap.Uint32("mme_ue_id", mme), zap.Int("payload_len", len(payload)), zap.String("ecm_state", emm.ECMConnected.String()))
	return s.sendProtectedNAS(ue, plain, "Downlink Generic NAS Transport (LPP)")
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
		plain, e := emm.EncodeDownlinkGenericNASTransport(emm.GenericMessageContainerTypeLPP, b)
		if e != nil || s.sendProtectedNAS(ue, plain, "Downlink Generic NAS Transport (LPP)") != nil {
			s.lppPendingMu.Unlock()
			return
		}
		s.lppPending[mme] = q[1:]
		if len(q) == 1 {
			delete(s.lppPending, mme)
		}
		metrics.PositioningPendingLPPMessages.Dec()
		metrics.PositioningLPPDownlinkTotal.WithLabelValues("resumed").Inc()
		s.log.Info("positioning.lpp.delivered", zap.Uint32("mme_ue_id", mme), zap.Int("payload_len", len(b)), zap.Int("pending_queue_depth", len(q)-1))
		s.lppPendingMu.Unlock()
	}
}

// ClearPendingLPP is called by the owning SLs transaction on every terminal
// path. It invalidates any queued idle-mode NAS delivery before a later
// Service Request can observe it.
func (s *Server) ClearPendingLPP(mme uint32) {
	s.lppPendingMu.Lock()
	count := len(s.lppPending[mme])
	delete(s.lppPending, mme)
	if count > 0 {
		metrics.PositioningPendingLPPMessages.Sub(float64(count))
		s.log.Info("positioning.lpp.cleanup", zap.Uint32("mme_ue_id", mme), zap.Int("pending_queue_depth", count))
	}
	s.lppPendingMu.Unlock()
}

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
	ue.Unlock()
	if remote == "" {
		return fmt.Errorf("s1ap: positioning UE has no S1 binding")
	}
	list := []pdu.ProtocolIE{{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeMMEUEApID(mme)}, {ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(enb)}, {ID: pdu.IERoutingID, Criticality: aper.CriticalityReject, Value: []byte{routing}}, {ID: pdu.IELPPaPDU, Criticality: aper.CriticalityReject, Value: append([]byte(nil), payload...)}}
	return s.sendToAddr(remote, pdu.BuildInitiatingMessage(pdu.ProcDownlinkUEAssociatedLPPaTransport, aper.CriticalityIgnore, list))
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
