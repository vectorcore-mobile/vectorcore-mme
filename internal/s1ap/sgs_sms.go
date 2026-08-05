package s1ap

import (
	"fmt"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/sgsap"
	"github.com/vectorcore/mme/internal/uecontext"
)

// SMS over SGs is a transparent NAS-message-container relay (TS 29.118
// §9.4.15): the VLR/MSC owns the CP/RP protocol end to end, so unlike SGd
// (internal/diameter/sgd, internal/s1ap/sms.go) the MME never parses
// CP-DATA/CP-ACK/CP-ERROR or synthesizes an RP-ACK itself here - it only
// relays the opaque NAS message container in each direction and reuses the
// existing transport-neutral pieces (sendSMSCP, PageUE) unchanged. This
// matches how open5gs's sgsap_handle_downlink_unitdata /
// OGS_NAS_EPS_UPLINK_NAS_TRANSPORT handling behave.

type pendingSGsMTSMS struct {
	nasContainer []byte
	state        string // "received" | "paging"
}

// selectSMSPath decides which core-side SMS transport a UE's MO SMS should
// use: "sgd", "sgs", or "" if neither is registered. Only consulted when
// both are enabled and the UE is registered on both does
// sms.preferred_transport break the tie.
func (s *Server) selectSMSPath(ue *uecontext.Context) string {
	ue.Lock()
	sgsOK := s.sgsCfg.Enabled && ue.SGsState == uecontext.SGsUEAssociated
	sgdOK := s.sgdCfg.Enabled && ue.SMSRegistrationState == uecontext.SMSRegistrationRegistered
	ue.Unlock()
	switch {
	case sgsOK && sgdOK:
		if s.smsCfg.PreferredTransport == "sgs" {
			return "sgs"
		}
		return "sgd"
	case sgsOK:
		return "sgs"
	case sgdOK:
		return "sgd"
	default:
		return ""
	}
}

// relayUplinkSMSToSGs forwards a UE's uplink SMS NAS container (whatever CP
// message it is - CP-DATA, CP-ACK, or CP-ERROR) to the VLR unparsed, as
// SGsAP-UPLINK-UNITDATA.
func (s *Server) relayUplinkSMSToSGs(ue *uecontext.Context, cpdu []byte) error {
	ue.Lock()
	imsi := ue.IMSI
	mmeUEID := ue.MMEUES1APID
	vlrName := ue.SGsVLRName
	imeisv := ue.IMEISV
	tai := ue.TAI
	ue.Unlock()
	if vlrName == "" {
		return fmt.Errorf("sgs: no VLR association for uplink SMS relay")
	}
	req := sgsap.UplinkUnitdata{IMSI: imsi, NASMessageContainer: cpdu, TAI: tai}
	if imeisv != "" {
		req.IMEISV = imeisv
	}
	if err := s.vlr.SendUplinkUnitdata(vlrName, req); err != nil {
		metrics.SMSMORequestsTotal.WithLabelValues("failure").Inc()
		s.log.Warn("sgs: failed to relay uplink SMS to VLR",
			zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi), zap.String("vlr_name", vlrName), zap.Error(err))
		return err
	}
	metrics.SMSMORequestsTotal.WithLabelValues("success").Inc()
	s.log.Info("sgs: uplink SMS relayed to VLR", zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi), zap.String("vlr_name", vlrName))
	return nil
}

// HandleDownlinkUnitdata relays a VLR-originated SMS NAS container to the UE.
// A connected UE gets it immediately; an idle UE is paged first and the
// container is delivered once deliverPendingSGsMT runs after the UE
// reconnects. There is no SGsAP answer to send back for this message (TS
// 29.118 downlink-unitdata is one-way, unlike SGd's TFR/TFA).
func (s *Server) HandleDownlinkUnitdata(vlrName string, d *sgsap.DownlinkUnitdata) {
	if d == nil {
		return
	}
	metrics.SMSMTRequestsTotal.WithLabelValues("received").Inc()
	ue, ok := s.ueManager.GetByIMSI(d.IMSI)
	if !ok {
		s.log.Warn("sgs: DOWNLINK-UNITDATA for unknown IMSI", zap.String("vlr_name", vlrName), zap.String("imsi", d.IMSI))
		return
	}
	ue.Lock()
	connected := ue.ECMState == emm.ECMConnected
	mmeUEID := ue.MMEUES1APID
	ue.Unlock()

	pending := &pendingSGsMTSMS{nasContainer: append([]byte(nil), d.NASMessageContainer...), state: "received"}
	if connected {
		if err := s.sendSMSCP(ue, pending.nasContainer); err != nil {
			metrics.SMSMTRequestsTotal.WithLabelValues("failure").Inc()
			s.log.Warn("sgs: failed to relay downlink SMS to UE", zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", d.IMSI), zap.Error(err))
			return
		}
		metrics.SMSMTRequestsTotal.WithLabelValues("delivered").Inc()
		s.log.Info("sgs: downlink SMS relayed to UE", zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", d.IMSI))
		return
	}

	if _, loaded := s.pendingSGsMT.LoadOrStore(d.IMSI, pending); loaded {
		metrics.SMSDuplicateMessagesTotal.WithLabelValues("sgs_mt_downlink").Inc()
		s.log.Info("sgs: downlink SMS already pending for IMSI, dropping duplicate", zap.String("imsi", d.IMSI))
		return
	}
	if err := s.PageUE(d.IMSI); err != nil {
		s.pendingSGsMT.Delete(d.IMSI)
		metrics.SMSMTPagingTotal.WithLabelValues("failure").Inc()
		s.log.Warn("sgs: paging failed for downlink SMS", zap.String("imsi", d.IMSI), zap.Error(err))
		return
	}
	pending.state = "paging"
	metrics.SMSMTPagingTotal.WithLabelValues("started").Inc()
	s.log.Info("sgs: downlink SMS queued, paging UE", zap.String("imsi", d.IMSI))
}

// deliverPendingSGsMT runs after a Service Request's ICS response has made
// the S1 context usable again, delivering any SMS NAS container that
// HandleDownlinkUnitdata deferred while the UE was paged.
func (s *Server) deliverPendingSGsMT(ue *uecontext.Context) {
	ue.Lock()
	imsi := ue.IMSI
	ue.Unlock()
	if imsi == "" {
		return
	}
	v, ok := s.pendingSGsMT.LoadAndDelete(imsi)
	if !ok {
		return
	}
	pending := v.(*pendingSGsMTSMS)
	if pending.state != "paging" {
		return
	}
	if err := s.sendSMSCP(ue, pending.nasContainer); err != nil {
		metrics.SMSMTRequestsTotal.WithLabelValues("failure").Inc()
		s.log.Warn("sgs: failed to deliver deferred downlink SMS after paging", zap.String("imsi", imsi), zap.Error(err))
		return
	}
	metrics.SMSMTRequestsTotal.WithLabelValues("delivered").Inc()
	s.log.Info("sgs: deferred downlink SMS delivered after paging", zap.String("imsi", imsi))
}
