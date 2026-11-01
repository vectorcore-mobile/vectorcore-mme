package s6a

import (
	"context"
	"fmt"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/fiorix/go-diameter/v4/diam/avp"
	"github.com/fiorix/go-diameter/v4/diam/datatype"
	"github.com/fiorix/go-diameter/v4/diam/dict"
	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/roaming"
)

// Alert-Reason (TS 29.272 §7.3.83, AVP 1434, Enumerated, M/V 10415). go-diameter's
// built-in S6a dictionary lists it in the Notify command but does not define
// the AVP, so it is encoded by code here.
const (
	avpAlertReason uint32 = 1434

	AlertReasonUEPresent         int32 = 0
	AlertReasonUEMemoryAvailable int32 = 1
)

// SendNotifyAlert sends a Notify-Request (TS 29.272 §5.2.5.1) carrying
// Alert-Reason and waits for the Notify-Answer. It returns the NOA result
// code (Result-Code, or Experimental-Result-Code when that is what the HSS
// sent). The HSS uses the alert to clear MNRF/MCEF and alert the SMS-SC.
//
// dest names the subscriber's HSS as chosen at attach (roaming); an empty
// DestinationRealm means the home realm via the selected S6a peer.
func (h *Handlers) SendNotifyAlert(ctx context.Context, dest roaming.S6aRequest, alertReason int32) (uint32, error) {
	if dest.SubscriberIMSI == "" {
		return 0, fmt.Errorf("s6a: NOR without IMSI")
	}
	realm := dest.DestinationRealm
	if realm == "" {
		realm = h.diameterCfg.OriginRealm
	}
	selected, err := h.selectPeer(realm)
	if err != nil {
		return 0, fmt.Errorf("s6a: route NOR for %s: %w", realm, err)
	}
	host := dest.DestinationHost
	if host == "" && realm == h.diameterCfg.OriginRealm {
		host = selected.DestinationHost
	}
	sid := h.newSessionID(dest.SubscriberIMSI)
	m := h.buildNOR(sid, dest.SubscriberIMSI, host, realm, alertReason)

	ch := make(chan uint32, 1)
	h.pendingNOR.Store(sid, ch)
	defer h.pendingNOR.Delete(sid)
	if _, err := m.WriteTo(selected.Connection); err != nil {
		h.reportTransactionFailure(selected)
		return 0, fmt.Errorf("s6a: NOR write: %w", err)
	}
	metrics.S6aRequestsTotal.WithLabelValues("NOR", "sent").Inc()
	h.log.Info("s6a: NOR sent", zap.String("imsi", dest.SubscriberIMSI), zap.String("session_id", sid),
		zap.String("destination_realm", realm), zap.Int32("alert_reason", alertReason))
	select {
	case code := <-ch:
		return code, nil
	case <-ctx.Done():
		metrics.S6aRequestsTotal.WithLabelValues("NOA", "timeout").Inc()
		return 0, fmt.Errorf("s6a: NOA wait: %w", ctx.Err())
	}
}

func (h *Handlers) buildNOR(sid, imsi, destHost, destRealm string, alertReason int32) *diam.Message {
	m := diam.NewRequest(diam.Notify, appIDS6a, dict.Default)
	m.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String(sid))
	m.NewAVP(avp.AuthSessionState, avp.Mbit, 0, datatype.Enumerated(1)) // NO_STATE_MAINTAINED
	m.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity(h.diameterCfg.OriginHost))
	m.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity(h.diameterCfg.OriginRealm))
	h.addDestinationRouting(m, destHost, destRealm)
	m.NewAVP(avp.UserName, avp.Mbit, 0, datatype.UTF8String(imsi))
	m.NewAVP(avpAlertReason, avp.Mbit|avp.Vbit, vendor3GPP, datatype.Enumerated(alertReason))
	return m
}

func (h *Handlers) handleNOA(_ diam.Conn, m *diam.Message) {
	var noa struct {
		SessionID          datatype.UTF8String `avp:"Session-Id"`
		ResultCode         uint32              `avp:"Result-Code"`
		ExperimentalResult struct {
			ExperimentalResultCode uint32 `avp:"Experimental-Result-Code"`
		} `avp:"Experimental-Result"`
	}
	if err := m.Unmarshal(&noa); err != nil {
		h.log.Warn("s6a: NOA decode failed", zap.Error(err))
		metrics.S6aRequestsTotal.WithLabelValues("NOA", "decode_error").Inc()
		return
	}
	code := noa.ResultCode
	if code == 0 {
		code = noa.ExperimentalResult.ExperimentalResultCode
	}
	status := "ok"
	if code != diam.Success {
		status = "error"
	}
	metrics.S6aRequestsTotal.WithLabelValues("NOA", status).Inc()
	h.log.Info("s6a: NOA received", zap.String("session_id", string(noa.SessionID)), zap.Uint32("result_code", code))
	v, ok := h.pendingNOR.Load(string(noa.SessionID))
	if !ok {
		h.log.Warn("s6a: late or unsolicited NOA", zap.String("session_id", string(noa.SessionID)))
		return
	}
	select {
	case v.(chan uint32) <- code:
	default:
	}
}
