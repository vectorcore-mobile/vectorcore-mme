package s6a

import (
	"fmt"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/fiorix/go-diameter/v4/diam/avp"
	"github.com/fiorix/go-diameter/v4/diam/datatype"
	"github.com/fiorix/go-diameter/v4/diam/dict"
	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/roaming"
)

// SendPUR sends a Purge-UE-Request to the HSS (on UE detach).
func (h *Handlers) SendPUR(imsi string) error {
	if !h.cfg.SendPUROnDetach {
		h.log.Debug("s6a: PUR disabled by config", zap.String("imsi", imsi))
		return nil
	}

	destinationRealm := h.diameterCfg.OriginRealm
	selected, err := h.selectPeer(destinationRealm)
	if err != nil {
		return err
	}

	m := h.buildPUR(imsi, selected.DestinationHost, destinationRealm)

	if _, err := m.WriteTo(selected.Connection); err != nil {
		h.reportTransactionFailure(selected)
		return fmt.Errorf("s6a: PUR write: %w", err)
	}

	metrics.S6aRequestsTotal.WithLabelValues("PUR", "sent").Inc()
	h.log.Info("s6a: PUR sent", zap.String("imsi", imsi))
	return nil
}

// SendPURToHSS preserves the HSS decision made at identity verification.
func (h *Handlers) SendPURToHSS(req roaming.S6aRequest) error {
	if !h.cfg.SendPUROnDetach {
		return nil
	}
	selected, err := h.selectPeer(req.DestinationRealm)
	if err != nil {
		return fmt.Errorf("s6a: route PUR for %s: %w", req.DestinationRealm, err)
	}
	destHost := req.DestinationHost
	if destHost == "" && req.DestinationRealm == h.diameterCfg.OriginRealm {
		destHost = selected.DestinationHost
	}
	m := h.buildPUR(req.SubscriberIMSI, destHost, req.DestinationRealm)
	if _, err := m.WriteTo(selected.Connection); err != nil {
		h.reportTransactionFailure(selected)
		return fmt.Errorf("s6a: PUR write: %w", err)
	}
	metrics.S6aRequestsTotal.WithLabelValues("PUR", "sent").Inc()
	h.log.Info("s6a: PUR sent", zap.String("destination_realm", req.DestinationRealm))
	return nil
}

func (h *Handlers) buildPUR(imsi, destHost, destRealm string) *diam.Message {
	sid := h.newSessionID(imsi)
	m := diam.NewRequest(diam.PurgeUE, appIDS6a, dict.Default)
	m.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String(sid))
	m.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity(h.diameterCfg.OriginHost))
	m.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity(h.diameterCfg.OriginRealm))
	h.addDestinationRouting(m, destHost, destRealm)
	m.NewAVP(avp.UserName, avp.Mbit, 0, datatype.UTF8String(imsi))
	m.NewAVP(avp.AuthSessionState, avp.Mbit, 0, datatype.Enumerated(1))
	return m
}

func (h *Handlers) handlePUA(_ diam.Conn, m *diam.Message) {
	var pua struct {
		SessionID          datatype.UTF8String `avp:"Session-Id"`
		ResultCode         uint32              `avp:"Result-Code"`
		ExperimentalResult struct {
			ExperimentalResultCode uint32 `avp:"Experimental-Result-Code"`
		} `avp:"Experimental-Result"`
	}
	if err := m.Unmarshal(&pua); err != nil {
		h.log.Warn("s6a: PUA decode failed", zap.Error(err))
		metrics.S6aRequestsTotal.WithLabelValues("PUA", "decode_error").Inc()
		return
	}

	resultCode := pua.ResultCode
	if resultCode == 0 && pua.ExperimentalResult.ExperimentalResultCode != 0 {
		resultCode = pua.ExperimentalResult.ExperimentalResultCode
	}
	status := "ok"
	if resultCode != 0 && resultCode != diam.Success {
		status = "error"
	}
	metrics.S6aRequestsTotal.WithLabelValues("PUA", status).Inc()
	h.log.Info("s6a: PUA received",
		zap.String("session_id", string(pua.SessionID)),
		zap.Uint32("result_code", resultCode),
		zap.String("status", status))
}
