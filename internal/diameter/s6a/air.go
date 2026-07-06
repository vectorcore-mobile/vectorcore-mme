package s6a

import (
	"fmt"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/fiorix/go-diameter/v4/diam/avp"
	"github.com/fiorix/go-diameter/v4/diam/datatype"
	"github.com/fiorix/go-diameter/v4/diam/dict"
	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/metrics"
)

// SendAIR sends an Authentication-Information-Request to the HSS.
// The result arrives asynchronously via handleAIA → nas.HandleAIAResult.
func (h *Handlers) SendAIR(imsi string, plmn [3]byte, mmeUEID uint32) error {
	conn, err := h.getConn()
	if err != nil {
		return err
	}

	hssHost, hssRealm, ok := peerMeta(conn)
	if !ok {
		return fmt.Errorf("s6a: peer metadata unavailable")
	}

	sid := h.newSessionID(imsi)
	h.pendingAIR.Store(sid, mmeUEID)

	m := diam.NewRequest(diam.AuthenticationInformation, appIDS6a, dict.Default)
	m.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String(sid))
	m.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity(h.nfCfg.OriginHost))
	m.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity(h.nfCfg.OriginRealm))
	m.NewAVP(avp.DestinationHost, avp.Mbit, 0, datatype.DiameterIdentity(hssHost))
	m.NewAVP(avp.DestinationRealm, avp.Mbit, 0, datatype.DiameterIdentity(hssRealm))
	m.NewAVP(avp.UserName, avp.Mbit, 0, datatype.UTF8String(imsi))
	m.NewAVP(avp.AuthSessionState, avp.Mbit, 0, datatype.Enumerated(1)) // NO_STATE_MAINTAINED
	m.NewAVP(avp.VisitedPLMNID, avp.Vbit|avp.Mbit, vendor3GPP, datatype.OctetString(plmn[:]))
	m.NewAVP(avp.RequestedEUTRANAuthenticationInfo, avp.Vbit|avp.Mbit, vendor3GPP, &diam.GroupedAVP{
		AVP: []*diam.AVP{
			diam.NewAVP(avp.NumberOfRequestedVectors, avp.Vbit|avp.Mbit, vendor3GPP, datatype.Unsigned32(1)),
			diam.NewAVP(avp.ImmediateResponsePreferred, avp.Vbit|avp.Mbit, vendor3GPP, datatype.Unsigned32(1)),
		},
	})

	if _, err := m.WriteTo(conn); err != nil {
		h.pendingAIR.Delete(sid)
		return fmt.Errorf("s6a: AIR write: %w", err)
	}

	metrics.S6aRequestsTotal.WithLabelValues("AIR", "sent").Inc()
	h.log.Info("s6a: AIR sent", zap.String("imsi", imsi), zap.Uint32("mme_ue_id", mmeUEID))
	return nil
}

// handleAIA processes an Authentication-Information-Answer from the HSS.
func (h *Handlers) handleAIA(c diam.Conn, m *diam.Message) {
	type EUtranVector struct {
		RAND  datatype.OctetString `avp:"RAND"`
		XRES  datatype.OctetString `avp:"XRES"`
		AUTN  datatype.OctetString `avp:"AUTN"`
		KASME datatype.OctetString `avp:"KASME"`
	}
	type AuthInfo struct {
		EUtranVector EUtranVector `avp:"E-UTRAN-Vector"`
	}
	type experimentalResult struct {
		ExperimentalResultCode uint32 `avp:"Experimental-Result-Code"`
	}
	type AIA struct {
		SessionID          string             `avp:"Session-Id"`
		ResultCode         uint32             `avp:"Result-Code"`
		ExperimentalResult experimentalResult `avp:"Experimental-Result"`
		AIs                []AuthInfo         `avp:"Authentication-Info"`
	}

	var aia AIA
	if err := m.Unmarshal(&aia); err != nil {
		h.log.Warn("s6a: AIA unmarshal error", zap.Error(err))
		metrics.S6aRequestsTotal.WithLabelValues("AIA", "error").Inc()
		return
	}

	v, ok := h.pendingAIR.LoadAndDelete(aia.SessionID)
	if !ok {
		h.log.Warn("s6a: AIA: no pending AIR for session", zap.String("session", aia.SessionID))
		return
	}
	mmeUEID := v.(uint32)

	metrics.S6aRequestsTotal.WithLabelValues("AIA", "ok").Inc()

	if aia.ResultCode != diam.Success || aia.ExperimentalResult.ExperimentalResultCode != 0 {
		errCode := aia.ResultCode
		if errCode == 0 {
			errCode = aia.ExperimentalResult.ExperimentalResultCode
		}
		h.log.Warn("s6a: AIA failure",
			zap.Uint32("result_code", errCode),
			zap.Uint32("mme_ue_id", mmeUEID))
		h.nas.HandleAIAResult(mmeUEID, nil, nil, nil, nil,
			fmt.Errorf("s6a: AIA result code %d", errCode))
		return
	}

	if len(aia.AIs) == 0 || len(aia.AIs[0].EUtranVector.RAND) == 0 {
		h.log.Warn("s6a: AIA: no authentication vectors", zap.Uint32("mme_ue_id", mmeUEID))
		h.nas.HandleAIAResult(mmeUEID, nil, nil, nil, nil,
			fmt.Errorf("s6a: AIA: no E-UTRAN vectors"))
		return
	}

	vec := aia.AIs[0].EUtranVector
	h.log.Info("s6a: AIA received", zap.Uint32("mme_ue_id", mmeUEID))
	h.nas.HandleAIAResult(mmeUEID,
		[]byte(vec.RAND),
		[]byte(vec.XRES),
		[]byte(vec.AUTN),
		[]byte(vec.KASME),
		nil)
}
