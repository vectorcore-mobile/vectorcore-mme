package s6a

import (
	"encoding/hex"
	"fmt"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/fiorix/go-diameter/v4/diam/avp"
	"github.com/fiorix/go-diameter/v4/diam/datatype"
	"github.com/fiorix/go-diameter/v4/diam/dict"
	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/metrics"
)

// SendULR sends an Update-Location-Request to the HSS.
// The result arrives asynchronously via handleULA → nas.HandleULAResult.
func (h *Handlers) SendULR(imsi string, plmn [3]byte, mmeUEID uint32) error {
	conn, err := h.getConn()
	if err != nil {
		return err
	}

	hssHost, hssRealm, ok := peerMeta(conn)
	if !ok {
		return fmt.Errorf("s6a: peer metadata unavailable")
	}

	sid := h.newSessionID(imsi)
	h.pendingULR.Store(sid, mmeUEID)

	m := diam.NewRequest(diam.UpdateLocation, appIDS6a, dict.Default)
	m.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String(sid))
	m.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity(h.nfCfg.OriginHost))
	m.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity(h.nfCfg.OriginRealm))
	m.NewAVP(avp.DestinationHost, avp.Mbit, 0, datatype.DiameterIdentity(hssHost))
	m.NewAVP(avp.DestinationRealm, avp.Mbit, 0, datatype.DiameterIdentity(hssRealm))
	m.NewAVP(avp.UserName, avp.Mbit, 0, datatype.UTF8String(imsi))
	m.NewAVP(avp.AuthSessionState, avp.Mbit, 0, datatype.Enumerated(1)) // NO_STATE_MAINTAINED
	m.NewAVP(avp.RATType, avp.Vbit|avp.Mbit, vendor3GPP, datatype.Enumerated(ratTypeEUTRAN))
	m.NewAVP(avp.ULRFlags, avp.Vbit|avp.Mbit, vendor3GPP, datatype.Unsigned32(ulrFlags))
	m.NewAVP(avp.VisitedPLMNID, avp.Vbit|avp.Mbit, vendor3GPP, datatype.OctetString(plmn[:]))

	if _, err := m.WriteTo(conn); err != nil {
		h.pendingULR.Delete(sid)
		return fmt.Errorf("s6a: ULR write: %w", err)
	}

	metrics.S6aRequestsTotal.WithLabelValues("ULR", "sent").Inc()
	h.log.Info("s6a: ULR sent", zap.String("imsi", imsi), zap.Uint32("mme_ue_id", mmeUEID))
	return nil
}

// handleULA processes an Update-Location-Answer from the HSS.
func (h *Handlers) handleULA(c diam.Conn, m *diam.Message) {
	type APNConfig struct {
		ContextIdentifier uint32 `avp:"Context-Identifier"`
		ServiceSelection  string `avp:"Service-Selection"`
	}
	type APNProfile struct {
		ContextIdentifier                uint32      `avp:"Context-Identifier"`
		AllAPNConfigurationsIncluded     int32       `avp:"All-APN-Configurations-Included-Indicator"`
		APNConfiguration                 []APNConfig `avp:"APN-Configuration"`
	}
	type SubscriptionData struct {
		MSISDN                  datatype.OctetString `avp:"MSISDN"`
		APNConfigurationProfile APNProfile           `avp:"APN-Configuration-Profile"`
	}
	type experimentalResult struct {
		ExperimentalResultCode uint32 `avp:"Experimental-Result-Code"`
	}
	type ULA struct {
		SessionID          string             `avp:"Session-Id"`
		ResultCode         uint32             `avp:"Result-Code"`
		ExperimentalResult experimentalResult `avp:"Experimental-Result"`
		ULAFlags           uint32             `avp:"ULA-Flags"`
		SubscriptionData   SubscriptionData   `avp:"Subscription-Data"`
	}

	var ula ULA
	if err := m.Unmarshal(&ula); err != nil {
		h.log.Warn("s6a: ULA unmarshal error", zap.Error(err))
		metrics.S6aRequestsTotal.WithLabelValues("ULA", "error").Inc()
		return
	}

	v, ok := h.pendingULR.LoadAndDelete(ula.SessionID)
	if !ok {
		h.log.Warn("s6a: ULA: no pending ULR for session", zap.String("session", ula.SessionID))
		return
	}
	mmeUEID := v.(uint32)

	metrics.S6aRequestsTotal.WithLabelValues("ULA", "ok").Inc()

	if ula.ResultCode != diam.Success || ula.ExperimentalResult.ExperimentalResultCode != 0 {
		errCode := ula.ResultCode
		if errCode == 0 {
			errCode = ula.ExperimentalResult.ExperimentalResultCode
		}
		h.log.Warn("s6a: ULA failure",
			zap.Uint32("result_code", errCode),
			zap.Uint32("mme_ue_id", mmeUEID))
		h.nas.HandleULAResult(mmeUEID, "", "",
			fmt.Errorf("s6a: ULA result code %d", errCode))
		return
	}

	// Decode MSISDN (BCD-encoded OctetString)
	msisdn := decodeMSISDN([]byte(ula.SubscriptionData.MSISDN))

	// Extract default APN from the first APN configuration
	apn := ""
	if len(ula.SubscriptionData.APNConfigurationProfile.APNConfiguration) > 0 {
		apn = ula.SubscriptionData.APNConfigurationProfile.APNConfiguration[0].ServiceSelection
	}

	h.log.Info("s6a: ULA received",
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.String("msisdn", msisdn),
		zap.String("apn", apn))
	h.nas.HandleULAResult(mmeUEID, msisdn, apn, nil)
}

// decodeMSISDN decodes a BCD-encoded MSISDN OctetString from the HSS.
// Returns empty string if decoding fails.
func decodeMSISDN(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	// MSISDN is encoded as per TS 29.002: TON/NPI byte + BCD digits
	// For simplicity, just return hex encoding if decoding is complex
	if len(data) < 2 {
		return hex.EncodeToString(data)
	}
	// Skip TON/NPI byte, decode BCD
	digits := make([]byte, 0, (len(data)-1)*2)
	for _, b := range data[1:] {
		lo := b & 0x0F
		hi := (b >> 4) & 0x0F
		if lo <= 9 {
			digits = append(digits, '0'+lo)
		}
		if hi <= 9 {
			digits = append(digits, '0'+hi)
		}
	}
	return string(digits)
}
