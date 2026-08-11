package s6a

import (
	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/fiorix/go-diameter/v4/diam/avp"
	"github.com/fiorix/go-diameter/v4/diam/datatype"
	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/gateway"
	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/nas/emm"
)

// handleCLR processes a Cancel-Location-Request from the HSS.
// The HSS sends this when the subscriber is deregistered or moved.
func (h *Handlers) handleCLR(c diam.Conn, m *diam.Message) {
	type CLR struct {
		SessionID        string                    `avp:"Session-Id"`
		AuthSessionState int32                     `avp:"Auth-Session-State"`
		OriginHost       datatype.DiameterIdentity `avp:"Origin-Host"`
		OriginRealm      datatype.DiameterIdentity `avp:"Origin-Realm"`
		UserName         string                    `avp:"User-Name"`
		CancellationType int32                     `avp:"Cancellation-Type"`
	}

	var clr CLR
	if err := m.Unmarshal(&clr); err != nil {
		h.log.Warn("s6a: CLR unmarshal error", zap.Error(err))
		return
	}

	h.log.Info("s6a: CLR received",
		zap.String("imsi", clr.UserName),
		zap.Int32("cancellation_type", clr.CancellationType))
	metrics.S6aRequestsTotal.WithLabelValues("CLR", "received").Inc()

	// Send Cancel-Location-Answer
	a := m.Answer(diam.Success)
	a.InsertAVP(diam.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String(clr.SessionID)))
	a.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity(h.nfCfg.OriginHost))
	a.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity(h.nfCfg.OriginRealm))
	a.NewAVP(avp.AuthSessionState, avp.Mbit, 0, datatype.Enumerated(clr.AuthSessionState))
	if _, err := a.WriteTo(c); err != nil {
		h.log.Warn("s6a: CLA write error", zap.Error(err))
		return
	}
	metrics.S6aRequestsTotal.WithLabelValues("CLA", "sent").Inc()

	// Initiate network-triggered detach if UE is attached
	if clr.UserName != "" {
		if ue, ok := h.ueManager.GetByIMSI(clr.UserName); ok {
			ue.Lock()
			mmeUEID := ue.MMEUES1APID
			wasRegistered := ue.EMMState == emm.StateRegistered
			ue.Unlock()
			h.log.Info("s6a: CLR: UE found, triggering detach",
				zap.String("imsi", clr.UserName),
				zap.Uint32("mme_ue_id", mmeUEID))
			// Clean up S-GW session and S1AP resources.
			if h.detachFn != nil {
				h.detachFn(ue)
			}
			h.ueManager.Remove(ue)
			if wasRegistered {
				metrics.AttachedUEs.Dec()
			}
		}
	}
}

// handleIDR processes an Insert-Subscriber-Data-Request from the HSS.
func (h *Handlers) handleIDR(c diam.Conn, m *diam.Message) {
	type SubscriptionData struct {
		AccessRestrictionData uint32 `avp:"Access-Restriction-Data"`
	}
	type IDR struct {
		SessionID        string                    `avp:"Session-Id"`
		AuthSessionState int32                     `avp:"Auth-Session-State"`
		OriginHost       datatype.DiameterIdentity `avp:"Origin-Host"`
		OriginRealm      datatype.DiameterIdentity `avp:"Origin-Realm"`
		UserName         string                    `avp:"User-Name"`
		SubscriptionData SubscriptionData          `avp:"Subscription-Data"`
	}

	var idr IDR
	if err := m.Unmarshal(&idr); err != nil {
		h.log.Warn("s6a: IDR unmarshal error", zap.Error(err))
		return
	}

	h.log.Info("s6a: IDR received",
		zap.String("imsi", idr.UserName),
		zap.Uint32("access_restriction_data", idr.SubscriptionData.AccessRestrictionData))
	metrics.S6aRequestsTotal.WithLabelValues("IDR", "received").Inc()

	// Send Insert-Subscriber-Data-Answer
	a := m.Answer(diam.Success)
	a.InsertAVP(diam.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String(idr.SessionID)))
	a.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity(h.nfCfg.OriginHost))
	a.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity(h.nfCfg.OriginRealm))
	a.NewAVP(avp.AuthSessionState, avp.Mbit, 0, datatype.Enumerated(idr.AuthSessionState))
	if _, err := a.WriteTo(c); err != nil {
		h.log.Warn("s6a: IDA write error", zap.Error(err))
	}
	metrics.S6aRequestsTotal.WithLabelValues("IDA", "sent").Inc()

	// TS 29.272 §3.2: on receiving Access-Restriction-Data, the MME shall
	// replace stored information rather than merge it. If the attached UE is
	// now WB-E-UTRAN-restricted, it may no longer remain on E-UTRAN.
	if idr.UserName == "" {
		return
	}
	restriction := gateway.AccessRestrictionData(idr.SubscriptionData.AccessRestrictionData)
	ue, ok := h.ueManager.GetByIMSI(idr.UserName)
	if !ok {
		return
	}
	ue.Lock()
	ue.AccessRestrictionData = restriction
	mmeUEID := ue.MMEUES1APID
	wasRegistered := ue.EMMState == emm.StateRegistered
	restricted := ue.LTEAccessRestricted()
	ue.Unlock()
	if !restricted {
		return
	}
	h.log.Info("s6a: IDR: UE now WB-E-UTRAN restricted, triggering detach",
		zap.String("imsi", idr.UserName),
		zap.Uint32("mme_ue_id", mmeUEID))
	if h.detachFn != nil {
		h.detachFn(ue)
	}
	h.ueManager.Remove(ue)
	if wasRegistered {
		metrics.AttachedUEs.Dec()
	}
}
