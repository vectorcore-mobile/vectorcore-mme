package s1ap

import (
	"encoding/hex"
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"github.com/vectorcore/mme/internal/uecontext"
)

const ueRadioCapabilityLogBytes = 96

func (s *Server) handleUECapabilityInfoIndication(remoteAddr string, p *pdu.PDU, ieList []pdu.ProtocolIE) {
	var mmeUEID uint32
	var enbUEID uint32
	var radioCapability []byte
	var lteMIndicated bool

	for _, ie := range ieList {
		switch ie.ID {
		case pdu.IEMMEUES1APID:
			id, err := ies.DecodeMMEUEApID(ie.Value)
			if err != nil {
				s.log.Warn("s1ap: UECapabilityInfoIndication MME UE S1AP ID decode error",
					zap.String("remote", remoteAddr),
					zap.Error(err))
				s.sendErrorIndication(remoteAddr, p, 0, enbUEID, ies.CauseGroupProtocol, ies.CauseProtocolFalselyConstructedMessage)
				return
			}
			mmeUEID = id
		case pdu.IEENBS1APID:
			id, err := ies.DecodeENBUEApID(ie.Value)
			if err != nil {
				s.log.Warn("s1ap: UECapabilityInfoIndication eNB UE S1AP ID decode error",
					zap.String("remote", remoteAddr),
					zap.Error(err))
				s.sendErrorIndication(remoteAddr, p, mmeUEID, 0, ies.CauseGroupProtocol, ies.CauseProtocolFalselyConstructedMessage)
				return
			}
			enbUEID = id
		case pdu.IEUERadioCapability:
			capability, err := ies.DecodeUERadioCapability(ie.Value)
			if err != nil {
				s.log.Warn("s1ap: UECapabilityInfoIndication UE radio capability decode error",
					zap.String("remote", remoteAddr),
					zap.Int("raw_len", len(ie.Value)),
					zap.String("raw", truncateHex(ie.Value, ueRadioCapabilityLogBytes)),
					zap.Error(err))
				s.sendErrorIndication(remoteAddr, p, mmeUEID, enbUEID, ies.CauseGroupProtocol, ies.CauseProtocolFalselyConstructedMessage)
				return
			}
			radioCapability = capability
		case pdu.IELTEMIndication:
			if err := ies.DecodeLTEMIndication(ie.Value); err != nil {
				s.log.Warn("s1ap: UECapabilityInfoIndication LTE-M Indication decode error",
					zap.String("remote", remoteAddr),
					zap.Error(err))
				s.sendErrorIndication(remoteAddr, p, mmeUEID, enbUEID, ies.CauseGroupProtocol, ies.CauseProtocolFalselyConstructedMessage)
				return
			}
			lteMIndicated = true
		}
	}

	ue, ok := s.findUEForUEAssociatedMessage(remoteAddr, p, mmeUEID, enbUEID)
	if ok && len(radioCapability) > 0 {
		ue.Lock()
		ue.UERadioCapability = append(ue.UERadioCapability[:0], radioCapability...)
		ue.UpdatedAt = time.Now()
		ue.Unlock()
	}
	if ok {
		// UECapabilityReported is set unconditionally: it's the evidence that
		// makes a *missing* LTE-M Indication meaningful (see
		// WBEUTRANExceptLTEMAccessRestricted), not just a present one.
		ue.Lock()
		ue.UECapabilityReported = true
		if lteMIndicated {
			ue.LTEMIndicated = true
		}
		ue.UpdatedAt = time.Now()
		ue.Unlock()
		s.enforceLTEMAccessRestriction(ue)
	}

	fields := []zap.Field{
		zap.String("remote", remoteAddr),
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.Uint32("enb_ue_id", enbUEID),
		zap.Int("ue_radio_capability_len", len(radioCapability)),
		zap.String("ue_radio_capability_hex", truncateHex(radioCapability, ueRadioCapabilityLogBytes)),
		zap.Bool("lte_m_indicated", lteMIndicated),
	}
	if !ok {
		fields = append(fields, zap.Bool("ue_context_found", false))
		s.log.Warn("s1ap: UECapabilityInfoIndication received for unknown UE", fields...)
		return
	}

	s.log.Debug("s1ap: UECapabilityInfoIndication received", fields...)
}

// enforceLTEMAccessRestriction checks Access-Restriction-Data bits 11/12
// (LTE-M / WB-E-UTRAN-Except-LTE-M) against the now-current LTEMIndicated/
// UECapabilityReported state and, if violated, forces the UE off — mirroring
// the existing HSS-pushed-restriction-mid-session pattern in
// internal/diameter/s6a/clr.go's handleIDR (Access-Restriction-Data update
// via IDR triggers the same HandleNetworkDetach + ueManager.Remove sequence
// when the now-attached UE is no longer permitted). Unlike bit 4/6, which are
// known before Attach Accept and so are rejected outright, this can only be
// discovered after the UE is already attached (LTE-M status arrives via a
// later message), so the only remedy is disconnecting it once known.
func (s *Server) enforceLTEMAccessRestriction(ue *uecontext.Context) {
	ue.Lock()
	imsi := ue.IMSI
	mmeUEID := ue.MMEUES1APID
	restricted := ue.LTEMAccessRestricted() || ue.WBEUTRANExceptLTEMAccessRestricted()
	ue.Unlock()
	if !restricted {
		return
	}
	s.log.Info("s1ap: UE now LTE-M-access restricted by HSS, triggering detach",
		zap.String("imsi", imsi),
		zap.Uint32("mme_ue_id", mmeUEID))
	s.HandleNetworkDetach(ue)
	s.ueManager.Remove(ue)
}

func (s *Server) findUEByS1APIDs(remoteAddr string, mmeUEID, enbUEID uint32) (*uecontext.Context, bool) {
	if mmeUEID != 0 {
		if ue, ok := s.ueManager.GetByMMEID(mmeUEID); ok {
			return ue, true
		}
	}
	if enbUEID == 0 {
		return nil, false
	}
	for _, ue := range s.ueManager.List() {
		ue.Lock()
		match := ue.ENBGlobalID == remoteAddr && ue.ENBS1APID == enbUEID
		ue.Unlock()
		if match {
			return ue, true
		}
	}
	return nil, false
}

func truncateHex(b []byte, max int) string {
	if max > 0 && len(b) > max {
		return hex.EncodeToString(b[:max]) + "..."
	}
	return hex.EncodeToString(b)
}
