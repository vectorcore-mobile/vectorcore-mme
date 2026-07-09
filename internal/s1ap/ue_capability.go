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

func (s *Server) handleUECapabilityInfoIndication(remoteAddr string, _ *pdu.PDU, ieList []pdu.ProtocolIE) {
	var mmeUEID uint32
	var enbUEID uint32
	var radioCapability []byte

	for _, ie := range ieList {
		switch ie.ID {
		case pdu.IEMMEUES1APID:
			id, err := ies.DecodeMMEUEApID(ie.Value)
			if err != nil {
				s.log.Warn("s1ap: UECapabilityInfoIndication MME UE S1AP ID decode error",
					zap.String("remote", remoteAddr),
					zap.Error(err))
				continue
			}
			mmeUEID = id
		case pdu.IEENBS1APID:
			id, err := ies.DecodeENBUEApID(ie.Value)
			if err != nil {
				s.log.Warn("s1ap: UECapabilityInfoIndication eNB UE S1AP ID decode error",
					zap.String("remote", remoteAddr),
					zap.Error(err))
				continue
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
				continue
			}
			radioCapability = capability
		}
	}

	ue, ok := s.findUEByS1APIDs(remoteAddr, mmeUEID, enbUEID)
	if ok && len(radioCapability) > 0 {
		ue.Lock()
		ue.UERadioCapability = append(ue.UERadioCapability[:0], radioCapability...)
		ue.UpdatedAt = time.Now()
		ue.Unlock()
	}

	fields := []zap.Field{
		zap.String("remote", remoteAddr),
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.Uint32("enb_ue_id", enbUEID),
		zap.Int("ue_radio_capability_len", len(radioCapability)),
		zap.String("ue_radio_capability_hex", truncateHex(radioCapability, ueRadioCapabilityLogBytes)),
	}
	if !ok {
		fields = append(fields, zap.Bool("ue_context_found", false))
		s.log.Warn("s1ap: UECapabilityInfoIndication received for unknown UE", fields...)
		return
	}

	s.log.Info("s1ap: UECapabilityInfoIndication received", fields...)
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
