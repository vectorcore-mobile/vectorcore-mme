package s1ap

import (
	"encoding/hex"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
)

type criticalityDiagnosticItem struct {
	Criticality aper.Criticality
	IEID        uint16
	TypeOfError uint8
}

const (
	typeOfErrorNotUnderstood uint8 = 0
	typeOfErrorMissing       uint8 = 1
)

func (s *Server) sendErrorIndication(remoteAddr string, trigger *pdu.PDU, mmeUEID, enbUEID uint32, group ies.CauseGroup, cause uint8, items ...criticalityDiagnosticItem) {
	ieList := make([]pdu.ProtocolIE, 0, 4)
	if mmeUEID != 0 {
		ieList = append(ieList, pdu.ProtocolIE{
			ID:          pdu.IEMMEUES1APID,
			Criticality: aper.CriticalityIgnore,
			Value:       ies.EncodeMMEUEApID(mmeUEID),
		})
	}
	if enbUEID != 0 {
		ieList = append(ieList, pdu.ProtocolIE{
			ID:          pdu.IEENBS1APID,
			Criticality: aper.CriticalityIgnore,
			Value:       ies.EncodeENBUEApID(enbUEID),
		})
	}
	ieList = append(ieList, pdu.ProtocolIE{
		ID:          pdu.IECause,
		Criticality: aper.CriticalityIgnore,
		Value:       ies.EncodeCause(group, cause),
	})
	if trigger != nil {
		ieList = append(ieList, pdu.ProtocolIE{
			ID:          pdu.IECriticalityDiagnostics,
			Criticality: aper.CriticalityIgnore,
			Value:       encodeCriticalityDiagnostics(trigger.ProcedureCode, trigger.Type, trigger.Criticality, items),
		})
	}

	msg := pdu.BuildInitiatingMessage(pdu.ProcErrorIndication, aper.CriticalityIgnore, ieList)
	s.log.Warn("s1ap: sending ErrorIndication",
		zap.String("remote", remoteAddr),
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.Uint32("enb_ue_id", enbUEID),
		zap.String("cause_group_name", ies.CauseGroupName(group)),
		zap.Uint8("cause", cause),
		zap.String("cause_name", ies.CauseName(group, cause)),
		zap.String("s1ap_hex", hex.EncodeToString(msg)))
	if err := s.sendToAddr(remoteAddr, msg); err != nil {
		s.log.Warn("s1ap: ErrorIndication send failed", zap.String("remote", remoteAddr), zap.Error(err))
		return
	}
	metrics.S1APMessagesTotal.WithLabelValues("ErrorIndication", "outbound", "ok").Inc()
}

func encodeCriticalityDiagnostics(procCode uint8, triggeringMessage pdu.PDUType, procCriticality aper.Criticality, items []criticalityDiagnosticItem) []byte {
	w := aper.NewBitWriter()
	w.WriteBit(0)
	w.WriteBit(1)
	w.WriteBit(1)
	w.WriteBit(1)
	if len(items) > 0 {
		w.WriteBit(1)
	} else {
		w.WriteBit(0)
	}
	w.WriteBit(0)
	w.AlignToByte()
	w.WriteOctet(procCode)
	w.WriteBits(uint64(triggeringMessage), 2)
	aper.EncodeCriticality(w, procCriticality)
	if len(items) > 0 {
		_ = aper.EncodeConstrainedWholeNumber(w, int64(len(items)), 1, 256)
		for _, item := range items {
			w.WriteBit(0)
			w.WriteBit(0)
			aper.EncodeCriticality(w, item.Criticality)
			_ = aper.EncodeConstrainedWholeNumber(w, int64(item.IEID), 0, 65535)
			w.WriteBit(0)
			_ = aper.EncodeConstrainedWholeNumber(w, int64(item.TypeOfError), 0, 1)
		}
	}
	return w.Bytes()
}
