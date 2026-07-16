package s1ap

import (
	"encoding/hex"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
)

func (s *Server) handleUEContextModificationResponse(remoteAddr string, p *pdu.PDU, ieList []pdu.ProtocolIE) {
	mmeUEID, enbUEID := extractUEIDsFromIEList(ieList)
	fields := []zap.Field{
		zap.String("remote", remoteAddr),
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.Uint32("enb_ue_id", enbUEID),
	}
	for _, ie := range ieList {
		if ie.ID != pdu.IECriticalityDiagnostics {
			continue
		}
		fields = append(fields, decodeCriticalityDiagnosticsFields(ie.Value)...)
	}
	if p != nil {
		fields = append(fields, zap.String("raw_pdu_hex", hex.EncodeToString(p.Raw)))
	}
	s.log.Info("s1ap: UE Context Modification Response received", fields...)
	metrics.S1APMessagesTotal.WithLabelValues("UEContextModification", "inbound", "success").Inc()
}

func (s *Server) handleUEContextModificationFailure(remoteAddr string, p *pdu.PDU, ieList []pdu.ProtocolIE) {
	mmeUEID, enbUEID := extractUEIDsFromIEList(ieList)
	fields := []zap.Field{
		zap.String("remote", remoteAddr),
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.Uint32("enb_ue_id", enbUEID),
	}
	for _, ie := range ieList {
		switch ie.ID {
		case pdu.IECause:
			if group, cause, err := ies.DecodeCause(ie.Value); err == nil {
				fields = append(fields,
					zap.String("cause_group_name", ies.CauseGroupName(group)),
					zap.Uint8("cause", cause),
					zap.String("cause_name", ies.CauseName(group, cause)))
			}
		case pdu.IECriticalityDiagnostics:
			fields = append(fields, decodeCriticalityDiagnosticsFields(ie.Value)...)
		}
	}
	if p != nil {
		fields = append(fields, zap.String("raw_pdu_hex", hex.EncodeToString(p.Raw)))
	}
	s.log.Warn("s1ap: UE Context Modification Failure received", fields...)
	metrics.S1APMessagesTotal.WithLabelValues("UEContextModification", "inbound", "failure").Inc()
}
