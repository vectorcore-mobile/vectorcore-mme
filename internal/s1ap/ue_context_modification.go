package s1ap

import (
	"encoding/hex"
	"fmt"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
)

// SendUEContextModificationForCSFB signals mobile originating CS Fallback to
// the eNB via the CS Fallback Indicator IE (TS 36.413 §9.1.4.8). Unlike MT
// CSFB, where paging happens before the NAS payload is decoded (so the
// indicator can ride the resuming Initial Context Setup Request, see
// s1setup.go), an MO CSFB Extended Service Request only becomes known after
// the UE already has an established NAS signalling connection - so this
// sends the minimal, otherwise-empty UE Context Modification Request TS
// 36.413 allows (only MME-UE-S1AP-ID/eNB-UE-S1AP-ID are mandatory) purely
// to carry that one IE after the fact. The eNB's response/failure is
// handled by handleUEContextModificationResponse/Failure above, which only
// log - there is nothing further for the MME to do once the eNB
// acknowledges the redirection.
func (s *Server) SendUEContextModificationForCSFB(mmeUEID uint32) error {
	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		return fmt.Errorf("s1ap: UE %d not found", mmeUEID)
	}
	ue.Lock()
	enbAddr := ue.ENBGlobalID
	enbUEID := ue.ENBS1APID
	ue.Unlock()
	if enbAddr == "" {
		return fmt.Errorf("s1ap: UE %d has no active S1 binding", mmeUEID)
	}

	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeMMEUEApID(mmeUEID)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(enbUEID)},
		{ID: pdu.IECSFallbackIndicator, Criticality: aper.CriticalityReject, Value: ies.EncodeCSFallbackIndicator()},
	}
	msg := pdu.BuildInitiatingMessage(pdu.ProcUEContextModification, aper.CriticalityReject, ieList)
	if err := s.sendToAddr(enbAddr, msg); err != nil {
		return fmt.Errorf("s1ap: UE Context Modification (CSFB) send: %w", err)
	}
	s.log.Info("s1ap: UE Context Modification Request sent (MO CSFB)",
		zap.Uint32("mme_ue_id", mmeUEID), zap.Uint32("enb_ue_id", enbUEID), zap.String("enb", enbAddr))
	metrics.S1APMessagesTotal.WithLabelValues("UEContextModification", "outbound", "sent").Inc()
	return nil
}

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
