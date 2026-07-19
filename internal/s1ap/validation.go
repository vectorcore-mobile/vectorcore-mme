package s1ap

import (
	"fmt"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"github.com/vectorcore/mme/internal/uecontext"
)

type procedureValidationIssue struct {
	Kind     string
	IEID     uint16
	Name     string
	Expected aper.Criticality
	Actual   aper.Criticality
}

func (s *Server) validateInboundProcedureIEs(remoteAddr string, p *pdu.PDU, ieList []pdu.ProtocolIE) bool {
	if p == nil {
		return true
	}
	issues := validateProcedureIEs(p.ProcedureCode, p.Type, ieList)
	if len(issues) == 0 {
		return true
	}
	mmeUEID, enbUEID := extractUEIDsFromIEList(ieList)
	fields := []zap.Field{
		zap.String("remote", remoteAddr),
		zap.Uint8("procedure_code", p.ProcedureCode),
		zap.String("triggering_message", p.Type.String()),
	}
	for _, issue := range issues {
		fields = append(fields,
			zap.String("validation_issue", issue.Kind),
			zap.Uint16("ie_id", issue.IEID),
			zap.String("ie_name", issue.Name))
		if issue.Kind == "unexpected-criticality" {
			fields = append(fields,
				zap.String("actual_criticality", issue.Actual.String()),
				zap.String("expected_criticality", issue.Expected.String()))
		}
	}
	s.log.Warn("s1ap: inbound procedure IE validation failed", fields...)
	if p.Type != pdu.PDUTypeInitiatingMessage {
		return false
	}
	fatalIssues := make([]procedureValidationIssue, 0, len(issues))
	notifyOnlyIssues := make([]procedureValidationIssue, 0, len(issues))
	for _, issue := range issues {
		if issue.Kind == "unknown-ie-notify" {
			notifyOnlyIssues = append(notifyOnlyIssues, issue)
			continue
		}
		fatalIssues = append(fatalIssues, issue)
	}
	if len(notifyOnlyIssues) > 0 {
		s.sendErrorIndication(remoteAddr, p, mmeUEID, enbUEID, ies.CauseGroupProtocol, ies.CauseProtocolAbstractSyntaxErrorIgnoreAndNotify, validationIssuesToDiagnostics(notifyOnlyIssues)...)
	}
	if len(fatalIssues) == 0 {
		return true
	}
	cause := ies.CauseProtocolSemanticError
	for _, issue := range fatalIssues {
		if issue.Kind == "duplicate-ie" || issue.Kind == "out-of-order-ie" {
			cause = ies.CauseProtocolFalselyConstructedMessage
			break
		}
	}
	s.sendErrorIndication(remoteAddr, p, mmeUEID, enbUEID, ies.CauseGroupProtocol, cause, validationIssuesToDiagnostics(fatalIssues)...)
	return false
}

func validateProcedureIEs(procCode uint8, pduType pdu.PDUType, ieList []pdu.ProtocolIE) []procedureValidationIssue {
	expected := map[uint16]pdu.IEInfo{}
	for key, info := range pdu.Phase1ProcedureIEs {
		if key.ProcedureCode == procCode && key.PDUType == pduType {
			expected[key.IEID] = info
		}
	}
	if len(expected) == 0 {
		return nil
	}

	seen := make(map[uint16]struct{}, len(ieList))
	issues := make([]procedureValidationIssue, 0)
	ordering := procedureIEOrder(procCode, pduType)
	lastOrder := -1
	for _, ie := range ieList {
		info, ok := expected[ie.ID]
		if !ok {
			if ie.Criticality == aper.CriticalityReject {
				issues = append(issues, procedureValidationIssue{
					Kind:     "unknown-ie-reject",
					IEID:     ie.ID,
					Name:     fmt.Sprintf("unknown-%d", ie.ID),
					Expected: aper.CriticalityReject,
					Actual:   ie.Criticality,
				})
			} else if ie.Criticality == aper.CriticalityNotify {
				issues = append(issues, procedureValidationIssue{
					Kind:     "unknown-ie-notify",
					IEID:     ie.ID,
					Name:     fmt.Sprintf("unknown-%d", ie.ID),
					Expected: aper.CriticalityNotify,
					Actual:   ie.Criticality,
				})
			}
			continue
		}
		if _, ok := seen[ie.ID]; ok {
			issues = append(issues, procedureValidationIssue{
				Kind:     "duplicate-ie",
				IEID:     ie.ID,
				Name:     info.Name,
				Expected: info.Criticality,
				Actual:   ie.Criticality,
			})
			continue
		}
		seen[ie.ID] = struct{}{}
		if len(ordering) > 0 {
			orderIdx, ok := ordering[ie.ID]
			if ok {
				if orderIdx < lastOrder {
					issues = append(issues, procedureValidationIssue{
						Kind:     "out-of-order-ie",
						IEID:     ie.ID,
						Name:     info.Name,
						Expected: info.Criticality,
						Actual:   ie.Criticality,
					})
				} else {
					lastOrder = orderIdx
				}
			}
		}
		if ie.Criticality != info.Criticality {
			issues = append(issues, procedureValidationIssue{
				Kind:     "unexpected-criticality",
				IEID:     ie.ID,
				Name:     info.Name,
				Expected: info.Criticality,
				Actual:   ie.Criticality,
			})
		}
	}
	for ieID, info := range expected {
		if info.Presence != pdu.IEPresenceMandatory {
			continue
		}
		if _, ok := seen[ieID]; ok {
			continue
		}
		issues = append(issues, procedureValidationIssue{
			Kind:     "missing-mandatory-ie",
			IEID:     ieID,
			Name:     info.Name,
			Expected: info.Criticality,
		})
	}
	return issues
}

func validationIssuesToDiagnostics(issues []procedureValidationIssue) []criticalityDiagnosticItem {
	items := make([]criticalityDiagnosticItem, 0, len(issues))
	for _, issue := range issues {
		item := criticalityDiagnosticItem{
			Criticality: issue.Expected,
			IEID:        issue.IEID,
			TypeOfError: typeOfErrorNotUnderstood,
		}
		switch issue.Kind {
		case "missing-mandatory-ie":
			item.TypeOfError = typeOfErrorMissing
		default:
			item.TypeOfError = typeOfErrorNotUnderstood
		}
		items = append(items, item)
	}
	return items
}

func procedureIEOrder(procCode uint8, pduType pdu.PDUType) map[uint16]int {
	key := pdu.ProcedureIEKey{ProcedureCode: procCode, PDUType: pduType}
	if seq, ok := pdu.Phase1ProcedureIEOrder[key]; ok {
		ordering := make(map[uint16]int, len(seq))
		for idx, ieID := range seq {
			ordering[ieID] = idx
		}
		return ordering
	}
	return nil
}

func extractUEIDsFromIEList(ieList []pdu.ProtocolIE) (uint32, uint32) {
	var mmeUEID uint32
	var enbUEID uint32
	for _, ie := range ieList {
		switch ie.ID {
		case pdu.IEMMEUES1APID:
			if id, err := ies.DecodeMMEUEApID(ie.Value); err == nil {
				mmeUEID = id
			}
		case pdu.IEENBS1APID:
			if id, err := ies.DecodeENBUEApID(ie.Value); err == nil {
				enbUEID = id
			}
		}
	}
	return mmeUEID, enbUEID
}

func (s *Server) findUEForUEAssociatedMessage(remoteAddr string, p *pdu.PDU, mmeUEID, enbUEID uint32) (*uecontext.Context, bool) {
	if mmeUEID == 0 {
		if enbUEID != 0 {
			if ue, ok := s.findUEByS1APIDs(remoteAddr, 0, enbUEID); ok {
				return ue, true
			}
		}
		s.sendErrorIndication(remoteAddr, p, 0, enbUEID, ies.CauseGroupProtocol, ies.CauseProtocolSemanticError)
		return nil, false
	}
	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		s.sendErrorIndication(remoteAddr, p, mmeUEID, enbUEID, ies.CauseGroupRadioNetwork, ies.CauseRadioNetworkUnknownMMEUES1APID)
		return nil, false
	}

	ue.Lock()
	boundRemote := ue.ENBGlobalID
	boundENBID := ue.ENBS1APID
	ue.Unlock()

	if enbUEID == 0 {
		s.sendErrorIndication(remoteAddr, p, mmeUEID, 0, ies.CauseGroupProtocol, ies.CauseProtocolSemanticError)
		return nil, false
	}
	if boundRemote != "" && boundRemote != remoteAddr {
		s.sendErrorIndication(remoteAddr, p, mmeUEID, enbUEID, ies.CauseGroupRadioNetwork, ies.CauseRadioNetworkUnknownMMEUES1APID)
		return nil, false
	}
	if boundENBID != 0 && boundENBID != enbUEID {
		s.sendErrorIndication(remoteAddr, p, mmeUEID, enbUEID, ies.CauseGroupRadioNetwork, ies.CauseRadioNetworkUnknownPairUES1APID)
		return nil, false
	}
	return ue, true
}
