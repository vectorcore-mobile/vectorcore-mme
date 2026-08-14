package s1ap

import (
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"go.uber.org/zap"
)

// handleSecondaryRATDataUsageReport decodes and logs the eNB's TS 36.413
// SECONDARY RAT DATA USAGE REPORT (procedure code 52, a Rel-15 EN-DC
// addition; class 2, no response expected). It identifies the UE from the
// well-known MME/eNB UE S1AP IDs and logs every other IE present by ID and
// length — expected to be the SecondaryRATDataUsageReportList and
// optionally a Handover-Flag — so the report is visible instead of being
// silently dropped as an unhandled procedure. The reported NR secondary-RAT
// data volumes are not yet decoded in detail or relayed to the P-GW for
// charging (see docs/VectorCore_MME_Development_Notes.md §3.7).
func (s *Server) handleSecondaryRATDataUsageReport(remoteAddr string, ieList []pdu.ProtocolIE) {
	var mmeUEID, enbUEID uint32
	var reportIEIDs []uint16
	var reportIELengths []int

	for _, ie := range ieList {
		switch ie.ID {
		case pdu.IEMMEUES1APID:
			mmeUEID, _ = ies.DecodeMMEUEApID(ie.Value)
		case pdu.IEENBS1APID:
			enbUEID, _ = ies.DecodeENBUEApID(ie.Value)
		default:
			reportIEIDs = append(reportIEIDs, ie.ID)
			reportIELengths = append(reportIELengths, len(ie.Value))
		}
	}

	log := s.log.With(
		zap.String("remote", remoteAddr),
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.Uint32("enb_ue_id", enbUEID),
	)
	if ue, ok := s.ueManager.GetByMMEID(mmeUEID); ok {
		ue.Lock()
		imsi := ue.IMSI
		ue.Unlock()
		log = log.With(zap.String("imsi", imsi))
	}

	log.Info("s1ap: Secondary RAT Data Usage Report received (decode-only; not yet relayed to P-GW for charging)",
		zap.Uint16s("report_ie_ids", reportIEIDs),
		zap.Ints("report_ie_lengths", reportIELengths))
}
