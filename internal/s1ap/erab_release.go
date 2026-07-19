package s1ap

import (
	"fmt"
	"sort"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/gtpv2"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"github.com/vectorcore/mme/internal/uecontext"
)

type ERABReleaseItem struct {
	EBI        uint8
	CauseGroup ies.CauseGroup
	Cause      uint8
}

type ERABReleaseResponse struct {
	MMEUEID   uint32
	ENBUEID   uint32
	Released  []uint8
	Failed    []uint8
	UnknownIE []uint16
}

type dedicatedDeleteBearerReleaseOutcome struct {
	Cause       uint8
	ReleasedEBI []uint8
	FailedEBI   []uint8
	MissingEBI  []uint8
}

func (s *Server) SendERABReleaseRequestTracked(mmeUEID uint32, items []ERABReleaseItem, procedureKind string, transactionID string) error {
	if len(items) == 0 {
		return fmt.Errorf("s1ap: E-RAB Release Request requires at least one item")
	}
	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		return fmt.Errorf("s1ap: UE %d not found", mmeUEID)
	}
	ue.Lock()
	enbAddr := ue.ENBGlobalID
	enbS1APID := ue.ENBS1APID
	bindingGeneration := ue.S1BindingGeneration
	ue.Unlock()
	if enbAddr == "" || enbS1APID == 0 {
		return fmt.Errorf("s1ap: UE %d has no active S1 binding", mmeUEID)
	}
	if transactionID != "" {
		ebis := make([]uint8, 0, len(items))
		for _, item := range items {
			ebis = append(ebis, item.EBI)
		}
		s.registerPendingERABProcedureForEBIs(ue, transactionID, procedureKind, bindingGeneration, ebis)
	}

	msg, err := BuildERABReleaseRequest(mmeUEID, enbS1APID, items)
	if err != nil {
		if transactionID != "" {
			s.unregisterPendingERABProcedure(ue, transactionID)
		}
		return err
	}
	if err := s.sendToAddr(enbAddr, msg); err != nil {
		if transactionID != "" {
			s.unregisterPendingERABProcedure(ue, transactionID)
		}
		return err
	}
	return nil
}

func BuildERABReleaseRequest(mmeUEID uint32, enbS1APID uint32, items []ERABReleaseItem) ([]byte, error) {
	if len(items) == 0 {
		return nil, fmt.Errorf("s1ap: E-RAB Release Request requires at least one item")
	}
	seenEBI := make(map[uint8]struct{}, len(items))
	for _, item := range items {
		if item.EBI > 15 {
			return nil, fmt.Errorf("s1ap: invalid E-RAB ID %d", item.EBI)
		}
		if _, exists := seenEBI[item.EBI]; exists {
			return nil, fmt.Errorf("s1ap: duplicate E-RAB ID %d", item.EBI)
		}
		seenEBI[item.EBI] = struct{}{}
	}
	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeMMEUEApID(mmeUEID)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(enbS1APID)},
		{ID: pdu.IEERABToBeReleasedList, Criticality: aper.CriticalityIgnore, Value: encodeERABReleaseList(items)},
	}
	return pdu.BuildInitiatingMessage(pdu.ProcERABRelease, aper.CriticalityReject, ieList), nil
}

func encodeERABReleaseList(items []ERABReleaseItem) []byte {
	w := aper.NewBitWriter()
	_ = aper.EncodeConstrainedWholeNumber(w, int64(len(items)), 1, 256)
	w.AlignToByte()
	for _, item := range items {
		body := encodeERABReleaseItemBody(item)
		inner := pdu.EncodeIEContainer([]pdu.ProtocolIE{{
			ID:          pdu.IEERABItem,
			Criticality: aper.CriticalityIgnore,
			Value:       body,
		}})
		if len(inner) >= 2 {
			inner = inner[2:]
		}
		w.WriteOctets(inner)
	}
	return w.Bytes()
}

func encodeERABReleaseItemBody(item ERABReleaseItem) []byte {
	w := aper.NewBitWriter()
	w.WriteBit(0) // extension marker
	w.WriteBit(0) // iE-Extensions absent
	w.WriteBit(0) // E-RAB-ID root
	_ = aper.EncodeConstrainedWholeNumber(w, int64(item.EBI), 0, 15)
	w.WriteOctets(ies.EncodeCause(item.CauseGroup, item.Cause))
	return w.Bytes()
}

func decodeERABReleaseListBearerRelComp(data []byte) ([]uint8, error) {
	r := aper.NewBitReader(data)
	count, err := aper.DecodeConstrainedWholeNumber(r, 1, 256)
	if err != nil {
		return nil, fmt.Errorf("decode E-RAB release response list count: %w", err)
	}
	r.AlignToByte()
	out := make([]uint8, 0, int(count))
	for i := 0; i < int(count); i++ {
		ieID, err := aper.DecodeConstrainedWholeNumber(r, 0, 65535)
		if err != nil {
			return nil, fmt.Errorf("decode release response item IE ID: %w", err)
		}
		if uint16(ieID) != pdu.IEERABReleaseItemBearerRelComp {
			return nil, fmt.Errorf("unexpected E-RAB release response item IE ID %d", ieID)
		}
		if _, err := aper.DecodeCriticality(r); err != nil {
			return nil, fmt.Errorf("decode release response item criticality: %w", err)
		}
		itemBytes, err := aper.ReadOpenType(r)
		if err != nil {
			return nil, fmt.Errorf("read release response item: %w", err)
		}
		ebi, err := decodeERABReleaseItemBearerRelComp(itemBytes)
		if err != nil {
			return nil, err
		}
		out = append(out, ebi)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func decodeERABReleaseItemBearerRelComp(data []byte) (uint8, error) {
	r := aper.NewBitReader(data)
	if _, err := r.ReadBit(); err != nil {
		return 0, err
	}
	if _, err := r.ReadBit(); err != nil {
		return 0, err
	}
	ext, err := r.ReadBit()
	if err != nil {
		return 0, err
	}
	if ext != 0 {
		return 0, fmt.Errorf("unexpected E-RAB release item extension value")
	}
	id, err := aper.DecodeConstrainedWholeNumber(r, 0, 15)
	if err != nil {
		return 0, err
	}
	return uint8(id), nil
}

func decodeERABReleaseResponse(ieList []pdu.ProtocolIE) (*ERABReleaseResponse, error) {
	resp := &ERABReleaseResponse{}
	for _, ie := range ieList {
		switch ie.ID {
		case pdu.IEMMEUES1APID:
			v, err := ies.DecodeMMEUEApID(ie.Value)
			if err != nil {
				return nil, fmt.Errorf("decode MME-UE-S1AP-ID: %w", err)
			}
			resp.MMEUEID = v
		case pdu.IEENBS1APID:
			v, err := ies.DecodeENBUEApID(ie.Value)
			if err != nil {
				return nil, fmt.Errorf("decode eNB-UE-S1AP-ID: %w", err)
			}
			resp.ENBUEID = v
		case pdu.IEERABReleaseListERABRelComp:
			released, err := decodeERABReleaseListBearerRelComp(ie.Value)
			if err != nil {
				return nil, err
			}
			resp.Released = released
		case pdu.IEERABFailedToReleaseList:
			failed, err := decodeERABFailedToReleaseList(ie.Value)
			if err != nil {
				return nil, err
			}
			resp.Failed = failed
		default:
			resp.UnknownIE = append(resp.UnknownIE, ie.ID)
		}
	}
	return resp, nil
}

func decodeERABFailedToReleaseList(data []byte) ([]uint8, error) {
	items, err := decodeERABFailedToSetupList(data)
	if err != nil {
		return nil, err
	}
	out := make([]uint8, 0, len(items))
	for _, item := range items {
		out = append(out, item.EBI)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func (s *Server) handleERABReleaseComplete(remoteAddr string, p *pdu.PDU, raw []byte, ieList []pdu.ProtocolIE) {
	log := s.log.With(zap.String("remote", remoteAddr), zap.String("procedure", "ERABRelease"))
	resp, err := decodeERABReleaseResponse(ieList)
	if err != nil {
		log.Warn("s1ap: E-RAB Release Response decode failed",
			zap.Error(err),
			zap.String("raw_s1ap_hex", fmt.Sprintf("%x", raw)))
		return
	}
	ue, ok := s.findUEForUEAssociatedMessage(remoteAddr, p, resp.MMEUEID, resp.ENBUEID)
	if !ok {
		return
	}
	received := make(map[uint8]struct{}, len(resp.Released)+len(resp.Failed))
	for _, ebi := range resp.Released {
		received[ebi] = struct{}{}
	}
	for _, ebi := range resp.Failed {
		received[ebi] = struct{}{}
	}
	ue.Lock()
	proc, _, ambiguous := matchPendingERABProcedureLocked(ue, received)
	ue.Unlock()
	if proc == nil {
		log.Warn("s1ap: E-RAB Release Response could not be correlated",
			zap.Uint8s("released_ebis", resp.Released),
			zap.Uint8s("failed_ebis", resp.Failed),
			zap.Bool("ambiguous", ambiguous))
		return
	}
	switch proc.ProcedureKind {
	case "dedicated_delete_bearer":
		s.completeDedicatedDeleteBearerERABRelease(ue, proc, resp, log)
	case "dedicated_create_bearer_cleanup":
		s.completeDedicatedCreateBearerCleanupERABRelease(ue, proc, resp, log)
	case "pdn_disconnect_bearers":
		s.completePDNDisconnectERABRelease(ue, proc, resp, log)
	default:
		log.Warn("s1ap: E-RAB Release Response for unsupported procedure",
			zap.String("transaction_id", proc.TransactionID),
			zap.String("procedure_kind", proc.ProcedureKind))
	}
}

func (s *Server) completePDNDisconnectERABRelease(ue *uecontext.Context, proc *uecontext.PendingERABProcedure, resp *ERABReleaseResponse, log *zap.Logger) {
	outcome := evaluateDedicatedDeleteBearerReleaseOutcome(proc, resp)
	var linkedEBI uint8
	ue.Lock()
	for _, pdn := range ue.PDNs {
		if pdn == nil || pdn.State != "pdn-disconnect-erab-release-pending" {
			continue
		}
		linkedEBI = pdn.DefaultEBI
		pdn.State = "pdn-disconnect-erab-release-complete"
		break
	}
	for _, ebi := range outcome.ReleasedEBI {
		delete(ue.DedicatedBearers, ebi)
	}
	for _, ebi := range outcome.FailedEBI {
		delete(ue.DedicatedBearers, ebi)
	}
	for _, ebi := range outcome.MissingEBI {
		delete(ue.DedicatedBearers, ebi)
	}
	delete(ue.PendingERABProcedures, proc.TransactionID)
	ue.Unlock()

	log.Info("s1ap: PDN disconnect E-RAB release complete",
		zap.String("transaction_id", proc.TransactionID),
		zap.Uint8("linked_ebi", linkedEBI),
		zap.Uint8s("released_ebis", outcome.ReleasedEBI),
		zap.Uint8s("failed_ebis", outcome.FailedEBI),
		zap.Uint8s("missing_ebis", outcome.MissingEBI))
	if linkedEBI != 0 {
		s.sendDeleteSessionForPDN(ue, linkedEBI, log)
	}
}

func (s *Server) completeDedicatedDeleteBearerERABRelease(ue *uecontext.Context, proc *uecontext.PendingERABProcedure, resp *ERABReleaseResponse, log *zap.Logger) {
	ue.Lock()
	defer ue.Unlock()
	txKey, tx := findPendingBearerTransactionByIDLocked(ue, proc.TransactionID)
	if tx == nil || tx.Kind != bearerTxDelete {
		delete(ue.PendingERABProcedures, proc.TransactionID)
		return
	}
	outcome := evaluateDedicatedDeleteBearerReleaseOutcome(proc, resp)
	for _, ebi := range outcome.ReleasedEBI {
		delete(ue.DedicatedBearers, ebi)
	}
	for _, ebi := range outcome.FailedEBI {
		if proc := ue.DedicatedBearers[ebi]; proc != nil {
			proc.ERABEstablished = false
			proc.ERABFailed = true
			proc.State = "release-failed"
		}
	}
	for _, ebi := range outcome.MissingEBI {
		if proc := ue.DedicatedBearers[ebi]; proc != nil {
			proc.ERABEstablished = false
			proc.ERABFailed = true
			proc.State = "release-missing"
		}
	}
	delete(ue.PendingERABProcedures, proc.TransactionID)
	delete(ue.PendingBearerTransactions, txKey)
	go s.sendDeleteBearerResponse(tx.PeerAddress, tx.LocalTEID, tx.SequenceNum, outcome.Cause, deleteEBIsFromTx(tx, 0))
	log.Info("s1ap: Delete Bearer completed after E-RAB Release Response",
		zap.String("transaction_id", tx.ID),
		zap.Uint8s("released_ebis", outcome.ReleasedEBI),
		zap.Uint8s("failed_ebis", outcome.FailedEBI),
		zap.Uint8s("missing_ebis", outcome.MissingEBI),
		zap.Uint8("response_cause", outcome.Cause))
}

func (s *Server) completeDedicatedCreateBearerCleanupERABRelease(ue *uecontext.Context, proc *uecontext.PendingERABProcedure, resp *ERABReleaseResponse, log *zap.Logger) {
	ue.Lock()
	defer ue.Unlock()
	txKey, tx := findPendingBearerTransactionByIDLocked(ue, proc.TransactionID)
	if tx == nil || tx.Kind != bearerTxCreate {
		delete(ue.PendingERABProcedures, proc.TransactionID)
		return
	}
	outcome := evaluateDedicatedDeleteBearerReleaseOutcome(proc, resp)
	for _, ebi := range outcome.ReleasedEBI {
		if bearer := tx.Bearers[ebi]; bearer != nil {
			bearer.ERABEstablished = false
			bearer.ENBS1UTEID = 0
			bearer.ENBS1UIP = nil
		}
	}
	for _, ebi := range outcome.FailedEBI {
		if bearer := tx.Bearers[ebi]; bearer != nil {
			bearer.ERABEstablished = false
			bearer.ERABFailed = true
			bearer.ENBS1UTEID = 0
			bearer.ENBS1UIP = nil
		}
	}
	for _, ebi := range outcome.MissingEBI {
		if bearer := tx.Bearers[ebi]; bearer != nil {
			bearer.ERABEstablished = false
			bearer.ERABFailed = true
			bearer.ENBS1UTEID = 0
			bearer.ENBS1UIP = nil
		}
	}
	s.finalizeCreateBearerTransactionLocked(ue, txKey, tx)
	log.Info("s1ap: Create Bearer failed E-RAB cleanup complete",
		zap.String("transaction_id", tx.ID),
		zap.Uint8s("released_ebis", outcome.ReleasedEBI),
		zap.Uint8s("failed_ebis", outcome.FailedEBI),
		zap.Uint8s("missing_ebis", outcome.MissingEBI))
}

func evaluateDedicatedDeleteBearerReleaseOutcome(proc *uecontext.PendingERABProcedure, resp *ERABReleaseResponse) dedicatedDeleteBearerReleaseOutcome {
	releasedSet := make(map[uint8]struct{}, len(resp.Released))
	for _, ebi := range resp.Released {
		releasedSet[ebi] = struct{}{}
	}
	failedSet := make(map[uint8]struct{}, len(resp.Failed))
	for _, ebi := range resp.Failed {
		failedSet[ebi] = struct{}{}
	}
	outcome := dedicatedDeleteBearerReleaseOutcome{
		ReleasedEBI: make([]uint8, 0, len(resp.Released)),
		FailedEBI:   make([]uint8, 0, len(resp.Failed)),
	}
	for ebi := range proc.ExpectedEBIs {
		if _, ok := releasedSet[ebi]; ok {
			outcome.ReleasedEBI = append(outcome.ReleasedEBI, ebi)
			continue
		}
		if _, ok := failedSet[ebi]; ok {
			outcome.FailedEBI = append(outcome.FailedEBI, ebi)
			continue
		}
		outcome.MissingEBI = append(outcome.MissingEBI, ebi)
	}
	sort.Slice(outcome.ReleasedEBI, func(i, j int) bool { return outcome.ReleasedEBI[i] < outcome.ReleasedEBI[j] })
	sort.Slice(outcome.FailedEBI, func(i, j int) bool { return outcome.FailedEBI[i] < outcome.FailedEBI[j] })
	sort.Slice(outcome.MissingEBI, func(i, j int) bool { return outcome.MissingEBI[i] < outcome.MissingEBI[j] })
	switch {
	case len(outcome.ReleasedEBI) > 0 && len(outcome.FailedEBI) == 0 && len(outcome.MissingEBI) == 0:
		outcome.Cause = gtpv2.CauseRequestAccepted
	case len(outcome.ReleasedEBI) > 0:
		outcome.Cause = gtpv2.CauseRequestAcceptedPartially
	case len(outcome.FailedEBI) > 0 || len(outcome.MissingEBI) > 0:
		outcome.Cause = gtpv2.CauseRequestDenied
	default:
		outcome.Cause = gtpv2.CauseSystemFailure
	}
	return outcome
}
