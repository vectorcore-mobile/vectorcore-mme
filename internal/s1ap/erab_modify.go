package s1ap

import (
	"encoding/hex"
	"fmt"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/gtpv2"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"github.com/vectorcore/mme/internal/uecontext"
)

type ERABModifyItem struct {
	EBI                     uint8
	QCI                     uint8
	ARPPriority             uint8
	PreemptionCapability    bool
	PreemptionVulnerability bool
	BearerQoS               []byte
	NASPDU                  []byte
}

type ERABModifyResponse struct {
	MMEUEID                uint32
	ENBUEID                uint32
	Successful             []uint8
	Failed                 []ERABSetupFailure
	CriticalityDiagnostics []byte
}

func (s *Server) SendERABModifyRequestTracked(mmeUEID uint32, items []ERABModifyItem, procedureKind string, transactionID string) error {
	if len(items) == 0 {
		return fmt.Errorf("s1ap: E-RAB Modify Request requires at least one item")
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

	msg, err := BuildERABModifyRequest(mmeUEID, enbS1APID, nil, items)
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

func BuildERABModifyRequest(mmeUEID uint32, enbS1APID uint32, ueAMBR *UEAggregateMaximumBitrate, items []ERABModifyItem) ([]byte, error) {
	if len(items) == 0 {
		return nil, fmt.Errorf("s1ap: E-RAB Modify Request requires at least one item")
	}
	seenEBI := make(map[uint8]struct{}, len(items))
	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeMMEUEApID(mmeUEID)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(enbS1APID)},
	}
	if ueAMBR != nil {
		ieList = append(ieList, pdu.ProtocolIE{
			ID:          pdu.IEUEAggregateMaxBitrate,
			Criticality: aper.CriticalityReject,
			Value:       ies.EncodeUEAggregateMaxBitrate(ueAMBR.Downlink, ueAMBR.Uplink),
		})
	}
	for _, item := range items {
		if item.EBI > 15 {
			return nil, fmt.Errorf("s1ap: invalid E-RAB ID %d", item.EBI)
		}
		if _, exists := seenEBI[item.EBI]; exists {
			return nil, fmt.Errorf("s1ap: duplicate E-RAB ID %d", item.EBI)
		}
		seenEBI[item.EBI] = struct{}{}
		if len(item.NASPDU) == 0 {
			return nil, fmt.Errorf("s1ap: E-RAB %d modify requires NAS-PDU", item.EBI)
		}
	}
	ieList = append(ieList, pdu.ProtocolIE{
		ID:          pdu.IEERABToBeModifiedListBearerModReq,
		Criticality: aper.CriticalityReject,
		Value:       encodeERABModifyListBearerModReq(items),
	})
	return pdu.BuildInitiatingMessage(pdu.ProcERABModify, aper.CriticalityReject, ieList), nil
}

func encodeERABModifyListBearerModReq(items []ERABModifyItem) []byte {
	ow := aper.NewBitWriter()
	_ = aper.EncodeConstrainedWholeNumber(ow, int64(len(items)), 1, 256)
	ow.AlignToByte()
	for _, item := range items {
		itemBody := encodeERABModifyItemBody(item)
		inner := pdu.EncodeIEContainer([]pdu.ProtocolIE{{
			ID:          pdu.IEERABToBeModifiedItemBearerModReq,
			Criticality: aper.CriticalityReject,
			Value:       itemBody,
		}})
		if len(inner) >= 2 {
			inner = inner[2:]
		}
		ow.WriteOctets(inner)
	}
	return ow.Bytes()
}

func encodeERABModifyItemBody(item ERABModifyItem) []byte {
	qci := item.QCI
	if qci == 0 {
		qci = 9
	}
	arp := item.ARPPriority
	if arp == 0 {
		arp = 8
	}
	gbrInfo, gbrPresent := deriveGBRQosInformation(item.BearerQoS)

	w := aper.NewBitWriter()
	w.WriteBit(0) // extension marker
	w.WriteBit(0) // iE-Extensions absent
	w.WriteBit(0)
	_ = aper.EncodeConstrainedWholeNumber(w, int64(item.EBI), 0, 15)

	w.WriteBit(0) // QoS extension marker
	if gbrPresent {
		w.WriteBit(1)
	} else {
		w.WriteBit(0)
	}
	w.WriteBit(0) // iE-Extensions absent
	_ = aper.EncodeConstrainedWholeNumber(w, int64(qci), 0, 255)

	w.WriteBit(0) // ARP extension marker
	w.WriteBit(0) // iE-Extensions absent
	_ = aper.EncodeConstrainedWholeNumber(w, int64(arp), 0, 15)
	if item.PreemptionCapability {
		_ = aper.EncodeConstrainedWholeNumber(w, 1, 0, 1)
	} else {
		_ = aper.EncodeConstrainedWholeNumber(w, 0, 0, 1)
	}
	if item.PreemptionVulnerability {
		_ = aper.EncodeConstrainedWholeNumber(w, 1, 0, 1)
	} else {
		_ = aper.EncodeConstrainedWholeNumber(w, 0, 0, 1)
	}
	if gbrPresent {
		w.WriteBit(0)
		w.WriteBit(0)
		encodeBitRateForERABSetup(w, gbrInfo.MaxBitrateDL)
		encodeBitRateForERABSetup(w, gbrInfo.MaxBitrateUL)
		encodeBitRateForERABSetup(w, gbrInfo.GuaranteedBitrateDL)
		encodeBitRateForERABSetup(w, gbrInfo.GuaranteedBitrateUL)
	}

	w.AlignToByte()
	_ = aper.EncodeLength(w, len(item.NASPDU), 0, -1)
	w.WriteOctets(item.NASPDU)
	return w.Bytes()
}

func decodeERABModifyResponseList(data []byte) ([]uint8, error) {
	r := aper.NewBitReader(data)
	count, err := aper.DecodeConstrainedWholeNumber(r, 1, 256)
	if err != nil {
		return nil, fmt.Errorf("decode E-RAB modify response list count: %w", err)
	}
	r.AlignToByte()
	out := make([]uint8, 0, int(count))
	for i := 0; i < int(count); i++ {
		ieID, err := aper.DecodeConstrainedWholeNumber(r, 0, 65535)
		if err != nil {
			return nil, fmt.Errorf("decode E-RAB modify response item IE ID: %w", err)
		}
		if uint16(ieID) != pdu.IEERABModifyItemBearerModRes {
			return nil, fmt.Errorf("unexpected E-RAB modify response item IE ID %d", ieID)
		}
		if _, err := aper.DecodeCriticality(r); err != nil {
			return nil, fmt.Errorf("decode E-RAB modify response item criticality: %w", err)
		}
		itemBytes, err := aper.ReadOpenType(r)
		if err != nil {
			return nil, fmt.Errorf("read E-RAB modify response item: %w", err)
		}
		ebi, err := decodeERABModifyResponseItem(itemBytes)
		if err != nil {
			return nil, err
		}
		out = append(out, ebi)
	}
	return out, nil
}

func decodeERABModifyResponseItem(data []byte) (uint8, error) {
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
		return 0, fmt.Errorf("unexpected E-RAB modify item extension value")
	}
	id, err := aper.DecodeConstrainedWholeNumber(r, 0, 15)
	if err != nil {
		return 0, err
	}
	return uint8(id), nil
}

func decodeERABModifyResponse(ieList []pdu.ProtocolIE) (*ERABModifyResponse, error) {
	resp := &ERABModifyResponse{}
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
		case pdu.IEERABModifyListBearerModRes:
			modified, err := decodeERABModifyResponseList(ie.Value)
			if err != nil {
				return nil, err
			}
			resp.Successful = modified
		case pdu.IEERABFailedToModifyList:
			failed, err := decodeERABFailedToSetupList(ie.Value)
			if err != nil {
				return nil, err
			}
			resp.Failed = failed
		case pdu.IECriticalityDiagnostics:
			resp.CriticalityDiagnostics = append([]byte(nil), ie.Value...)
		}
	}
	return resp, nil
}

func (s *Server) handleERABModifyResponse(remoteAddr string, p *pdu.PDU, raw []byte, ieList []pdu.ProtocolIE) {
	log := s.log.With(zap.String("remote", remoteAddr), zap.String("procedure", "ERABModify"))
	resp, err := decodeERABModifyResponse(ieList)
	if err != nil {
		log.Warn("s1ap: E-RAB Modify Response decode failed",
			zap.Error(err),
			zap.String("raw_s1ap_hex", hex.EncodeToString(raw)))
		return
	}
	ue, ok := s.findUEForUEAssociatedMessage(remoteAddr, p, resp.MMEUEID, resp.ENBUEID)
	if !ok {
		return
	}
	received := make(map[uint8]struct{}, len(resp.Successful)+len(resp.Failed))
	for _, ebi := range resp.Successful {
		received[ebi] = struct{}{}
	}
	for _, failure := range resp.Failed {
		received[failure.EBI] = struct{}{}
	}
	ue.Lock()
	proc, _, ambiguous := matchPendingERABProcedureLocked(ue, received)
	ue.Unlock()
	if proc == nil {
		log.Warn("s1ap: E-RAB Modify Response could not be correlated",
			zap.Uint8s("modified_ebis", resp.Successful),
			zap.Bool("ambiguous", ambiguous))
		return
	}
	switch proc.ProcedureKind {
	case "dedicated_update_bearer":
		s.completeDedicatedUpdateBearerERABModify(ue, proc, resp, log)
	default:
		log.Warn("s1ap: E-RAB Modify Response for unsupported procedure",
			zap.String("transaction_id", proc.TransactionID),
			zap.String("procedure_kind", proc.ProcedureKind))
	}
}

func (s *Server) handleERABModifyFailure(remoteAddr string, p *pdu.PDU, ieList []pdu.ProtocolIE) {
	var mmeUEID uint32
	var enbUEID uint32
	var causeGroup ies.CauseGroup
	var cause uint8
	for _, ie := range ieList {
		switch ie.ID {
		case pdu.IEMMEUES1APID:
			if v, err := ies.DecodeMMEUEApID(ie.Value); err == nil {
				mmeUEID = v
			}
		case pdu.IEENBS1APID:
			if v, err := ies.DecodeENBUEApID(ie.Value); err == nil {
				enbUEID = v
			}
		case pdu.IECause:
			if g, c, err := ies.DecodeCause(ie.Value); err == nil {
				causeGroup = g
				cause = c
			}
		}
	}
	ue, ok := s.findUEForUEAssociatedMessage(remoteAddr, p, mmeUEID, enbUEID)
	if !ok {
		return
	}
	ue.Lock()
	var proc *uecontext.PendingERABProcedure
	for _, pending := range ue.PendingERABProcedures {
		if pending != nil && pending.ProcedureKind == "dedicated_update_bearer" {
			proc = pending
			break
		}
	}
	ue.Unlock()
	if proc == nil {
		return
	}
	s.failUpdateBearerTransactionByID(ue, proc.TransactionID, gtpv2.CauseRequestRejected)
	s.log.Warn("s1ap: E-RAB Modify Failure rejected dedicated bearer update",
		zap.String("remote", remoteAddr),
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.Uint32("enb_ue_id", enbUEID),
		zap.String("transaction_id", proc.TransactionID),
		zap.String("cause_group", ies.CauseGroupName(causeGroup)),
		zap.Uint8("cause", cause))
}

func (s *Server) completeDedicatedUpdateBearerERABModify(ue *uecontext.Context, proc *uecontext.PendingERABProcedure, resp *ERABModifyResponse, log *zap.Logger) {
	ue.Lock()
	defer ue.Unlock()
	txKey, tx := findPendingBearerTransactionByIDLocked(ue, proc.TransactionID)
	if tx == nil || tx.Kind != bearerTxUpdate {
		delete(ue.PendingERABProcedures, proc.TransactionID)
		return
	}
	for _, ebi := range resp.Successful {
		if bearer := tx.Bearers[ebi]; bearer != nil {
			bearer.ERABEstablished = true
			bearer.ERABFailed = false
		}
	}
	for _, failure := range resp.Failed {
		if bearer := tx.Bearers[failure.EBI]; bearer != nil {
			bearer.ERABFailed = true
			bearer.ERABEstablished = false
		}
	}
	s.maybeCompleteUpdateBearerLocked(ue, txKey, tx)
	_ = log
}
