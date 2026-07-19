package s1ap

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/gtpv2"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"github.com/vectorcore/mme/internal/uecontext"
)

type erabModificationIndicationItem struct {
	EBI  uint8
	TEID uint32
	IP   net.IP
}

type erabModificationFailure struct {
	EBI        uint8
	CauseGroup ies.CauseGroup
	Cause      uint8
}

type erabModificationIndication struct {
	MMEUEID     uint32
	ENBUEID     uint32
	Modified    []erabModificationIndicationItem
	NotModified []erabModificationIndicationItem
	UnknownIE   []uint16
}

type pendingERABModificationIndication struct {
	RemoteAddr        string
	MMEUEID           uint32
	ENBUEID           uint32
	CorrelationID     string
	RequestedModified map[uint8]erabModificationIndicationItem
	DesiredByEBI      map[uint8]erabModificationIndicationItem
	ImmediateFailures []erabModificationFailure
}

func (s *Server) handleERABModificationIndication(remoteAddr string, p *pdu.PDU, ieList []pdu.ProtocolIE) {
	log := s.log.With(zap.String("remote", remoteAddr), zap.String("procedure", "ERABModificationIndication"))
	ind, err := decodeERABModificationIndication(ieList)
	if err != nil {
		log.Warn("s1ap: E-RAB Modification Indication decode failed", zap.Error(err))
		return
	}
	ue, ok := s.findUEForUEAssociatedMessage(remoteAddr, p, ind.MMEUEID, ind.ENBUEID)
	if !ok {
		return
	}

	correlationID, req, pending, finalFailures, err := s.prepareERABModificationMBR(ue, remoteAddr, ind)
	if err != nil {
		log.Warn("s1ap: E-RAB Modification Indication preparation failed", zap.Error(err))
		return
	}
	if len(pending.RequestedModified) == 0 {
		sort.Slice(finalFailures, func(i, j int) bool { return finalFailures[i].EBI < finalFailures[j].EBI })
		if err := s.sendERABModificationConfirm(remoteAddr, ind.MMEUEID, ind.ENBUEID, nil, finalFailures, nil); err != nil {
			log.Warn("s1ap: E-RAB Modification Confirm send failed", zap.Error(err))
		}
		return
	}
	if req == nil {
		sort.Slice(finalFailures, func(i, j int) bool { return finalFailures[i].EBI < finalFailures[j].EBI })
		if err := s.sendERABModificationConfirm(remoteAddr, ind.MMEUEID, ind.ENBUEID, nil, finalFailures, nil); err != nil {
			log.Warn("s1ap: E-RAB Modification Confirm send failed", zap.Error(err))
		}
		return
	}

	s.pendingERABModificationInds.Store(correlationID, pending)
	if err := s.s11.SendMBR(ind.MMEUEID, req); err != nil {
		s.pendingERABModificationInds.Delete(correlationID)
		finalFailures = append(finalFailures, immediateTransportFailures(pending)...)
		sort.Slice(finalFailures, func(i, j int) bool { return finalFailures[i].EBI < finalFailures[j].EBI })
		log.Warn("s1ap: E-RAB Modification Indication S11 Modify Bearer failed", zap.Error(err))
		if sendErr := s.sendERABModificationConfirm(remoteAddr, ind.MMEUEID, ind.ENBUEID, nil, finalFailures, nil); sendErr != nil {
			log.Warn("s1ap: E-RAB Modification Confirm send failed", zap.Error(sendErr))
		}
	}
}

func (s *Server) prepareERABModificationMBR(ue *uecontext.Context, remoteAddr string, ind *erabModificationIndication) (string, *gtpv2.ModifyBearerRequest, *pendingERABModificationIndication, []erabModificationFailure, error) {
	ue.Lock()
	defer ue.Unlock()

	pending := &pendingERABModificationIndication{
		RemoteAddr:        remoteAddr,
		MMEUEID:           ind.MMEUEID,
		ENBUEID:           ind.ENBUEID,
		CorrelationID:     fmt.Sprintf("erabmodind-%d-%d", ind.MMEUEID, time.Now().UnixNano()),
		RequestedModified: make(map[uint8]erabModificationIndicationItem, len(ind.Modified)),
		DesiredByEBI:      make(map[uint8]erabModificationIndicationItem, len(ind.Modified)+len(ind.NotModified)),
	}
	for _, item := range ind.Modified {
		pending.RequestedModified[item.EBI] = cloneERABModificationItem(item)
		pending.DesiredByEBI[item.EBI] = cloneERABModificationItem(item)
	}
	for _, item := range ind.NotModified {
		if _, ok := pending.DesiredByEBI[item.EBI]; ok {
			pending.ImmediateFailures = append(pending.ImmediateFailures, erabModificationFailure{
				EBI:        item.EBI,
				CauseGroup: ies.CauseGroupProtocol,
				Cause:      ies.CauseProtocolSemanticError,
			})
			delete(pending.RequestedModified, item.EBI)
			delete(pending.DesiredByEBI, item.EBI)
			continue
		}
		pending.DesiredByEBI[item.EBI] = cloneERABModificationItem(item)
	}

	affectedDefaults := make(map[uint8]struct{})
	finalFailures := append([]erabModificationFailure(nil), pending.ImmediateFailures...)
	for ebi, item := range pending.DesiredByEBI {
		if item.TEID == 0 || item.IP == nil {
			if _, requested := pending.RequestedModified[ebi]; requested {
				finalFailures = append(finalFailures, erabModificationFailure{
					EBI:        ebi,
					CauseGroup: ies.CauseGroupTransport,
					Cause:      1,
				})
			}
			delete(pending.RequestedModified, ebi)
			delete(pending.DesiredByEBI, ebi)
			continue
		}
		defaultEBI, ok := findPDNDefaultEBIForBearerLocked(ue, ebi)
		if !ok {
			if _, requested := pending.RequestedModified[ebi]; requested {
				finalFailures = append(finalFailures, erabModificationFailure{
					EBI:        ebi,
					CauseGroup: ies.CauseGroupRadioNetwork,
					Cause:      30,
				})
			}
			delete(pending.RequestedModified, ebi)
			delete(pending.DesiredByEBI, ebi)
			continue
		}
		affectedDefaults[defaultEBI] = struct{}{}
	}

	if len(pending.RequestedModified) == 0 {
		return pending.CorrelationID, nil, pending, finalFailures, nil
	}
	sgwAddr := ue.SGWAddress
	sgwcTEID := ue.SGWC_TEID
	if sgwAddr == "" || sgwcTEID == 0 {
		return pending.CorrelationID, nil, pending, append(finalFailures, immediateTransportFailures(pending)...), nil
	}

	mbrBearers, err := buildFullPDNModifyBearerSetLocked(ue, affectedDefaults, pending.DesiredByEBI)
	if err != nil {
		return "", nil, nil, nil, err
	}
	if len(mbrBearers) == 0 {
		return pending.CorrelationID, nil, pending, append(finalFailures, immediateTransportFailures(pending)...), nil
	}
	req := &gtpv2.ModifyBearerRequest{
		SGWAddress:    sgwAddr,
		SGWC_TEID:     sgwcTEID,
		Bearers:       mbrBearers,
		RATType:       gtpv2.RATTypeEUTRAN,
		CorrelationID: pending.CorrelationID,
	}
	return pending.CorrelationID, req, pending, finalFailures, nil
}

func findPDNDefaultEBIForBearerLocked(ue *uecontext.Context, ebi uint8) (uint8, bool) {
	for _, pdn := range ue.PDNs {
		if pdn == nil || pdn.DefaultEBI == 0 || !pdn.ERABEstablished || pdn.ModifyBearerFailed {
			continue
		}
		if pdn.DefaultEBI == ebi {
			return pdn.DefaultEBI, true
		}
	}
	for _, bearer := range ue.DedicatedBearers {
		if bearer == nil || bearer.AssignedEBI == 0 || !bearer.ERABEstablished {
			continue
		}
		if bearer.AssignedEBI == ebi {
			return bearer.LinkedEBI, true
		}
	}
	if ue.DefaultEBI == ebi && ue.SGWU_TEID != 0 && len(ue.SGWU_IP) != 0 {
		return ue.DefaultEBI, true
	}
	return 0, false
}

func buildFullPDNModifyBearerSetLocked(ue *uecontext.Context, affectedDefaults map[uint8]struct{}, desiredByEBI map[uint8]erabModificationIndicationItem) ([]gtpv2.ModifyBearer, error) {
	if len(affectedDefaults) == 0 {
		return nil, nil
	}
	seen := make(map[uint8]struct{})
	out := make([]gtpv2.ModifyBearer, 0, len(desiredByEBI))
	for defaultEBI := range affectedDefaults {
		item, ok := desiredOrCurrentBearerTransportLocked(ue, defaultEBI, desiredByEBI)
		if !ok {
			return nil, fmt.Errorf("missing transport for default bearer EBI %d", defaultEBI)
		}
		out = append(out, gtpv2.ModifyBearer{EBI: defaultEBI, ENBU_TEID: item.TEID, ENBU_IP: append(net.IP(nil), item.IP...)})
		seen[defaultEBI] = struct{}{}
		for _, bearer := range ue.DedicatedBearers {
			if bearer == nil || bearer.AssignedEBI == 0 || bearer.LinkedEBI != defaultEBI || !bearer.ERABEstablished {
				continue
			}
			if _, exists := seen[bearer.AssignedEBI]; exists {
				continue
			}
			item, ok := desiredOrCurrentBearerTransportLocked(ue, bearer.AssignedEBI, desiredByEBI)
			if !ok {
				return nil, fmt.Errorf("missing transport for dedicated bearer EBI %d", bearer.AssignedEBI)
			}
			out = append(out, gtpv2.ModifyBearer{EBI: bearer.AssignedEBI, ENBU_TEID: item.TEID, ENBU_IP: append(net.IP(nil), item.IP...)})
			seen[bearer.AssignedEBI] = struct{}{}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EBI < out[j].EBI })
	return out, nil
}

func desiredOrCurrentBearerTransportLocked(ue *uecontext.Context, ebi uint8, desiredByEBI map[uint8]erabModificationIndicationItem) (erabModificationIndicationItem, bool) {
	if item, ok := desiredByEBI[ebi]; ok {
		return cloneERABModificationItem(item), true
	}
	for _, pdn := range ue.PDNs {
		if pdn == nil || pdn.DefaultEBI != ebi || !pdn.ERABEstablished || pdn.ENBU_TEID == 0 || len(pdn.ENBU_IP) == 0 {
			continue
		}
		return erabModificationIndicationItem{EBI: ebi, TEID: pdn.ENBU_TEID, IP: append(net.IP(nil), pdn.ENBU_IP...)}, true
	}
	if ue.DefaultEBI == ebi && ue.ENBU_TEID != 0 && len(ue.ENBU_IP) != 0 {
		return erabModificationIndicationItem{EBI: ebi, TEID: ue.ENBU_TEID, IP: append(net.IP(nil), ue.ENBU_IP...)}, true
	}
	for _, bearer := range ue.DedicatedBearers {
		if bearer == nil || bearer.AssignedEBI != ebi || !bearer.ERABEstablished || bearer.ENBS1UTEID == 0 || len(bearer.ENBS1UIP) == 0 {
			continue
		}
		return erabModificationIndicationItem{EBI: ebi, TEID: bearer.ENBS1UTEID, IP: append(net.IP(nil), bearer.ENBS1UIP...)}, true
	}
	return erabModificationIndicationItem{}, false
}

func (s *Server) handlePendingERABModificationMBRResult(mmeUEID uint32, correlationID string, resp *gtpv2.ModifyBearerResponse, err error) bool {
	v, ok := s.pendingERABModificationInds.LoadAndDelete(correlationID)
	if !ok {
		return false
	}
	pending := v.(*pendingERABModificationIndication)
	successful, failed, toRelease := evaluateERABModificationMBRResult(pending, resp, err)
	if err == nil && resp != nil {
		s.commitSuccessfulERABModificationState(mmeUEID, pending, resp, toRelease)
	}
	sort.Slice(successful, func(i, j int) bool { return successful[i] < successful[j] })
	sort.Slice(failed, func(i, j int) bool { return failed[i].EBI < failed[j].EBI })
	sort.Slice(toRelease, func(i, j int) bool { return toRelease[i] < toRelease[j] })
	if sendErr := s.sendERABModificationConfirm(pending.RemoteAddr, pending.MMEUEID, pending.ENBUEID, successful, failed, toRelease); sendErr != nil {
		s.log.Warn("s1ap: E-RAB Modification Confirm send failed",
			zap.Uint32("mme_ue_id", mmeUEID),
			zap.String("correlation_id", correlationID),
			zap.Error(sendErr))
	}
	return true
}

func evaluateERABModificationMBRResult(pending *pendingERABModificationIndication, resp *gtpv2.ModifyBearerResponse, err error) ([]uint8, []erabModificationFailure, []uint8) {
	failed := append([]erabModificationFailure(nil), pending.ImmediateFailures...)
	if err != nil || resp == nil {
		return nil, append(failed, immediateTransportFailures(pending)...), nil
	}
	modified := make(map[uint8]gtpv2.ModifyBearerBearerResult, len(resp.ModifiedBearers))
	for _, result := range resp.ModifiedBearers {
		modified[result.EBI] = result
	}
	removed := make(map[uint8]gtpv2.ModifyBearerBearerResult, len(resp.RemovedBearers))
	for _, result := range resp.RemovedBearers {
		removed[result.EBI] = result
	}
	successful := make([]uint8, 0, len(pending.RequestedModified))
	toRelease := make([]uint8, 0)
	for ebi := range pending.RequestedModified {
		if _, ok := removed[ebi]; ok {
			toRelease = append(toRelease, ebi)
			continue
		}
		if result, ok := modified[ebi]; ok {
			if result.Cause == 0 || result.Cause == gtpv2.CauseRequestAccepted || result.Cause == gtpv2.CauseRequestAcceptedPartially {
				successful = append(successful, ebi)
				continue
			}
			failed = append(failed, mapMBRBearerFailureToS1AP(ebi, result.Cause))
			continue
		}
		if resp.Cause == gtpv2.CauseRequestAccepted && len(resp.ModifiedBearers) == 0 && len(resp.RemovedBearers) == 0 {
			successful = append(successful, ebi)
			continue
		}
		failed = append(failed, erabModificationFailure{
			EBI:        ebi,
			CauseGroup: ies.CauseGroupMisc,
			Cause:      ies.CauseMiscUnspecified,
		})
	}
	return successful, dedupeERABModificationFailures(failed), toRelease
}

func (s *Server) commitSuccessfulERABModificationState(mmeUEID uint32, pending *pendingERABModificationIndication, resp *gtpv2.ModifyBearerResponse, toRelease []uint8) {
	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		return
	}
	ue.Lock()
	defer ue.Unlock()
	for _, result := range resp.ModifiedBearers {
		if result.Cause != 0 && result.Cause != gtpv2.CauseRequestAccepted && result.Cause != gtpv2.CauseRequestAcceptedPartially {
			continue
		}
		ebi := result.EBI
		item, ok := pending.DesiredByEBI[ebi]
		if !ok {
			continue
		}
		applyCommittedERABModificationItemLocked(ue, item)
	}
	for _, ebi := range toRelease {
		if ue.DefaultEBI == ebi {
			ue.ENBU_TEID = 0
			ue.ENBU_IP = nil
		}
		for _, pdn := range ue.PDNs {
			if pdn == nil || pdn.DefaultEBI != ebi {
				continue
			}
			pdn.ENBU_TEID = 0
			pdn.ENBU_IP = nil
			pdn.ERABEstablished = false
		}
		for _, bearer := range ue.DedicatedBearers {
			if bearer == nil || bearer.AssignedEBI != ebi {
				continue
			}
			bearer.ENBS1UTEID = 0
			bearer.ENBS1UIP = nil
			bearer.ERABEstablished = false
			bearer.ERABFailed = true
			bearer.State = "release-requested"
		}
	}
}

func applyCommittedERABModificationItemLocked(ue *uecontext.Context, item erabModificationIndicationItem) {
	if ue.DefaultEBI == item.EBI {
		ue.ENBU_TEID = item.TEID
		ue.ENBU_IP = append(net.IP(nil), item.IP...)
	}
	for _, pdn := range ue.PDNs {
		if pdn == nil || pdn.DefaultEBI != item.EBI {
			continue
		}
		pdn.ENBU_TEID = item.TEID
		pdn.ENBU_IP = append(net.IP(nil), item.IP...)
	}
	for _, bearer := range ue.DedicatedBearers {
		if bearer == nil || bearer.AssignedEBI != item.EBI {
			continue
		}
		bearer.ENBS1UTEID = item.TEID
		bearer.ENBS1UIP = append(net.IP(nil), item.IP...)
	}
}

func immediateTransportFailures(pending *pendingERABModificationIndication) []erabModificationFailure {
	out := make([]erabModificationFailure, 0, len(pending.RequestedModified))
	for ebi := range pending.RequestedModified {
		out = append(out, erabModificationFailure{
			EBI:        ebi,
			CauseGroup: ies.CauseGroupTransport,
			Cause:      0,
		})
	}
	return out
}

func dedupeERABModificationFailures(items []erabModificationFailure) []erabModificationFailure {
	seen := make(map[uint8]erabModificationFailure, len(items))
	for _, item := range items {
		seen[item.EBI] = item
	}
	out := make([]erabModificationFailure, 0, len(seen))
	for _, item := range seen {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EBI < out[j].EBI })
	return out
}

func mapMBRBearerFailureToS1AP(ebi uint8, cause uint8) erabModificationFailure {
	switch cause {
	case gtpv2.CauseContextNotFound:
		return erabModificationFailure{EBI: ebi, CauseGroup: ies.CauseGroupRadioNetwork, Cause: 30}
	case gtpv2.CauseRequestRejected:
		return erabModificationFailure{EBI: ebi, CauseGroup: ies.CauseGroupMisc, Cause: ies.CauseMiscUnspecified}
	default:
		return erabModificationFailure{EBI: ebi, CauseGroup: ies.CauseGroupTransport, Cause: 1}
	}
}

func cloneERABModificationItem(item erabModificationIndicationItem) erabModificationIndicationItem {
	return erabModificationIndicationItem{
		EBI:  item.EBI,
		TEID: item.TEID,
		IP:   append(net.IP(nil), item.IP...),
	}
}

func decodeERABModificationIndication(ieList []pdu.ProtocolIE) (*erabModificationIndication, error) {
	out := &erabModificationIndication{}
	for _, ie := range ieList {
		switch ie.ID {
		case pdu.IEMMEUES1APID:
			v, err := ies.DecodeMMEUEApID(ie.Value)
			if err != nil {
				return nil, fmt.Errorf("decode MME-UE-S1AP-ID: %w", err)
			}
			out.MMEUEID = v
		case pdu.IEENBS1APID:
			v, err := ies.DecodeENBUEApID(ie.Value)
			if err != nil {
				return nil, fmt.Errorf("decode eNB-UE-S1AP-ID: %w", err)
			}
			out.ENBUEID = v
		case pdu.IEERABToBeModifiedListBearerModInd:
			items, err := decodeERABModificationIndicationList(ie.Value, pdu.IEERABToBeModifiedItemBearerModInd)
			if err != nil {
				return nil, err
			}
			out.Modified = items
		case pdu.IEERABNotToBeModifiedListBearerModInd:
			items, err := decodeERABModificationIndicationList(ie.Value, pdu.IEERABNotToBeModifiedItemBearerModInd)
			if err != nil {
				return nil, err
			}
			out.NotModified = items
		default:
			out.UnknownIE = append(out.UnknownIE, ie.ID)
		}
	}
	return out, nil
}

func decodeERABModificationIndicationList(data []byte, expectedItemIE uint16) ([]erabModificationIndicationItem, error) {
	r := aper.NewBitReader(data)
	count, err := aper.DecodeConstrainedWholeNumber(r, 1, 256)
	if err != nil {
		return nil, fmt.Errorf("decode E-RAB modification indication list count: %w", err)
	}
	r.AlignToByte()
	out := make([]erabModificationIndicationItem, 0, int(count))
	for i := 0; i < int(count); i++ {
		ieID, err := aper.DecodeConstrainedWholeNumber(r, 0, 65535)
		if err != nil {
			return nil, fmt.Errorf("decode E-RAB modification indication item IE ID: %w", err)
		}
		if uint16(ieID) != expectedItemIE {
			return nil, fmt.Errorf("unexpected E-RAB modification indication item IE ID %d", ieID)
		}
		if _, err := aper.DecodeCriticality(r); err != nil {
			return nil, fmt.Errorf("decode E-RAB modification indication item criticality: %w", err)
		}
		itemBytes, err := aper.ReadOpenType(r)
		if err != nil {
			return nil, fmt.Errorf("read E-RAB modification indication item: %w", err)
		}
		item, err := decodeERABModificationIndicationItem(itemBytes)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}

func decodeERABModificationIndicationItem(data []byte) (erabModificationIndicationItem, error) {
	ir := aper.NewBitReader(data)
	if _, err := ir.ReadBit(); err != nil {
		return erabModificationIndicationItem{}, err
	}
	if _, err := ir.ReadBit(); err != nil {
		return erabModificationIndicationItem{}, err
	}
	erabIDExt, err := ir.ReadBit()
	if err != nil {
		return erabModificationIndicationItem{}, err
	}
	if erabIDExt != 0 {
		return erabModificationIndicationItem{}, fmt.Errorf("E-RAB modification indication item ID extension not supported")
	}
	erabID, err := aper.DecodeConstrainedWholeNumber(ir, 0, 15)
	if err != nil {
		return erabModificationIndicationItem{}, err
	}
	extBit, err := ir.ReadBit()
	if err != nil {
		return erabModificationIndicationItem{}, err
	}
	ir.AlignToByte()
	var addrBits int64
	if extBit == 0 {
		addrBits, err = aper.DecodeConstrainedWholeNumber(ir, 1, 160)
	} else {
		addrBits, err = aper.DecodeConstrainedWholeNumber(ir, 0, 65535)
	}
	if err != nil {
		return erabModificationIndicationItem{}, err
	}
	ir.AlignToByte()
	addrBytes, err := ir.ReadOctets(int((addrBits + 7) / 8))
	if err != nil || len(addrBytes) < 4 {
		return erabModificationIndicationItem{}, fmt.Errorf("invalid transportLayerAddress")
	}
	ir.AlignToByte()
	teidBytes, err := ir.ReadOctets(4)
	if err != nil {
		return erabModificationIndicationItem{}, err
	}
	return erabModificationIndicationItem{
		EBI:  uint8(erabID),
		IP:   net.IP(addrBytes[:4]).To4(),
		TEID: binary.BigEndian.Uint32(teidBytes),
	}, nil
}

func (s *Server) sendERABModificationConfirm(remoteAddr string, mmeUEID uint32, enbUEID uint32, successful []uint8, failed []erabModificationFailure, toRelease []uint8) error {
	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeMMEUEApID(mmeUEID)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeENBUEApID(enbUEID)},
	}
	if len(successful) > 0 {
		ieList = append(ieList, pdu.ProtocolIE{
			ID:          pdu.IEERABModifyListBearerModConf,
			Criticality: aper.CriticalityIgnore,
			Value:       encodeERABModificationConfirmSuccessList(successful),
		})
	}
	if len(failed) > 0 {
		ieList = append(ieList, pdu.ProtocolIE{
			ID:          pdu.IEERABFailedToModifyListBearerModConf,
			Criticality: aper.CriticalityIgnore,
			Value:       encodeERABFailureList(failed),
		})
	}
	if len(toRelease) > 0 {
		ieList = append(ieList, pdu.ProtocolIE{
			ID:          pdu.IEERABToBeReleasedListBearerModConf,
			Criticality: aper.CriticalityIgnore,
			Value:       encodeERABFailureList(erabFailuresFromEBIs(toRelease, ies.CauseGroupRadioNetwork, ies.CauseRadioNetworkNormalRelease)),
		})
	}
	return s.sendToAddr(remoteAddr, pdu.BuildSuccessfulOutcome(pdu.ProcERABModificationIndication, aper.CriticalityReject, ieList))
}

func encodeERABModificationConfirmSuccessList(ebis []uint8) []byte {
	w := aper.NewBitWriter()
	_ = aper.EncodeConstrainedWholeNumber(w, int64(len(ebis)), 1, 256)
	w.AlignToByte()
	for _, ebi := range ebis {
		body := encodeERABModificationConfirmSuccessItem(ebi)
		inner := pdu.EncodeIEContainer([]pdu.ProtocolIE{{
			ID:          pdu.IEERABModifyItemBearerModConf,
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

func encodeERABModificationConfirmSuccessItem(ebi uint8) []byte {
	w := aper.NewBitWriter()
	w.WriteBit(0)
	w.WriteBit(0)
	w.WriteBit(0)
	_ = aper.EncodeConstrainedWholeNumber(w, int64(ebi), 0, 15)
	return w.Bytes()
}

func encodeERABFailureList(items []erabModificationFailure) []byte {
	w := aper.NewBitWriter()
	_ = aper.EncodeConstrainedWholeNumber(w, int64(len(items)), 1, 256)
	w.AlignToByte()
	for _, item := range items {
		body := encodeERABFailureItem(item)
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

func encodeERABFailureItem(item erabModificationFailure) []byte {
	w := aper.NewBitWriter()
	w.WriteBit(0)
	w.WriteBit(0)
	w.WriteBit(0)
	_ = aper.EncodeConstrainedWholeNumber(w, int64(item.EBI), 0, 15)
	w.WriteOctets(ies.EncodeCause(item.CauseGroup, item.Cause))
	return w.Bytes()
}

func erabFailuresFromEBIs(ebis []uint8, group ies.CauseGroup, cause uint8) []erabModificationFailure {
	out := make([]erabModificationFailure, 0, len(ebis))
	for _, ebi := range ebis {
		out = append(out, erabModificationFailure{EBI: ebi, CauseGroup: group, Cause: cause})
	}
	return out
}
