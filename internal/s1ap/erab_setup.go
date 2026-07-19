package s1ap

import (
	"encoding/binary"
	"encoding/hex"
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

const (
	imsModifyBearerTimeout     = 2 * time.Second
	imsModifyBearerSettleDelay = 750 * time.Millisecond
)

func imsModifyBearerTimerName(ebi uint8) string {
	return fmt.Sprintf("IMSModifyBearer:%d", ebi)
}

func imsModifyBearerSettleTimerName(ebi uint8) string {
	return fmt.Sprintf("IMSModifyBearerSettle:%d", ebi)
}

type ERABSetupItem struct {
	EBI                     uint8
	QCI                     uint8
	ARPPriority             uint8
	PreemptionCapability    bool
	PreemptionVulnerability bool
	BearerQoS               []byte
	SGWS1UIPv4              net.IP
	SGWS1UTEID              uint32
	NASPDU                  []byte
}

type ERABSetupResult struct {
	EBI        uint8
	Success    bool
	ENBS1UIPv4 net.IP
	ENBS1UTEID uint32
	CauseGroup uint8
	Cause      uint32
}

type ERABSetupResponse struct {
	MMEUEID                uint32
	ENBUEID                uint32
	Successful             []ERABSetupSuccess
	Failed                 []ERABSetupFailure
	CriticalityDiagnostics []byte
}

type ERABSetupSuccess struct {
	EBI        uint8
	ENBS1UAddr net.IP
	ENBS1UTEID uint32
}

type ERABSetupFailure struct {
	EBI        uint8
	CauseGroup uint8
	Cause      uint32
}

type UEAggregateMaximumBitrate struct {
	Downlink uint64
	Uplink   uint64
}

func (s *Server) SendERABSetupRequest(mmeUEID uint32, items []ERABSetupItem) error {
	return s.SendERABSetupRequestTracked(mmeUEID, items, "", "")
}

func (s *Server) SendERABSetupRequestTracked(mmeUEID uint32, items []ERABSetupItem, procedureKind string, transactionID string) error {
	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		return fmt.Errorf("s1ap: UE %d not found", mmeUEID)
	}
	ue.Lock()
	enbAddr := ue.ENBGlobalID
	enbS1APID := ue.ENBS1APID
	bindingGeneration := ue.S1BindingGeneration
	ue.Unlock()
	if enbAddr == "" {
		return fmt.Errorf("s1ap: UE %d has no active S1 binding", mmeUEID)
	}
	if transactionID != "" {
		s.registerPendingERABProcedure(ue, transactionID, procedureKind, bindingGeneration, items)
		defer func() {
			if transactionID != "" {
				ue.Lock()
				if proc := ue.PendingERABProcedures[transactionID]; proc != nil && proc.S1BindingGeneration == bindingGeneration {
					ue.Unlock()
					return
				}
				ue.Unlock()
			}
		}()
	}

	downlink, uplink, err := subscriberUEAMBR(ue)
	if err != nil {
		if transactionID != "" {
			s.unregisterPendingERABProcedure(ue, transactionID)
		}
		return err
	}
	msg, erabValue, err := BuildERABSetupRequest(mmeUEID, enbS1APID, &UEAggregateMaximumBitrate{
		Downlink: downlink,
		Uplink:   uplink,
	}, items)
	if err != nil {
		if transactionID != "" {
			s.unregisterPendingERABProcedure(ue, transactionID)
		}
		return err
	}
	for _, item := range items {
		s.log.Debug("s1ap: E-RAB Setup Request item",
			zap.Uint32("mme_ue_id", mmeUEID),
			zap.Uint32("enb_ue_id", enbS1APID),
			zap.Uint64("s1_binding_generation", bindingGeneration),
			zap.Uint8("ebi", item.EBI),
			zap.Uint8("qci", item.QCI),
			zap.Uint8("arp", item.ARPPriority),
			zap.String("sgw_s1u_ip", item.SGWS1UIPv4.String()),
			zap.Uint32("sgw_s1u_teid", item.SGWS1UTEID),
			zap.Bool("nas_pdu_present", len(item.NASPDU) > 0),
			zap.Int("nas_pdu_len", len(item.NASPDU)))
	}
	s.log.Debug("s1ap: E-RAB Setup Request encoded",
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.String("erab_setup_list_hex", hex.EncodeToString(erabValue)),
		zap.String("s1ap_hex", hex.EncodeToString(msg)))
	if err := s.sendToAddr(enbAddr, msg); err != nil {
		if transactionID != "" {
			s.unregisterPendingERABProcedure(ue, transactionID)
		}
		return err
	}
	return nil
}

func BuildERABSetupRequest(mmeUEID uint32, enbS1APID uint32, ueAMBR *UEAggregateMaximumBitrate, items []ERABSetupItem) (msg []byte, erabList []byte, err error) {
	if len(items) == 0 {
		return nil, nil, fmt.Errorf("s1ap: E-RAB Setup Request requires at least one item")
	}
	if len(items) > 256 {
		return nil, nil, fmt.Errorf("s1ap: E-RAB Setup Request has too many items: %d", len(items))
	}
	seenEBI := map[uint8]bool{}
	for _, item := range items {
		if item.EBI > 15 {
			return nil, nil, fmt.Errorf("s1ap: invalid E-RAB ID %d", item.EBI)
		}
		if seenEBI[item.EBI] {
			return nil, nil, fmt.Errorf("s1ap: duplicate E-RAB ID %d", item.EBI)
		}
		seenEBI[item.EBI] = true
		if item.QCI > 255 {
			return nil, nil, fmt.Errorf("s1ap: invalid QCI %d", item.QCI)
		}
		if item.ARPPriority > 15 {
			return nil, nil, fmt.Errorf("s1ap: invalid ARP priority %d", item.ARPPriority)
		}
		if ip := item.SGWS1UIPv4.To4(); ip == nil {
			return nil, nil, fmt.Errorf("s1ap: E-RAB %d requires IPv4 SGW S1-U address", item.EBI)
		}
		if item.SGWS1UTEID == 0 {
			return nil, nil, fmt.Errorf("s1ap: E-RAB %d requires nonzero SGW S1-U TEID", item.EBI)
		}
		if len(item.NASPDU) == 0 {
			return nil, nil, fmt.Errorf("s1ap: E-RAB %d requires NAS-PDU", item.EBI)
		}
		if len(item.NASPDU) > aper.MaxASN1Length {
			return nil, nil, fmt.Errorf("s1ap: E-RAB %d NAS-PDU too large: %d", item.EBI, len(item.NASPDU))
		}
	}

	downlink, uplink := uint64(100000000), uint64(100000000)
	if ueAMBR != nil {
		downlink = ueAMBR.Downlink
		uplink = ueAMBR.Uplink
	}
	erabList = encodeERABSetupListBearerSUReq(items)
	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeMMEUEApID(mmeUEID)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(enbS1APID)},
		{ID: pdu.IEUEAggregateMaxBitrate, Criticality: aper.CriticalityReject, Value: ies.EncodeUEAggregateMaxBitrate(downlink, uplink)},
		{ID: pdu.IEERABToBeSetupListBearerSUReq, Criticality: aper.CriticalityReject, Value: erabList},
	}
	return pdu.BuildInitiatingMessage(pdu.ProcERABSetup, aper.CriticalityReject, ieList), erabList, nil
}

func encodeERABSetupListBearerSUReq(items []ERABSetupItem) []byte {
	ow := aper.NewBitWriter()
	_ = aper.EncodeConstrainedWholeNumber(ow, int64(len(items)), 1, 256)
	ow.AlignToByte()
	for _, item := range items {
		itemBody := encodeERABSetupItemBody(item)
		innerContainer := pdu.EncodeIEContainer([]pdu.ProtocolIE{
			{ID: pdu.IEERABToBeSetupItemBearerSUReq, Criticality: aper.CriticalityReject, Value: itemBody},
		})
		if len(innerContainer) >= 2 {
			innerContainer = innerContainer[2:]
		}
		ow.WriteOctets(innerContainer)
	}
	return ow.Bytes()
}

func encodeERABSetupItemBody(item ERABSetupItem) []byte {
	nasPDUPresent := len(item.NASPDU) > 0
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

	w.WriteBit(0) // E-RABToBeSetupItemBearerSUReq extension marker
	w.WriteBit(0) // iE-Extensions absent

	w.WriteBit(0)
	_ = aper.EncodeConstrainedWholeNumber(w, int64(item.EBI), 0, 15)

	w.WriteBit(0) // E-RABLevelQoSParameters extension marker
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
		w.WriteBit(0) // GBR-QosInformation extension marker
		w.WriteBit(0) // iE-Extensions absent
		encodeBitRateForERABSetup(w, gbrInfo.MaxBitrateDL)
		encodeBitRateForERABSetup(w, gbrInfo.MaxBitrateUL)
		encodeBitRateForERABSetup(w, gbrInfo.GuaranteedBitrateDL)
		encodeBitRateForERABSetup(w, gbrInfo.GuaranteedBitrateUL)
	}

	w.WriteBit(0)
	_ = aper.EncodeConstrainedWholeNumber(w, 32, 1, 160)
	w.AlignToByte()
	ip := item.SGWS1UIPv4.To4()
	if ip == nil {
		ip = net.IP{0, 0, 0, 0}
	}
	w.WriteOctets(ip[:4])

	w.AlignToByte()
	w.WriteOctet(byte(item.SGWS1UTEID >> 24))
	w.WriteOctet(byte(item.SGWS1UTEID >> 16))
	w.WriteOctet(byte(item.SGWS1UTEID >> 8))
	w.WriteOctet(byte(item.SGWS1UTEID))

	if nasPDUPresent {
		w.AlignToByte()
		_ = aper.EncodeLength(w, len(item.NASPDU), 0, -1)
		w.WriteOctets(item.NASPDU)
	}
	return w.Bytes()
}

type erabGBRQosInformation struct {
	MaxBitrateDL        uint64
	MaxBitrateUL        uint64
	GuaranteedBitrateDL uint64
	GuaranteedBitrateUL uint64
}

func deriveGBRQosInformation(bearerQoS []byte) (erabGBRQosInformation, bool) {
	if len(bearerQoS) < 22 {
		return erabGBRQosInformation{}, false
	}
	info := erabGBRQosInformation{
		MaxBitrateUL:        decodeBearerQoSBitrate(bearerQoS[2:7]),
		MaxBitrateDL:        decodeBearerQoSBitrate(bearerQoS[7:12]),
		GuaranteedBitrateUL: decodeBearerQoSBitrate(bearerQoS[12:17]),
		GuaranteedBitrateDL: decodeBearerQoSBitrate(bearerQoS[17:22]),
	}
	if info.MaxBitrateDL == 0 && info.MaxBitrateUL == 0 && info.GuaranteedBitrateDL == 0 && info.GuaranteedBitrateUL == 0 {
		return erabGBRQosInformation{}, false
	}
	return info, true
}

func decodeBearerQoSBitrate(b []byte) uint64 {
	var out uint64
	for _, octet := range b {
		out = (out << 8) | uint64(octet)
	}
	return out
}

func encodeBitRateForERABSetup(w *aper.BitWriter, bitrate uint64) {
	const maxBitRate = 10000000000
	if bitrate > maxBitRate {
		bitrate = maxBitRate
	}
	_ = aper.EncodeConstrainedWholeNumber(w, int64(bitrate), 0, maxBitRate)
}

func decodeERABSetupResponseList(data []byte) ([]ERABSetupSuccess, error) {
	r := aper.NewBitReader(data)
	count, err := aper.DecodeConstrainedWholeNumber(r, 1, 256)
	if err != nil {
		return nil, fmt.Errorf("decode E-RAB setup response list count: %w", err)
	}
	r.AlignToByte()
	results := make([]ERABSetupSuccess, 0, int(count))
	for i := 0; i < int(count); i++ {
		ieID, err := aper.DecodeConstrainedWholeNumber(r, 0, 65535)
		if err != nil {
			return nil, fmt.Errorf("decode E-RAB setup response item IE ID: %w", err)
		}
		_, err = aper.DecodeCriticality(r)
		if err != nil {
			return nil, fmt.Errorf("decode E-RAB setup response item criticality: %w", err)
		}
		itemBytes, err := aper.ReadOpenType(r)
		if err != nil {
			return nil, fmt.Errorf("read E-RAB setup response item: %w", err)
		}
		if uint16(ieID) != pdu.IEERABSetupItemBearerSURes {
			return nil, fmt.Errorf("unexpected E-RAB setup response item IE ID %d", ieID)
		}
		result, err := decodeERABSetupResponseItem(itemBytes)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	return results, nil
}

func decodeERABSetupResponseItem(data []byte) (ERABSetupSuccess, error) {
	ir := aper.NewBitReader(data)
	if _, err := ir.ReadBit(); err != nil {
		return ERABSetupSuccess{}, err
	}
	if _, err := ir.ReadBit(); err != nil {
		return ERABSetupSuccess{}, err
	}
	erabIDExt, err := ir.ReadBit()
	if err != nil {
		return ERABSetupSuccess{}, err
	}
	if erabIDExt != 0 {
		return ERABSetupSuccess{}, fmt.Errorf("E-RAB ID extension value not supported")
	}
	erabID, err := aper.DecodeConstrainedWholeNumber(ir, 0, 15)
	if err != nil {
		return ERABSetupSuccess{}, err
	}
	extBit, err := ir.ReadBit()
	if err != nil {
		return ERABSetupSuccess{}, err
	}
	ir.AlignToByte()
	var addrBits int64
	if extBit == 0 {
		addrBits, err = aper.DecodeConstrainedWholeNumber(ir, 1, 160)
	} else {
		addrBits, err = aper.DecodeConstrainedWholeNumber(ir, 0, 65535)
	}
	if err != nil {
		return ERABSetupSuccess{}, err
	}
	ir.AlignToByte()
	addrBytes, err := ir.ReadOctets(int((addrBits + 7) / 8))
	if err != nil || len(addrBytes) < 4 {
		return ERABSetupSuccess{}, fmt.Errorf("invalid transportLayerAddress")
	}
	ir.AlignToByte()
	teidBytes, err := ir.ReadOctets(4)
	if err != nil {
		return ERABSetupSuccess{}, err
	}
	return ERABSetupSuccess{
		EBI:        uint8(erabID),
		ENBS1UAddr: net.IP(addrBytes[:4]).To4(),
		ENBS1UTEID: binary.BigEndian.Uint32(teidBytes),
	}, nil
}

func decodeERABFailedToSetupList(data []byte) ([]ERABSetupFailure, error) {
	r := aper.NewBitReader(data)
	count, err := aper.DecodeConstrainedWholeNumber(r, 1, 256)
	if err != nil {
		return nil, fmt.Errorf("decode E-RAB failed-to-setup response list count: %w", err)
	}
	r.AlignToByte()
	results := make([]ERABSetupFailure, 0, int(count))
	for i := 0; i < int(count); i++ {
		if _, err := aper.DecodeConstrainedWholeNumber(r, 0, 65535); err != nil {
			return nil, fmt.Errorf("decode failed-to-setup item IE ID: %w", err)
		}
		if _, err := aper.DecodeCriticality(r); err != nil {
			return nil, fmt.Errorf("decode failed-to-setup item criticality: %w", err)
		}
		itemBytes, err := aper.ReadOpenType(r)
		if err != nil {
			return nil, fmt.Errorf("read failed-to-setup item: %w", err)
		}
		result, err := decodeERABFailedToSetupItem(itemBytes)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	return results, nil
}

func decodeERABFailedToSetupItem(data []byte) (ERABSetupFailure, error) {
	ir := aper.NewBitReader(data)
	if _, err := ir.ReadBit(); err != nil {
		return ERABSetupFailure{}, err
	}
	if _, err := ir.ReadBit(); err != nil {
		return ERABSetupFailure{}, err
	}
	erabIDExt, err := ir.ReadBit()
	if err != nil {
		return ERABSetupFailure{}, err
	}
	if erabIDExt != 0 {
		return ERABSetupFailure{}, fmt.Errorf("E-RAB failed item extension value not supported")
	}
	erabID, err := aper.DecodeConstrainedWholeNumber(ir, 0, 15)
	if err != nil {
		return ERABSetupFailure{}, err
	}
	group, cause, err := decodeCauseFromBitReader(ir)
	if err != nil {
		return ERABSetupFailure{}, err
	}
	return ERABSetupFailure{
		EBI:        uint8(erabID),
		CauseGroup: uint8(group),
		Cause:      uint32(cause),
	}, nil
}

func decodeCauseFromBitReader(r *aper.BitReader) (ies.CauseGroup, uint8, error) {
	if _, err := r.ReadBit(); err != nil {
		return 0, 0, err
	}
	groupBits, err := r.ReadBits(3)
	if err != nil {
		return 0, 0, err
	}
	group := ies.CauseGroup(groupBits)
	if _, err := r.ReadBit(); err != nil {
		return 0, 0, err
	}
	bits := 6
	switch group {
	case ies.CauseGroupTransport:
		bits = 1
	case ies.CauseGroupNAS:
		bits = 2
	case ies.CauseGroupProtocol:
		bits = 3
	case ies.CauseGroupMisc:
		bits = 5
	}
	value, err := r.ReadBits(bits)
	if err != nil {
		return 0, 0, err
	}
	return group, uint8(value), nil
}

func decodeERABSetupResponse(_ *pdu.PDU, ieList []pdu.ProtocolIE) (*ERABSetupResponse, []uint16, []int, []string, []string, bool, string, bool, string, error) {
	resp := &ERABSetupResponse{}
	ieIDs := make([]uint16, 0, len(ieList))
	ieLengths := make([]int, 0, len(ieList))
	ieHex := make([]string, 0, len(ieList))
	unknownIEs := []string{}
	var setupList []byte
	var failedList []byte
	for _, ie := range ieList {
		ieIDs = append(ieIDs, ie.ID)
		ieLengths = append(ieLengths, len(ie.Value))
		ieHex = append(ieHex, hex.EncodeToString(ie.Value))
		switch ie.ID {
		case pdu.IEMMEUES1APID:
			v, err := ies.DecodeMMEUEApID(ie.Value)
			if err != nil {
				return nil, ieIDs, ieLengths, ieHex, unknownIEs, len(setupList) > 0, hex.EncodeToString(setupList), len(failedList) > 0, hex.EncodeToString(failedList), fmt.Errorf("decode MME-UE-S1AP-ID: %w", err)
			}
			resp.MMEUEID = v
		case pdu.IEENBS1APID:
			v, err := ies.DecodeENBUEApID(ie.Value)
			if err != nil {
				return nil, ieIDs, ieLengths, ieHex, unknownIEs, len(setupList) > 0, hex.EncodeToString(setupList), len(failedList) > 0, hex.EncodeToString(failedList), fmt.Errorf("decode eNB-UE-S1AP-ID: %w", err)
			}
			resp.ENBUEID = v
		case pdu.IEERABSetupListBearerSURes:
			setupList = ie.Value
		case pdu.IEERABFailedToSetupListBearerSURes:
			failedList = ie.Value
		case pdu.IECriticalityDiagnostics:
			resp.CriticalityDiagnostics = append([]byte(nil), ie.Value...)
		default:
			meta, ok := pdu.Phase1ProcedureIEs[pdu.ProcedureIEKey{
				ProcedureCode: pdu.ProcERABSetup,
				PDUType:       pdu.PDUTypeSuccessfulOutcome,
				IEID:          ie.ID,
			}]
			if ok {
				unknownIEs = append(unknownIEs, fmt.Sprintf("id=%d name=%s len=%d", ie.ID, meta.Name, len(ie.Value)))
			} else {
				unknownIEs = append(unknownIEs, fmt.Sprintf("id=%d len=%d", ie.ID, len(ie.Value)))
			}
		}
	}
	if len(setupList) > 0 {
		successes, err := decodeERABSetupResponseList(setupList)
		if err != nil {
			return nil, ieIDs, ieLengths, ieHex, unknownIEs, true, hex.EncodeToString(setupList), len(failedList) > 0, hex.EncodeToString(failedList), err
		}
		resp.Successful = successes
	}
	if len(failedList) > 0 {
		failures, err := decodeERABFailedToSetupList(failedList)
		if err != nil {
			return nil, ieIDs, ieLengths, ieHex, unknownIEs, len(setupList) > 0, hex.EncodeToString(setupList), true, hex.EncodeToString(failedList), err
		}
		resp.Failed = failures
	}
	return resp, ieIDs, ieLengths, ieHex, unknownIEs, len(setupList) > 0, hex.EncodeToString(setupList), len(failedList) > 0, hex.EncodeToString(failedList), nil
}

func (s *Server) handleERABSetupResponse(remoteAddr string, p *pdu.PDU, raw []byte, ieList []pdu.ProtocolIE) {
	resp, ieIDs, ieLengths, ieHex, unknownIEs, setupPresent, setupHex, failedPresent, failedHex, err := decodeERABSetupResponse(p, ieList)
	if err != nil {
		s.log.Warn("s1ap: E-RAB Setup Response decode failed",
			zap.String("remote", remoteAddr),
			zap.Uint32("procedure_code", uint32(p.ProcedureCode)),
			zap.String("pdu_choice", p.Type.String()),
			zap.String("criticality", p.Criticality.String()),
			zap.String("raw_s1ap_hex", hex.EncodeToString(raw)),
			zap.Int("ie_count", len(ieList)),
			zap.Uint16s("ie_ids", ieIDs),
			zap.Ints("ie_lengths", ieLengths),
			zap.Strings("ie_hex", ieHex),
			zap.Bool("setup_list_present", setupPresent),
			zap.String("setup_list_hex", setupHex),
			zap.Bool("failed_list_present", failedPresent),
			zap.String("failed_list_hex", failedHex),
			zap.Strings("unknown_ies", unknownIEs),
			zap.Error(err))
		return
	}
	log := s.log.With(
		zap.String("remote", remoteAddr),
		zap.Uint32("mme_ue_id", resp.MMEUEID),
		zap.Uint32("enb_ue_id", resp.ENBUEID))
	ue, ok := s.findUEForUEAssociatedMessage(remoteAddr, p, resp.MMEUEID, resp.ENBUEID)
	if !ok {
		return
	}
	ue.Lock()
	pendingIDs, expectedEBIs, bindingGeneration := pendingERABDiagnosticsLocked(ue)
	ue.Unlock()
	if len(unknownIEs) > 0 {
		log.Warn("s1ap: E-RAB Setup Response contains unsupported IEs",
			zap.Strings("unknown_ies", unknownIEs))
	}
	log.Debug("s1ap: E-RAB Setup Response decoded",
		zap.Uint32("procedure_code", uint32(p.ProcedureCode)),
		zap.String("pdu_choice", p.Type.String()),
		zap.String("criticality", p.Criticality.String()),
		zap.String("raw_s1ap_hex", hex.EncodeToString(raw)),
		zap.Int("ie_count", len(ieList)),
		zap.Uint16s("ie_ids", ieIDs),
		zap.Ints("ie_lengths", ieLengths),
		zap.Strings("ie_hex", ieHex),
		zap.Bool("setup_list_present", setupPresent),
		zap.String("setup_list_hex", setupHex),
		zap.Bool("failed_list_present", failedPresent),
		zap.String("failed_list_hex", failedHex),
		zap.Strings("pending_transaction_ids", pendingIDs),
		zap.Uint8s("expected_ebis", expectedEBIs),
		zap.Uint64("s1_binding_generation", bindingGeneration))
	received := map[uint8]struct{}{}
	successEBIs := make([]uint8, 0, len(resp.Successful))
	for _, result := range resp.Successful {
		successEBIs = append(successEBIs, result.EBI)
		received[result.EBI] = struct{}{}
		log.Debug("s1ap: E-RAB Setup Response item",
			zap.Uint8("ebi", result.EBI),
			zap.Bool("success", true),
			zap.String("enb_s1u_ip", result.ENBS1UAddr.String()),
			zap.Uint32("enb_s1u_teid", result.ENBS1UTEID))
	}
	failedEBIs := make([]uint8, 0, len(resp.Failed))
	for _, result := range resp.Failed {
		failedEBIs = append(failedEBIs, result.EBI)
		received[result.EBI] = struct{}{}
		log.Debug("s1ap: E-RAB Setup Response item",
			zap.Uint8("ebi", result.EBI),
			zap.Bool("success", false),
			zap.Uint8("cause_group", result.CauseGroup),
			zap.Uint32("cause", result.Cause))
	}
	if len(resp.Successful) == 0 && len(resp.Failed) == 0 {
		log.Warn("s1ap: E-RAB Setup Response contains no setup or failure items")
		return
	}
	ue.Lock()
	proc, matchReason, ambiguous := matchPendingERABProcedureLocked(ue, received)
	ue.Unlock()
	if proc == nil {
		log.Warn("s1ap: E-RAB Setup Response could not be correlated",
			zap.Uint8s("received_success_ebis", successEBIs),
			zap.Uint8s("received_failed_ebis", failedEBIs),
			zap.Bool("ambiguous", ambiguous))
		return
	}
	matchedExpected := sortedExpectedEBIs(proc.ExpectedEBIs)
	log.Debug("s1ap: E-RAB Setup Response correlated",
		zap.Uint8s("received_success_ebis", successEBIs),
		zap.Uint8s("received_failed_ebis", failedEBIs),
		zap.String("matched_transaction_id", proc.TransactionID),
		zap.Uint8s("expected_ebis", matchedExpected),
		zap.String("match_reason", matchReason),
		zap.Bool("ambiguous", ambiguous))
	s.applyERABSetupResponseForProcedure(ue, proc, resp, log)
}

func (s *Server) applyERABSetupResponseForProcedure(ue *uecontext.Context, proc *uecontext.PendingERABProcedure, resp *ERABSetupResponse, log *zap.Logger) {
	for _, success := range resp.Successful {
		result := ERABSetupResult{
			EBI:        success.EBI,
			Success:    true,
			ENBS1UIPv4: append(net.IP(nil), success.ENBS1UAddr...),
			ENBS1UTEID: success.ENBS1UTEID,
		}
		if proc.ProcedureKind == "dedicated_create_bearer" {
			s.completeDedicatedERABSetupForBearer(ue, result, log)
			continue
		}
		s.completeIMSDefaultERABSetupForBearer(ue, result, log)
	}
	for _, failure := range resp.Failed {
		result := ERABSetupResult{
			EBI:        failure.EBI,
			Success:    false,
			CauseGroup: failure.CauseGroup,
			Cause:      failure.Cause,
		}
		if proc.ProcedureKind == "dedicated_create_bearer" {
			s.completeDedicatedERABSetupForBearer(ue, result, log)
			continue
		}
		s.completeIMSDefaultERABSetupForBearer(ue, result, log)
	}
	ue.Lock()
	allCovered := true
	for ebi := range proc.ExpectedEBIs {
		if !containsERABResult(resp.Successful, resp.Failed, ebi) {
			allCovered = false
			break
		}
	}
	if allCovered {
		delete(ue.PendingERABProcedures, proc.TransactionID)
	}
	ue.Unlock()
}

func (s *Server) completeIMSDefaultERABSetupForBearer(ue *uecontext.Context, result ERABSetupResult, log *zap.Logger) {
	ue.Lock()
	var target *uecontext.PDNContext
	for _, pdn := range ue.PDNs {
		if pdn.DefaultEBI == result.EBI {
			target = pdn
			break
		}
	}
	if target == nil {
		ue.Unlock()
		log.Warn("s1ap: E-RAB Setup Response for unknown EBI", zap.Uint8("ebi", result.EBI))
		return
	}
	if !result.Success {
		target.ERABEstablished = false
		target.State = "erab-setup-failed"
		apn := target.APN
		ue.Unlock()
		log.Warn("s1ap: IMS E-RAB Setup failed",
			zap.String("apn", apn),
			zap.Uint8("ebi", result.EBI),
			zap.Uint8("cause_group", result.CauseGroup),
			zap.Uint32("cause", result.Cause))
		return
	}
	target.ENBU_TEID = result.ENBS1UTEID
	target.ENBU_IP = append(net.IP(nil), result.ENBS1UIPv4...)
	target.ERABEstablished = true
	apn := target.APN
	if target.ModifyBearerAccepted {
		target.State = "active"
	} else {
		target.State = "access-established"
	}
	ue.Unlock()

	log.Info("s1ap: IMS default bearer access established",
		zap.String("apn", apn),
		zap.Uint8("ebi", result.EBI),
		zap.Bool("modify_bearer_accepted", target.ModifyBearerAccepted))
	s.maybeAdvanceDefaultBearer(ue, result.EBI, "erab-established", log)
}

func (s *Server) maybeAdvanceDefaultBearer(ue *uecontext.Context, ebi uint8, trigger string, log *zap.Logger) {
	ue.Lock()
	var target *uecontext.PDNContext
	for _, pdn := range ue.PDNs {
		if pdn.DefaultEBI == ebi {
			target = pdn
			break
		}
	}
	if target == nil {
		ue.Unlock()
		return
	}
	nasAccepted := target.NASAccepted
	erabEstablished := target.ERABEstablished
	modifyBearerSent := target.ModifyBearerSent
	modifyBearerAccepted := target.ModifyBearerAccepted
	modifyBearerFailed := target.ModifyBearerFailed
	modifyBearerDeferred := target.ModifyBearerDeferred
	linkedBearerReady := nasAccepted && erabEstablished && modifyBearerAccepted
	if linkedBearerReady {
		target.State = "active"
		ue.Unlock()
		log.Info("s1ap: IMS default bearer ready",
			zap.Uint32("mme_ue_id", ue.MMEUES1APID),
			zap.String("imsi", ue.IMSI),
			zap.String("apn", target.APN),
			zap.Uint8("ebi", ebi),
			zap.Bool("nas_accepted", nasAccepted),
			zap.Bool("erab_established", erabEstablished),
			zap.Bool("modify_bearer_sent", modifyBearerSent),
			zap.Bool("modify_bearer_accepted", modifyBearerAccepted),
			zap.Bool("modify_bearer_failed", modifyBearerFailed),
			zap.Bool("linked_bearer_ready", linkedBearerReady),
			zap.String("trigger", trigger))
		s.resumePendingCreateBearersForLinkedEBI(ue, ebi, "modify_bearer_accepted")
		return
	}
	if modifyBearerFailed {
		target.State = "modify-bearer-failed"
		ue.Unlock()
		log.Warn("s1ap: IMS default bearer advance blocked by Modify Bearer failure",
			zap.Uint32("mme_ue_id", ue.MMEUES1APID),
			zap.String("imsi", ue.IMSI),
			zap.String("apn", target.APN),
			zap.Uint8("ebi", ebi),
			zap.Bool("nas_accepted", nasAccepted),
			zap.Bool("erab_established", erabEstablished),
			zap.Bool("modify_bearer_sent", modifyBearerSent),
			zap.Bool("modify_bearer_accepted", modifyBearerAccepted),
			zap.Bool("modify_bearer_failed", modifyBearerFailed),
			zap.Bool("linked_bearer_ready", linkedBearerReady),
			zap.String("trigger", trigger))
		s.failPendingCreateBearersForLinkedEBI(ue, ebi, gtpv2.CauseRequestRejected, "modify_bearer_failed")
		return
	}
	if hasPendingCreateBearerForLinkedEBILocked(ue, ebi) {
		if nasAccepted && erabEstablished && !modifyBearerSent {
			target.State = "access-established"
		}
		ue.Unlock()
		if nasAccepted && erabEstablished && !modifyBearerSent {
			log.Debug("s1ap: IMS default bearer access ready, resuming linked Create Bearer before MBR",
				zap.Uint32("mme_ue_id", ue.MMEUES1APID),
				zap.String("imsi", ue.IMSI),
				zap.String("apn", target.APN),
				zap.Uint8("ebi", ebi),
				zap.Bool("nas_accepted", nasAccepted),
				zap.Bool("erab_established", erabEstablished),
				zap.Bool("modify_bearer_sent", modifyBearerSent),
				zap.Bool("modify_bearer_accepted", modifyBearerAccepted),
				zap.Bool("modify_bearer_failed", modifyBearerFailed),
				zap.String("trigger", trigger))
			s.resumePendingCreateBearersForLinkedEBI(ue, ebi, "linked_access_ready")
			return
		}
		log.Debug("s1ap: IMS default bearer waiting for linked Create Bearer completion before MBR",
			zap.Uint32("mme_ue_id", ue.MMEUES1APID),
			zap.String("imsi", ue.IMSI),
			zap.String("apn", target.APN),
			zap.Uint8("ebi", ebi),
			zap.Bool("nas_accepted", nasAccepted),
			zap.Bool("erab_established", erabEstablished),
			zap.Bool("modify_bearer_sent", modifyBearerSent),
			zap.Bool("modify_bearer_accepted", modifyBearerAccepted),
			zap.Bool("modify_bearer_failed", modifyBearerFailed),
			zap.String("trigger", trigger))
		return
	}
	if !nasAccepted || !erabEstablished || modifyBearerSent {
		if nasAccepted && erabEstablished {
			if modifyBearerSent && !modifyBearerAccepted && !modifyBearerFailed {
				target.State = "modify-bearer-pending"
			} else {
				target.State = "access-established"
			}
		}
		ue.Unlock()
		log.Debug("s1ap: IMS default bearer waiting for completion",
			zap.Uint32("mme_ue_id", ue.MMEUES1APID),
			zap.String("imsi", ue.IMSI),
			zap.String("apn", target.APN),
			zap.Uint8("ebi", ebi),
			zap.Bool("nas_accepted", nasAccepted),
			zap.Bool("erab_established", erabEstablished),
			zap.Bool("modify_bearer_sent", modifyBearerSent),
			zap.Bool("modify_bearer_accepted", modifyBearerAccepted),
			zap.Bool("modify_bearer_failed", modifyBearerFailed),
			zap.Bool("linked_bearer_ready", linkedBearerReady),
			zap.String("trigger", trigger))
		return
	}
	if modifyBearerDeferred {
		target.State = "access-established"
		apn := target.APN
		imsi := ue.IMSI
		ue.Unlock()
		log.Debug("s1ap: IMS default bearer waiting for linked bearer settle before MBR",
			zap.Uint32("mme_ue_id", ue.MMEUES1APID),
			zap.String("imsi", imsi),
			zap.String("apn", apn),
			zap.Uint8("ebi", ebi),
			zap.String("trigger", trigger))
		return
	}

	target.ModifyBearerDeferred = true
	target.State = "access-established"
	mmeUEID := ue.MMEUES1APID
	apn := target.APN
	imsi := ue.IMSI
	ue.StopTimer(imsModifyBearerSettleTimerName(ebi))
	ue.StartTimer(imsModifyBearerSettleTimerName(ebi), imsModifyBearerSettleDelay, func() {
		s.onIMSModifyBearerSettleTimeout(mmeUEID, ebi)
	})
	ue.Unlock()

	log.Debug("s1ap: IMS default bearer ready; deferring standalone MBR until linked bearer activity settles",
		zap.String("imsi", imsi),
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.String("apn", apn),
		zap.Uint8("ebi", ebi),
		zap.String("trigger", trigger))
}

func (s *Server) startIMSModifyBearerTimer(ue *uecontext.Context, ebi uint8) {
	if ue == nil || ebi == 0 {
		return
	}
	timerName := imsModifyBearerTimerName(ebi)
	ue.Lock()
	mmeUEID := ue.MMEUES1APID
	ue.StartTimer(timerName, imsModifyBearerTimeout, func() {
		s.onIMSModifyBearerTimeout(mmeUEID, ebi)
	})
	ue.Unlock()
}

func (s *Server) sendIMSModifyBearerNow(ue *uecontext.Context, ebi uint8, trigger string, log *zap.Logger) {
	ue.Lock()
	var target *uecontext.PDNContext
	for _, pdn := range ue.PDNs {
		if pdn != nil && pdn.DefaultEBI == ebi {
			target = pdn
			break
		}
	}
	if target == nil || !target.NASAccepted || !target.ERABEstablished || target.ModifyBearerSent || target.ModifyBearerAccepted || target.ModifyBearerFailed {
		ue.Unlock()
		return
	}
	target.ModifyBearerDeferred = false
	target.ModifyBearerSent = true
	target.State = "modify-bearer-pending"
	mmeUEID := ue.MMEUES1APID
	mbr := &gtpv2.ModifyBearerRequest{
		SGWAddress:            target.SGWAddress,
		SGWC_TEID:             target.SGWC_TEID,
		EBI:                   target.DefaultEBI,
		ENBU_TEID:             target.ENBU_TEID,
		ENBU_IP:               append(net.IP(nil), target.ENBU_IP...),
		RATType:               gtpv2.RATTypeEUTRAN,
		IncludeIndicationCRSI: true,
		OmitRATType:           true,
	}
	apn := target.APN
	imsi := ue.IMSI
	ue.StopTimer(imsModifyBearerSettleTimerName(ebi))
	ue.Unlock()

	log.Debug("s1ap: sending IMS S11 Modify Bearer Request",
		zap.String("imsi", imsi),
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.String("apn", apn),
		zap.Uint8("ebi", ebi),
		zap.Uint32("sgwc_teid", mbr.SGWC_TEID),
		zap.String("sequence_number", "allocated-in-s11-client"),
		zap.Uint32("enb_s1u_teid", mbr.ENBU_TEID),
		zap.String("enb_s1u_ipv4", mbr.ENBU_IP.String()),
		zap.String("trigger", trigger))
	if err := s.s11.SendMBR(mmeUEID, mbr); err != nil {
		log.Warn("s1ap: IMS SendMBR failed", zap.String("apn", apn), zap.Uint8("ebi", ebi), zap.Error(err))
		ue.Lock()
		if current := findPDNByLinkedEBILocked(ue, ebi); current != nil {
			current.ModifyBearerDeferred = false
			current.ModifyBearerSent = false
			current.ModifyBearerFailed = true
			current.State = "modify-bearer-failed"
		}
		ue.Unlock()
		s.failPendingCreateBearersForLinkedEBI(ue, ebi, gtpv2.CauseRequestRejected, "modify_bearer_send_failed")
		return
	}
	s.startIMSModifyBearerTimer(ue, ebi)
}

func (s *Server) onIMSModifyBearerSettleTimeout(mmeUEID uint32, ebi uint8) {
	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		return
	}

	ue.Lock()
	target := findPDNByLinkedEBILocked(ue, ebi)
	if target == nil || !target.ModifyBearerDeferred || target.ModifyBearerSent || target.ModifyBearerAccepted || target.ModifyBearerFailed {
		ue.StopTimer(imsModifyBearerSettleTimerName(ebi))
		ue.Unlock()
		return
	}
	if hasPendingCreateBearerForLinkedEBILocked(ue, ebi) {
		imsi := ue.IMSI
		apn := target.APN
		ue.StopTimer(imsModifyBearerSettleTimerName(ebi))
		ue.StartTimer(imsModifyBearerSettleTimerName(ebi), imsModifyBearerSettleDelay, func() {
			s.onIMSModifyBearerSettleTimeout(mmeUEID, ebi)
		})
		ue.Unlock()
		s.log.Info("s1ap: IMS Modify Bearer settle delayed by additional linked Create Bearer activity",
			zap.Uint32("mme_ue_id", mmeUEID),
			zap.String("imsi", imsi),
			zap.String("apn", apn),
			zap.Uint8("ebi", ebi))
		return
	}
	ue.Unlock()
	s.sendIMSModifyBearerNow(ue, ebi, "linked-bearer-settled", s.log)
}

func (s *Server) onIMSModifyBearerTimeout(mmeUEID uint32, ebi uint8) {
	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		return
	}

	ue.Lock()
	var target *uecontext.PDNContext
	for _, pdn := range ue.PDNs {
		if pdn != nil && pdn.DefaultEBI == ebi {
			target = pdn
			break
		}
	}
	if target == nil || !target.ModifyBearerSent || target.ModifyBearerAccepted || target.ModifyBearerFailed || target.State != "modify-bearer-pending" {
		ue.StopTimer(imsModifyBearerTimerName(ebi))
		ue.Unlock()
		return
	}

	apn := target.APN
	imsi := ue.IMSI
	sgwAddr := target.SGWAddress
	sgwcTEID := target.SGWC_TEID
	enbTEID := target.ENBU_TEID
	enbIP := append(net.IP(nil), target.ENBU_IP...)
	fallbackSent := target.ModifyBearerFallbackSent

	if !fallbackSent && sgwcTEID != 0 && enbTEID != 0 && enbIP != nil {
		target.ModifyBearerFallbackSent = true
		ue.StopTimer(imsModifyBearerTimerName(ebi))
		ue.StartTimer(imsModifyBearerTimerName(ebi), imsModifyBearerTimeout, func() {
			s.onIMSModifyBearerTimeout(mmeUEID, ebi)
		})
		ue.Unlock()

		s.log.Warn("s1ap: IMS Modify Bearer timeout; sending standalone fallback MBR",
			zap.Uint32("mme_ue_id", mmeUEID),
			zap.String("imsi", imsi),
			zap.String("apn", apn),
			zap.Uint8("ebi", ebi))
		if err := s.s11.SendMBR(mmeUEID, &gtpv2.ModifyBearerRequest{
			SGWAddress:            sgwAddr,
			SGWC_TEID:             sgwcTEID,
			EBI:                   ebi,
			ENBU_TEID:             enbTEID,
			ENBU_IP:               enbIP,
			RATType:               gtpv2.RATTypeEUTRAN,
			IncludeIndicationCRSI: true,
			OmitRATType:           true,
		}); err != nil {
			ue.Lock()
			if current := findPDNByLinkedEBILocked(ue, ebi); current != nil && current.State == "modify-bearer-pending" {
				current.ModifyBearerFailed = true
				current.State = "modify-bearer-failed"
			}
			ue.StopTimer(imsModifyBearerTimerName(ebi))
			ue.Unlock()
			s.log.Warn("s1ap: standalone IMS fallback MBR send failed",
				zap.Uint32("mme_ue_id", mmeUEID),
				zap.String("imsi", imsi),
				zap.String("apn", apn),
				zap.Uint8("ebi", ebi),
				zap.Error(err))
			s.failPendingCreateBearersForLinkedEBI(ue, ebi, gtpv2.CauseRequestRejected, "modify_bearer_fallback_send_failed")
		}
		return
	}

	target.ModifyBearerFailed = true
	target.State = "modify-bearer-failed"
	ue.StopTimer(imsModifyBearerTimerName(ebi))
	ue.Unlock()

	s.log.Warn("s1ap: IMS Modify Bearer timed out after fallback",
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.String("imsi", imsi),
		zap.String("apn", apn),
		zap.Uint8("ebi", ebi))
	s.failPendingCreateBearersForLinkedEBI(ue, ebi, gtpv2.CauseRequestRejected, "modify_bearer_timeout")
}

func hasPendingCreateBearerForLinkedEBILocked(ue *uecontext.Context, linkedEBI uint8) bool {
	for _, tx := range ue.PendingBearerTransactions {
		if tx.Kind != bearerTxCreate || tx.LinkedEBI != linkedEBI || isCreateBearerTerminal(tx.CreateState) {
			continue
		}
		return true
	}
	return false
}

func (s *Server) registerPendingERABProcedure(ue *uecontext.Context, transactionID string, procedureKind string, bindingGeneration uint64, items []ERABSetupItem) {
	ebis := make([]uint8, 0, len(items))
	for _, item := range items {
		ebis = append(ebis, item.EBI)
	}
	s.registerPendingERABProcedureForEBIs(ue, transactionID, procedureKind, bindingGeneration, ebis)
}

func (s *Server) registerPendingERABProcedureForEBIs(ue *uecontext.Context, transactionID string, procedureKind string, bindingGeneration uint64, ebis []uint8) {
	ue.Lock()
	defer ue.Unlock()
	if ue.PendingERABProcedures == nil {
		ue.PendingERABProcedures = make(map[string]*uecontext.PendingERABProcedure)
	}
	expected := make(map[uint8]struct{}, len(ebis))
	for _, ebi := range ebis {
		expected[ebi] = struct{}{}
	}
	ue.PendingERABProcedures[transactionID] = &uecontext.PendingERABProcedure{
		TransactionID:       transactionID,
		ProcedureKind:       procedureKind,
		ExpectedEBIs:        expected,
		S1BindingGeneration: bindingGeneration,
		CreatedAt:           time.Now(),
		Deadline:            time.Now().Add(createBearerOverallTimeout),
	}
}

func (s *Server) unregisterPendingERABProcedure(ue *uecontext.Context, transactionID string) {
	ue.Lock()
	defer ue.Unlock()
	delete(ue.PendingERABProcedures, transactionID)
}

func matchPendingERABProcedureLocked(ue *uecontext.Context, received map[uint8]struct{}) (*uecontext.PendingERABProcedure, string, bool) {
	var exact []*uecontext.PendingERABProcedure
	var subset []*uecontext.PendingERABProcedure
	for _, proc := range ue.PendingERABProcedures {
		if proc.S1BindingGeneration != 0 && proc.S1BindingGeneration != ue.S1BindingGeneration {
			continue
		}
		match := true
		for ebi := range received {
			if _, ok := proc.ExpectedEBIs[ebi]; !ok {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		if len(received) == len(proc.ExpectedEBIs) {
			exact = append(exact, proc)
		} else {
			subset = append(subset, proc)
		}
	}
	if len(exact) == 1 {
		return exact[0], "exact_expected_ebi_set", false
	}
	if len(exact) > 1 {
		return nil, "", true
	}
	if len(subset) == 1 {
		return subset[0], "subset_of_expected_ebis", false
	}
	if len(subset) > 1 {
		return nil, "", true
	}
	return nil, "", false
}

func pendingERABDiagnosticsLocked(ue *uecontext.Context) ([]string, []uint8, uint64) {
	pendingIDs := make([]string, 0, len(ue.PendingERABProcedures))
	expectedMap := map[uint8]struct{}{}
	for id, proc := range ue.PendingERABProcedures {
		pendingIDs = append(pendingIDs, id)
		for ebi := range proc.ExpectedEBIs {
			expectedMap[ebi] = struct{}{}
		}
	}
	sort.Strings(pendingIDs)
	return pendingIDs, sortedExpectedEBIs(expectedMap), ue.S1BindingGeneration
}

func sortedExpectedEBIs(expected map[uint8]struct{}) []uint8 {
	out := make([]uint8, 0, len(expected))
	for ebi := range expected {
		out = append(out, ebi)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func containsERABResult(successes []ERABSetupSuccess, failures []ERABSetupFailure, ebi uint8) bool {
	for _, success := range successes {
		if success.EBI == ebi {
			return true
		}
	}
	for _, failure := range failures {
		if failure.EBI == ebi {
			return true
		}
	}
	return false
}
