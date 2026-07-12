package s1ap

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/gtpv2"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"github.com/vectorcore/mme/internal/uecontext"
)

type ERABSetupItem struct {
	EBI                     uint8
	QCI                     uint8
	ARPPriority             uint8
	PreemptionCapability    bool
	PreemptionVulnerability bool
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
	Cause      uint8
}

type UEAggregateMaximumBitrate struct {
	Downlink uint64
	Uplink   uint64
}

func (s *Server) SendERABSetupRequest(mmeUEID uint32, items []ERABSetupItem) error {
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

	msg, erabValue, err := BuildERABSetupRequest(mmeUEID, enbS1APID, nil, items)
	if err != nil {
		return err
	}
	for _, item := range items {
		s.log.Info("s1ap: E-RAB Setup Request item",
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
	return s.sendToAddr(enbAddr, msg)
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

	w := aper.NewBitWriter()

	w.WriteBit(0) // E-RABToBeSetupItemBearerSUReq extension marker
	w.WriteBit(0) // iE-Extensions absent

	w.WriteBit(0)
	_ = aper.EncodeConstrainedWholeNumber(w, int64(item.EBI), 0, 15)

	w.WriteBit(0) // E-RABLevelQoSParameters extension marker
	w.WriteBit(0) // gbrQosInformation absent
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

func decodeERABSetupResponseList(data []byte) ([]ERABSetupResult, error) {
	r := aper.NewBitReader(data)
	count, err := aper.DecodeConstrainedWholeNumber(r, 1, 256)
	if err != nil {
		return nil, fmt.Errorf("decode E-RAB setup response list count: %w", err)
	}
	r.AlignToByte()
	results := make([]ERABSetupResult, 0, int(count))
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

func decodeERABSetupResponseItem(data []byte) (ERABSetupResult, error) {
	ir := aper.NewBitReader(data)
	if _, err := ir.ReadBit(); err != nil {
		return ERABSetupResult{}, err
	}
	if _, err := ir.ReadBit(); err != nil {
		return ERABSetupResult{}, err
	}
	erabIDExt, err := ir.ReadBit()
	if err != nil {
		return ERABSetupResult{}, err
	}
	if erabIDExt != 0 {
		return ERABSetupResult{}, fmt.Errorf("E-RAB ID extension value not supported")
	}
	erabID, err := aper.DecodeConstrainedWholeNumber(ir, 0, 15)
	if err != nil {
		return ERABSetupResult{}, err
	}
	extBit, err := ir.ReadBit()
	if err != nil {
		return ERABSetupResult{}, err
	}
	ir.AlignToByte()
	var addrBits int64
	if extBit == 0 {
		addrBits, err = aper.DecodeConstrainedWholeNumber(ir, 1, 160)
	} else {
		addrBits, err = aper.DecodeConstrainedWholeNumber(ir, 0, 65535)
	}
	if err != nil {
		return ERABSetupResult{}, err
	}
	ir.AlignToByte()
	addrBytes, err := ir.ReadOctets(int((addrBits + 7) / 8))
	if err != nil || len(addrBytes) < 4 {
		return ERABSetupResult{}, fmt.Errorf("invalid transportLayerAddress")
	}
	ir.AlignToByte()
	teidBytes, err := ir.ReadOctets(4)
	if err != nil {
		return ERABSetupResult{}, err
	}
	return ERABSetupResult{
		EBI:        uint8(erabID),
		Success:    true,
		ENBS1UIPv4: net.IP(addrBytes[:4]).To4(),
		ENBS1UTEID: binary.BigEndian.Uint32(teidBytes),
	}, nil
}

func (s *Server) handleERABSetupResponse(remoteAddr string, _ *pdu.PDU, ieList []pdu.ProtocolIE) {
	var mmeUEID uint32
	var enbUEID uint32
	var setupList []byte
	for _, ie := range ieList {
		switch ie.ID {
		case pdu.IEMMEUES1APID:
			mmeUEID, _ = ies.DecodeMMEUEApID(ie.Value)
		case pdu.IEENBS1APID:
			enbUEID, _ = ies.DecodeENBUEApID(ie.Value)
		case pdu.IEERABSetupListBearerSURes:
			setupList = ie.Value
		}
	}
	log := s.log.With(
		zap.String("remote", remoteAddr),
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.Uint32("enb_ue_id", enbUEID))
	if len(setupList) == 0 {
		log.Warn("s1ap: E-RAB Setup Response missing setup list")
		return
	}
	results, err := decodeERABSetupResponseList(setupList)
	if err != nil {
		log.Warn("s1ap: E-RAB Setup Response decode failed",
			zap.Error(err),
			zap.String("erab_setup_list_hex", hex.EncodeToString(setupList)))
		return
	}
	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		log.Warn("s1ap: E-RAB Setup Response UE not found")
		return
	}
	for _, result := range results {
		log.Info("s1ap: E-RAB Setup Response item",
			zap.Uint8("ebi", result.EBI),
			zap.Bool("success", result.Success),
			zap.String("enb_s1u_ip", result.ENBS1UIPv4.String()),
			zap.Uint32("enb_s1u_teid", result.ENBS1UTEID))
		if !result.Success {
			continue
		}
		s.completeERABSetupForBearer(ue, result, log)
	}
}

func (s *Server) completeERABSetupForBearer(ue *uecontext.Context, result ERABSetupResult, log *zap.Logger) {
	if s.completeDedicatedERABSetupForBearer(ue, result, log) {
		return
	}
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
	target.ENBU_TEID = result.ENBS1UTEID
	target.ENBU_IP = append(net.IP(nil), result.ENBS1UIPv4...)
	target.ERABEstablished = true
	target.State = "modify-bearer-pending"
	mmeUEID := ue.MMEUES1APID
	mbr := &gtpv2.ModifyBearerRequest{
		SGWAddress: target.SGWAddress,
		SGWC_TEID:  target.SGWC_TEID,
		EBI:        target.DefaultEBI,
		ENBU_TEID:  target.ENBU_TEID,
		ENBU_IP:    append(net.IP(nil), target.ENBU_IP...),
		RATType:    gtpv2.RATTypeEUTRAN,
	}
	apn := target.APN
	ue.Unlock()

	log.Info("s1ap: sending IMS S11 Modify Bearer Request",
		zap.String("apn", apn),
		zap.Uint8("ebi", result.EBI),
		zap.Uint32("sgwc_teid", mbr.SGWC_TEID),
		zap.Uint32("enb_s1u_teid", mbr.ENBU_TEID),
		zap.String("enb_s1u_ipv4", mbr.ENBU_IP.String()))
	if err := s.s11.SendMBR(mmeUEID, mbr); err != nil {
		log.Warn("s1ap: IMS SendMBR failed", zap.String("apn", apn), zap.Uint8("ebi", result.EBI), zap.Error(err))
		ue.Lock()
		if target.State == "modify-bearer-pending" {
			target.State = "modify-bearer-failed"
		}
		ue.Unlock()
	}
}
