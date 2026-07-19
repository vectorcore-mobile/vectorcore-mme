package s1ap

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/gtpv2"
	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/models"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/security"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"github.com/vectorcore/mme/internal/uecontext"
)

type pathSwitchBearer struct {
	EBI  uint8
	TEID uint32
	IP   net.IP
}

// handlePathSwitchRequest handles S1AP Path Switch Request from a target eNB.
// This is the MME-side of an X2 handover: the UE has already moved to the target eNB
// over X2; the target eNB now requests the MME to update the S-GW downlink path.
func (s *Server) handlePathSwitchRequest(remoteAddr string, p *pdu.PDU, ieList []pdu.ProtocolIE) {
	var mmeUEID uint32
	var enbUEID uint32
	var uplinkListValue []byte

	for _, ie := range ieList {
		switch ie.ID {
		case pdu.IEMMEUES1APID:
			id, _ := ies.DecodeMMEUEApID(ie.Value)
			mmeUEID = id
		case pdu.IEENBS1APID:
			id, _ := ies.DecodeENBUEApID(ie.Value)
			enbUEID = id
		case pdu.IEERABToBeSwitchedInUplinkList:
			uplinkListValue = ie.Value
		}
	}

	log := s.log.With(
		zap.String("remote", remoteAddr),
		zap.String("procedure", "PathSwitchRequest"),
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.Uint32("enb_ue_id", enbUEID),
	)

	metrics.PathSwitchTotal.WithLabelValues("attempt").Inc()

	// Look up UE context.
	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		log.Warn("s1ap: PathSwitch: UE not found")
		metrics.PathSwitchTotal.WithLabelValues("ue_not_found").Inc()
		s.sendPathSwitchFailure(remoteAddr, mmeUEID, enbUEID)
		return
	}

	// Validate UE state and snapshot bearer info.
	ue.Lock()
	emmState := ue.EMMState
	sgwcTEID := ue.SGWC_TEID
	sgwAddr := ue.SGWAddress
	ue.Unlock()

	if emmState != emm.StateRegistered {
		log.Warn("s1ap: PathSwitch: UE not EMM-REGISTERED", zap.Stringer("emm_state", emmState))
		metrics.PathSwitchTotal.WithLabelValues("ue_not_found").Inc()
		s.sendPathSwitchFailure(remoteAddr, mmeUEID, enbUEID)
		return
	}
	if sgwcTEID == 0 {
		log.Warn("s1ap: PathSwitch: no active bearer")
		metrics.PathSwitchTotal.WithLabelValues("no_bearer").Inc()
		s.sendPathSwitchFailure(remoteAddr, mmeUEID, enbUEID)
		return
	}

	// Decode the full uplink E-RAB list and build the bearer updates to send on S11.
	uplinkBearers, err := decodePathSwitchERABList(uplinkListValue)
	if err != nil {
		log.Warn("s1ap: PathSwitch: E-RAB decode failed", zap.Error(err))
		metrics.PathSwitchTotal.WithLabelValues("decode_error").Inc()
		s.sendPathSwitchFailure(remoteAddr, mmeUEID, enbUEID)
		return
	}
	if len(uplinkBearers) == 0 {
		log.Warn("s1ap: PathSwitch: no uplink bearers provided")
		metrics.PathSwitchTotal.WithLabelValues("decode_error").Inc()
		s.sendPathSwitchFailure(remoteAddr, mmeUEID, enbUEID)
		return
	}

	mbrBearers, bearerErr := pathSwitchMBRBearersLocked(ue, uplinkBearers)
	if bearerErr != nil {
		log.Warn("s1ap: PathSwitch: invalid bearer list", zap.Error(bearerErr))
		metrics.PathSwitchTotal.WithLabelValues("no_bearer").Inc()
		s.sendPathSwitchFailure(remoteAddr, mmeUEID, enbUEID)
		return
	}

	log = log.With(zap.Int("bearer_count", len(mbrBearers)))
	log.Info("s1ap: PathSwitch: sending Modify Bearer Request")

	// Kick off MBR + Ack/Failure in a goroutine so we don't block the SCTP receive loop.
	go func() {
		mbr := &gtpv2.ModifyBearerRequest{
			SGWAddress: sgwAddr,
			SGWC_TEID:  sgwcTEID,
			Bearers:    mbrBearers,
			RATType:    gtpv2.RATTypeEUTRAN,
		}
		if err := s.s11.SendMBR(mmeUEID, mbr); err != nil {
			log.Warn("s1ap: PathSwitch: MBR failed", zap.Error(err))
			metrics.PathSwitchTotal.WithLabelValues("s11_error").Inc()
			s.sendPathSwitchFailure(remoteAddr, mmeUEID, enbUEID)
			return
		}

		// MBR succeeded — update UE context under lock.
		ue.Lock()
		ue.ENBS1APID = enbUEID
		ue.ENBGlobalID = remoteAddr
		applyPathSwitchBearersLocked(ue, uplinkBearers)
		ue.SetECMState(emm.ECMConnected)

		// Pre-compute next NH for the subsequent handover (TS 33.401 §A.4).
		currentNH := ue.NH
		currentNCC := ue.NCC
		if len(currentNH) == 32 {
			if nextNH, nhErr := security.DeriveNH(ue.KASME, currentNH); nhErr == nil {
				ue.NH = nextNH
				ue.NCC = (currentNCC + 1) % 8
			}
		}

		// Snapshot for Ack.
		ackNH := currentNH
		ackNCC := currentNCC
		ue.Unlock()

		log.Info("s1ap: PathSwitch: success, sending Ack",
			zap.Uint8("ncc", ackNCC))
		metrics.PathSwitchTotal.WithLabelValues("success").Inc()

		secCtxValue := encodeSecurityContextIE(ackNH, ackNCC)
		s.sendPathSwitchAck(remoteAddr, mmeUEID, enbUEID, secCtxValue)

		s.persistUERecoverySnapshot(ue, models.RecoveryStateActiveSnapshot, "ESTABLISHED")
	}()
}

func pathSwitchMBRBearersLocked(ue *uecontext.Context, requested []pathSwitchBearer) ([]gtpv2.ModifyBearer, error) {
	ue.Lock()
	defer ue.Unlock()

	if len(requested) == 0 {
		return nil, fmt.Errorf("path switch E-RAB: empty bearer list")
	}

	known := make(map[uint8]struct{}, len(ue.PDNs)+len(ue.DedicatedBearers)+1)
	for _, pdn := range ue.PDNs {
		if pdn == nil || pdn.DefaultEBI == 0 || !pdn.ERABEstablished || pdn.ModifyBearerFailed {
			continue
		}
		known[pdn.DefaultEBI] = struct{}{}
	}
	if ue.DefaultEBI != 0 && ue.SGWU_TEID != 0 && len(ue.SGWU_IP) != 0 {
		known[ue.DefaultEBI] = struct{}{}
	}
	for _, bearer := range ue.DedicatedBearers {
		if bearer == nil || bearer.AssignedEBI == 0 || !bearer.ERABEstablished || bearer.SGWS1UTEID == 0 || len(bearer.SGWS1UIP) == 0 {
			continue
		}
		known[bearer.AssignedEBI] = struct{}{}
	}

	seen := make(map[uint8]struct{}, len(requested))
	out := make([]gtpv2.ModifyBearer, 0, len(requested))
	for _, bearer := range requested {
		if bearer.TEID == 0 || len(bearer.IP) == 0 {
			return nil, fmt.Errorf("path switch E-RAB: missing transport for EBI %d", bearer.EBI)
		}
		if _, ok := seen[bearer.EBI]; ok {
			return nil, fmt.Errorf("path switch E-RAB: duplicate EBI %d", bearer.EBI)
		}
		if _, ok := known[bearer.EBI]; !ok {
			return nil, fmt.Errorf("path switch E-RAB: unknown EBI %d", bearer.EBI)
		}
		seen[bearer.EBI] = struct{}{}
		out = append(out, gtpv2.ModifyBearer{
			EBI:       bearer.EBI,
			ENBU_TEID: bearer.TEID,
			ENBU_IP:   append(net.IP(nil), bearer.IP...),
		})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].EBI < out[j].EBI })
	return out, nil
}

func applyPathSwitchBearersLocked(ue *uecontext.Context, bearers []pathSwitchBearer) {
	for _, bearer := range bearers {
		if ue.DefaultEBI == bearer.EBI {
			ue.ENBU_TEID = bearer.TEID
			ue.ENBU_IP = append(net.IP(nil), bearer.IP...)
		}
		for _, pdn := range ue.PDNs {
			if pdn == nil || pdn.DefaultEBI != bearer.EBI {
				continue
			}
			pdn.ENBU_TEID = bearer.TEID
			pdn.ENBU_IP = append(net.IP(nil), bearer.IP...)
		}
		for _, dedicated := range ue.DedicatedBearers {
			if dedicated == nil || dedicated.AssignedEBI != bearer.EBI {
				continue
			}
			dedicated.ENBS1UTEID = bearer.TEID
			dedicated.ENBS1UIP = append(net.IP(nil), bearer.IP...)
		}
	}
}

// decodePathSwitchERABs parses the E-RABToBeSwitchedInUplinkList IE value
// to extract the first item's E-RAB-ID, eNB S1-U TEID, and IP address.
//
// Wire format:
//
//	SEQUENCE OF (count constrained 1..256), align
//	Each item: IE container [id:2B][criticality:2bits][opentype]
//	Inner E-RABToBeSwitchedInUplinkItem SEQUENCE (same layout as ICS response items):
//	  ext=0(1b), iE-Extensions optional bit(1b), align,
//	  E-RAB-ID(0..15, 4b), transportLayerAddress BIT STRING (1..160,...), GTP-TEID(4B)
func decodePathSwitchERABs(data []byte) (ebi uint8, teid uint32, ip net.IP, err error) {
	bearers, err := decodePathSwitchERABList(data)
	if err != nil {
		return 0, 0, nil, err
	}
	first := bearers[0]
	return first.EBI, first.TEID, first.IP, nil
}

func decodePathSwitchERABList(data []byte) ([]pathSwitchBearer, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("path switch E-RAB: too short")
	}
	r := aper.NewBitReader(data)

	count, decErr := aper.DecodeConstrainedWholeNumber(r, 1, 256)
	if decErr != nil || count == 0 {
		return nil, fmt.Errorf("path switch E-RAB: bad count")
	}
	r.AlignToByte()

	bearers := make([]pathSwitchBearer, 0, count)
	for idx := int64(0); idx < count; idx++ {
		// Read IE wrapper (accept any item IE ID — different eNB implementations may vary).
		_, decErr = aper.DecodeConstrainedWholeNumber(r, 0, 65535) // item IE ID (ignored)
		if decErr != nil {
			return nil, fmt.Errorf("path switch E-RAB: IE ID decode failed")
		}
		_, decErr = aper.DecodeCriticality(r)
		if decErr != nil {
			return nil, fmt.Errorf("path switch E-RAB: criticality decode failed")
		}
		itemBytes, openErr := aper.ReadOpenType(r)
		if openErr != nil {
			return nil, fmt.Errorf("path switch E-RAB: open type read failed")
		}

		// Decode inner E-RABToBeSwitchedInUplinkItem SEQUENCE.
		ir := aper.NewBitReader(itemBytes)
		if _, decErr = ir.ReadBit(); decErr != nil {
			return nil, fmt.Errorf("path switch E-RAB: inner ext bit")
		}
		if _, decErr = ir.ReadBit(); decErr != nil {
			return nil, fmt.Errorf("path switch E-RAB: inner opt bit")
		}
		erabID, idErr := aper.DecodeConstrainedWholeNumber(ir, 0, 15)
		if idErr != nil {
			return nil, fmt.Errorf("path switch E-RAB: E-RAB-ID decode failed")
		}

		extBit, bitErr := ir.ReadBit()
		if bitErr != nil {
			return nil, fmt.Errorf("path switch E-RAB: transport address ext decode failed")
		}
		var addrBits int64
		if extBit == 0 {
			addrBits, decErr = aper.DecodeConstrainedWholeNumber(ir, 1, 160)
		} else {
			addrBits, decErr = aper.DecodeConstrainedWholeNumber(ir, 0, 65535)
		}
		if decErr != nil {
			return nil, fmt.Errorf("path switch E-RAB: transport address length decode failed")
		}
		ir.AlignToByte()
		numBytes := int((addrBits + 7) / 8)
		addrBytes, decErr := ir.ReadOctets(numBytes)
		if decErr != nil || numBytes < 4 {
			return nil, fmt.Errorf("path switch E-RAB: transport address decode failed")
		}
		parsedIP := net.IP(addrBytes[:4]).To4()
		if parsedIP == nil {
			return nil, fmt.Errorf("path switch E-RAB: invalid IPv4 transport address")
		}

		ir.AlignToByte()
		teidBytes, teidErr := ir.ReadOctets(4)
		if teidErr != nil {
			return nil, fmt.Errorf("path switch E-RAB: GTP-TEID decode failed")
		}

		bearers = append(bearers, pathSwitchBearer{
			EBI:  uint8(erabID),
			TEID: binary.BigEndian.Uint32(teidBytes),
			IP:   parsedIP,
		})
	}

	return bearers, nil
}

// encodeSecurityContextIE encodes the SecurityContext IE value for Path Switch Ack.
//
// SecurityContext SEQUENCE (TS 36.413):
//
//	extension bit (0), iE-Extensions optional bit (0),
//	nextHopChainingCount INTEGER(0..7) [3 bits],
//	nextHopParameter BIT STRING SIZE(256) [32 bytes / 256 bits, not byte-aligned here]
func encodeSecurityContextIE(nh []byte, ncc uint8) []byte {
	w := aper.NewBitWriter()
	w.WriteBit(0) // extension marker
	w.WriteBit(0) // iE-Extensions absent
	_ = aper.EncodeConstrainedWholeNumber(w, int64(ncc), 0, 7)
	// nextHopParameter follows immediately after the 3-bit NCC with no byte alignment.
	var padded [32]byte
	copy(padded[:], nh)
	for _, b := range padded {
		for bit := 7; bit >= 0; bit-- {
			w.WriteBit((b >> bit) & 1)
		}
	}
	return w.Bytes()
}

// sendPathSwitchAck sends S1AP Path Switch Request Acknowledge to the target eNB.
func (s *Server) sendPathSwitchAck(enbAddr string, mmeUEID, enbUEID uint32, secCtxValue []byte) {
	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeMMEUEApID(mmeUEID)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeENBUEApID(enbUEID)},
		{ID: pdu.IESecurityContext, Criticality: aper.CriticalityReject, Value: secCtxValue},
	}
	msg := pdu.BuildSuccessfulOutcome(pdu.ProcPathSwitchRequest, aper.CriticalityReject, ieList)
	s.sendToAddr(enbAddr, msg)
}

// sendPathSwitchFailure sends S1AP Path Switch Request Failure to the target eNB.
func (s *Server) sendPathSwitchFailure(enbAddr string, mmeUEID, enbUEID uint32) {
	causeValue := ies.EncodeCause(ies.CauseGroupRadioNetwork, ies.CauseRadioNetworkUnspecified)
	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeMMEUEApID(mmeUEID)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeENBUEApID(enbUEID)},
		{ID: pdu.IECause, Criticality: aper.CriticalityIgnore, Value: causeValue},
	}
	msg := pdu.BuildUnsuccessfulOutcome(pdu.ProcPathSwitchRequest, aper.CriticalityReject, ieList)
	s.sendToAddr(enbAddr, msg)
}
