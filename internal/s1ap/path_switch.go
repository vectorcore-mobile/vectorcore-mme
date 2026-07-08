package s1ap

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

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
	defaultEBI := ue.DefaultEBI
	ue.Unlock()

	if emmState != emm.StateRegistered {
		log.Warn("s1ap: PathSwitch: UE not EMM-REGISTERED", zap.Stringer("emm_state", emmState))
		metrics.PathSwitchTotal.WithLabelValues("ue_not_found").Inc()
		s.sendPathSwitchFailure(remoteAddr, mmeUEID, enbUEID)
		return
	}
	if sgwcTEID == 0 || defaultEBI == 0 {
		log.Warn("s1ap: PathSwitch: no active bearer")
		metrics.PathSwitchTotal.WithLabelValues("no_bearer").Inc()
		s.sendPathSwitchFailure(remoteAddr, mmeUEID, enbUEID)
		return
	}

	// Decode new eNB S1-U F-TEID from E-RABToBeSwitchedInUplinkList.
	newEBI, newTEID, newIP, err := decodePathSwitchERABs(uplinkListValue)
	if err != nil {
		log.Warn("s1ap: PathSwitch: E-RAB decode failed", zap.Error(err))
		metrics.PathSwitchTotal.WithLabelValues("decode_error").Inc()
		s.sendPathSwitchFailure(remoteAddr, mmeUEID, enbUEID)
		return
	}

	log = log.With(zap.Uint8("ebi", newEBI), zap.Uint32("new_teid", newTEID), zap.Stringer("new_ip", newIP))
	log.Info("s1ap: PathSwitch: sending Modify Bearer Request")

	// Kick off MBR + Ack/Failure in a goroutine so we don't block the SCTP receive loop.
	go func() {
		mbr := &gtpv2.ModifyBearerRequest{
			SGWAddress: sgwAddr,
			SGWC_TEID:  sgwcTEID,
			EBI:        defaultEBI,
			ENBU_TEID:  newTEID,
			ENBU_IP:    newIP,
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
		ue.ENBU_TEID = newTEID
		ue.ENBU_IP = append(net.IP(nil), newIP...)
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

		// Snapshot for Ack and DB.
		ackNH := currentNH
		ackNCC := currentNCC
		dbCtx := buildPathSwitchDBContext(ue)
		ue.Unlock()

		log.Info("s1ap: PathSwitch: success, sending Ack",
			zap.Uint8("ncc", ackNCC))
		metrics.PathSwitchTotal.WithLabelValues("success").Inc()

		secCtxValue := encodeSecurityContextIE(ackNH, ackNCC)
		s.sendPathSwitchAck(remoteAddr, mmeUEID, enbUEID, secCtxValue)

		if s.store != nil {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := s.store.UpsertUEContext(ctx, dbCtx); err != nil {
					s.log.Warn("s1ap: PathSwitch: DB upsert failed",
						zap.Uint32("mme_ue_id", mmeUEID), zap.Error(err))
				}
			}()
		}
	}()
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
	if len(data) < 2 {
		return 0, 0, nil, fmt.Errorf("path switch E-RAB: too short")
	}
	r := aper.NewBitReader(data)

	count, decErr := aper.DecodeConstrainedWholeNumber(r, 1, 256)
	if decErr != nil || count == 0 {
		return 0, 0, nil, fmt.Errorf("path switch E-RAB: bad count")
	}
	r.AlignToByte()

	// Read IE wrapper (accept any item IE ID — different eNB implementations may vary).
	_, decErr = aper.DecodeConstrainedWholeNumber(r, 0, 65535) // item IE ID (ignored)
	if decErr != nil {
		return 0, 0, nil, fmt.Errorf("path switch E-RAB: IE ID decode failed")
	}
	_, decErr = aper.DecodeCriticality(r)
	if decErr != nil {
		return 0, 0, nil, fmt.Errorf("path switch E-RAB: criticality decode failed")
	}
	itemBytes, decErr := aper.ReadOpenType(r)
	if decErr != nil {
		return 0, 0, nil, fmt.Errorf("path switch E-RAB: open type read failed")
	}

	// Decode inner E-RABToBeSwitchedInUplinkItem SEQUENCE.
	ir := aper.NewBitReader(itemBytes)
	// Extension marker
	if _, decErr = ir.ReadBit(); decErr != nil {
		return 0, 0, nil, fmt.Errorf("path switch E-RAB: inner ext bit")
	}
	// iE-Extensions optional bit
	if _, decErr = ir.ReadBit(); decErr != nil {
		return 0, 0, nil, fmt.Errorf("path switch E-RAB: inner opt bit")
	}
	// E-RAB-ID (0..15) — immediately follows option bits with no alignment
	erabID, decErr := aper.DecodeConstrainedWholeNumber(ir, 0, 15)
	if decErr != nil {
		return 0, 0, nil, fmt.Errorf("path switch E-RAB: E-RAB-ID decode failed")
	}

	// transportLayerAddress BIT STRING (1..160,...): ext bit, constrained length, align, bytes.
	extBit, _ := ir.ReadBit()
	var addrBits int64
	if extBit == 0 {
		addrBits, _ = aper.DecodeConstrainedWholeNumber(ir, 1, 160)
	} else {
		addrBits, _ = aper.DecodeConstrainedWholeNumber(ir, 0, 65535)
	}
	ir.AlignToByte()
	numBytes := int((addrBits + 7) / 8)
	addrBytes, decErr := ir.ReadOctets(numBytes)
	if decErr != nil || numBytes < 4 {
		return 0, 0, nil, fmt.Errorf("path switch E-RAB: transport address decode failed")
	}
	parsedIP := net.IP(addrBytes[:4]).To4()

	// GTP-TEID OCTET STRING (SIZE 4) — fixed, no length prefix.
	ir.AlignToByte()
	teidBytes, decErr := ir.ReadOctets(4)
	if decErr != nil {
		return 0, 0, nil, fmt.Errorf("path switch E-RAB: GTP-TEID decode failed")
	}
	parsedTEID := binary.BigEndian.Uint32(teidBytes)

	return uint8(erabID), parsedTEID, parsedIP, nil
}

// encodeSecurityContextIE encodes the SecurityContext IE value for Path Switch Ack.
//
// SecurityContext SEQUENCE (TS 36.413):
//
//	extension bit (0), iE-Extensions optional bit (0), align,
//	nextHopChainingCount INTEGER(0..7) [3 bits], align,
//	nextHopParameter BIT STRING SIZE(256) [32 bytes]
func encodeSecurityContextIE(nh []byte, ncc uint8) []byte {
	w := aper.NewBitWriter()
	w.WriteBit(0) // extension marker
	w.WriteBit(0) // iE-Extensions absent
	// nextHopChainingCount: INTEGER (0..7), 3 bits, MSB first
	_ = aper.EncodeConstrainedWholeNumber(w, int64(ncc), 0, 7)
	w.AlignToByte()
	// nextHopParameter: BIT STRING SIZE(256) — fixed length, no length prefix, 32 bytes
	if len(nh) >= 32 {
		w.WriteOctets(nh[:32])
	} else {
		// Pad with zeros if NH is short (should not happen in normal operation)
		padded := make([]byte, 32)
		copy(padded, nh)
		w.WriteOctets(padded)
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

// buildPathSwitchDBContext snapshots UE fields for persistence after a successful path switch.
// Must be called under ue.Lock().
func buildPathSwitchDBContext(ue *uecontext.Context) *models.UEContext {
	db := &models.UEContext{
		MMEUES1APID:  ue.MMEUES1APID,
		IMSI:         ue.IMSI,
		EMMState:     ue.EMMState.String(),
		KASME:        append([]byte(nil), ue.KASME...),
		KNASint:      append([]byte(nil), ue.KNASint...),
		KNASenc:      append([]byte(nil), ue.KNASenc...),
		ULNASCount:   uint32(ue.ULNASCount),
		DLNASCount:   uint32(ue.DLNASCount),
		IntAlg:       ue.IntAlg,
		EncAlg:       ue.EncAlg,
		ENBS1APID:    ue.ENBS1APID,
		ENBGlobalID:  ue.ENBGlobalID,
		DefaultEBI:   uint32(ue.DefaultEBI),
		SGWU_TEID:    ue.SGWU_TEID,
		SGWC_TEID:    ue.SGWC_TEID,
		ENBU_TEID:    ue.ENBU_TEID,
		NH:           append([]byte(nil), ue.NH...),
		NCC:          ue.NCC,
		LastModified: time.Now().UTC().Format(time.RFC3339),
	}
	if ue.MSISDN != "" {
		ms := ue.MSISDN
		db.MSISDN = &ms
	}
	if ue.APN != "" {
		a := ue.APN
		db.APN = &a
	}
	if ue.UEIPv4 != nil {
		db.UEIPv4 = ue.UEIPv4.String()
	}
	if ue.SGWU_IP != nil {
		db.SGWU_IP = ue.SGWU_IP.String()
	}
	if ue.SGWC_IP != nil {
		db.SGWC_IP = ue.SGWC_IP.String()
	}
	if ue.ENBU_IP != nil {
		db.ENBU_IP = ue.ENBU_IP.String()
	}
	if ue.GUTI != nil {
		g := uecontext.SerialiseGUTI(ue.GUTI)
		db.GUTI = &g
	}
	if ue.TAI != nil {
		db.TAI = fmt.Sprintf("%02X%02X%02X-%04X",
			ue.TAI.PLMN[0], ue.TAI.PLMN[1], ue.TAI.PLMN[2], ue.TAI.TAC)
	}
	return db
}
