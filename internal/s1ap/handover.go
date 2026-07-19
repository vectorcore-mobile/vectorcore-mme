package s1ap

import (
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

// handleHandoverRequired handles an S1AP Handover Required from the source eNB.
// This is step 1 of the intra-MME S1 handover (TS 23.401 §5.5.1.2).
func (s *Server) handleHandoverRequired(remoteAddr string, p *pdu.PDU, ieList []pdu.ProtocolIE) {
	var mmeUEID uint32
	var enbUEID uint32
	var causeBytes []byte
	var targetIDBytes []byte
	var srcToTgtBytes []byte

	for _, ie := range ieList {
		switch ie.ID {
		case pdu.IEMMEUES1APID:
			mmeUEID, _ = ies.DecodeMMEUEApID(ie.Value)
		case pdu.IEENBS1APID:
			enbUEID, _ = ies.DecodeENBUEApID(ie.Value)
		case pdu.IECause:
			causeBytes = ie.Value
		case pdu.IETargetID:
			targetIDBytes = ie.Value
		case pdu.IESourceToTargetTransparentContainer:
			srcToTgtBytes = ie.Value
		}
	}

	log := s.log.With(
		zap.String("remote", remoteAddr),
		zap.String("procedure", "HandoverRequired"),
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.Uint32("enb_ue_id", enbUEID),
	)

	metrics.HandoverTotal.WithLabelValues("preparation", "attempt").Inc()

	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		log.Warn("s1ap: HandoverRequired: UE not found")
		metrics.HandoverTotal.WithLabelValues("preparation", "ue_not_found").Inc()
		s.sendHandoverPrepFailure(remoteAddr, mmeUEID, enbUEID,
			ies.EncodeCause(ies.CauseGroupRadioNetwork, ies.CauseRadioNetworkUnspecified))
		return
	}

	ue.Lock()
	emmState := ue.EMMState
	ecmState := ue.ECMState
	sgwcTEID := ue.SGWC_TEID
	defaultEBI := ue.DefaultEBI
	srcENBAddr := ue.ENBGlobalID
	srcENBS1APID := ue.ENBS1APID
	hoState := ue.HOState
	nh := append([]byte(nil), ue.NH...)
	ncc := ue.NCC
	sgwuTEID := ue.SGWU_TEID
	sgwuIP := append([]byte(nil), ue.SGWU_IP...)
	ueNetCap := ue.UENetworkCapability
	intAlg := ue.IntAlg
	encAlg := ue.EncAlg
	ueAMBRDown := ue.UEAMBRDown
	ueAMBRUp := ue.UEAMBRUp
	apn := ue.APN
	apnCfg, haveAPNCfg := subscriberAPNConfigForResumeLocked(ue, ue.APN)
	ue.Unlock()

	if emmState != emm.StateRegistered {
		log.Warn("s1ap: HandoverRequired: UE not EMM-REGISTERED", zap.Stringer("emm_state", emmState))
		metrics.HandoverTotal.WithLabelValues("preparation", "wrong_state").Inc()
		s.sendHandoverPrepFailure(remoteAddr, mmeUEID, enbUEID,
			ies.EncodeCause(ies.CauseGroupRadioNetwork, ies.CauseRadioNetworkUnspecified))
		return
	}
	if ecmState != emm.ECMConnected {
		log.Warn("s1ap: HandoverRequired: UE not ECM-CONNECTED")
		metrics.HandoverTotal.WithLabelValues("preparation", "wrong_state").Inc()
		s.sendHandoverPrepFailure(remoteAddr, mmeUEID, enbUEID,
			ies.EncodeCause(ies.CauseGroupRadioNetwork, ies.CauseRadioNetworkUnspecified))
		return
	}
	if sgwcTEID == 0 || defaultEBI == 0 {
		log.Warn("s1ap: HandoverRequired: no active bearer")
		metrics.HandoverTotal.WithLabelValues("preparation", "no_bearer").Inc()
		s.sendHandoverPrepFailure(remoteAddr, mmeUEID, enbUEID,
			ies.EncodeCause(ies.CauseGroupRadioNetwork, ies.CauseRadioNetworkUnspecified))
		return
	}
	if srcENBAddr != remoteAddr {
		log.Warn("s1ap: HandoverRequired: remote addr does not match UE source eNB",
			zap.String("ue_enb_addr", srcENBAddr))
		metrics.HandoverTotal.WithLabelValues("preparation", "wrong_state").Inc()
		s.sendHandoverPrepFailure(remoteAddr, mmeUEID, enbUEID,
			ies.EncodeCause(ies.CauseGroupRadioNetwork, ies.CauseRadioNetworkUnspecified))
		return
	}
	if hoState != uecontext.HOStateNone {
		log.Warn("s1ap: HandoverRequired: UE already in handover", zap.Uint8("ho_state", uint8(hoState)))
		metrics.HandoverTotal.WithLabelValues("preparation", "wrong_state").Inc()
		s.sendHandoverPrepFailure(remoteAddr, mmeUEID, enbUEID,
			ies.EncodeCause(ies.CauseGroupRadioNetwork, ies.CauseRadioNetworkUnspecified))
		return
	}
	if ueAMBRDown == 0 || ueAMBRUp == 0 {
		log.Warn("s1ap: HandoverRequired: missing UE AMBR",
			zap.Uint32("ue_ambr_down", ueAMBRDown),
			zap.Uint32("ue_ambr_up", ueAMBRUp))
		metrics.HandoverTotal.WithLabelValues("preparation", "wrong_state").Inc()
		s.sendHandoverPrepFailure(remoteAddr, mmeUEID, enbUEID,
			ies.EncodeCause(ies.CauseGroupRadioNetwork, ies.CauseRadioNetworkUnspecified))
		return
	}
	if !haveAPNCfg {
		log.Warn("s1ap: HandoverRequired: missing subscriber APN policy",
			zap.String("apn", apn))
		metrics.HandoverTotal.WithLabelValues("preparation", "wrong_state").Inc()
		s.sendHandoverPrepFailure(remoteAddr, mmeUEID, enbUEID,
			ies.EncodeCause(ies.CauseGroupRadioNetwork, ies.CauseRadioNetworkUnspecified))
		return
	}
	if missing := validateSubscriberAPNPolicy(&apnCfg); len(missing) != 0 {
		log.Warn("s1ap: HandoverRequired: incomplete subscriber APN policy",
			zap.String("apn", apn),
			zap.Strings("missing_fields", missing))
		metrics.HandoverTotal.WithLabelValues("preparation", "wrong_state").Inc()
		s.sendHandoverPrepFailure(remoteAddr, mmeUEID, enbUEID,
			ies.EncodeCause(ies.CauseGroupRadioNetwork, ies.CauseRadioNetworkUnspecified))
		return
	}

	targetGlobalID, err := decodeTargetID(targetIDBytes)
	if err != nil {
		log.Warn("s1ap: HandoverRequired: TargetID decode failed", zap.Error(err))
		metrics.HandoverTotal.WithLabelValues("preparation", "no_target_enb").Inc()
		s.sendHandoverPrepFailure(remoteAddr, mmeUEID, enbUEID,
			ies.EncodeCause(ies.CauseGroupRadioNetwork, ies.CauseRadioNetworkUnknownTargetID))
		return
	}

	targetAddr, found := s.findENBByGlobalID(targetGlobalID)
	if !found {
		log.Warn("s1ap: HandoverRequired: target eNB not found",
			zap.String("target_global_enb_id", targetGlobalID.Serialise()))
		metrics.HandoverTotal.WithLabelValues("preparation", "no_target_enb").Inc()
		s.sendHandoverPrepFailure(remoteAddr, mmeUEID, enbUEID,
			ies.EncodeCause(ies.CauseGroupRadioNetwork, ies.CauseRadioNetworkUnknownTargetID))
		return
	}

	log = log.With(zap.String("target_addr", targetAddr))
	log.Info("s1ap: HandoverRequired: sending Handover Request to target")

	ue.Lock()
	ue.HOState = uecontext.HOStatePreparing
	ue.HOSrcENBAddr = srcENBAddr
	ue.HOSrcENBS1APID = srcENBS1APID
	ue.HOTargetENBAddr = targetAddr
	ue.HOSrcToTgtContainer = srcToTgtBytes
	ue.StartTimer("T_HO_PREP", 2*time.Second, func() {
		s.handoverPrepTimeout(mmeUEID, enbUEID)
	})
	ue.Unlock()

	b := &BearerInfo{
		EBI:                     defaultEBI,
		QCI:                     apnCfg.QCI,
		ARPPriority:             apnCfg.ARPPriority,
		PreemptionCapability:    apnCfg.PreemptionCapability,
		PreemptionVulnerability: apnCfg.PreemptionVulnerability,
		SGWU_TEID:               sgwuTEID,
		SGWU_IP:                 sgwuIP,
	}
	s.sendHandoverRequest(targetAddr, mmeUEID, b, uint64(ueAMBRDown), uint64(ueAMBRUp), nh, ncc, causeBytes, srcToTgtBytes, ueNetCap, intAlg, encAlg)
}

// handleHandoverRequestAck handles S1AP Handover Request Acknowledge from the target eNB.
// This is step 3 — complete preparation phase, send Handover Command to source.
func (s *Server) handleHandoverRequestAck(remoteAddr string, p *pdu.PDU, ieList []pdu.ProtocolIE) {
	var mmeUEID uint32
	var tgtENBUEID uint32
	var admittedListBytes []byte
	var tgtToSrcBytes []byte

	for _, ie := range ieList {
		switch ie.ID {
		case pdu.IEMMEUES1APID:
			mmeUEID, _ = ies.DecodeMMEUEApID(ie.Value)
		case pdu.IEENBS1APID:
			tgtENBUEID, _ = ies.DecodeENBUEApID(ie.Value)
		case pdu.IEERABAdmittedList:
			admittedListBytes = ie.Value
		case pdu.IETargetToSourceTransparentContainer:
			tgtToSrcBytes = ie.Value
		}
	}

	log := s.log.With(
		zap.String("remote", remoteAddr),
		zap.String("procedure", "HandoverRequestAck"),
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.Uint32("tgt_enb_ue_id", tgtENBUEID),
	)

	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		log.Warn("s1ap: HandoverRequestAck: UE not found")
		return
	}

	ue.Lock()
	hoState := ue.HOState
	tgtAddr := ue.HOTargetENBAddr
	srcAddr := ue.HOSrcENBAddr
	srcENBUEID := ue.HOSrcENBS1APID
	ue.Unlock()

	if hoState != uecontext.HOStatePreparing {
		log.Warn("s1ap: HandoverRequestAck: UE not in HOStatePreparing", zap.Uint8("ho_state", uint8(hoState)))
		return
	}
	if remoteAddr != tgtAddr {
		log.Warn("s1ap: HandoverRequestAck: unexpected sender",
			zap.String("expected", tgtAddr))
		return
	}

	ebi, teid, ip, err := decodeERABAdmittedList(admittedListBytes)
	if err != nil {
		log.Warn("s1ap: HandoverRequestAck: E-RABAdmittedList decode failed", zap.Error(err))
		metrics.HandoverTotal.WithLabelValues("preparation", "failure").Inc()
		ue.Lock()
		ue.StopTimer("T_HO_PREP")
		ue.HOState = uecontext.HOStateNone
		ue.HOSrcENBAddr = ""
		ue.HOSrcENBS1APID = 0
		ue.HOTargetENBAddr = ""
		ue.HOSrcToTgtContainer = nil
		ue.Unlock()
		s.sendHandoverPrepFailure(srcAddr, mmeUEID, srcENBUEID,
			ies.EncodeCause(ies.CauseGroupRadioNetwork, ies.CauseRadioNetworkUnspecified))
		return
	}

	log.Info("s1ap: HandoverRequestAck: sending Handover Command",
		zap.Uint8("ebi", ebi), zap.Uint32("tgt_teid", teid), zap.Stringer("tgt_ip", ip))

	ue.Lock()
	ue.StopTimer("T_HO_PREP")
	ue.HOTargetENBUEID = tgtENBUEID
	ue.HOTargetENBU_TEID = teid
	ue.HOTargetENBU_IP = append(net.IP(nil), ip...)
	ue.HOState = uecontext.HOStateExecuting
	ue.StartTimer("T_HO_EXEC", 10*time.Second, func() {
		s.handoverExecTimeout(mmeUEID, tgtAddr, tgtENBUEID)
	})
	ue.Unlock()

	metrics.HandoverTotal.WithLabelValues("preparation", "success").Inc()
	s.sendHandoverCommand(srcAddr, mmeUEID, srcENBUEID, tgtToSrcBytes)
}

// handleHandoverRequestFailure handles S1AP Handover Request Failure (target rejected).
func (s *Server) handleHandoverRequestFailure(remoteAddr string, p *pdu.PDU, ieList []pdu.ProtocolIE) {
	var mmeUEID uint32

	for _, ie := range ieList {
		if ie.ID == pdu.IEMMEUES1APID {
			mmeUEID, _ = ies.DecodeMMEUEApID(ie.Value)
		}
	}

	log := s.log.With(
		zap.String("remote", remoteAddr),
		zap.String("procedure", "HandoverRequestFailure"),
		zap.Uint32("mme_ue_id", mmeUEID),
	)

	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		log.Warn("s1ap: HandoverRequestFailure: UE not found")
		return
	}

	ue.Lock()
	hoState := ue.HOState
	tgtAddr := ue.HOTargetENBAddr
	srcAddr := ue.HOSrcENBAddr
	srcENBUEID := ue.HOSrcENBS1APID
	ue.Unlock()

	if hoState != uecontext.HOStatePreparing {
		log.Warn("s1ap: HandoverRequestFailure: UE not in HOStatePreparing")
		return
	}
	if remoteAddr != tgtAddr {
		log.Warn("s1ap: HandoverRequestFailure: unexpected sender")
		return
	}

	log.Info("s1ap: HandoverRequestFailure: sending Prep Failure to source")
	metrics.HandoverTotal.WithLabelValues("preparation", "failure").Inc()

	ue.Lock()
	ue.StopTimer("T_HO_PREP")
	ue.HOState = uecontext.HOStateNone
	ue.HOSrcENBAddr = ""
	ue.HOSrcENBS1APID = 0
	ue.HOTargetENBAddr = ""
	ue.HOSrcToTgtContainer = nil
	ue.Unlock()

	s.sendHandoverPrepFailure(srcAddr, mmeUEID, srcENBUEID,
		ies.EncodeCause(ies.CauseGroupRadioNetwork, ies.CauseRadioNetworkHOCancelled))
}

// handleHandoverNotify handles S1AP Handover Notify from the target eNB.
// The UE has arrived at the target. Commit the S11 path update and release the source.
func (s *Server) handleHandoverNotify(remoteAddr string, p *pdu.PDU, ieList []pdu.ProtocolIE) {
	var mmeUEID uint32
	var tgtENBUEID uint32

	for _, ie := range ieList {
		switch ie.ID {
		case pdu.IEMMEUES1APID:
			mmeUEID, _ = ies.DecodeMMEUEApID(ie.Value)
		case pdu.IEENBS1APID:
			tgtENBUEID, _ = ies.DecodeENBUEApID(ie.Value)
		}
	}

	log := s.log.With(
		zap.String("remote", remoteAddr),
		zap.String("procedure", "HandoverNotify"),
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.Uint32("tgt_enb_ue_id", tgtENBUEID),
	)

	metrics.HandoverTotal.WithLabelValues("execution", "attempt").Inc()

	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		log.Warn("s1ap: HandoverNotify: UE not found")
		metrics.HandoverTotal.WithLabelValues("execution", "ue_not_found").Inc()
		return
	}

	ue.Lock()
	hoState := ue.HOState
	tgtAddr := ue.HOTargetENBAddr
	srcAddr := ue.HOSrcENBAddr
	srcENBUEID := ue.HOSrcENBS1APID
	sgwcTEID := ue.SGWC_TEID
	sgwAddr := ue.SGWAddress
	defaultEBI := ue.DefaultEBI
	newTEID := ue.HOTargetENBU_TEID
	newIP := append(net.IP(nil), ue.HOTargetENBU_IP...)
	ue.Unlock()

	if hoState != uecontext.HOStateExecuting {
		log.Warn("s1ap: HandoverNotify: UE not in HOStateExecuting", zap.Uint8("ho_state", uint8(hoState)))
		return
	}
	if remoteAddr != tgtAddr {
		log.Warn("s1ap: HandoverNotify: unexpected sender", zap.String("expected", tgtAddr))
		return
	}

	ue.Lock()
	ue.StopTimer("T_HO_EXEC")
	ue.Unlock()

	log.Info("s1ap: HandoverNotify: sending Modify Bearer Request",
		zap.Uint32("new_teid", newTEID), zap.Stringer("new_ip", newIP))

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
			log.Warn("s1ap: HandoverNotify: MBR failed — UE is on target eNB regardless", zap.Error(err))
			metrics.HandoverTotal.WithLabelValues("execution", "s11_error").Inc()
		}

		// UE IS on target eNB regardless of MBR outcome — commit the switch.
		ue.Lock()
		ue.ENBS1APID = tgtENBUEID
		ue.ENBGlobalID = tgtAddr
		ue.ENBU_TEID = newTEID
		ue.ENBU_IP = append(net.IP(nil), newIP...)
		ue.HOState = uecontext.HOStateNone
		ue.HOSrcENBAddr = ""
		ue.HOSrcENBS1APID = 0
		ue.HOTargetENBAddr = ""
		ue.HOTargetENBUEID = 0
		ue.HOTargetENBU_TEID = 0
		ue.HOTargetENBU_IP = nil
		ue.HOSrcToTgtContainer = nil
		ue.SetECMState(emm.ECMConnected)

		// Advance NH/NCC for the next handover (TS 33.401 §7.2.8).
		if len(ue.NH) == 32 {
			if nextNH, nhErr := security.DeriveNH(ue.KASME, ue.NH); nhErr == nil {
				ue.NH = nextNH
				ue.NCC = (ue.NCC + 1) % 8
			}
		}

		ue.Unlock()

		metrics.HandoverTotal.WithLabelValues("execution", "success").Inc()
		log.Info("s1ap: HandoverNotify: success, releasing source eNB",
			zap.String("src_addr", srcAddr))

		// Release source eNB UE context.
		s.sendUEContextReleaseCommandCause(srcAddr, mmeUEID, srcENBUEID,
			ies.CauseGroupRadioNetwork, ies.CauseRadioNetworkSuccessfulHandover)

		s.persistUERecoverySnapshot(ue, models.RecoveryStateActiveSnapshot, "ESTABLISHED")
	}()
}

// handoverPrepTimeout fires when T_HO_PREP expires. Sends Prep Failure to source and clears HO state.
func (s *Server) handoverPrepTimeout(mmeUEID, srcENBUEID uint32) {
	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		return
	}

	ue.Lock()
	if ue.HOState != uecontext.HOStatePreparing {
		ue.Unlock()
		return
	}
	srcAddr := ue.HOSrcENBAddr
	ue.HOState = uecontext.HOStateNone
	ue.HOSrcENBAddr = ""
	ue.HOSrcENBS1APID = 0
	ue.HOTargetENBAddr = ""
	ue.HOSrcToTgtContainer = nil
	ue.Unlock()

	s.log.Warn("s1ap: T_HO_PREP expired, sending Prep Failure",
		zap.Uint32("mme_ue_id", mmeUEID))
	metrics.HandoverTotal.WithLabelValues("preparation", "timeout").Inc()

	s.sendHandoverPrepFailure(srcAddr, mmeUEID, srcENBUEID,
		ies.EncodeCause(ies.CauseGroupRadioNetwork, ies.CauseRadioNetworkUnspecified))
}

// handoverExecTimeout fires when T_HO_EXEC expires. Releases the target eNB UE context.
func (s *Server) handoverExecTimeout(mmeUEID uint32, tgtAddr string, tgtENBUEID uint32) {
	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		return
	}

	ue.Lock()
	if ue.HOState != uecontext.HOStateExecuting {
		ue.Unlock()
		return
	}
	ue.HOState = uecontext.HOStateNone
	ue.HOSrcENBAddr = ""
	ue.HOSrcENBS1APID = 0
	ue.HOTargetENBAddr = ""
	ue.HOTargetENBUEID = 0
	ue.HOTargetENBU_TEID = 0
	ue.HOTargetENBU_IP = nil
	ue.HOSrcToTgtContainer = nil
	ue.Unlock()

	s.log.Warn("s1ap: T_HO_EXEC expired, releasing target eNB UE context",
		zap.Uint32("mme_ue_id", mmeUEID))
	metrics.HandoverTotal.WithLabelValues("execution", "timeout").Inc()

	s.sendUEContextReleaseCommandCause(tgtAddr, mmeUEID, tgtENBUEID,
		ies.CauseGroupRadioNetwork, ies.CauseRadioNetworkUnspecified)
}

// decodeTargetID decodes the TargetID IE value to a GlobalENBID.
//
// Wire format for TargeteNB-ID (intra-LTE):
//
//	Byte 0: ext(0,1b) + CHOICE index(2b, 0=targetENB-ID) + 5 padding bits
//	Byte 1: TargeteNB-ID SEQUENCE ext(0,1b) + iE-Extensions opt(0,1b) + 6 padding bits
//	Bytes 2+: Global-ENB-ID = PLMN(3B) + eNB-ID CHOICE + BIT STRING
func decodeTargetID(data []byte) (ies.GlobalENBID, error) {
	if len(data) < 2 {
		return ies.GlobalENBID{}, fmt.Errorf("s1ap: TargetID too short: %d bytes", len(data))
	}
	// Skip 2 preamble bytes; Global-ENB-ID starts at offset 2.
	return ies.DecodeGlobalENBID(data[2:])
}

// findENBByGlobalID searches s.enbs for an eNB whose GlobalENBID matches g.
// Returns the remote address (map key) if found.
func (s *Server) findENBByGlobalID(g ies.GlobalENBID) (string, bool) {
	target := g.Serialise()
	var foundAddr string
	s.enbs.Range(func(k, v any) bool {
		enb := v.(*ENBContext)
		if enb.GlobalENBID.Serialise() == target {
			foundAddr = k.(string)
			return false // stop iteration
		}
		return true
	})
	return foundAddr, foundAddr != ""
}

// decodeERABAdmittedList parses the E-RABAdmittedList IE value (IE 18) and returns
// the first item's E-RAB-ID, downlink S1-U GTP-TEID, and IP address.
//
// Wire format (SEQUENCE OF, each item is an IE container):
//
//	count (1..256), align
//	[id:2B][crit:2bits][opentype] for each item
//	Inner E-RABAdmittedItem SEQUENCE:
//	  ext(0,1b) | dL-transportLayerAddress opt(1b) | dL-gTP-TEID opt(1b) |
//	  uL-TransportLayerAddress opt(1b) | uL-GTP-TEID opt(1b) | iE-Extensions opt(1b)  — 6 bits total
//	  E-RAB-ID (0..15, 4b) — no alignment before this
//	  transportLayerAddress BIT STRING (1..160,...)
//	  GTP-TEID OCTET STRING (SIZE 4)
func decodeERABAdmittedList(data []byte) (ebi uint8, teid uint32, ip net.IP, err error) {
	if len(data) < 2 {
		return 0, 0, nil, fmt.Errorf("s1ap: E-RABAdmittedList: too short")
	}
	r := aper.NewBitReader(data)

	count, decErr := aper.DecodeConstrainedWholeNumber(r, 1, 256)
	if decErr != nil || count == 0 {
		return 0, 0, nil, fmt.Errorf("s1ap: E-RABAdmittedList: bad count")
	}
	r.AlignToByte()

	// IE wrapper.
	if _, decErr = aper.DecodeConstrainedWholeNumber(r, 0, 65535); decErr != nil {
		return 0, 0, nil, fmt.Errorf("s1ap: E-RABAdmittedList: IE ID decode failed")
	}
	if _, decErr = aper.DecodeCriticality(r); decErr != nil {
		return 0, 0, nil, fmt.Errorf("s1ap: E-RABAdmittedList: criticality decode failed")
	}
	itemBytes, decErr := aper.ReadOpenType(r)
	if decErr != nil {
		return 0, 0, nil, fmt.Errorf("s1ap: E-RABAdmittedList: open type read failed")
	}

	// Decode inner E-RABAdmittedItem SEQUENCE.
	ir := aper.NewBitReader(itemBytes)
	// 6 preamble bits: ext + 5 optionals (all 0 for minimal case)
	for i := 0; i < 6; i++ {
		if _, decErr = ir.ReadBit(); decErr != nil {
			return 0, 0, nil, fmt.Errorf("s1ap: E-RABAdmittedItem: preamble bit %d: %w", i, decErr)
		}
	}

	// E-RAB-ID (0..15, 4 bits) — immediately after preamble bits, no alignment.
	erabID, decErr := aper.DecodeConstrainedWholeNumber(ir, 0, 15)
	if decErr != nil {
		return 0, 0, nil, fmt.Errorf("s1ap: E-RABAdmittedItem: E-RAB-ID: %w", decErr)
	}

	// transportLayerAddress BIT STRING (1..160,...).
	extBit, _ := ir.ReadBit()
	var addrBits int64
	if extBit == 0 {
		addrBits, _ = aper.DecodeConstrainedWholeNumber(ir, 1, 160)
	} else {
		addrBits, _ = aper.DecodeConstrainedWholeNumber(ir, 0, 65535)
	}
	ir.AlignToByte()
	numBytes := int((addrBits + 7) / 8)
	addrData, decErr := ir.ReadOctets(numBytes)
	if decErr != nil || numBytes < 4 {
		return 0, 0, nil, fmt.Errorf("s1ap: E-RABAdmittedItem: transport address: %w", decErr)
	}
	parsedIP := net.IP(addrData[:4]).To4()

	// GTP-TEID OCTET STRING (SIZE 4) — fixed, no length prefix.
	ir.AlignToByte()
	teidBytes, decErr := ir.ReadOctets(4)
	if decErr != nil {
		return 0, 0, nil, fmt.Errorf("s1ap: E-RABAdmittedItem: GTP-TEID: %w", decErr)
	}

	return uint8(erabID), binary.BigEndian.Uint32(teidBytes), parsedIP, nil
}

// encodeHOERABList encodes an E-RABToBeSetupListHOReq (IE 53) with one item (IE 27).
// The item body is identical to encodeERABList with no NAS-PDU; only the IE IDs differ.
func encodeHOERABList(b *BearerInfo) ([]byte, error) {
	if b == nil {
		return nil, fmt.Errorf("s1ap: handover E-RAB requires bearer info")
	}
	if b.QCI == 0 {
		return nil, fmt.Errorf("s1ap: handover E-RAB missing bearer QCI")
	}
	if b.ARPPriority == 0 {
		return nil, fmt.Errorf("s1ap: handover E-RAB missing bearer ARP priority")
	}
	w := aper.NewBitWriter()

	// E-RABToBeSetupItemHOReq preamble: ext=0, data-fwd-not-possible opt=0, iE-Ext opt=0
	w.WriteBit(0) // extension marker
	w.WriteBit(0) // data-Forwarding-Not-Possible absent
	w.WriteBit(0) // iE-Extensions absent

	// E-RAB-ID (0..15)
	_ = aper.EncodeConstrainedWholeNumber(w, int64(b.EBI), 0, 15)

	// E-RABLevelQoSParameters SEQUENCE
	w.WriteBit(0) // extension marker
	w.WriteBit(0) // gbrQosInformation absent
	w.WriteBit(0) // iE-Extensions absent
	_ = aper.EncodeConstrainedWholeNumber(w, int64(b.QCI), 0, 255)
	// AllocationAndRetentionPriority SEQUENCE
	w.WriteBit(0) // extension marker
	w.WriteBit(0) // iE-Extensions absent
	_ = aper.EncodeConstrainedWholeNumber(w, int64(b.ARPPriority), 0, 15)
	if b.PreemptionCapability {
		_ = aper.EncodeConstrainedWholeNumber(w, 1, 0, 1)
	} else {
		_ = aper.EncodeConstrainedWholeNumber(w, 0, 0, 1)
	}
	if b.PreemptionVulnerability {
		_ = aper.EncodeConstrainedWholeNumber(w, 1, 0, 1)
	} else {
		_ = aper.EncodeConstrainedWholeNumber(w, 0, 0, 1)
	}

	// transportLayerAddress BIT STRING (SIZE 1..160)
	w.WriteBit(0) // no extension
	_ = aper.EncodeConstrainedWholeNumber(w, 32, 1, 160)
	w.AlignToByte()
	if len(b.SGWU_IP) >= 4 {
		w.WriteOctets(b.SGWU_IP[:4])
	} else {
		w.WriteOctets([]byte{0, 0, 0, 0})
	}

	// GTP-TEID OCTET STRING (SIZE 4)
	w.AlignToByte()
	w.WriteOctet(byte(b.SGWU_TEID >> 24))
	w.WriteOctet(byte(b.SGWU_TEID >> 16))
	w.WriteOctet(byte(b.SGWU_TEID >> 8))
	w.WriteOctet(byte(b.SGWU_TEID))

	itemBody := w.Bytes()

	// Wrap in inner IE container (IE 27, criticality=reject).
	innerContainer := pdu.EncodeIEContainer([]pdu.ProtocolIE{
		{ID: pdu.IEERABToBeSetupItemHOReq, Criticality: aper.CriticalityReject, Value: itemBody},
	})
	if len(innerContainer) >= 2 {
		innerContainer = innerContainer[2:] // strip count prefix
	}

	// Outer: SEQUENCE OF count=1
	ow := aper.NewBitWriter()
	_ = aper.EncodeConstrainedWholeNumber(ow, 1, 1, 256)
	ow.AlignToByte()
	ow.WriteOctets(innerContainer)
	return ow.Bytes(), nil
}

// sendHandoverRequest sends an S1AP Handover Request to the target eNB.
func (s *Server) sendHandoverRequest(
	targetAddr string,
	mmeUEID uint32,
	b *BearerInfo,
	ueAMBRDown uint64,
	ueAMBRUp uint64,
	nh []byte,
	ncc uint8,
	causeBytes []byte,
	srcToTgt []byte,
	ueNetCap []byte,
	intAlg, encAlg uint8,
) {
	if causeBytes == nil {
		causeBytes = ies.EncodeCause(ies.CauseGroupRadioNetwork, ies.CauseRadioNetworkUnspecified)
	}

	erabListValue, err := encodeHOERABList(b)
	if err != nil {
		s.log.Error("s1ap: failed to encode handover E-RAB list", zap.Error(err), zap.Uint32("mme_ue_id", mmeUEID))
		return
	}
	secCtxValue := encodeSecurityContextIE(nh, ncc)

	// UESecurityCapabilities: extract EEA/EIA bytes from stored UE network capability.
	// Byte 0 of UE network capability is the EEA octet; byte 1 is the EIA octet.
	var encAlgsByte, intAlgsByte uint8
	encAlgsByte = 1 << (7 - encAlg) // bit for the selected algorithm (EEA0=bit7, EEA1=bit6, EEA2=bit5)
	intAlgsByte = 1 << (7 - intAlg) // bit for the selected algorithm

	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeMMEUEApID(mmeUEID)},
		{ID: pdu.IEHandoverType, Criticality: aper.CriticalityReject, Value: ies.EncodeHandoverType(0)}, // intralte
		{ID: pdu.IECause, Criticality: aper.CriticalityIgnore, Value: causeBytes},
		{ID: pdu.IEUEAggregateMaxBitrate, Criticality: aper.CriticalityReject, Value: ies.EncodeUEAggregateMaxBitrate(ueAMBRDown, ueAMBRUp)},
		{ID: pdu.IEERABToBeSetupListHOReq, Criticality: aper.CriticalityReject, Value: erabListValue},
		{ID: pdu.IESourceToTargetTransparentContainer, Criticality: aper.CriticalityReject, Value: srcToTgt},
		{ID: pdu.IEUESecurityCapabilities, Criticality: aper.CriticalityReject, Value: ies.EncodeUESecurityCapabilities(encAlgsByte, intAlgsByte)},
		{ID: pdu.IESecurityContext, Criticality: aper.CriticalityReject, Value: secCtxValue},
	}
	msg := pdu.BuildInitiatingMessage(pdu.ProcHandoverResourceAllocation, aper.CriticalityReject, ieList)
	s.sendToAddr(targetAddr, msg)
	metrics.S1APMessagesTotal.WithLabelValues("HandoverRequest", "outbound", "sent").Inc()
}

// sendHandoverCommand sends S1AP Handover Command to the source eNB.
func (s *Server) sendHandoverCommand(srcAddr string, mmeUEID, srcENBUEID uint32, tgtToSrc []byte) {
	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeMMEUEApID(mmeUEID)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(srcENBUEID)},
		{ID: pdu.IEHandoverType, Criticality: aper.CriticalityReject, Value: ies.EncodeHandoverType(0)},
		{ID: pdu.IETargetToSourceTransparentContainer, Criticality: aper.CriticalityReject, Value: tgtToSrc},
	}
	msg := pdu.BuildSuccessfulOutcome(pdu.ProcHandoverPreparation, aper.CriticalityReject, ieList)
	s.sendToAddr(srcAddr, msg)
	metrics.S1APMessagesTotal.WithLabelValues("HandoverCommand", "outbound", "sent").Inc()
}

// sendHandoverPrepFailure sends S1AP Handover Preparation Failure to the source eNB.
func (s *Server) sendHandoverPrepFailure(srcAddr string, mmeUEID, srcENBUEID uint32, causeBytes []byte) {
	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeMMEUEApID(mmeUEID)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeENBUEApID(srcENBUEID)},
		{ID: pdu.IECause, Criticality: aper.CriticalityIgnore, Value: causeBytes},
	}
	msg := pdu.BuildUnsuccessfulOutcome(pdu.ProcHandoverPreparation, aper.CriticalityReject, ieList)
	s.sendToAddr(srcAddr, msg)
	metrics.S1APMessagesTotal.WithLabelValues("HandoverPrepFailure", "outbound", "sent").Inc()
}
