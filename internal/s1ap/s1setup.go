package s1ap

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/models"
	"github.com/vectorcore/mme/internal/nas/security"
	"github.com/vectorcore/mme/internal/peertracker"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
)

func (s *Server) handleS1SetupRequest(remoteAddr string, p *pdu.PDU, ieList []pdu.ProtocolIE) {
	start := time.Now()
	log := s.log.With(zap.String("remote", remoteAddr), zap.String("procedure", "S1Setup"))

	// Extract mandatory IEs
	var globalENBID *ies.GlobalENBID
	var enbName string
	var supportedTAs []SupportedTA

	for _, ie := range ieList {
		switch ie.ID {
		case pdu.IEGlobal_ENB_ID:
			g, err := ies.DecodeGlobalENBID(ie.Value)
			if err != nil {
				log.Error("s1ap: GlobalENBID decode error", zap.Error(err))
				s.sendS1SetupFailure(remoteAddr, p, ies.CauseGroupProtocol, 0)
				return
			}
			globalENBID = &g

		case pdu.IEeNBname:
			// VisibleString (optional) — raw APER encoded, just extract if we can
			r := aper.NewBitReader(ie.Value)
			name, err := aper.DecodeVisibleStringExt(r, 1, 150)
			if err == nil {
				enbName = name
			}

		case pdu.IESupportedTAs:
			supportedTAs = decodeSupportedTAs(ie.Value)
		}
	}

	if globalENBID == nil {
		log.Warn("s1ap: S1Setup missing Global-ENB-ID")
		s.sendS1SetupFailure(remoteAddr, p, ies.CauseGroupProtocol, 0)
		return
	}

	log = log.With(
		zap.String("global_enb_id", globalENBID.Serialise()),
		zap.String("global_enb_plmn_raw", fmt.Sprintf("%02X%02X%02X", globalENBID.PLMNRaw[0], globalENBID.PLMNRaw[1], globalENBID.PLMNRaw[2])),
		zap.String("enb_name", enbName),
	)
	log.Info("s1ap: S1 Setup Request")

	// Register the eNB connection
	enb := &ENBContext{
		GlobalENBID:  *globalENBID,
		ENBName:      enbName,
		SupportedTAs: supportedTAs,
		RemoteAddr:   remoteAddr,
	}
	// We need a Conn — but in handleMessage we only have remoteAddr.
	// The Conn is created during the SCTP accept loop. For now, we'll wire this up
	// in the SCTP layer by having the server also act as a send dispatcher.
	s.enbs.Store(remoteAddr, enb)

	// Track in peer tracker
	s.enbTracker.Add(peertracker.Peer{
		Name:       enbName,
		RemoteAddr: remoteAddr,
		Transport:  "sctp",
	})
	metrics.S1APConnectedENBs.Set(float64(s.enbTracker.Count()))

	// Persist eNB registration
	go func() {
		tas, _ := json.Marshal(supportedTAs)
		reg := &models.ENBRegistration{
			GlobalENBID:  globalENBID.Serialise(),
			ENBName:      enbName,
			SupportedTAs: string(tas),
			RemoteAddr:   remoteAddr,
			LastSeen:     time.Now().UTC().Format(time.RFC3339),
			LastModified: time.Now().UTC().Format(time.RFC3339),
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.store.UpsertENBRegistration(ctx, reg); err != nil {
			log.Warn("s1ap: ENB registration store error", zap.Error(err))
		}
	}()

	// Build S1 Setup Response
	resp := pdu.Encode(&pdu.PDU{
		Type:          pdu.PDUTypeSuccessfulOutcome,
		ProcedureCode: pdu.ProcS1Setup,
		Criticality:   aper.CriticalityReject,
		Value:         pdu.EncodeProcedureIEContainer(s.buildS1SetupResponseIEs()),
	})
	s.sendToAddr(remoteAddr, resp)

	log.Info("s1ap: sent S1 Setup Response",
		zap.Duration("duration", time.Since(start)))
	metrics.S1APMessagesTotal.WithLabelValues("S1Setup", "inbound", "success").Inc()
}

func (s *Server) buildS1SetupResponseIEs() []pdu.ProtocolIE {
	// ServedGUMMEIs (mandatory): list of GUMMEIs served by this MME
	// Global-MME-ID, ServedGroupIDs, ServedMMECs, ServedPLMNs
	gummeiValue := s.encodeServedGUMMEIs()

	return []pdu.ProtocolIE{
		{
			ID:          pdu.IEServedGUMMEIs,
			Criticality: aper.CriticalityReject,
			Value:       gummeiValue,
		},
		{
			ID:          pdu.IERelativeMMECapacity,
			Criticality: aper.CriticalityIgnore,
			Value:       ies.EncodeRelativeMMECapacity(255),
		},
	}
}

func (s *Server) encodeServedGUMMEIs() []byte {
	plmn, _ := ies.EncodePLMN(s.nfCfg.MCC, s.nfCfg.MNC)

	w := aper.NewBitWriter()
	// ServedGUMMEIs ::= SEQUENCE (SIZE (1..8)) OF ServedGUMMEIsItem
	_ = aper.EncodeConstrainedWholeNumber(w, 1, 1, 8)

	w.WriteBit(0) // ServedGUMMEIsItem SEQUENCE extension = 0
	w.WriteBit(0) // iE-Extensions absent

	// ServedPLMNs ::= SEQUENCE (SIZE (1..32)) OF OCTET STRING (SIZE (3))
	_ = aper.EncodeConstrainedWholeNumber(w, 1, 1, 32)
	_ = aper.EncodeOctetString(w, plmn, 3, 3)

	// ServedGroupIDs ::= SEQUENCE (SIZE (1..65535)) OF OCTET STRING (SIZE (2))
	_ = aper.EncodeConstrainedWholeNumber(w, 1, 1, 65535)
	_ = aper.EncodeOctetString(w, []byte{byte(s.nfCfg.MMEGI >> 8), byte(s.nfCfg.MMEGI)}, 2, 2)

	// ServedMMECs ::= SEQUENCE (SIZE (1..256)) OF OCTET STRING (SIZE (1))
	_ = aper.EncodeConstrainedWholeNumber(w, 1, 1, 256)
	_ = aper.EncodeOctetString(w, []byte{s.nfCfg.MMEC}, 1, 1)

	return w.Bytes()
}

func (s *Server) sendS1SetupFailure(remoteAddr string, p *pdu.PDU, group ies.CauseGroup, value uint8) {
	failureIEs := []pdu.ProtocolIE{
		{
			ID:          pdu.IECause,
			Criticality: aper.CriticalityIgnore,
			Value:       ies.EncodeCause(group, value),
		},
	}
	resp := pdu.Encode(&pdu.PDU{
		Type:          pdu.PDUTypeUnsuccessfulOutcome,
		ProcedureCode: pdu.ProcS1Setup,
		Criticality:   aper.CriticalityReject,
		Value:         pdu.EncodeProcedureIEContainer(failureIEs),
	})
	s.sendToAddr(remoteAddr, resp)
	metrics.S1APMessagesTotal.WithLabelValues("S1Setup", "inbound", "error").Inc()
}

// handleReset handles an S1AP Reset message from an eNB.
func (s *Server) handleReset(remoteAddr string, p *pdu.PDU, ieList []pdu.ProtocolIE) {
	s.log.Info("s1ap: Reset received", zap.String("remote", remoteAddr))
	// Send Reset Acknowledge
	resp := pdu.BuildSuccessfulOutcome(pdu.ProcReset, aper.CriticalityReject, nil)
	s.sendToAddr(remoteAddr, resp)
}

// decodeSupportedTAs is a best-effort decoder for the SupportedTAs IE.
func decodeSupportedTAs(data []byte) []SupportedTA {
	if tas, ok := decodeSupportedTAsWithItemHeader(data); ok {
		return tas
	}
	tas, _ := decodeSupportedTAsBareItem(data)
	return tas
}

func decodeSupportedTAsWithItemHeader(data []byte) ([]SupportedTA, bool) {
	r := aper.NewBitReader(data)
	count, err := aper.DecodeConstrainedWholeNumber(r, 1, 256)
	if err != nil || count < 1 {
		return nil, false
	}
	out := make([]SupportedTA, 0, int(count))
	for i := 0; i < int(count); i++ {
		ext, err := r.ReadBit()
		if err != nil || ext != 0 {
			return nil, false
		}
		if _, err := r.ReadBit(); err != nil { // iE-Extensions absent/present
			return nil, false
		}
		ta, err := decodeSupportedTAItemFields(r)
		if err != nil {
			return nil, false
		}
		out = append(out, ta)
	}
	return out, true
}

func decodeSupportedTAsBareItem(data []byte) ([]SupportedTA, bool) {
	r := aper.NewBitReader(data)
	count, err := aper.DecodeConstrainedWholeNumber(r, 1, 256)
	if err != nil || count < 1 {
		return nil, false
	}
	out := make([]SupportedTA, 0, int(count))
	for i := 0; i < int(count); i++ {
		ta, err := decodeSupportedTAItemFields(r)
		if err != nil {
			return nil, false
		}
		out = append(out, ta)
	}
	return out, true
}

func decodeSupportedTAItemFields(r *aper.BitReader) (SupportedTA, error) {
	tacBytes, err := aper.DecodeOctetString(r, 2, 2)
	if err != nil {
		return SupportedTA{}, err
	}
	plmnCount, err := aper.DecodeConstrainedWholeNumber(r, 1, 6)
	if err != nil {
		return SupportedTA{}, err
	}
	ta := SupportedTA{TAC: uint16(tacBytes[0])<<8 | uint16(tacBytes[1])}
	for i := 0; i < int(plmnCount); i++ {
		plmn, err := aper.DecodeOctetString(r, 3, 3)
		if err != nil {
			return SupportedTA{}, err
		}
		mcc, mnc, err := ies.DecodePLMN(plmn)
		if err != nil {
			return SupportedTA{}, err
		}
		ta.BroadcastPLMNs = append(ta.BroadcastPLMNs, BroadcastPLMN{MCC: mcc, MNC: mnc})
	}
	return ta, nil
}

// sendToAddr sends raw bytes to the given remote address.
// In Phase 1, we use a goroutine-safe send map indexed by remoteAddr.
func (s *Server) sendToAddr(remoteAddr string, data []byte) {
	v, ok := s.sends.Load(remoteAddr)
	if !ok {
		s.log.Warn("s1ap: sendToAddr: no send channel for", zap.String("remote", remoteAddr))
		return
	}
	ch := v.(chan<- []byte)
	select {
	case ch <- data:
	default:
		s.log.Warn("s1ap: sendToAddr: send buffer full", zap.String("remote", remoteAddr))
	}
}

// SendDownlinkNAS sends a Downlink NAS Transport PDU to a UE.
// This implements the NASTransport interface.
func (s *Server) SendDownlinkNAS(mmeUEID uint32, nasPDU []byte) error {
	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		return fmt.Errorf("s1ap: UE %d not found", mmeUEID)
	}
	ue.Lock()
	enbAddr := ue.ENBGlobalID
	enbS1APID := ue.ENBS1APID
	ue.Unlock()

	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeMMEUEApID(mmeUEID)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(enbS1APID)},
		{ID: pdu.IENAS_PDU, Criticality: aper.CriticalityReject, Value: ies.EncodeNASPDU(nasPDU)},
	}
	msg := pdu.BuildInitiatingMessage(pdu.ProcDownlinkNASTransport, aper.CriticalityIgnore, ieList)
	s.sendToAddr(enbAddr, msg)
	return nil
}

// SendInitialContextSetup sends an Initial Context Setup Request to the eNB.
// When bearer is non-nil the E-RAB list contains a single default bearer item
// (EBI, SGW S1-U TEID/IP, NAS-PDU). When bearer is nil the list is empty and
// the NAS-PDU is sent as standalone IE 26 for backward compatibility.
func (s *Server) SendInitialContextSetup(mmeUEID uint32, nasPDU []byte, bearer *BearerInfo) error {
	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		return fmt.Errorf("s1ap: UE %d not found", mmeUEID)
	}
	ue.Lock()
	enbAddr := ue.ENBGlobalID
	enbS1APID := ue.ENBS1APID
	kasme := ue.KASME
	ulNASCount := uint32(ue.ULNASCount)
	ueCap := append([]byte(nil), ue.UENetworkCapability...)
	ue.Unlock()

	// Derive KeNB per TS 33.401 §A.3: KDF(KASME, FC=0x11, UL_NAS_COUNT as 4-byte BE).
	kenb, err := security.DeriveKeNB(kasme, ulNASCount)
	if err != nil {
		s.log.Error("s1ap: DeriveKeNB failed", zap.Error(err))
		return fmt.Errorf("DeriveKeNB: %w", err)
	}

	// Pre-compute the first NH (NCC=1) for future handover preparation (TS 33.401 §A.4).
	if nh, nhErr := security.DeriveNH(kasme, kenb); nhErr == nil {
		ue.Lock()
		ue.NH = nh
		ue.NCC = 1
		ue.Unlock()
	}

	// Echo the UE's actual EEA/EIA bitmasks received in the Attach Request.
	// UENetworkCapability byte 0 = EEA bitmap, byte 1 = EIA bitmap.
	var eeaByte, eiaByte uint8
	if len(ueCap) >= 2 {
		eeaByte = ueCap[0]
		eiaByte = ueCap[1]
	}
	secCapValue := ies.EncodeUESecurityCapabilities(eeaByte, eiaByte)

	var erabValue []byte
	var ieList []pdu.ProtocolIE

	if bearer != nil {
		erabValue = encodeERABList(bearer, nasPDU)
		ieList = []pdu.ProtocolIE{
			{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeMMEUEApID(mmeUEID)},
			{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(enbS1APID)},
			{ID: pdu.IEUEAggregateMaxBitrate, Criticality: aper.CriticalityReject, Value: ies.EncodeUEAggregateMaxBitrate(100000000, 100000000)},
			{ID: pdu.IEERABToBeSetupListCtxtSUReq, Criticality: aper.CriticalityReject, Value: erabValue},
			{ID: pdu.IEUESecurityCapabilities, Criticality: aper.CriticalityReject, Value: secCapValue},
			{ID: pdu.IESecurityKey, Criticality: aper.CriticalityReject, Value: ies.EncodeSecurityKey(kenb)},
		}
	} else {
		ieList = []pdu.ProtocolIE{
			{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeMMEUEApID(mmeUEID)},
			{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(enbS1APID)},
			{ID: pdu.IEUEAggregateMaxBitrate, Criticality: aper.CriticalityReject, Value: ies.EncodeUEAggregateMaxBitrate(100000000, 100000000)},
			{ID: pdu.IEERABToBeSetupListCtxtSUReq, Criticality: aper.CriticalityReject, Value: encodeEmptyERABList()},
			{ID: pdu.IEUESecurityCapabilities, Criticality: aper.CriticalityReject, Value: secCapValue},
			{ID: pdu.IESecurityKey, Criticality: aper.CriticalityReject, Value: ies.EncodeSecurityKey(kenb)},
			{ID: pdu.IENAS_PDU, Criticality: aper.CriticalityIgnore, Value: ies.EncodeNASPDU(nasPDU)},
		}
	}

	msg := pdu.BuildInitiatingMessage(pdu.ProcInitialContextSetup, aper.CriticalityReject, ieList)
	s.sendToAddr(enbAddr, msg)
	return nil
}

// encodeEmptyERABList encodes an empty E-RAB-To-Be-Setup list (count=0).
func encodeEmptyERABList() []byte {
	w := aper.NewBitWriter()
	_ = aper.EncodeConstrainedWholeNumber(w, 0, 0, 256)
	return w.Bytes()
}

// encodeERABList encodes an E-RABToBeSetupListCtxtSUReq with one item containing
// the SGW S1-U endpoint and (optionally) a NAS-PDU.
//
// The outer structure is an inner IE container (IE 52) wrapping an APER-encoded
// E-RABToBeSetupItemCtxtSUReq SEQUENCE per TS 36.413 §9.2.1.2.
//
// APER layout of E-RABToBeSetupItemCtxtSUReq:
//
//	ext=0 | nAS-PDU-present=0|1 | iE-Extensions-present=0
//	E-RAB-ID (0..15): 4 bits constrained
//	E-RABLevelQoSParameters SEQUENCE: ext=0, QCI(0..255), ARP
//	transportLayerAddress BIT STRING (SIZE 1..160,...): ext=0, constrained-len=32, 4-byte IP
//	GTP-TEID OCTET STRING (SIZE 4): 4 bytes big-endian
//	nAS-PDU OCTET STRING (unconstrained): length+bytes  [only when present]
func encodeERABList(b *BearerInfo, nasPDU []byte) []byte {
	nasPDUPresent := len(nasPDU) > 0

	// Encode the item SEQUENCE body
	w := aper.NewBitWriter()

	// Preamble: extension=0, nAS-PDU OPTIONAL present/absent, iE-Extensions=0
	w.WriteBit(0) // extension marker
	if nasPDUPresent {
		w.WriteBit(1) // nAS-PDU OPTIONAL present
	} else {
		w.WriteBit(0) // nAS-PDU OPTIONAL absent
	}
	w.WriteBit(0) // iE-Extensions absent

	// E-RAB-ID (CONSTRAINED WHOLE NUMBER 0..15)
	_ = aper.EncodeConstrainedWholeNumber(w, int64(b.EBI), 0, 15)

	// E-RABLevelQoSParameters SEQUENCE
	w.WriteBit(0) // extension marker
	// AllocationAndRetentionPriority OPTIONAL absent? No — it's mandatory.
	// gbrQosInformation OPTIONAL absent
	w.WriteBit(0) // gbrQosInformation absent
	w.WriteBit(0) // iE-Extensions absent
	// QCI (0..255)
	_ = aper.EncodeConstrainedWholeNumber(w, 9, 0, 255)
	// AllocationAndRetentionPriority SEQUENCE
	w.WriteBit(0) // extension marker
	w.WriteBit(0) // iE-Extensions absent
	// priorityLevel (0..15)
	_ = aper.EncodeConstrainedWholeNumber(w, 8, 0, 15)
	// pre-emptionCapability ENUM (0..1): 0 = shall-not-trigger
	_ = aper.EncodeConstrainedWholeNumber(w, 0, 0, 1)
	// pre-emptionVulnerability ENUM (0..1): 1 = pre-emptable
	_ = aper.EncodeConstrainedWholeNumber(w, 1, 0, 1)

	// transportLayerAddress BIT STRING (SIZE(1..160,...)):
	// extension=0, length=32 (constrained 1..160)
	w.WriteBit(0) // no extension
	_ = aper.EncodeConstrainedWholeNumber(w, 32, 1, 160)
	w.AlignToByte()
	if len(b.SGWU_IP) >= 4 {
		w.WriteOctets(b.SGWU_IP[:4])
	} else {
		w.WriteOctets([]byte{0, 0, 0, 0})
	}

	// GTP-TEID OCTET STRING (SIZE 4) — fixed size, no length prefix
	w.AlignToByte()
	w.WriteOctet(byte(b.SGWU_TEID >> 24))
	w.WriteOctet(byte(b.SGWU_TEID >> 16))
	w.WriteOctet(byte(b.SGWU_TEID >> 8))
	w.WriteOctet(byte(b.SGWU_TEID))

	// nAS-PDU OCTET STRING (unconstrained) — only if present
	if nasPDUPresent {
		w.AlignToByte()
		_ = aper.EncodeLength(w, len(nasPDU), 0, -1)
		w.WriteOctets(nasPDU)
	}

	itemBody := w.Bytes()

	// Wrap the item body as a single-IE inner container (IE 52, criticality=reject).
	// EncodeIEContainer produces: [count:2B][id:2B][crit:1B][opentype_len][value].
	// We want just the inner part (no outer count), so we strip the 2-byte count prefix.
	innerContainer := pdu.EncodeIEContainer([]pdu.ProtocolIE{
		{ID: pdu.IEERABToBeSetupItemCtxtSUReq, Criticality: aper.CriticalityReject, Value: itemBody},
	})
	// Strip the 2-byte count that EncodeIEContainer prepends (count=1 → 0x00 0x01).
	// The E-RABToBeSetupListCtxtSUReq IE value starts directly with the IE fields.
	if len(innerContainer) >= 2 {
		innerContainer = innerContainer[2:]
	}

	// Outer: SEQUENCE OF (count=1, constrained 1..256)
	ow := aper.NewBitWriter()
	_ = aper.EncodeConstrainedWholeNumber(ow, 1, 1, 256)
	ow.AlignToByte()
	ow.WriteOctets(innerContainer)
	return ow.Bytes()
}
