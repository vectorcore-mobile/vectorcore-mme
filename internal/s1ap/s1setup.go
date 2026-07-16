package s1ap

import (
	"context"
	"encoding/hex"
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
	var supportedTAsPresent bool
	var defaultPagingDRXPresent bool

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
			decoded, err := decodeSupportedTAsStrict(ie.Value)
			if err != nil {
				log.Warn("s1ap: SupportedTAs decode error; accepting S1Setup with empty SupportedTAs for compatibility",
					zap.Error(err),
					zap.String("supported_tas_hex", hex.EncodeToString(ie.Value)))
				supportedTAs = nil
				supportedTAsPresent = true
				break
			}
			supportedTAs = decoded
			supportedTAsPresent = true
		case pdu.IEDefaultPagingDRX:
			if _, err := ies.DecodePagingDRX(ie.Value); err != nil {
				log.Error("s1ap: DefaultPagingDRX decode error", zap.Error(err))
				s.sendS1SetupFailure(remoteAddr, p, ies.CauseGroupProtocol, ies.CauseProtocolFalselyConstructedMessage)
				return
			}
			defaultPagingDRXPresent = true
		}
	}

	if globalENBID == nil || !supportedTAsPresent || !defaultPagingDRXPresent {
		log.Warn("s1ap: S1Setup missing mandatory IE",
			zap.Bool("global_enb_id_present", globalENBID != nil),
			zap.Bool("supported_tas_present", supportedTAsPresent),
			zap.Bool("default_paging_drx_present", defaultPagingDRXPresent))
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

	tasJSON := encodeSupportedTAsJSON(supportedTAs)
	now := time.Now().UTC()

	// Track in peer tracker
	s.enbTracker.Add(peertracker.Peer{
		Name:         enbName,
		GlobalENBID:  globalENBID.Serialise(),
		SupportedTAs: string(tasJSON),
		RemoteAddr:   remoteAddr,
		Transport:    "sctp",
		LastSeen:     now,
	})
	metrics.S1APConnectedENBs.Set(float64(s.enbTracker.Count()))

	// Persist eNB registration
	go func() {
		reg := &models.ENBRegistration{
			GlobalENBID:  globalENBID.Serialise(),
			ENBName:      enbName,
			SupportedTAs: string(tasJSON),
			RemoteAddr:   remoteAddr,
			LastSeen:     now.Format(time.RFC3339),
			LastModified: now.Format(time.RFC3339),
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

func encodeSupportedTAsJSON(tas []SupportedTA) string {
	if tas == nil {
		tas = []SupportedTA{}
	}
	b, err := json.Marshal(tas)
	if err != nil {
		return "[]"
	}
	return string(b)
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
	log := s.log.With(zap.String("remote", remoteAddr), zap.String("procedure", "Reset"))
	var causePresent bool
	var resetTypePresent bool
	for _, ie := range ieList {
		switch ie.ID {
		case pdu.IECause:
			if _, _, err := ies.DecodeCause(ie.Value); err != nil {
				log.Warn("s1ap: Reset Cause decode error", zap.Error(err))
				s.sendErrorIndication(remoteAddr, p, 0, 0, ies.CauseGroupProtocol, ies.CauseProtocolFalselyConstructedMessage)
				return
			}
			causePresent = true
		case pdu.IEResetType:
			if err := validateResetType(ie.Value); err != nil {
				log.Warn("s1ap: Reset ResetType decode error", zap.Error(err))
				s.sendErrorIndication(remoteAddr, p, 0, 0, ies.CauseGroupProtocol, ies.CauseProtocolFalselyConstructedMessage)
				return
			}
			resetTypePresent = true
		}
	}
	if !causePresent || !resetTypePresent {
		log.Warn("s1ap: Reset missing mandatory IE",
			zap.Bool("cause_present", causePresent),
			zap.Bool("reset_type_present", resetTypePresent))
		diagItems := make([]criticalityDiagnosticItem, 0, 2)
		if !causePresent {
			diagItems = append(diagItems, criticalityDiagnosticItem{Criticality: aper.CriticalityIgnore, IEID: pdu.IECause, TypeOfError: typeOfErrorMissing})
		}
		if !resetTypePresent {
			diagItems = append(diagItems, criticalityDiagnosticItem{Criticality: aper.CriticalityReject, IEID: pdu.IEResetType, TypeOfError: typeOfErrorMissing})
		}
		s.sendErrorIndication(remoteAddr, p, 0, 0, ies.CauseGroupProtocol, ies.CauseProtocolSemanticError, diagItems...)
		return
	}
	log.Info("s1ap: Reset received")
	// Send Reset Acknowledge
	resp := pdu.BuildSuccessfulOutcome(pdu.ProcReset, aper.CriticalityReject, nil)
	s.sendToAddr(remoteAddr, resp)
}

func validateResetType(data []byte) error {
	r := aper.NewBitReader(data)
	ext, err := r.ReadBit()
	if err != nil {
		return err
	}
	if ext != 0 {
		return fmt.Errorf("ies: ResetType extension not supported")
	}
	choice, err := r.ReadBit()
	if err != nil {
		return err
	}
	switch choice {
	case 0:
		innerExt, err := r.ReadBit()
		if err != nil {
			return err
		}
		if innerExt != 0 {
			return fmt.Errorf("ies: ResetAll extension not supported")
		}
		if _, err := aper.DecodeConstrainedWholeNumber(r, 0, 0); err != nil {
			return err
		}
	case 1:
		if r.Remaining() == 0 {
			return fmt.Errorf("ies: partOfS1-Interface list missing")
		}
	default:
		return fmt.Errorf("ies: unsupported ResetType choice %d", choice)
	}
	return nil
}

// decodeSupportedTAs is a best-effort decoder for the SupportedTAs IE.
func decodeSupportedTAs(data []byte) []SupportedTA {
	if tas, ok := decodeSupportedTAsWithItemHeader(data); ok {
		return tas
	}
	tas, _ := decodeSupportedTAsBareItem(data)
	if len(tas) > 0 {
		return tas
	}
	if tas, ok := decodeSupportedTAsWithItemHeaderPackedTAC(data); ok {
		return tas
	}
	tas, _ = decodeSupportedTAsBareItemPackedTAC(data)
	return tas
}

func decodeSupportedTAsStrict(data []byte) ([]SupportedTA, error) {
	if tas, ok := decodeSupportedTAsWithItemHeader(data); ok {
		return tas, nil
	}
	if tas, ok := decodeSupportedTAsBareItem(data); ok {
		return tas, nil
	}
	if tas, ok := decodeSupportedTAsWithItemHeaderPackedTAC(data); ok {
		return tas, nil
	}
	if tas, ok := decodeSupportedTAsBareItemPackedTAC(data); ok {
		return tas, nil
	}
	if tas := decodeSupportedTAs(data); len(tas) > 0 {
		valid := true
		for _, ta := range tas {
			if len(ta.BroadcastPLMNs) == 0 {
				valid = false
				break
			}
		}
		if valid {
			return tas, nil
		}
	}
	return nil, fmt.Errorf("ies: SupportedTAs decode failed")
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

func decodeSupportedTAsWithItemHeaderPackedTAC(data []byte) ([]SupportedTA, bool) {
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
		if _, err := r.ReadBit(); err != nil {
			return nil, false
		}
		ta, err := decodeSupportedTAItemFieldsPackedTAC(r)
		if err != nil {
			return nil, false
		}
		out = append(out, ta)
	}
	return out, true
}

func decodeSupportedTAsBareItemPackedTAC(data []byte) ([]SupportedTA, bool) {
	r := aper.NewBitReader(data)
	count, err := aper.DecodeConstrainedWholeNumber(r, 1, 256)
	if err != nil || count < 1 {
		return nil, false
	}
	out := make([]SupportedTA, 0, int(count))
	for i := 0; i < int(count); i++ {
		ta, err := decodeSupportedTAItemFieldsPackedTAC(r)
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

func decodeSupportedTAItemFieldsPackedTAC(r *aper.BitReader) (SupportedTA, error) {
	tacBits, err := r.ReadBits(16)
	if err != nil {
		return SupportedTA{}, err
	}
	plmnCount, err := aper.DecodeConstrainedWholeNumber(r, 1, 6)
	if err != nil {
		return SupportedTA{}, err
	}
	ta := SupportedTA{TAC: uint16(tacBits)}
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
func (s *Server) sendToAddr(remoteAddr string, data []byte) error {
	if remoteAddr == "" {
		err := fmt.Errorf("s1ap: sendToAddr: empty remote")
		s.log.Warn("s1ap: sendToAddr: no send channel for", zap.String("remote", remoteAddr), zap.Error(err))
		return err
	}
	v, ok := s.sends.Load(remoteAddr)
	if !ok {
		err := fmt.Errorf("s1ap: sendToAddr: no send channel for %q", remoteAddr)
		s.log.Warn("s1ap: sendToAddr: no send channel for", zap.String("remote", remoteAddr), zap.Error(err))
		return err
	}
	ch := v.(chan<- []byte)
	select {
	case ch <- data:
		return nil
	default:
		err := fmt.Errorf("s1ap: sendToAddr: send buffer full for %q", remoteAddr)
		s.log.Warn("s1ap: sendToAddr: send buffer full", zap.String("remote", remoteAddr), zap.Error(err))
		return err
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
	bindingGeneration := ue.S1BindingGeneration
	bindingState := ue.S1BindingState
	ue.Unlock()
	if enbAddr == "" {
		return fmt.Errorf("s1ap: UE %d has no active S1 binding remote=%q enb_ue_id=%d state=%s generation=%d",
			mmeUEID, enbAddr, enbS1APID, bindingState.String(), bindingGeneration)
	}

	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeMMEUEApID(mmeUEID)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(enbS1APID)},
		{ID: pdu.IENAS_PDU, Criticality: aper.CriticalityReject, Value: ies.EncodeNASPDU(nasPDU)},
	}
	msg := pdu.BuildInitiatingMessage(pdu.ProcDownlinkNASTransport, aper.CriticalityIgnore, ieList)
	return s.sendToAddr(enbAddr, msg)
}

// SendInitialContextSetup sends an Initial Context Setup Request to the eNB.
// The bearer path is mandatory because Rel-16 requires a non-empty
// E-RABToBeSetupListCtxtSUReq.
func (s *Server) SendInitialContextSetup(mmeUEID uint32, nasPDU []byte, bearer *BearerInfo) error {
	if bearer == nil {
		return fmt.Errorf("s1ap: InitialContextSetup requires at least one bearer")
	}
	return s.SendInitialContextSetupWithBearers(mmeUEID, nasPDU, []BearerInfo{*bearer})
}

func (s *Server) SendInitialContextSetupWithBearers(mmeUEID uint32, nasPDU []byte, bearers []BearerInfo) error {
	if len(bearers) == 0 {
		return fmt.Errorf("s1ap: InitialContextSetup requires at least one bearer")
	}
	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		return fmt.Errorf("s1ap: UE %d not found", mmeUEID)
	}
	ue.Lock()
	enbAddr := ue.ENBGlobalID
	enbS1APID := ue.ENBS1APID
	bindingGeneration := ue.S1BindingGeneration
	bindingState := ue.S1BindingState
	kasme := ue.KASME
	ulNASCount := uint32(ue.ULNASCount)
	ueCap := append([]byte(nil), ue.UENetworkCapability...)
	ue.Unlock()
	if enbAddr == "" {
		return fmt.Errorf("s1ap: UE %d has no active S1 binding remote=%q enb_ue_id=%d state=%s generation=%d",
			mmeUEID, enbAddr, enbS1APID, bindingState.String(), bindingGeneration)
	}

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
	encAlgBits := uint16(eeaByte<<1) << 8
	intAlgBits := uint16(eiaByte<<1) << 8

	var erabValue []byte
	var ieList []pdu.ProtocolIE

	if len(bearers) > 0 {
		erabValue = encodeERABList(bearers, nasPDU)
		ambrValue := ies.EncodeUEAggregateMaxBitrate(100000000, 100000000)
		ieList = []pdu.ProtocolIE{
			{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeMMEUEApID(mmeUEID)},
			{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(enbS1APID)},
			{ID: pdu.IEUEAggregateMaxBitrate, Criticality: aper.CriticalityReject, Value: ambrValue},
			{ID: pdu.IEERABToBeSetupListCtxtSUReq, Criticality: aper.CriticalityReject, Value: erabValue},
			{ID: pdu.IEUESecurityCapabilities, Criticality: aper.CriticalityReject, Value: secCapValue},
			{ID: pdu.IESecurityKey, Criticality: aper.CriticalityReject, Value: ies.EncodeSecurityKey(kenb)},
		}
	}

	msg := pdu.BuildInitiatingMessage(pdu.ProcInitialContextSetup, aper.CriticalityReject, ieList)
	logFields := []zap.Field{
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.Uint32("enb_ue_id", enbS1APID),
		zap.Strings("ie_list", describeS1APIEList(ieList)),
		zap.String("ue_ambr_hex", hex.EncodeToString(findS1APIEValue(ieList, pdu.IEUEAggregateMaxBitrate))),
		zap.Uint64("ue_ambr_downlink", 100000000),
		zap.Uint64("ue_ambr_uplink", 100000000),
		zap.String("nas_ue_security_capability", hex.EncodeToString(ueCap)),
		zap.String("derived_s1ap_encryption_algorithms_bits", fmt.Sprintf("%016b", encAlgBits)),
		zap.String("derived_s1ap_integrity_algorithms_bits", fmt.Sprintf("%016b", intAlgBits)),
		zap.String("encoded_ue_security_capabilities_hex", hex.EncodeToString(secCapValue)),
		zap.String("ics_hex", hex.EncodeToString(msg)),
	}
	if len(bearers) > 0 {
		logFields = append(logFields,
			zap.String("erab_list_hex", hex.EncodeToString(erabValue)),
			zap.String("erab_item_hex", hex.EncodeToString(firstERABItemValue(erabValue))),
			zap.String("erab_item_optional_bitmap", fmt.Sprintf("nas_pdu_present=%t ie_extensions_present=false", len(nasPDU) > 0)),
			zap.Int("erab_item_count", len(bearers)),
			zap.String("erab_id_encoded_bits", fmt.Sprintf("integer_extension=0 value=%04b", bearers[0].EBI&0x0f)),
			zap.String("qos_encoded_summary", fmt.Sprintf("qci=%d arp_priority=%d preemption_capability=%t preemption_vulnerability=%t", effectiveBearerQCI(bearers[0]), effectiveBearerARP(bearers[0]), bearers[0].PreemptionCapability, effectivePreemptionVulnerability(bearers[0]))),
			zap.String("transport_layer_address", fmt.Sprintf("extension=0 bits=32 ipv4=%s encoded_bitstring=%s", hex.EncodeToString(firstIPv4Bytes(bearers[0].SGWU_IP)), hex.EncodeToString(firstIPv4Bytes(bearers[0].SGWU_IP)))),
			zap.String("gtp_teid_encoded_hex", fmt.Sprintf("%08x", bearers[0].SGWU_TEID)),
			zap.Int("nas_pdu_len", len(nasPDU)),
			zap.String("nas_pdu_hex", hex.EncodeToString(nasPDU)),
		)
	}
	s.log.Debug("s1ap: Initial Context Setup Request encoded", logFields...)
	return s.sendToAddr(enbAddr, msg)
}

func describeS1APIEList(ieList []pdu.ProtocolIE) []string {
	out := make([]string, 0, len(ieList))
	for _, ie := range ieList {
		out = append(out, fmt.Sprintf("id=%d criticality=%d len=%d", ie.ID, ie.Criticality, len(ie.Value)))
	}
	return out
}

func findS1APIEValue(ieList []pdu.ProtocolIE, id uint16) []byte {
	for _, ie := range ieList {
		if ie.ID == id {
			return ie.Value
		}
	}
	return nil
}

func firstERABItemValue(erabList []byte) []byte {
	r := aper.NewBitReader(erabList)
	if _, err := aper.DecodeConstrainedWholeNumber(r, 1, 256); err != nil {
		return nil
	}
	r.AlignToByte()
	if _, err := aper.DecodeConstrainedWholeNumber(r, 0, 65535); err != nil {
		return nil
	}
	if _, err := aper.DecodeCriticality(r); err != nil {
		return nil
	}
	item, err := aper.ReadOpenType(r)
	if err != nil {
		return nil
	}
	return item
}

func firstIPv4Bytes(ip []byte) []byte {
	if len(ip) >= 4 {
		return ip[:4]
	}
	return []byte{0, 0, 0, 0}
}

// encodeEmptyERABList encodes an empty E-RAB-To-Be-Setup list (count=0).
// encodeERABList encodes an E-RABToBeSetupListCtxtSUReq with one or more items.
//
// The outer structure is an inner IE container (IE 52) wrapping an APER-encoded
// E-RABToBeSetupItemCtxtSUReq SEQUENCE per TS 36.413 §9.2.1.2.
//
// APER layout of E-RABToBeSetupItemCtxtSUReq:
//
//	ext=0 | nAS-PDU-present=0|1 | iE-Extensions-present=0
//	E-RAB-ID (0..15,...): extension bit + 4 bits constrained
//	E-RABLevelQoSParameters SEQUENCE: ext=0, QCI(0..255), ARP
//	transportLayerAddress BIT STRING (SIZE 1..160,...): ext=0, constrained-len=32, 4-byte IP
//	GTP-TEID OCTET STRING (SIZE 4): 4 bytes big-endian
//	nAS-PDU OCTET STRING (unconstrained): length+bytes  [only when present]
//
// When multiple bearers are encoded, only the first item can carry NAS-PDU and
// callers should normally pass nil for resume/service-request flows.
func encodeERABList(bearers []BearerInfo, nasPDU []byte) []byte {
	ow := aper.NewBitWriter()
	_ = aper.EncodeConstrainedWholeNumber(ow, int64(len(bearers)), 1, 256)
	ow.AlignToByte()
	for i, bearer := range bearers {
		itemNAS := []byte(nil)
		if i == 0 && len(nasPDU) > 0 {
			itemNAS = nasPDU
		}
		itemBody := encodeERABItemBody(bearer, itemNAS)
		innerContainer := pdu.EncodeIEContainer([]pdu.ProtocolIE{
			{ID: pdu.IEERABToBeSetupItemCtxtSUReq, Criticality: aper.CriticalityReject, Value: itemBody},
		})
		if len(innerContainer) >= 2 {
			innerContainer = innerContainer[2:]
		}
		ow.WriteOctets(innerContainer)
	}
	return ow.Bytes()
}

func encodeERABItemBody(b BearerInfo, nasPDU []byte) []byte {
	nasPDUPresent := len(nasPDU) > 0

	w := aper.NewBitWriter()

	w.WriteBit(0) // extension marker
	if nasPDUPresent {
		w.WriteBit(1)
	} else {
		w.WriteBit(0)
	}
	w.WriteBit(0)

	w.WriteBit(0)
	_ = aper.EncodeConstrainedWholeNumber(w, int64(b.EBI), 0, 15)

	w.WriteBit(0) // extension marker
	w.WriteBit(0) // gbrQosInformation absent
	w.WriteBit(0) // iE-Extensions absent
	_ = aper.EncodeConstrainedWholeNumber(w, int64(effectiveBearerQCI(b)), 0, 255)
	w.WriteBit(0) // extension marker
	w.WriteBit(0) // iE-Extensions absent
	_ = aper.EncodeConstrainedWholeNumber(w, int64(effectiveBearerARP(b)), 0, 15)
	if b.PreemptionCapability {
		_ = aper.EncodeConstrainedWholeNumber(w, 1, 0, 1)
	} else {
		_ = aper.EncodeConstrainedWholeNumber(w, 0, 0, 1)
	}
	if effectivePreemptionVulnerability(b) {
		_ = aper.EncodeConstrainedWholeNumber(w, 1, 0, 1)
	} else {
		_ = aper.EncodeConstrainedWholeNumber(w, 0, 0, 1)
	}

	w.WriteBit(0) // no extension
	_ = aper.EncodeConstrainedWholeNumber(w, 32, 1, 160)
	w.AlignToByte()
	if len(b.SGWU_IP) >= 4 {
		w.WriteOctets(b.SGWU_IP[:4])
	} else {
		w.WriteOctets([]byte{0, 0, 0, 0})
	}

	w.AlignToByte()
	w.WriteOctet(byte(b.SGWU_TEID >> 24))
	w.WriteOctet(byte(b.SGWU_TEID >> 16))
	w.WriteOctet(byte(b.SGWU_TEID >> 8))
	w.WriteOctet(byte(b.SGWU_TEID))

	if nasPDUPresent {
		w.AlignToByte()
		_ = aper.EncodeLength(w, len(nasPDU), 0, -1)
		w.WriteOctets(nasPDU)
	}

	return w.Bytes()
}

func effectiveBearerQCI(b BearerInfo) uint8 {
	if b.QCI != 0 {
		return b.QCI
	}
	return 9
}

func effectiveBearerARP(b BearerInfo) uint8 {
	if b.ARPPriority != 0 {
		return b.ARPPriority
	}
	return 8
}

func effectivePreemptionVulnerability(b BearerInfo) bool {
	if b.PreemptionVulnerability {
		return true
	}
	return true
}
