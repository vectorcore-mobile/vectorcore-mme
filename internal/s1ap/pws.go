package s1ap

import (
	"fmt"
	"sync"
	"time"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"github.com/vectorcore/mme/internal/sbcap"
	"go.uber.org/zap"
)

type pwsTransaction struct {
	baseKey           string
	peer              string
	procedure         uint8
	messageID, serial [2]byte
	pending           map[string]struct{}
	areaLists         []sbcap.AreaList
	emptyENBs         [][]byte // canonical Global-ENB-ID values for Kill responses with no area list
	mu                sync.Mutex
}

// SetPWSIndicationSender installs the SBc-AP association bridge. It is kept as
// a callback to avoid making S1AP own CBC transport or warning persistence.
func (s *Server) SetPWSIndicationSender(fn func(peer string, payload []byte))    { s.pwsIndication = fn }
func (s *Server) SetPWSForwarder(fn func(procedure uint8, ies []pdu.ProtocolIE)) { s.pwsForward = fn }

func (s *Server) handlePWSForward(procedure uint8, ies []pdu.ProtocolIE) {
	if s.pwsForward != nil {
		s.pwsForward(procedure, ies)
	}
}

// S1AP PWS IE IDs, TS 36.413 Annex A.
const (
	ieMessageIdentifier          uint16 = 111
	ieSerialNumber               uint16 = 112
	ieWarningAreaList            uint16 = 113
	ieRepetitionPeriod           uint16 = 114
	ieNumberOfBroadcastRequest   uint16 = 115
	ieWarningType                uint16 = 116
	ieWarningSecurityInformation uint16 = 117
	ieDataCodingScheme           uint16 = 118
	ieWarningMessageContents     uint16 = 119
	ieConcurrentWarningIndicator uint16 = 142
)

// SendSBcAPWarning routes one CBC request to the currently connected eNBs and
// sends an S1AP WriteReplaceWarningRequest or KillRequest. It keeps no active
// warning database; callers retain only bounded response correlation state.
func (s *Server) SendSBcAPWarning(procedure uint8, req *sbcap.WarningRequest) ([]string, error) {
	return s.SendSBcAPWarningForPeer("", procedure, req, 30*time.Second)
}

func (s *Server) SendSBcAPWarningForPeer(peer string, procedure uint8, req *sbcap.WarningRequest, timeout time.Duration) ([]string, error) {
	if req == nil {
		return nil, fmt.Errorf("s1ap: nil SBc-AP warning request")
	}
	targets, err := s.resolveSBcAPTargets(req)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("s1ap: no connected eNB matches SBc-AP target")
	}
	message, err := s.buildPWSRequest(procedure, req)
	if err != nil {
		return nil, err
	}
	var tx *pwsTransaction
	if req.SendIndication && peer != "" {
		// An eNB response carries no CBC identity.  Reserve the response
		// correlation identity globally while retaining the originating peer in
		// tx, so two CBCs cannot make one eNB response complete both requests.
		// The second request is rejected deterministically instead of corrupting
		// either CBC's aggregation.
		baseKey := pwsResponseKey(procedure, req.MessageIdentifier, req.SerialNumber)
		s.pwsTransactionMu.Lock()
		if _, exists := s.pwsTransactionBases[baseKey]; exists {
			s.pwsTransactionMu.Unlock()
			return nil, fmt.Errorf("s1ap: SBc-AP warning transaction already in flight for peer and identity")
		}
		s.pwsTransactionBases[baseKey] = struct{}{}
		s.pwsTransactionMu.Unlock()
		tx = &pwsTransaction{baseKey: baseKey, peer: peer, procedure: procedure, messageID: req.MessageIdentifier, serial: req.SerialNumber, pending: make(map[string]struct{}, len(targets))}
		for _, target := range targets {
			tx.pending[target] = struct{}{}
		}
		// Store before queuing requests: a fast eNB response must never race
		// transaction installation and be silently dropped.
		s.pwsTransactions.Store(tx.baseKey, tx)
		go s.expirePWSTransaction(tx, timeout)
	}
	var sent []string
	for _, remote := range targets {
		if err := s.sendToAddr(remote, message); err != nil {
			if tx != nil {
				tx.mu.Lock()
				delete(tx.pending, remote)
				tx.mu.Unlock()
			}
			continue
		}
		sent = append(sent, remote)
		if p, err := pdu.Decode(message); err == nil {
			if ies, err := pdu.DecodeIEContainer(p.Value); err == nil {
				ids, lengths := make([]uint16, 0, len(ies)), make([]int, 0, len(ies))
				for _, ie := range ies {
					ids, lengths = append(ids, ie.ID), append(lengths, len(ie.Value))
				}
				s.log.Debug("s1ap: PWS request sent", zap.Uint8("procedure", p.ProcedureCode), zap.String("message_identifier", fmt.Sprintf("%02x%02x", req.MessageIdentifier[0], req.MessageIdentifier[1])), zap.String("serial_number", fmt.Sprintf("%02x%02x", req.SerialNumber[0], req.SerialNumber[1])), zap.String("selected_enb", remote), zap.Uint16s("ie_ids", ids), zap.Ints("ie_lengths", lengths), zap.String("encoded_pdu_hex", fmt.Sprintf("%x", message)))
			}
		}
	}
	if len(sent) == 0 {
		if tx != nil {
			s.pwsTransactions.Delete(tx.baseKey)
			s.releasePWSTransactionBase(tx.baseKey)
		}
		return nil, fmt.Errorf("s1ap: PWS request could not be queued to any selected eNB")
	}
	return sent, nil
}

func (s *Server) expirePWSTransaction(tx *pwsTransaction, timeout time.Duration) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	<-timer.C
	if value, ok := s.pwsTransactions.LoadAndDelete(tx.baseKey); ok {
		metrics.SBcAPTransactionsTotal.WithLabelValues("timeout").Inc()
		timedOut := value.(*pwsTransaction)
		timedOut.mu.Lock()
		pending := len(timedOut.pending)
		timedOut.mu.Unlock()
		if s.log != nil {
			s.log.Info("s1ap: PWS transaction timeout", zap.String("warning_identity", timedOut.baseKey), zap.Int("pending_enbs", pending), zap.String("completion_reason", "timeout"))
		}
		s.finishPWSTransaction(timedOut)
	}
}

func (s *Server) releasePWSTransactionBase(baseKey string) {
	s.pwsTransactionMu.Lock()
	delete(s.pwsTransactionBases, baseKey)
	s.pwsTransactionMu.Unlock()
}

func pwsTransactionKey(peer string, procedure uint8, messageID, serial [2]byte) string {
	return fmt.Sprintf("%s:%d:%02x%02x:%02x%02x", peer, procedure, messageID[0], messageID[1], serial[0], serial[1])
}

func pwsResponseKey(procedure uint8, messageID, serial [2]byte) string {
	return fmt.Sprintf("%d:%02x%02x:%02x%02x", procedure, messageID[0], messageID[1], serial[0], serial[1])
}

func (s *Server) handlePWSResponse(remote string, procedure uint8, ies []pdu.ProtocolIE) {
	var messageID, serial [2]byte
	var haveMessageID, haveSerial bool
	var areas *sbcap.AreaList
	for _, ie := range ies {
		if ie.ID == ieMessageIdentifier {
			v, err := sbcapMessageID(ie.Value)
			if err != nil {
				return
			}
			messageID = v
			haveMessageID = true
		}
		if ie.ID == ieSerialNumber {
			v, err := sbcapMessageID(ie.Value)
			if err != nil {
				return
			}
			serial = v
			haveSerial = true
		}
		if procedure == pdu.ProcWriteReplaceWarning && ie.ID == 120 { // Broadcast Completed Area List
			v, err := sbcap.DecodeS1CompletedAreaList(ie.Value)
			if err != nil {
				if s.log != nil {
					s.log.Warn("s1ap: invalid BroadcastCompletedAreaList", zap.String("remote", remote), zap.Error(err))
				}
				return
			}
			areas = &v
			if s.log != nil {
				s.log.Info("s1ap: PWS response area decoded", zap.String("source_protocol", "S1AP"), zap.String("source_asn1_type", "BroadcastCompletedAreaList"), zap.String("area_alternative", pwsAreaKind(v.Kind)), zap.Int("area_entries", pwsAreaEntries(v)), zap.String("responding_enb", remote))
			}
		}
		if procedure == pdu.ProcKill && ie.ID == 141 { // Broadcast Cancelled Area List
			v, err := sbcap.DecodeS1CancelledAreaList(ie.Value)
			if err != nil {
				if s.log != nil {
					s.log.Warn("s1ap: invalid BroadcastCancelledAreaList", zap.String("remote", remote), zap.Error(err))
				}
				return
			}
			areas = &v
			if s.log != nil {
				s.log.Info("s1ap: PWS response area decoded", zap.String("source_protocol", "S1AP"), zap.String("source_asn1_type", "BroadcastCancelledAreaList"), zap.String("area_alternative", pwsAreaKind(v.Kind)), zap.Int("area_entries", pwsAreaEntries(v)), zap.String("responding_enb", remote))
			}
		}
	}
	if !haveMessageID || !haveSerial {
		return
	}
	sbcProcedure := sbcap.ProcedureWriteReplaceWarning
	if procedure == pdu.ProcKill {
		sbcProcedure = sbcap.ProcedureStopWarning
	}
	s.pwsTransactions.Range(func(key, value any) bool {
		tx := value.(*pwsTransaction)
		if tx.procedure != sbcProcedure || tx.messageID != messageID || tx.serial != serial {
			return true
		}
		tx.mu.Lock()
		_, waiting := tx.pending[remote]
		if waiting {
			delete(tx.pending, remote)
			if areas != nil {
				tx.areaLists = append(tx.areaLists, *areas)
			} else if procedure == pdu.ProcKill {
				if global := s.globalENBIDForRemote(remote); len(global) != 0 {
					tx.emptyENBs = append(tx.emptyENBs, global)
				}
			}
		}
		done := waiting && len(tx.pending) == 0
		remaining := len(tx.pending)
		tx.mu.Unlock()
		if s.log != nil {
			if waiting {
				s.log.Info("s1ap: PWS response matched transaction", zap.String("warning_identity", tx.baseKey), zap.String("responding_enb", remote), zap.Int("remaining_pending_enbs", remaining))
			} else {
				s.log.Debug("s1ap: duplicate or unexpected PWS response", zap.String("warning_identity", tx.baseKey), zap.String("responding_enb", remote))
			}
		}
		if done && s.pwsTransactions.CompareAndDelete(key, tx) {
			metrics.SBcAPTransactionsTotal.WithLabelValues("completed").Inc()
			if s.log != nil {
				s.log.Info("s1ap: PWS transaction complete", zap.String("warning_identity", tx.baseKey), zap.String("completion_reason", "all-responses"))
			}
			s.finishPWSTransaction(tx)
		}
		return true
	})
}

func (s *Server) finishPWSTransaction(tx *pwsTransaction) {
	s.releasePWSTransactionBase(tx.baseKey)
	if s.pwsIndication == nil {
		return
	}
	tx.mu.Lock()
	areaLists := append([]sbcap.AreaList(nil), tx.areaLists...)
	emptyENBs := append([][]byte(nil), tx.emptyENBs...)
	tx.mu.Unlock()
	// A cell-ID form is valid for either indication and preserves all reported
	// cells when different eNBs report different (TAI/EAI/cell) alternatives.
	area := sbcap.MergeAreaLists(areaLists, tx.procedure == sbcap.ProcedureStopWarning)
	var encoded []byte
	var emptyEncoded []byte
	var err error
	if len(area.Cells) != 0 {
		if tx.procedure == sbcap.ProcedureStopWarning {
			encoded, err = sbcap.EncodeCancelledAreaList(area)
		} else {
			encoded, err = sbcap.EncodeCompletedAreaList(area)
		}
	}
	if tx.procedure == sbcap.ProcedureStopWarning && len(emptyENBs) != 0 {
		emptyEncoded, err = sbcap.EncodeBroadcastEmptyAreaList(deduplicatePWSGlobalENBIDs(emptyENBs))
	}
	if err != nil {
		if s.log != nil {
			s.log.Warn("s1ap: cannot encode SBc-AP PWS area result", zap.String("warning_identity", tx.baseKey), zap.Error(err))
		}
		return
	}
	payload, err := sbcap.BuildWarningIndicationWithEmptyAreaList(tx.procedure, tx.messageID, tx.serial, encoded, emptyEncoded)
	if err == nil {
		if s.log != nil {
			areaType := "none"
			if len(encoded) != 0 {
				areaType = pwsAreaKind(area.Kind)
			}
			ieID := sbcap.IEBroadcastScheduledAreaList
			if tx.procedure == sbcap.ProcedureStopWarning {
				ieID = sbcap.IEBroadcastCancelledAreaList
			}
			s.log.Info("s1ap: PWS result mapped to SBc-AP", zap.String("destination_protocol", "SBc-AP"), zap.String("destination_asn1_type", map[bool]string{true: "Broadcast-Cancelled-Area-List", false: "Broadcast-Scheduled-Area-List"}[tx.procedure == sbcap.ProcedureStopWarning]), zap.String("area_alternative", areaType), zap.Int("aggregated_entries", pwsAreaEntries(area)), zap.Uint16("encoded_ie_id", ieID), zap.Int("encoded_ie_length", len(encoded)), zap.Int("broadcast_empty_enbs", len(emptyENBs)))
		}
		s.pwsIndication(tx.peer, payload)
	}
}

func (s *Server) globalENBIDForRemote(remote string) []byte {
	value, ok := s.enbs.Load(remote)
	if !ok {
		return nil
	}
	enb := value.(*ENBContext)
	enb.mu.Lock()
	global := enb.GlobalENBID
	setupComplete := enb.SetupComplete
	enb.mu.Unlock()
	if !setupComplete {
		return nil
	}
	encoded, err := ies.EncodeGlobalENBID(global)
	if err != nil {
		return nil
	}
	return encoded
}

func deduplicatePWSGlobalENBIDs(ids [][]byte) [][]byte {
	seen := make(map[string]struct{}, len(ids))
	out := make([][]byte, 0, len(ids))
	for _, id := range ids {
		key := string(id)
		if _, exists := seen[key]; !exists {
			seen[key] = struct{}{}
			out = append(out, id)
		}
	}
	return out
}

func pwsAreaKind(kind sbcap.AreaKind) string {
	switch kind {
	case sbcap.AreaCells:
		return "cell-id"
	case sbcap.AreaTAIs:
		return "tai"
	case sbcap.AreaEAIs:
		return "emergency-area-id"
	default:
		return "unknown"
	}
}

func pwsAreaEntries(area sbcap.AreaList) int {
	n := len(area.Cells)
	taiGroups := area.TAIGroups
	if area.Kind == sbcap.AreaTAIs && len(taiGroups) == 0 {
		taiGroups = area.Groups
	}
	for _, group := range taiGroups {
		n += len(group.Cells)
	}
	eaiGroups := area.EAIGroups
	if area.Kind == sbcap.AreaEAIs && len(eaiGroups) == 0 {
		eaiGroups = area.Groups
	}
	for _, group := range eaiGroups {
		n += len(group.Cells)
	}
	return n
}

func sbcapMessageID(value []byte) ([2]byte, error) {
	var out [2]byte
	r := aper.NewBitReader(value)
	bits, err := aper.DecodeBitString(r, 16, 16)
	if err != nil || len(bits.Bytes) != 2 {
		return out, fmt.Errorf("invalid PWS message identity")
	}
	copy(out[:], bits.Bytes)
	return out, nil
}

func (s *Server) resolveSBcAPTargets(req *sbcap.WarningRequest) ([]string, error) {
	if len(req.GlobalENBID) != 0 {
		global, err := ies.DecodeGlobalENBID(req.GlobalENBID)
		if err != nil {
			return nil, fmt.Errorf("s1ap: invalid SBc-AP Global eNB ID: %w", err)
		}
		var selected []string
		s.enbs.Range(func(key, value any) bool {
			enb := value.(*ENBContext)
			enb.mu.Lock()
			match := enb.SetupComplete && enb.GlobalENBID.Serialise() == global.Serialise()
			remote := enb.RemoteAddr
			enb.mu.Unlock()
			if match {
				selected = append(selected, remote)
			}
			return true
		})
		return selected, nil
	}
	if len(req.TAIList) == 0 {
		return s.allENBAddrs(), nil
	}
	tais, err := sbcap.DecodeTAIList(req.TAIList)
	if err != nil {
		return nil, err
	}
	selected := make(map[string]struct{})
	for _, target := range tais {
		mcc, mnc, err := ies.DecodePLMN(target.PLMN[:])
		if err != nil {
			return nil, err
		}
		s.enbs.Range(func(_, value any) bool {
			enb := value.(*ENBContext)
			enb.mu.Lock()
			defer enb.mu.Unlock()
			if !enb.SetupComplete {
				return true
			}
			for _, served := range effectiveRoutingTAs(enb) {
				if served.TAC != target.TAC {
					continue
				}
				for _, plmn := range served.BroadcastPLMNs {
					if plmn.MCC == mcc && plmn.MNC == mnc {
						selected[enb.RemoteAddr] = struct{}{}
						return true
					}
				}
			}
			return true
		})
	}
	addrs := make([]string, 0, len(selected))
	for remote := range selected {
		addrs = append(addrs, remote)
	}
	return addrs, nil
}

func (s *Server) buildPWSRequest(procedure uint8, req *sbcap.WarningRequest) ([]byte, error) {
	var s1Procedure uint8
	switch procedure {
	case sbcap.ProcedureWriteReplaceWarning:
		s1Procedure = pdu.ProcWriteReplaceWarning
	case sbcap.ProcedureStopWarning:
		s1Procedure = pdu.ProcKill
	default:
		return nil, fmt.Errorf("s1ap: unsupported SBc-AP procedure %d", procedure)
	}
	// Preserve the ASN.1 declaration order, rather than map iteration order.
	// Criticalities are the S1AP WriteReplaceWarningRequest IE criticalities.
	mapping := []struct {
		sbc, s1     uint16
		criticality aper.Criticality
	}{
		{sbcap.IEMessageIdentifier, ieMessageIdentifier, aper.CriticalityReject},
		{sbcap.IESerialNumber, ieSerialNumber, aper.CriticalityReject},
		{sbcap.IEWarningAreaList, ieWarningAreaList, aper.CriticalityIgnore},
		{sbcap.IERepetitionPeriod, ieRepetitionPeriod, aper.CriticalityReject},
		{sbcap.IENumberOfBroadcastsRequested, ieNumberOfBroadcastRequest, aper.CriticalityReject},
		{sbcap.IEWarningType, ieWarningType, aper.CriticalityIgnore},
		{sbcap.IEWarningSecurityInformation, ieWarningSecurityInformation, aper.CriticalityIgnore},
		{sbcap.IEDataCodingScheme, ieDataCodingScheme, aper.CriticalityIgnore},
		{sbcap.IEWarningMessageContent, ieWarningMessageContents, aper.CriticalityIgnore},
	}
	list := make([]pdu.ProtocolIE, 0, len(mapping)+1)
	for _, m := range mapping {
		if value := req.IEs[m.sbc]; value != nil {
			list = append(list, pdu.ProtocolIE{ID: m.s1, Criticality: m.criticality, Value: value})
		}
	}
	if req.ConcurrentWarning {
		// The SBc-AP and S1AP root ASN.1 types are both
		// ENUMERATED { true }, but re-encode it so no open-type bytes cross
		// protocol boundaries without validation.
		value, err := encodeConcurrentWarningS1AP()
		if err != nil {
			return nil, err
		}
		list = append(list, pdu.ProtocolIE{ID: ieConcurrentWarningIndicator, Criticality: aper.CriticalityReject, Value: value})
	}
	return pdu.BuildInitiatingMessage(s1Procedure, aper.CriticalityReject, list), nil
}

func encodeConcurrentWarningS1AP() ([]byte, error) {
	// ENUMERATED { true } has zero value bits. ProtocolIE values are APER open
	// types, so the value is carried in one octet of zero alignment padding.
	return []byte{0}, nil
}

func decodeConcurrentWarningS1AP(value []byte) (bool, error) {
	if len(value) != 1 {
		return false, fmt.Errorf("S1AP concurrent warning indicator length %d, want 1", len(value))
	}
	if value[0] != 0 {
		return false, fmt.Errorf("S1AP concurrent warning indicator non-zero padding")
	}
	return true, nil
}
