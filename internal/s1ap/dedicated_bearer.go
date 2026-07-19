package s1ap

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/gtpv2"
	nas "github.com/vectorcore/mme/internal/nas"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/esm"
	"github.com/vectorcore/mme/internal/nas/security"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/uecontext"
)

const (
	bearerTxCreate      = "create"
	bearerTxUpdate      = "update"
	bearerTxLocalUpdate = "local_update"
	bearerTxDelete      = "delete"

	createBearerOverallTimeout   = 30 * time.Second
	maxPendingCreateBearersPerUE = 4
)

type cachedCreateBearerResponse struct {
	Peer    string
	TEID    uint32
	Seq     uint32
	Cause   uint8
	Bearers []gtpv2.CreateBearerBearer
	Meta    *gtpv2.CreateBearerResponseMeta
}

func dedicatedBearerQoSLogFields(raw []byte, fallbackQCI uint8) []zap.Field {
	debug := esm.InspectDedicatedBearerQoSForDebug(raw, fallbackQCI)
	fields := []zap.Field{
		zap.String("bearer_qos_raw_hex", hex.EncodeToString(raw)),
		zap.Uint8("bearer_qos_fallback_qci", debug.FallbackQCI),
		zap.Bool("bearer_qos_raw_parse_ok", debug.RawParseOK),
		zap.Uint8("bearer_qos_raw_qci", debug.RawQCI),
		zap.Uint8("bearer_qos_effective_qci", debug.EffectiveQCI),
		zap.Uint64("bearer_qos_raw_ul_mbr_bps", debug.RawUplinkMBR),
		zap.Uint64("bearer_qos_raw_dl_mbr_bps", debug.RawDownlinkMBR),
		zap.Uint64("bearer_qos_raw_ul_gbr_bps", debug.RawUplinkGBR),
		zap.Uint64("bearer_qos_raw_dl_gbr_bps", debug.RawDownlinkGBR),
		zap.Uint64("bearer_qos_normalized_ul_mbr_bps", debug.NormalizedUplinkMBR),
		zap.Uint64("bearer_qos_normalized_dl_mbr_bps", debug.NormalizedDownlinkMBR),
		zap.Uint64("bearer_qos_normalized_ul_gbr_bps", debug.NormalizedUplinkGBR),
		zap.Uint64("bearer_qos_normalized_dl_gbr_bps", debug.NormalizedDownlinkGBR),
		zap.Bool("bearer_qos_normalized_fields_filled", debug.NormalizedFieldsFilled),
		zap.Bool("bearer_qos_fallback_to_qci_only", debug.FallbackToQCIOnly),
		zap.Uint8("bearer_qos_encoded_length", debug.EncodedLength),
		zap.String("bearer_qos_encoded_hex", debug.EncodedHex),
	}
	if debug.RawParseError != "" {
		fields = append(fields, zap.String("bearer_qos_raw_parse_error", debug.RawParseError))
	}
	return fields
}

func bearerTxKey(peer string, msgType uint8, teid uint32, seq uint32) string {
	return fmt.Sprintf("%s|%d|%08x|%06x", peer, msgType, teid, seq)
}

func (s *Server) HandleCreateBearerRequest(peer string, req *gtpv2.CreateBearerRequest) {
	ue, linked := s.findUEByLocalS11TEID(req.TEID, req.LinkedEBI)
	if ue == nil || linked == nil {
		s.log.Warn("s1ap: Create Bearer Request for unknown linked bearer",
			zap.String("peer", peer),
			zap.Uint32("seq", req.SeqNum),
			zap.Uint32("local_teid", req.TEID),
			zap.Uint8("linked_ebi", req.LinkedEBI))
		s.sendCreateBearerResponse(peer, req.TEID, req.SeqNum, gtpv2.CauseContextNotFound, req.Bearers)
		return
	}

	key := bearerTxKey(peer, gtpv2.MsgCreateBearerRequest, req.TEID, req.SeqNum)
	if cached, ok := s.completedCreateBearerResponses.Load(key); ok {
		resp := cached.(*cachedCreateBearerResponse)
		s.log.Info("s11: retransmitted Create Bearer Request matched cached final response",
			zap.String("peer", peer),
			zap.Uint32("seq", req.SeqNum),
			zap.Uint32("local_teid", req.TEID),
			zap.Uint8("cause", resp.Cause))
		s.sendCreateBearerResponseWithMeta(resp.Peer, resp.TEID, resp.Seq, resp.Cause, append([]gtpv2.CreateBearerBearer(nil), resp.Bearers...), resp.Meta)
		return
	}
	fingerprint := createBearerFingerprint(req)
	var shouldPage bool
	var shouldResume bool
	var transactionID string
	var assignedEBIs []uint8
	var pageIMSI string
	ue.Lock()
	if ue.PendingBearerTransactions == nil {
		ue.PendingBearerTransactions = map[string]*uecontext.DedicatedBearerTransaction{}
	}
	if ue.EBIReservations == nil {
		ue.EBIReservations = map[uint8]uecontext.EBIReservation{}
	}
	if linked != nil && linked.ModifyBearerDeferred {
		linked.ModifyBearerDeferred = false
		ue.StopTimer(imsModifyBearerSettleTimerName(req.LinkedEBI))
		s.log.Info("s1ap: deferred IMS Modify Bearer cancelled due to new linked Create Bearer activity",
			zap.String("imsi", ue.IMSI),
			zap.Uint32("mme_ue_id", ue.MMEUES1APID),
			zap.Uint8("linked_ebi", req.LinkedEBI),
			zap.Uint32("sequence_number", req.SeqNum))
	}
	for _, existing := range ue.PendingBearerTransactions {
		if existing.Kind != bearerTxCreate || existing.Fingerprint != fingerprint || isCreateBearerTerminal(existing.CreateState) {
			continue
		}
		if createBearerCanSupersedeTransport(existing.CreateState) {
			refreshEquivalentCreateBearerTransport(existing, peer, req)
		}
		s.log.Warn("s11: equivalent Create Bearer already pending",
			zap.String("imsi", ue.IMSI),
			zap.Uint32("mme_ue_id", ue.MMEUES1APID),
			zap.String("existing_transaction_id", existing.ID),
			zap.Uint32("new_sequence_number", req.SeqNum),
			zap.Uint8("linked_ebi", req.LinkedEBI),
			zap.String("bearer_fingerprint", fingerprint),
			zap.String("action", "collapsed"))
		ue.Unlock()
		return
	}
	if _, exists := ue.PendingBearerTransactions[key]; exists {
		ue.Unlock()
		s.log.Info("s1ap: duplicate pending Create Bearer Request ignored",
			zap.String("peer", peer), zap.Uint32("seq", req.SeqNum), zap.Uint32("local_teid", req.TEID))
		return
	}
	pendingCreates := 0
	for _, tx := range ue.PendingBearerTransactions {
		if tx.Kind == bearerTxCreate && !isCreateBearerTerminal(tx.CreateState) {
			pendingCreates++
		}
	}
	if pendingCreates >= maxPendingCreateBearersPerUE {
		ue.Unlock()
		s.log.Warn("s11: Create Bearer pending limit exceeded",
			zap.String("imsi", ue.IMSI),
			zap.Uint32("mme_ue_id", ue.MMEUES1APID),
			zap.Int("pending_create_bearers", pendingCreates))
		s.sendCreateBearerResponse(peer, req.TEID, req.SeqNum, gtpv2.CauseRequestDenied, req.Bearers)
		return
	}
	if err := assignDedicatedEBIsLocked(ue, req.Bearers); err != nil {
		ue.Unlock()
		s.log.Warn("s1ap: Create Bearer EBI allocation failed",
			zap.String("peer", peer), zap.Uint32("seq", req.SeqNum), zap.Error(err))
		s.sendCreateBearerResponse(peer, req.TEID, req.SeqNum, gtpv2.CauseAllDynamicAddressesOccupied, req.Bearers)
		return
	}

	now := time.Now()
	transactionID = fmt.Sprintf("cbr-%d-%08x-%06x", ue.MMEUES1APID, req.TEID, req.SeqNum)
	tx := &uecontext.DedicatedBearerTransaction{
		ID:          transactionID,
		Kind:        bearerTxCreate,
		PeerAddress: peer,
		LocalTEID:   req.TEID,
		SequenceNum: req.SeqNum,
		LinkedEBI:   req.LinkedEBI,
		Fingerprint: fingerprint,
		Bearers:     map[uint8]*uecontext.DedicatedBearerContext{},
		CreateState: uecontext.CreateBearerReceived,
		State:       string(uecontext.CreateBearerReceived),
		CreatedAt:   now,
		Deadline:    now.Add(createBearerOverallTimeout),
	}
	for i := range req.Bearers {
		b := &req.Bearers[i]
		assigned := b.AssignedEBI
		if assigned == 0 {
			assigned = b.EBI
		}
		qci := b.QCI
		if qci == 0 {
			qci = 9
		}
		proc := &uecontext.DedicatedBearerContext{
			TransactionID: transactionID,
			RequestedEBI:  b.RequestedEBI,
			AssignedEBI:   assigned,
			LinkedEBI:     req.LinkedEBI,
			PTI:           0,
			QCI:           qci,
			ARP:           b.ARP,
			BearerQoS:     append([]byte(nil), b.BearerQoS...),
			TFT:           append([]byte(nil), b.TFT...),
			SGWS1UTEID:    b.SGWS1UTEID,
			SGWS1UIP:      append(net.IP(nil), b.SGWS1UIP...),
			State:         "create-pending",
		}
		tx.Bearers[assigned] = proc
		tx.EBIs = append(tx.EBIs, assigned)
		ue.EBIReservations[assigned] = uecontext.EBIReservation{
			EBI:           assigned,
			TransactionID: transactionID,
			ReservedAt:    now,
		}
		assignedEBIs = append(assignedEBIs, assigned)
		fields := []zap.Field{
			zap.String("imsi", ue.IMSI),
			zap.Uint32("mme_ue_id", ue.MMEUES1APID),
			zap.Uint32("sequence_number", req.SeqNum),
			zap.Uint8("linked_ebi", req.LinkedEBI),
			zap.Uint8("requested_ebi", b.RequestedEBI),
			zap.Uint8("assigned_ebi", assigned),
			zap.Uint8("pti", 0),
			zap.Uint8("qci", qci),
			zap.Uint8("arp", b.ARP),
			zap.String("tft_hex", hex.EncodeToString(b.TFT)),
			zap.String("sgw_s1u_ip", net.IP(b.SGWS1UIP).String()),
			zap.Uint32("sgw_s1u_teid", b.SGWS1UTEID),
			zap.String("transaction_state", tx.State),
		}
		fields = append(fields, dedicatedBearerQoSLogFields(b.BearerQoS, qci)...)
		s.log.Debug("s1ap: Create Bearer procedure started", fields...)
	}
	sort.Slice(tx.EBIs, func(i, j int) bool { return tx.EBIs[i] < tx.EBIs[j] })
	ue.PendingBearerTransactions[key] = tx
	mmeID := ue.MMEUES1APID
	imsi := ue.IMSI
	emmState := ue.EMMState
	ecmState := ue.ECMState
	activeS1 := hasActiveS1BindingLocked(ue)
	if !linkedBearerReadyLocked(ue, req.LinkedEBI) {
		tx.CreateState = uecontext.CreateBearerWaitingForLink
		tx.State = string(tx.CreateState)
		s.log.Debug("s11: Create Bearer Request waiting for linked bearer readiness",
			zap.String("imsi", imsi),
			zap.Uint32("mme_ue_id", mmeID),
			zap.Uint32("sequence_number", req.SeqNum),
			zap.Uint8("linked_ebi", req.LinkedEBI),
			zap.String("transaction_id", transactionID),
			zap.String("state", tx.State))
	} else if !activeS1 && emmState == emm.StateRegistered && ecmState == emm.ECMIdle {
		tx.CreateState = uecontext.CreateBearerWaitingForUE
		tx.State = string(tx.CreateState)
		pageIMSI = imsi
		shouldPage = ue.PagingAttempts == 0
		tx.PagingAttempts = ue.PagingAttempts
		s.log.Debug("s11: Create Bearer Request held for idle UE",
			zap.String("imsi", imsi),
			zap.Uint32("mme_ue_id", mmeID),
			zap.Uint32("sequence_number", req.SeqNum),
			zap.Uint8("linked_ebi", req.LinkedEBI),
			zap.Int("bearer_count", len(req.Bearers)),
			zap.Uint8s("assigned_ebis", assignedEBIs),
			zap.Stringer("ecm_state", ecmState),
			zap.Stringer("emm_state", emmState),
			zap.String("transaction_id", transactionID),
			zap.String("state", tx.State))
	} else if activeS1 && ecmState == emm.ECMConnected {
		shouldResume = true
	} else {
		delete(ue.PendingBearerTransactions, key)
		releaseCreateBearerReservationsLocked(ue, tx)
		ue.Unlock()
		s.sendCreateBearerResponse(peer, req.TEID, req.SeqNum, gtpv2.CauseRequestDenied, req.Bearers)
		return
	}
	ue.Unlock()

	s.startCreateBearerTimeout(ue, key)
	if shouldPage {
		if err := s.PageUE(pageIMSI); err != nil && err != ErrAlreadyPaging && err != ErrAlreadyConnected {
			s.log.Warn("s1ap: paging UE for pending Create Bearer failed",
				zap.String("imsi", pageIMSI),
				zap.Uint32("mme_ue_id", mmeID),
				zap.String("transaction_id", transactionID),
				zap.Error(err))
			s.failCreateBearerTransaction(ue, key, gtpv2.CauseRequestDenied)
			return
		}
		ue.Lock()
		if tx := ue.PendingBearerTransactions[key]; tx != nil {
			tx.CreateState = uecontext.CreateBearerPaging
			tx.State = string(tx.CreateState)
			tx.PagingAt = time.Now()
			tx.PagingAttempts = ue.PagingAttempts
		}
		pagingAttempt := ue.PagingAttempts
		taiCount := 0
		if ue.TAI != nil {
			taiCount = 1
		}
		ue.Unlock()
		s.log.Info("s1ap: paging UE for pending Create Bearer",
			zap.String("imsi", pageIMSI),
			zap.Uint32("mme_ue_id", mmeID),
			zap.String("transaction_id", transactionID),
			zap.Uint8("paging_attempt", pagingAttempt),
			zap.Int("tai_count", taiCount))
		return
	}
	if shouldResume {
		s.resumeCreateBearerTransaction(ue, key)
	}
}

func (s *Server) ResumePendingNetworkBearerProcedures(ue *uecontext.Context) {
	ue.Lock()
	var keys []string
	var imsi string
	var mmeID uint32
	for key, tx := range ue.PendingBearerTransactions {
		if tx.Kind != bearerTxCreate {
			continue
		}
		switch tx.CreateState {
		case uecontext.CreateBearerWaitingForUE, uecontext.CreateBearerPaging, uecontext.CreateBearerWaitingForLink:
			keys = append(keys, key)
		}
	}
	imsi = ue.IMSI
	mmeID = ue.MMEUES1APID
	ue.Unlock()
	for _, key := range keys {
		s.log.Info("s1ap: resuming pending Create Bearer after S1 binding restored",
			zap.String("imsi", imsi),
			zap.Uint32("mme_ue_id", mmeID),
			zap.String("transaction_id", txIDForLog(ue, key)),
			zap.String("transaction_key", key))
		s.resumeCreateBearerTransaction(ue, key)
	}
}

func (s *Server) resumeCreateBearerTransaction(ue *uecontext.Context, key string) {
	ue.Lock()
	tx := ue.PendingBearerTransactions[key]
	if tx == nil || tx.Kind != bearerTxCreate || isCreateBearerTerminal(tx.CreateState) {
		ue.Unlock()
		return
	}
	if !hasActiveS1BindingLocked(ue) || ue.ECMState != emm.ECMConnected {
		tx.CreateState = uecontext.CreateBearerWaitingForUE
		tx.State = string(tx.CreateState)
		ue.Unlock()
		return
	}
	if !linkedBearerActiveLocked(ue, tx.LinkedEBI) {
		delete(ue.PendingBearerTransactions, key)
		releaseCreateBearerReservationsLocked(ue, tx)
		ue.Unlock()
		s.sendCreateBearerResponse(tx.PeerAddress, tx.LocalTEID, tx.SequenceNum, gtpv2.CauseContextNotFound, createBearersFromTx(tx))
		return
	}
	if !linkedBearerReadyLocked(ue, tx.LinkedEBI) {
		tx.CreateState = uecontext.CreateBearerWaitingForLink
		tx.State = string(tx.CreateState)
		ue.Unlock()
		return
	}
	tx.CreateState = uecontext.CreateBearerActivatingNAS
	tx.State = string(tx.CreateState)
	var erabItems []ERABSetupItem
	assignedEBIs := append([]uint8(nil), tx.EBIs...)
	for _, ebi := range tx.EBIs {
		proc := tx.Bearers[ebi]
		if proc == nil {
			continue
		}
		res, ok := ue.EBIReservations[ebi]
		if !ok || res.TransactionID != tx.ID {
			ue.Unlock()
			s.failCreateBearerTransaction(ue, key, gtpv2.CauseRequestDenied)
			return
		}
		plain := esm.EncodeActivateDedicatedEPSBearerContextRequest(proc.AssignedEBI, proc.LinkedEBI, proc.PTI, proc.BearerQoS, proc.QCI, proc.TFT, proc.PCO)
		protected, _, err := protectNASLocked(ue, plain)
		if err != nil {
			ue.Unlock()
			s.log.Warn("s1ap: failed to protect resumed Activate Dedicated EPS Bearer Context Request",
				zap.String("transaction_id", tx.ID),
				zap.Uint8("assigned_ebi", proc.AssignedEBI),
				zap.Error(err))
			s.failCreateBearerTransaction(ue, key, gtpv2.CauseRequestDenied)
			return
		}
		ue.DLNASCount.Increment()
		proc.State = "nas-sent"
		erabItems = append(erabItems, ERABSetupItem{
			EBI:                     proc.AssignedEBI,
			QCI:                     proc.QCI,
			ARPPriority:             arpPriority(proc.ARP),
			PreemptionCapability:    preemptionCapability(proc.ARP),
			PreemptionVulnerability: preemptionVulnerability(proc.ARP),
			BearerQoS:               append([]byte(nil), proc.BearerQoS...),
			SGWS1UIPv4:              proc.SGWS1UIP.To4(),
			SGWS1UTEID:              proc.SGWS1UTEID,
			NASPDU:                  protected,
		})
	}
	tx.CreateState = uecontext.CreateBearerSettingUpERAB
	tx.State = string(tx.CreateState)
	ue.LastDownlinkNASMessage = "Activate Dedicated EPS Bearer Context Request"
	mmeID := ue.MMEUES1APID
	imsi := ue.IMSI
	transactionID := tx.ID
	sequence := tx.SequenceNum
	ue.Unlock()

	s.log.Debug("s1ap: resuming pending Create Bearer after S1 binding restored",
		zap.String("imsi", imsi),
		zap.Uint32("mme_ue_id", mmeID),
		zap.String("transaction_id", transactionID),
		zap.Uint32("sequence_number", sequence),
		zap.Uint8s("assigned_ebis", assignedEBIs))
	if err := s.SendERABSetupRequestTracked(mmeID, erabItems, "dedicated_create_bearer", transactionID); err != nil {
		s.log.Warn("s1ap: E-RAB Setup Request for resumed dedicated bearer failed",
			zap.Uint32("mme_ue_id", mmeID),
			zap.String("transaction_id", transactionID),
			zap.Error(err))
		s.failCreateBearerTransaction(ue, key, gtpv2.CauseRequestDenied)
		return
	}
	ue.Lock()
	if tx := ue.PendingBearerTransactions[key]; tx != nil && tx.ID == transactionID {
		tx.CreateState = uecontext.CreateBearerWaitingResults
		tx.State = string(tx.CreateState)
	}
	ue.Unlock()
}

func (s *Server) HandleUpdateBearerRequest(peer string, req *gtpv2.UpdateBearerRequest) {
	ue, _ := s.findUEByLocalS11TEID(req.TEID, 0)
	if ue == nil {
		s.sendUpdateBearerResponse(peer, req.TEID, req.SeqNum, gtpv2.CauseContextNotFound, req.Bearers)
		return
	}
	key := bearerTxKey(peer, gtpv2.MsgUpdateBearerRequest, req.TEID, req.SeqNum)
	ue.Lock()
	if ue.PendingBearerTransactions == nil {
		ue.PendingBearerTransactions = map[string]*uecontext.DedicatedBearerTransaction{}
	}
	if _, exists := ue.PendingBearerTransactions[key]; exists {
		ue.Unlock()
		return
	}
	if existingTx, existingEBI, conflict := findConflictingPendingNetworkUpdateLocked(ue, req.Bearers); conflict {
		imsi := ue.IMSI
		mmeUEID := ue.MMEUES1APID
		ue.Unlock()
		s.log.Warn("s11: overlapping Update Bearer Request rejected",
			zap.String("imsi", imsi),
			zap.Uint32("mme_ue_id", mmeUEID),
			zap.Uint32("sequence_number", req.SeqNum),
			zap.Uint8("assigned_ebi", existingEBI),
			zap.String("conflicting_transaction_id", existingTx.ID),
			zap.String("conflicting_transaction_kind", existingTx.Kind))
		s.sendUpdateBearerResponse(peer, req.TEID, req.SeqNum, gtpv2.CauseRequestDenied, req.Bearers)
		return
	}
	tx := &uecontext.DedicatedBearerTransaction{
		ID:          fmt.Sprintf("ubr-%d-%08x-%06x", ue.MMEUES1APID, req.TEID, req.SeqNum),
		Kind:        bearerTxUpdate,
		PeerAddress: peer,
		LocalTEID:   req.TEID,
		SequenceNum: req.SeqNum,
		Bearers:     map[uint8]*uecontext.DedicatedBearerContext{},
		State:       "modifying",
		CreatedAt:   time.Now(),
	}
	mmeID := ue.MMEUES1APID
	var nasToSend [][]byte
	var erabItems []ERABModifyItem
	erabModifyRequired := hasActiveS1BindingLocked(ue)
	for _, b := range req.Bearers {
		active := ue.DedicatedBearers[b.EBI]
		if active == nil {
			continue
		}
		next := *active
		next.TransactionID = tx.ID
		next.PTI = 0
		next.NASAccepted = false
		next.NASRejected = false
		next.FailureCause = 0
		applyUpdateBearerRequestToDedicatedBearer(&next, b)
		if erabModifyRequired && active.ERABEstablished {
			next.ERABEstablished = false
			next.ERABFailed = false
		}
		next.State = "update-pending"
		tx.Bearers[b.EBI] = &next
		tx.EBIs = append(tx.EBIs, b.EBI)
		plain := esm.EncodeModifyEPSBearerContextRequest(b.EBI, 0, next.QCI, b.BearerQoS, b.TFT, b.PCO)
		protected, _, err := protectNASLocked(ue, plain)
		if err != nil {
			ue.Unlock()
			s.sendUpdateBearerResponse(peer, req.TEID, req.SeqNum, gtpv2.CauseRequestDenied, req.Bearers)
			return
		}
		ue.DLNASCount.Increment()
		nasToSend = append(nasToSend, protected)
		if erabModifyRequired && active.ERABEstablished {
			erabItems = append(erabItems, ERABModifyItem{
				EBI:                     b.EBI,
				QCI:                     next.QCI,
				ARPPriority:             arpPriority(next.ARP),
				PreemptionCapability:    preemptionCapability(next.ARP),
				PreemptionVulnerability: preemptionVulnerability(next.ARP),
				BearerQoS:               append([]byte(nil), next.BearerQoS...),
				NASPDU:                  protected,
			})
		}
		fields := []zap.Field{
			zap.String("imsi", ue.IMSI),
			zap.Uint32("mme_ue_id", mmeID),
			zap.Uint32("sequence_number", req.SeqNum),
			zap.Uint8("assigned_ebi", b.EBI),
			zap.Uint8("qci", next.QCI),
			zap.String("tft_hex", hex.EncodeToString(b.TFT)),
		}
		fields = append(fields, dedicatedBearerQoSLogFields(b.BearerQoS, next.QCI)...)
		s.log.Debug("s1ap: Update Bearer NAS Modify sent", fields...)
	}
	if len(tx.Bearers) == 0 {
		ue.Unlock()
		s.sendUpdateBearerResponse(peer, req.TEID, req.SeqNum, gtpv2.CauseContextNotFound, req.Bearers)
		return
	}
	ue.PendingBearerTransactions[key] = tx
	ue.LastDownlinkNASMessage = "Modify EPS Bearer Context Request"
	ue.StartTimer(uecontext.TimerUpdateBearerPrefix+key, createBearerOverallTimeout, func() {
		s.onUpdateBearerTimeout(ue, key)
	})
	ue.Unlock()
	for _, protected := range nasToSend {
		if err := s.SendDownlinkNAS(mmeID, protected); err != nil {
			s.failUpdateBearerTransaction(ue, key, gtpv2.CauseRequestDenied)
			return
		}
	}
	if len(erabItems) > 0 {
		if err := s.SendERABModifyRequestTracked(mmeID, erabItems, "dedicated_update_bearer", tx.ID); err != nil {
			s.log.Warn("s1ap: E-RAB Modify Request for Update Bearer failed",
				zap.Uint32("mme_ue_id", mmeID),
				zap.String("transaction_id", tx.ID),
				zap.Error(err))
			s.failUpdateBearerTransaction(ue, key, gtpv2.CauseRequestDenied)
			return
		}
	}
}

func (s *Server) HandleLocalBearerResourceModification(ue *uecontext.Context, req *esm.BearerResourceModificationRequest) error {
	ue.Lock()
	if ue.PendingBearerTransactions == nil {
		ue.PendingBearerTransactions = map[string]*uecontext.DedicatedBearerTransaction{}
	}
	active := ue.DedicatedBearers[req.LinkedEPSBearerID]
	if active == nil {
		ue.Unlock()
		return fmt.Errorf("linked bearer %d not active", req.LinkedEPSBearerID)
	}
	key := fmt.Sprintf("brm|%d|%d|%d", ue.MMEUES1APID, req.LinkedEPSBearerID, req.ProcedureTransactionID)
	if _, exists := ue.PendingBearerTransactions[key]; exists {
		ue.Unlock()
		return nil
	}
	next := *active
	next.TransactionID = fmt.Sprintf("brm-%d-%02x-%02x", ue.MMEUES1APID, req.LinkedEPSBearerID, req.ProcedureTransactionID)
	next.PTI = req.ProcedureTransactionID
	if len(req.TFA) > 0 {
		next.TFT = append([]byte(nil), req.TFA...)
	}
	tx := &uecontext.DedicatedBearerTransaction{
		ID:        next.TransactionID,
		Kind:      bearerTxLocalUpdate,
		LinkedEBI: active.LinkedEBI,
		EBIs:      []uint8{req.LinkedEPSBearerID},
		Bearers: map[uint8]*uecontext.DedicatedBearerContext{
			req.LinkedEPSBearerID: &next,
		},
		State:     "ue-initiated-modifying",
		CreatedAt: time.Now(),
	}
	plain := esm.EncodeModifyEPSBearerContextRequest(active.AssignedEBI, req.ProcedureTransactionID, next.QCI, next.BearerQoS, next.TFT, next.PCO)
	protected, _, err := protectNASLocked(ue, plain)
	if err != nil {
		ue.Unlock()
		return err
	}
	ue.DLNASCount.Increment()
	ue.PendingBearerTransactions[key] = tx
	ue.LastDownlinkNASMessage = "Modify EPS Bearer Context Request"
	mmeID := ue.MMEUES1APID
	imsi := ue.IMSI
	assignedEBI := active.AssignedEBI
	linkedEBI := active.LinkedEBI
	qci := next.QCI
	bearerQoS := append([]byte(nil), next.BearerQoS...)
	tft := append([]byte(nil), next.TFT...)
	ue.Unlock()

	fields := []zap.Field{
		zap.String("imsi", imsi),
		zap.Uint32("mme_ue_id", mmeID),
		zap.Uint8("assigned_ebi", assignedEBI),
		zap.Uint8("linked_ebi", linkedEBI),
		zap.Uint8("pti", req.ProcedureTransactionID),
		zap.Uint8("qci", qci),
		zap.String("tft_hex", hex.EncodeToString(tft)),
	}
	fields = append(fields, dedicatedBearerQoSLogFields(bearerQoS, qci)...)
	s.log.Debug("s1ap: Bearer Resource Modification NAS Modify sent", fields...)

	if err := s.SendDownlinkNAS(mmeID, protected); err != nil {
		ue.Lock()
		delete(ue.PendingBearerTransactions, key)
		ue.Unlock()
		return err
	}
	return nil
}

func (s *Server) HandleDeleteBearerRequest(peer string, req *gtpv2.DeleteBearerRequest) {
	ue, _ := s.findUEByLocalS11TEID(req.TEID, 0)
	if ue == nil {
		s.sendDeleteBearerResponse(peer, req.TEID, req.SeqNum, gtpv2.CauseContextNotFound, req.EBIs)
		return
	}
	key := bearerTxKey(peer, gtpv2.MsgDeleteBearerRequest, req.TEID, req.SeqNum)
	ue.Lock()
	if ue.PendingBearerTransactions == nil {
		ue.PendingBearerTransactions = map[string]*uecontext.DedicatedBearerTransaction{}
	}
	if _, exists := ue.PendingBearerTransactions[key]; exists {
		ue.Unlock()
		return
	}
	tx := &uecontext.DedicatedBearerTransaction{
		ID:          fmt.Sprintf("dbr-%d-%08x-%06x", ue.MMEUES1APID, req.TEID, req.SeqNum),
		Kind:        bearerTxDelete,
		PeerAddress: peer,
		LocalTEID:   req.TEID,
		SequenceNum: req.SeqNum,
		EBIs:        append([]uint8(nil), req.EBIs...),
		Bearers:     map[uint8]*uecontext.DedicatedBearerContext{},
		State:       "deleting",
		CreatedAt:   time.Now(),
	}
	mmeID := ue.MMEUES1APID
	var nasToSend [][]byte
	for _, ebi := range req.EBIs {
		active := ue.DedicatedBearers[ebi]
		if active == nil {
			continue
		}
		copyBearer := *active
		copyBearer.TransactionID = tx.ID
		copyBearer.PTI = 0
		copyBearer.State = "delete-pending"
		tx.Bearers[ebi] = &copyBearer
		plain := esm.EncodeDeactivateEPSBearerContextRequest(ebi, 0, esm.ESMCauseRegularDeactivation)
		protected, _, err := protectNASLocked(ue, plain)
		if err != nil {
			ue.Unlock()
			s.sendDeleteBearerResponse(peer, req.TEID, req.SeqNum, gtpv2.CauseRequestDenied, req.EBIs)
			return
		}
		ue.DLNASCount.Increment()
		nasToSend = append(nasToSend, protected)
		s.log.Info("s1ap: Delete Bearer NAS Deactivate sent",
			zap.String("imsi", ue.IMSI),
			zap.Uint32("mme_ue_id", mmeID),
			zap.Uint32("sequence_number", req.SeqNum),
			zap.Uint8("assigned_ebi", ebi))
	}
	if len(tx.Bearers) == 0 {
		ue.Unlock()
		s.sendDeleteBearerResponse(peer, req.TEID, req.SeqNum, gtpv2.CauseRequestAccepted, req.EBIs)
		return
	}
	ue.PendingBearerTransactions[key] = tx
	ue.LastDownlinkNASMessage = "Deactivate EPS Bearer Context Request"
	ue.Unlock()
	for _, protected := range nasToSend {
		if err := s.SendDownlinkNAS(mmeID, protected); err != nil {
			s.sendDeleteBearerResponse(peer, req.TEID, req.SeqNum, gtpv2.CauseRequestDenied, req.EBIs)
			return
		}
	}
}

func (s *Server) handleDedicatedBearerNASResponse(ue *uecontext.Context, resp *esm.BearerProcedureResponse, log *zap.Logger) {
	ue.Lock()
	defer ue.Unlock()
	key, tx, ok := findPendingBearerTransactionForResponseLocked(ue, resp)
	if ok {
		proc := tx.Bearers[resp.EPSBearerID]
		switch resp.MessageType {
		case esm.MsgActivateDedicatedEPSBearerContextAccept:
			res, hasReservation := ue.EBIReservations[resp.EPSBearerID]
			if !hasReservation || res.TransactionID != tx.ID || proc.TransactionID != tx.ID {
				log.Warn("s1ap: stale Activate Dedicated EPS Bearer Context Accept ignored",
					zap.Uint8("assigned_ebi", resp.EPSBearerID),
					zap.String("transaction_id", tx.ID))
				return
			}
			proc.NASAccepted = true
			log.Debug("s1ap: Activate Dedicated EPS Bearer Context Accept received",
				zap.Uint8("assigned_ebi", resp.EPSBearerID),
				zap.Uint8("linked_ebi", proc.LinkedEBI),
				zap.Uint8("pti", resp.ProcedureTransactionID))
			s.maybeCompleteCreateBearerLocked(ue, key, tx)
		case esm.MsgActivateDedicatedEPSBearerContextReject:
			res, hasReservation := ue.EBIReservations[resp.EPSBearerID]
			if !hasReservation || res.TransactionID != tx.ID || proc.TransactionID != tx.ID {
				log.Warn("s1ap: stale Activate Dedicated EPS Bearer Context Reject ignored",
					zap.Uint8("assigned_ebi", resp.EPSBearerID),
					zap.String("transaction_id", tx.ID))
				return
			}
			proc.NASRejected = true
			proc.FailureCause = resp.Cause
			s.maybeCompleteCreateBearerLocked(ue, key, tx)
		case esm.MsgModifyEPSBearerContextAccept:
			if tx.Kind == bearerTxUpdate {
				proc.NASAccepted = true
				s.maybeCompleteUpdateBearerLocked(ue, key, tx)
			} else {
				ue.DedicatedBearers[resp.EPSBearerID] = proc
				delete(ue.PendingBearerTransactions, key)
				log.Debug("s1ap: Bearer Resource Modification accepted",
					zap.Uint8("assigned_ebi", resp.EPSBearerID),
					zap.Uint8("pti", resp.ProcedureTransactionID))
			}
		case esm.MsgModifyEPSBearerContextReject:
			if tx.Kind == bearerTxUpdate {
				delete(ue.PendingERABProcedures, tx.ID)
				delete(ue.PendingBearerTransactions, key)
				go s.sendUpdateBearerResponse(tx.PeerAddress, tx.LocalTEID, tx.SequenceNum, gtpv2.CauseUERefuses, updateBearersFromTx(tx))
			} else {
				delete(ue.PendingBearerTransactions, key)
				log.Debug("s1ap: Bearer Resource Modification rejected",
					zap.Uint8("assigned_ebi", resp.EPSBearerID),
					zap.Uint8("pti", resp.ProcedureTransactionID),
					zap.Uint8("esm_cause", resp.Cause))
			}
		case esm.MsgDeactivateEPSBearerContextAccept:
			proc.NASAccepted = true
			if !allDeleteBearerNASAccepted(tx) {
				return
			}
			if shouldReleaseDedicatedBearersOverS1Locked(ue, tx) {
				items := make([]ERABReleaseItem, 0, len(tx.Bearers))
				for _, ebi := range sortedTxBearerEBIs(tx) {
					items = append(items, ERABReleaseItem{
						EBI:        ebi,
						CauseGroup: ies.CauseGroupNAS,
						Cause:      ies.CauseNASNormalRelease,
					})
				}
				tx.State = "waiting_erab_release"
				go func(mmeUEID uint32, items []ERABReleaseItem, txID string) {
					if err := s.SendERABReleaseRequestTracked(mmeUEID, items, "dedicated_delete_bearer", txID); err != nil {
						s.log.Warn("s1ap: E-RAB Release Request for Delete Bearer failed",
							zap.Uint32("mme_ue_id", mmeUEID),
							zap.String("transaction_id", txID),
							zap.Error(err))
						s.failDeleteBearerAfterERABReleaseError(mmeUEID, txID)
					}
				}(ue.MMEUES1APID, items, tx.ID)
				return
			}
			for ebi := range tx.Bearers {
				delete(ue.DedicatedBearers, ebi)
			}
			delete(ue.PendingBearerTransactions, key)
			go s.sendDeleteBearerResponse(tx.PeerAddress, tx.LocalTEID, tx.SequenceNum, gtpv2.CauseRequestAccepted, deleteEBIsFromTx(tx, 0))
		}
		return
	}
	if resp.MessageType == esm.MsgModifyEPSBearerContextAccept || resp.MessageType == esm.MsgModifyEPSBearerContextReject {
		if bearer := ue.DedicatedBearers[resp.EPSBearerID]; bearer != nil {
			log.Debug("s1ap: stale dedicated bearer NAS modify response ignored",
				zap.Uint8("assigned_ebi", resp.EPSBearerID),
				zap.Uint8("message_type", resp.MessageType),
				zap.String("bearer_state", bearer.State),
				zap.String("last_transaction_id", bearer.TransactionID))
			return
		}
	}
	log.Warn("s1ap: bearer NAS response for unknown EBI",
		zap.Uint8("assigned_ebi", resp.EPSBearerID),
		zap.Uint8("message_type", resp.MessageType),
		zap.Strings("pending_bearer_transactions", pendingBearerTransactionSummariesLocked(ue)))
}

func (s *Server) completeDedicatedERABSetupForBearer(ue *uecontext.Context, result ERABSetupResult, log *zap.Logger) bool {
	ue.Lock()
	defer ue.Unlock()
	for key, tx := range ue.PendingBearerTransactions {
		if tx.Kind != bearerTxCreate {
			continue
		}
		proc := tx.Bearers[result.EBI]
		if proc == nil {
			continue
		}
		res, ok := ue.EBIReservations[result.EBI]
		if !ok || res.TransactionID != tx.ID {
			log.Warn("s1ap: stale dedicated E-RAB Setup Response ignored",
				zap.Uint8("assigned_ebi", result.EBI),
				zap.String("transaction_id", tx.ID))
			return true
		}
		proc.ENBS1UTEID = result.ENBS1UTEID
		proc.ENBS1UIP = append(net.IP(nil), result.ENBS1UIPv4...)
		proc.ERABEstablished = result.Success
		proc.ERABFailed = !result.Success
		log.Debug("s1ap: dedicated E-RAB Setup Response item",
			zap.Uint8("assigned_ebi", result.EBI),
			zap.Uint8("qci", proc.QCI),
			zap.Uint32("sgw_s1u_teid", proc.SGWS1UTEID),
			zap.Uint32("enb_s1u_teid", result.ENBS1UTEID),
			zap.Bool("success", result.Success),
			zap.Uint32("cause", result.Cause))
		s.maybeCompleteCreateBearerLocked(ue, key, tx)
		return true
	}
	return false
}

func (s *Server) maybeCompleteCreateBearerLocked(ue *uecontext.Context, key string, tx *uecontext.DedicatedBearerTransaction) {
	if tx.Kind != bearerTxCreate {
		return
	}
	if tx.CreateState == uecontext.CreateBearerCleaningUpERAB {
		return
	}
	allDone := true
	for _, proc := range tx.Bearers {
		if proc.NASRejected || proc.ERABFailed {
			continue
		}
		if !(proc.NASAccepted && proc.ERABEstablished) {
			allDone = false
			break
		}
	}
	if !allDone {
		return
	}
	releaseItems := failedCreateBearerReleaseItems(tx)
	if len(releaseItems) > 0 && hasActiveS1BindingLocked(ue) {
		tx.CreateState = uecontext.CreateBearerCleaningUpERAB
		tx.State = string(tx.CreateState)
		mmeUEID := ue.MMEUES1APID
		transactionID := tx.ID
		go func(items []ERABReleaseItem) {
			if err := s.SendERABReleaseRequestTracked(mmeUEID, items, "dedicated_create_bearer_cleanup", transactionID); err != nil {
				s.log.Warn("s1ap: E-RAB Release Request for failed Create Bearer cleanup failed",
					zap.Uint32("mme_ue_id", mmeUEID),
					zap.String("transaction_id", transactionID),
					zap.Error(err))
				s.failCreateBearerCleanupAfterERABReleaseError(mmeUEID, transactionID)
			}
		}(releaseItems)
		return
	}
	s.finalizeCreateBearerTransactionLocked(ue, key, tx)
}

func (s *Server) failCreateBearerTransaction(ue *uecontext.Context, key string, cause uint8) {
	ue.Lock()
	tx := ue.PendingBearerTransactions[key]
	if tx != nil {
		delete(ue.PendingERABProcedures, tx.ID)
		ue.StopTimer(uecontext.TimerCreateBearerPrefix + key)
		delete(ue.PendingBearerTransactions, key)
		releaseCreateBearerReservationsLocked(ue, tx)
		tx.CreateState = uecontext.CreateBearerFailed
		tx.State = string(tx.CreateState)
	}
	ue.Unlock()
	if tx != nil {
		s.sendFinalCreateBearerResponse(tx, cause, createBearersFromTx(tx), time.Since(tx.CreatedAt), 0, len(tx.Bearers))
	}
}

func (s *Server) failUpdateBearerTransaction(ue *uecontext.Context, key string, cause uint8) {
	ue.Lock()
	tx := ue.PendingBearerTransactions[key]
	if tx != nil {
		ue.StopTimer(uecontext.TimerUpdateBearerPrefix + key)
		delete(ue.PendingERABProcedures, tx.ID)
		delete(ue.PendingBearerTransactions, key)
	}
	ue.Unlock()
	if tx != nil {
		s.sendUpdateBearerResponse(tx.PeerAddress, tx.LocalTEID, tx.SequenceNum, cause, updateBearersFromTx(tx))
	}
}

func (s *Server) failUpdateBearerTransactionByID(ue *uecontext.Context, txID string, cause uint8) {
	ue.Lock()
	key, tx := findPendingBearerTransactionByIDLocked(ue, txID)
	if tx != nil {
		ue.StopTimer(uecontext.TimerUpdateBearerPrefix + key)
		delete(ue.PendingERABProcedures, tx.ID)
		delete(ue.PendingBearerTransactions, key)
	}
	ue.Unlock()
	if tx != nil {
		s.sendUpdateBearerResponse(tx.PeerAddress, tx.LocalTEID, tx.SequenceNum, cause, updateBearersFromTx(tx))
	}
}

func (s *Server) maybeCompleteUpdateBearerLocked(ue *uecontext.Context, key string, tx *uecontext.DedicatedBearerTransaction) {
	if tx == nil || tx.Kind != bearerTxUpdate {
		return
	}
	waitingForERAB := ue.PendingERABProcedures[tx.ID] != nil
	for _, proc := range tx.Bearers {
		if proc == nil {
			continue
		}
		if proc.ERABFailed {
			ue.StopTimer(uecontext.TimerUpdateBearerPrefix + key)
			delete(ue.PendingERABProcedures, tx.ID)
			delete(ue.PendingBearerTransactions, key)
			go s.sendUpdateBearerResponse(tx.PeerAddress, tx.LocalTEID, tx.SequenceNum, gtpv2.CauseRequestRejected, updateBearersFromTx(tx))
			return
		}
		if !proc.NASAccepted {
			return
		}
		if waitingForERAB && !proc.ERABEstablished {
			return
		}
	}
	for ebi, proc := range tx.Bearers {
		ue.DedicatedBearers[ebi] = proc
	}
	ue.StopTimer(uecontext.TimerUpdateBearerPrefix + key)
	delete(ue.PendingERABProcedures, tx.ID)
	delete(ue.PendingBearerTransactions, key)
	go s.sendUpdateBearerResponse(tx.PeerAddress, tx.LocalTEID, tx.SequenceNum, gtpv2.CauseRequestAccepted, updateBearersFromTx(tx))
}

func (s *Server) onUpdateBearerTimeout(ue *uecontext.Context, key string) {
	ue.Lock()
	tx := ue.PendingBearerTransactions[key]
	if tx == nil || tx.Kind != bearerTxUpdate {
		ue.Unlock()
		return
	}
	ue.StopTimer(uecontext.TimerUpdateBearerPrefix + key)
	delete(ue.PendingERABProcedures, tx.ID)
	delete(ue.PendingBearerTransactions, key)
	ue.Unlock()
	s.log.Warn("s11: pending Update Bearer timed out",
		zap.String("transaction_id", tx.ID),
		zap.Duration("duration", time.Since(tx.CreatedAt)))
	s.sendUpdateBearerResponse(tx.PeerAddress, tx.LocalTEID, tx.SequenceNum, gtpv2.CauseRequestDenied, updateBearersFromTx(tx))
}

func (s *Server) finalizeCreateBearerTransactionLocked(ue *uecontext.Context, key string, tx *uecontext.DedicatedBearerTransaction) {
	cause, successful, failed := evaluateCreateBearerOutcome(tx)
	bearers := createBearersFromTx(tx)
	for _, proc := range tx.Bearers {
		if proc.NASAccepted && proc.ERABEstablished {
			proc.State = "active"
			ue.DedicatedBearers[proc.AssignedEBI] = proc
		}
		delete(ue.EBIReservations, proc.AssignedEBI)
	}
	delete(ue.PendingERABProcedures, tx.ID)
	ue.StopTimer(uecontext.TimerCreateBearerPrefix + key)
	delete(ue.PendingBearerTransactions, key)
	if successful > 0 {
		tx.CreateState = uecontext.CreateBearerCompleted
	} else {
		tx.CreateState = uecontext.CreateBearerFailed
	}
	tx.State = string(tx.CreateState)
	duration := time.Since(tx.CreatedAt)
	go s.sendFinalCreateBearerResponse(tx, cause, bearers, duration, successful, failed)
}

func evaluateCreateBearerOutcome(tx *uecontext.DedicatedBearerTransaction) (uint8, int, int) {
	successful := 0
	failed := 0
	anyNASReject := false
	anyFailure := false
	for _, proc := range tx.Bearers {
		if proc.NASAccepted && proc.ERABEstablished {
			successful++
			continue
		}
		failed++
		if proc.NASRejected {
			anyNASReject = true
		}
		if proc.NASRejected || proc.ERABFailed {
			anyFailure = true
		}
	}
	switch {
	case successful == len(tx.Bearers):
		return gtpv2.CauseRequestAccepted, successful, failed
	case successful > 0:
		return gtpv2.CauseRequestAcceptedPartially, successful, failed
	case anyNASReject:
		return gtpv2.CauseUERefuses, successful, failed
	case anyFailure:
		return gtpv2.CauseRequestRejected, successful, failed
	default:
		return gtpv2.CauseRequestDenied, successful, failed
	}
}

func (s *Server) sendFinalCreateBearerResponse(tx *uecontext.DedicatedBearerTransaction, cause uint8, bearers []gtpv2.CreateBearerBearer, duration time.Duration, successful int, failed int) {
	if !tx.TryMarkResponseSent() {
		return
	}
	responseTEID := tx.LocalTEID
	var meta *gtpv2.CreateBearerResponseMeta
	if tx != nil && tx.LinkedEBI != 0 {
		if ue, pdn := s.findUEByLocalS11TEID(tx.LocalTEID, tx.LinkedEBI); ue != nil && pdn != nil {
			responseTEID = pdn.SGWC_TEID
			meta = createBearerResponseMetaFromUE(ue, s.buildPLMN())
		}
	}
	s.completedCreateBearerResponses.Store(
		bearerTxKey(tx.PeerAddress, gtpv2.MsgCreateBearerRequest, tx.LocalTEID, tx.SequenceNum),
		&cachedCreateBearerResponse{
			Peer:    tx.PeerAddress,
			TEID:    responseTEID,
			Seq:     tx.SequenceNum,
			Cause:   cause,
			Bearers: append([]gtpv2.CreateBearerBearer(nil), bearers...),
			Meta:    meta,
		},
	)
	if !s.sendCreateBearerResponseWithOptionalPiggyback(tx, cause, bearers) {
		s.sendCreateBearerResponseWithMeta(tx.PeerAddress, responseTEID, tx.SequenceNum, cause, bearers, meta)
	}
	s.advanceLinkedDefaultBearerAfterCreateBearerResponse(tx, cause)
	s.log.Debug("s11: Create Bearer transaction completed",
		zap.String("transaction_id", tx.ID),
		zap.Duration("duration", duration),
		zap.Int("bearer_count", len(bearers)),
		zap.Int("successful_bearers", successful),
		zap.Int("failed_bearers", failed),
		zap.Uint8("response_cause", cause),
		zap.Bool("response_sent", true))
}

func (s *Server) sendCreateBearerResponseWithOptionalPiggyback(tx *uecontext.DedicatedBearerTransaction, cause uint8, bearers []gtpv2.CreateBearerBearer) bool {
	responder, ok := s.s11.(S11BearerResponder)
	if !ok || tx == nil || tx.LinkedEBI == 0 {
		return false
	}
	if cause != gtpv2.CauseRequestAccepted && cause != gtpv2.CauseRequestAcceptedPartially {
		return false
	}
	ue, pdn := s.findUEByLocalS11TEID(tx.LocalTEID, tx.LinkedEBI)
	if ue == nil || pdn == nil {
		return false
	}

	ue.Lock()
	if !pdn.NASAccepted || !pdn.ERABEstablished || pdn.ModifyBearerSent || pdn.ModifyBearerAccepted || pdn.ModifyBearerFailed {
		ue.Unlock()
		return false
	}
	imsi := ue.IMSI
	mmeUEID := ue.MMEUES1APID
	responseTEID := pdn.SGWC_TEID
	var meta *gtpv2.CreateBearerResponseMeta
	if ue.TAI != nil && ue.ECGIECI != 0 {
		meta = &gtpv2.CreateBearerResponseMeta{
			IncludeULI: true,
			ULIPLMN:    s.buildPLMN(),
			ULITAC:     ue.TAI.TAC,
			ULIECI:     ue.ECGIECI,
		}
	}
	apn := pdn.APN
	ue.Unlock()

	if err := responder.SendCreateBearerResponse(tx.PeerAddress, responseTEID, tx.SequenceNum, cause, bearers, meta); err != nil {
		s.log.Warn("s1ap: Create Bearer Response send failed before IMS Modify Bearer Request",
			zap.String("transaction_id", tx.ID),
			zap.String("imsi", imsi),
			zap.String("apn", apn),
			zap.Uint8("linked_ebi", tx.LinkedEBI),
			zap.Error(err))
		return false
	}
	s.log.Debug("s1ap: Create Bearer Response sent; standalone IMS Modify Bearer remains deferred",
		zap.String("transaction_id", tx.ID),
		zap.String("imsi", imsi),
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.String("apn", apn),
		zap.Uint8("linked_ebi", tx.LinkedEBI))
	return true
}

func (s *Server) advanceLinkedDefaultBearerAfterCreateBearerResponse(tx *uecontext.DedicatedBearerTransaction, cause uint8) {
	if tx == nil || tx.LinkedEBI == 0 {
		return
	}
	ue, _ := s.findUEByLocalS11TEID(tx.LocalTEID, tx.LinkedEBI)
	if ue == nil {
		return
	}
	s.log.Debug("s1ap: evaluating linked default bearer after Create Bearer response",
		zap.String("transaction_id", tx.ID),
		zap.String("imsi", ue.IMSI),
		zap.Uint32("mme_ue_id", ue.MMEUES1APID),
		zap.Uint8("linked_ebi", tx.LinkedEBI),
		zap.Uint8("create_bearer_cause", cause),
		zap.String("trigger", "create_bearer_response_sent"))
	s.maybeAdvanceDefaultBearer(ue, tx.LinkedEBI, "create-bearer-response-sent", s.log)
}

func (s *Server) startCreateBearerTimeout(ue *uecontext.Context, key string) {
	ue.Lock()
	timerName := uecontext.TimerCreateBearerPrefix + key
	ue.StartTimer(timerName, createBearerOverallTimeout, func() {
		s.onCreateBearerTimeout(ue, key)
	})
	ue.Unlock()
}

func (s *Server) onCreateBearerTimeout(ue *uecontext.Context, key string) {
	ue.Lock()
	tx := ue.PendingBearerTransactions[key]
	if tx == nil || tx.Kind != bearerTxCreate || isCreateBearerTerminal(tx.CreateState) {
		ue.Unlock()
		return
	}
	ue.StopTimer(uecontext.TimerCreateBearerPrefix + key)
	delete(ue.PendingERABProcedures, tx.ID)
	delete(ue.PendingBearerTransactions, key)
	releaseCreateBearerReservationsLocked(ue, tx)
	tx.CreateState = uecontext.CreateBearerTimedOut
	tx.State = string(tx.CreateState)
	duration := time.Since(tx.CreatedAt)
	pagingAttempts := tx.PagingAttempts
	bearers := createBearersFromTx(tx)
	ue.Unlock()
	s.log.Warn("s11: pending Create Bearer timed out",
		zap.String("transaction_id", tx.ID),
		zap.String("state", string(tx.CreateState)),
		zap.Duration("duration", duration),
		zap.Uint8("paging_attempts", pagingAttempts),
		zap.Bool("rollback_complete", true))
	s.sendFinalCreateBearerResponse(tx, gtpv2.CauseRequestDenied, bearers, duration, 0, len(bearers))
}

func (s *Server) findUEByLocalS11TEID(teid uint32, linkedEBI uint8) (*uecontext.Context, *uecontext.PDNContext) {
	var foundUE *uecontext.Context
	var foundPDN *uecontext.PDNContext
	s.ueManager.Range(func(ue *uecontext.Context) bool {
		ue.Lock()
		defer ue.Unlock()
		if pdn := ue.PendingPDN; pdn != nil {
			if pdn.LocalS11TEID == teid && (linkedEBI == 0 || pdn.DefaultEBI == linkedEBI) {
				foundUE = ue
				foundPDN = pdn
				return false
			}
		}
		for _, pdn := range ue.PDNs {
			if pdn.LocalS11TEID == teid && (linkedEBI == 0 || pdn.DefaultEBI == linkedEBI) {
				foundUE = ue
				foundPDN = pdn
				return false
			}
		}
		if ue.LocalS11TEID == teid && (linkedEBI == 0 || ue.DefaultEBI == linkedEBI) {
			foundUE = ue
			foundPDN = &uecontext.PDNContext{DefaultEBI: ue.DefaultEBI}
			return false
		}
		return true
	})
	return foundUE, foundPDN
}

func assignDedicatedEBIsLocked(ue *uecontext.Context, bearers []gtpv2.CreateBearerBearer) error {
	used := map[uint8]bool{}
	if ue.DefaultEBI != 0 {
		used[ue.DefaultEBI] = true
	}
	for _, pdn := range ue.PDNs {
		if pdn.DefaultEBI != 0 {
			used[pdn.DefaultEBI] = true
		}
	}
	if ue.PendingPDN != nil && ue.PendingPDN.DefaultEBI != 0 {
		used[ue.PendingPDN.DefaultEBI] = true
	}
	for ebi := range ue.DedicatedBearers {
		used[ebi] = true
	}
	for ebi := range ue.EBIReservations {
		used[ebi] = true
	}
	for _, tx := range ue.PendingBearerTransactions {
		for ebi := range tx.Bearers {
			used[ebi] = true
		}
	}
	return gtpv2.AssignRequestedBearerIDs(bearers, used)
}

func hasActiveS1BindingLocked(ue *uecontext.Context) bool {
	return ue.ECMState == emm.ECMConnected &&
		ue.S1BindingState == uecontext.S1BindingActive &&
		ue.ENBGlobalID != "" &&
		ue.ENBS1APID != 0
}

func shouldReleaseDedicatedBearersOverS1Locked(ue *uecontext.Context, tx *uecontext.DedicatedBearerTransaction) bool {
	if !hasActiveS1BindingLocked(ue) {
		return false
	}
	for _, proc := range tx.Bearers {
		if proc == nil {
			continue
		}
		if proc.ERABEstablished || proc.ENBS1UTEID != 0 || len(proc.ENBS1UIP) != 0 {
			return true
		}
	}
	return false
}

func allDeleteBearerNASAccepted(tx *uecontext.DedicatedBearerTransaction) bool {
	if tx == nil {
		return false
	}
	for _, proc := range tx.Bearers {
		if proc == nil || !proc.NASAccepted {
			return false
		}
	}
	return true
}

func sortedTxBearerEBIs(tx *uecontext.DedicatedBearerTransaction) []uint8 {
	out := make([]uint8, 0, len(tx.Bearers))
	for ebi := range tx.Bearers {
		out = append(out, ebi)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func findPendingBearerTransactionByIDLocked(ue *uecontext.Context, txID string) (string, *uecontext.DedicatedBearerTransaction) {
	for key, tx := range ue.PendingBearerTransactions {
		if tx != nil && tx.ID == txID {
			return key, tx
		}
	}
	return "", nil
}

func (s *Server) failDeleteBearerAfterERABReleaseError(mmeUEID uint32, txID string) {
	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		return
	}
	ue.Lock()
	key, tx := findPendingBearerTransactionByIDLocked(ue, txID)
	if tx == nil {
		ue.Unlock()
		return
	}
	delete(ue.PendingERABProcedures, txID)
	delete(ue.PendingBearerTransactions, key)
	ue.Unlock()
	s.sendDeleteBearerResponse(tx.PeerAddress, tx.LocalTEID, tx.SequenceNum, gtpv2.CauseRequestDenied, deleteEBIsFromTx(tx, 0))
}

func linkedBearerActiveLocked(ue *uecontext.Context, linkedEBI uint8) bool {
	if linkedEBI == 0 {
		return true
	}
	if ue.DefaultEBI == linkedEBI {
		return true
	}
	for _, pdn := range ue.PDNs {
		if pdn.DefaultEBI == linkedEBI && !pdnDisconnectInProgress(pdn) {
			return true
		}
	}
	return false
}

func linkedBearerReadyLocked(ue *uecontext.Context, linkedEBI uint8) bool {
	if linkedEBI == 0 {
		return true
	}
	for _, pdn := range ue.PDNs {
		if pdn.DefaultEBI != linkedEBI {
			continue
		}
		if pdnDisconnectInProgress(pdn) {
			return false
		}
		return pdn.NASAccepted && pdn.ERABEstablished && !pdn.ModifyBearerFailed
	}
	if ue.DefaultEBI == linkedEBI {
		return true
	}
	return false
}

func (s *Server) resumePendingCreateBearersForLinkedEBI(ue *uecontext.Context, linkedEBI uint8, trigger string) {
	ue.Lock()
	var keys []string
	imsi := ue.IMSI
	mmeID := ue.MMEUES1APID
	for key, tx := range ue.PendingBearerTransactions {
		if tx.Kind != bearerTxCreate || tx.LinkedEBI != linkedEBI || tx.CreateState != uecontext.CreateBearerWaitingForLink {
			continue
		}
		keys = append(keys, key)
	}
	ue.Unlock()
	for _, key := range keys {
		s.log.Info("s1ap: resuming pending Create Bearer after linked bearer became ready",
			zap.String("imsi", imsi),
			zap.Uint32("mme_ue_id", mmeID),
			zap.String("transaction_id", txIDForLog(ue, key)),
			zap.Uint8("linked_ebi", linkedEBI),
			zap.String("trigger", trigger))
		s.resumeCreateBearerTransaction(ue, key)
	}
}

func (s *Server) failPendingCreateBearersForLinkedEBI(ue *uecontext.Context, linkedEBI uint8, cause uint8, pendingAction string) {
	ue.Lock()
	var keys []string
	imsi := ue.IMSI
	mmeID := ue.MMEUES1APID
	for key, tx := range ue.PendingBearerTransactions {
		if tx.Kind != bearerTxCreate || tx.LinkedEBI != linkedEBI || isCreateBearerTerminal(tx.CreateState) {
			continue
		}
		keys = append(keys, key)
	}
	ue.Unlock()
	for _, key := range keys {
		s.log.Warn("s1ap: failing pending Create Bearer after linked bearer failure",
			zap.String("imsi", imsi),
			zap.Uint32("mme_ue_id", mmeID),
			zap.String("transaction_id", txIDForLog(ue, key)),
			zap.Uint8("linked_ebi", linkedEBI),
			zap.Uint8("mbr_cause", cause),
			zap.String("pending_action", pendingAction))
		s.failCreateBearerTransaction(ue, key, cause)
	}
}

func (s *Server) failCreateBearersWaitingForLinkedBearer(ue *uecontext.Context, cause uint8, pendingAction string) {
	ue.Lock()
	var keys []string
	imsi := ue.IMSI
	mmeID := ue.MMEUES1APID
	for key, tx := range ue.PendingBearerTransactions {
		if tx.Kind != bearerTxCreate || tx.CreateState != uecontext.CreateBearerWaitingForLink {
			continue
		}
		keys = append(keys, key)
	}
	ue.Unlock()
	for _, key := range keys {
		s.log.Warn("s1ap: failing pending Create Bearer after linked bearer lost UE access",
			zap.String("imsi", imsi),
			zap.Uint32("mme_ue_id", mmeID),
			zap.String("transaction_id", txIDForLog(ue, key)),
			zap.Uint8("cause", cause),
			zap.String("pending_action", pendingAction))
		s.failCreateBearerTransaction(ue, key, cause)
	}
}

func releaseCreateBearerReservationsLocked(ue *uecontext.Context, tx *uecontext.DedicatedBearerTransaction) {
	if tx == nil {
		return
	}
	for ebi, res := range ue.EBIReservations {
		if res.TransactionID == tx.ID {
			delete(ue.EBIReservations, ebi)
		}
	}
}

func failedCreateBearerReleaseItems(tx *uecontext.DedicatedBearerTransaction) []ERABReleaseItem {
	items := make([]ERABReleaseItem, 0, len(tx.Bearers))
	for _, proc := range tx.Bearers {
		if proc == nil {
			continue
		}
		if proc.NASAccepted && proc.ERABEstablished {
			continue
		}
		if !proc.ERABEstablished && proc.ENBS1UTEID == 0 && len(proc.ENBS1UIP) == 0 {
			continue
		}
		items = append(items, ERABReleaseItem{
			EBI:        proc.AssignedEBI,
			CauseGroup: ies.CauseGroupNAS,
			Cause:      ies.CauseNASNormalRelease,
		})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].EBI < items[j].EBI })
	return items
}

func (s *Server) failCreateBearerCleanupAfterERABReleaseError(mmeUEID uint32, txID string) {
	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		return
	}
	ue.Lock()
	key, tx := findPendingBearerTransactionByIDLocked(ue, txID)
	if tx == nil {
		ue.Unlock()
		return
	}
	for _, proc := range tx.Bearers {
		if proc == nil {
			continue
		}
		proc.ERABEstablished = false
		proc.ENBS1UTEID = 0
		proc.ENBS1UIP = nil
	}
	s.finalizeCreateBearerTransactionLocked(ue, key, tx)
	ue.Unlock()
}

func isCreateBearerTerminal(state uecontext.CreateBearerState) bool {
	switch state {
	case uecontext.CreateBearerCompleted, uecontext.CreateBearerFailed, uecontext.CreateBearerTimedOut:
		return true
	default:
		return false
	}
}

func createBearerCanSupersedeTransport(state uecontext.CreateBearerState) bool {
	return !isCreateBearerTerminal(state)
}

func refreshEquivalentCreateBearerTransport(tx *uecontext.DedicatedBearerTransaction, peer string, req *gtpv2.CreateBearerRequest) {
	if tx == nil || req == nil {
		return
	}
	tx.PeerAddress = peer
	tx.LocalTEID = req.TEID
	tx.SequenceNum = req.SeqNum
	for i := range req.Bearers {
		if i >= len(tx.EBIs) {
			break
		}
		if proc := tx.Bearers[tx.EBIs[i]]; proc != nil {
			proc.SGWS1UTEID = req.Bearers[i].SGWS1UTEID
			proc.SGWS1UIP = append(net.IP(nil), req.Bearers[i].SGWS1UIP...)
		}
	}
}

func createBearerFingerprint(req *gtpv2.CreateBearerRequest) string {
	parts := make([]string, 0, len(req.Bearers))
	for _, b := range req.Bearers {
		h := sha256.Sum256(b.TFT)
		parts = append(parts, fmt.Sprintf("qci=%d|arp=%d|tft=%x", b.QCI, b.ARP, h[:]))
	}
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(fmt.Sprintf("linked=%d|count=%d|%s", req.LinkedEBI, len(req.Bearers), strings.Join(parts, ";"))))
	return hex.EncodeToString(sum[:])
}

func txIDForLog(ue *uecontext.Context, key string) string {
	ue.Lock()
	defer ue.Unlock()
	if tx := ue.PendingBearerTransactions[key]; tx != nil {
		return tx.ID
	}
	return ""
}

func createBearersFromTx(tx *uecontext.DedicatedBearerTransaction) []gtpv2.CreateBearerBearer {
	out := make([]gtpv2.CreateBearerBearer, 0, len(tx.Bearers))
	for _, proc := range tx.Bearers {
		bearerCause := gtpv2.CauseRequestRejected
		if proc.NASAccepted && proc.ERABEstablished {
			bearerCause = gtpv2.CauseRequestAccepted
		}
		out = append(out, gtpv2.CreateBearerBearer{
			RequestedEBI: proc.RequestedEBI,
			AssignedEBI:  proc.AssignedEBI,
			EBI:          proc.AssignedEBI,
			Cause:        bearerCause,
			QCI:          proc.QCI,
			ARP:          proc.ARP,
			BearerQoS:    append([]byte(nil), proc.BearerQoS...),
			TFT:          append([]byte(nil), proc.TFT...),
			SGWS1UTEID:   proc.SGWS1UTEID,
			SGWS1UIP:     append([]byte(nil), proc.SGWS1UIP...),
			ENBS1UTEID:   proc.ENBS1UTEID,
			ENBS1UIP:     append([]byte(nil), proc.ENBS1UIP...),
		})
	}
	return out
}

func updateBearersFromTx(tx *uecontext.DedicatedBearerTransaction) []gtpv2.UpdateBearerBearer {
	out := make([]gtpv2.UpdateBearerBearer, 0, len(tx.Bearers))
	for _, proc := range tx.Bearers {
		out = append(out, gtpv2.UpdateBearerBearer{
			EBI:       proc.AssignedEBI,
			QCI:       proc.QCI,
			ARP:       proc.ARP,
			BearerQoS: append([]byte(nil), proc.BearerQoS...),
			TFT:       append([]byte(nil), proc.TFT...),
			PCO:       append([]byte(nil), proc.PCO...),
		})
	}
	return out
}

func deleteEBIsFromTx(tx *uecontext.DedicatedBearerTransaction, fallback uint8) []uint8 {
	if len(tx.EBIs) > 0 {
		return append([]uint8(nil), tx.EBIs...)
	}
	out := make([]uint8, 0, len(tx.Bearers)+1)
	for ebi := range tx.Bearers {
		out = append(out, ebi)
	}
	if len(out) == 0 && fallback != 0 {
		out = append(out, fallback)
	}
	return out
}

func createBearerResponseMetaFromUE(ue *uecontext.Context, gtpPLMN [3]byte) *gtpv2.CreateBearerResponseMeta {
	if ue == nil {
		return nil
	}
	ue.Lock()
	defer ue.Unlock()
	if ue.TAI == nil || ue.ECGIECI == 0 {
		return nil
	}
	if gtpPLMN == [3]byte{} {
		gtpPLMN = ue.ECGIPLMN
	}
	return &gtpv2.CreateBearerResponseMeta{
		IncludeULI: true,
		ULIPLMN:    gtpPLMN,
		ULITAC:     ue.TAI.TAC,
		ULIECI:     ue.ECGIECI,
	}
}

func updateBearerResponseMetaFromUE(ue *uecontext.Context, gtpPLMN [3]byte) *gtpv2.UpdateBearerResponseMeta {
	if ue == nil {
		return nil
	}
	ue.Lock()
	defer ue.Unlock()
	if ue.TAI == nil || ue.ECGIECI == 0 {
		return nil
	}
	if gtpPLMN == [3]byte{} {
		gtpPLMN = ue.ECGIPLMN
	}
	return &gtpv2.UpdateBearerResponseMeta{
		IncludeULI: true,
		ULIPLMN:    gtpPLMN,
		ULITAC:     ue.TAI.TAC,
		ULIECI:     ue.ECGIECI,
	}
}

func deleteBearerResponseMetaFromUE(ue *uecontext.Context, gtpPLMN [3]byte) *gtpv2.DeleteBearerResponseMeta {
	if ue == nil {
		return nil
	}
	ue.Lock()
	defer ue.Unlock()
	if ue.TAI == nil || ue.ECGIECI == 0 {
		return nil
	}
	if gtpPLMN == [3]byte{} {
		gtpPLMN = ue.ECGIPLMN
	}
	return &gtpv2.DeleteBearerResponseMeta{
		IncludeULI:          true,
		ULIPLMN:             gtpPLMN,
		ULITAC:              ue.TAI.TAC,
		ULIECI:              ue.ECGIECI,
		IncludeULITimestamp: true,
		ULITimestamp:        uint32(time.Now().UTC().Unix()) + 2208988800,
	}
}

func (s *Server) sendCreateBearerResponse(peer string, teid uint32, seq uint32, cause uint8, bearers []gtpv2.CreateBearerBearer) {
	s.sendCreateBearerResponseWithMeta(peer, teid, seq, cause, bearers, nil)
}

func (s *Server) sendCreateBearerResponseWithMeta(peer string, teid uint32, seq uint32, cause uint8, bearers []gtpv2.CreateBearerBearer, meta *gtpv2.CreateBearerResponseMeta) {
	responder, ok := s.s11.(S11BearerResponder)
	if !ok {
		s.log.Warn("s1ap: S11 client cannot send Create Bearer Response")
		return
	}
	if err := responder.SendCreateBearerResponse(peer, teid, seq, cause, bearers, meta); err != nil {
		s.log.Warn("s1ap: Create Bearer Response send failed", zap.String("peer", peer), zap.Uint32("seq", seq), zap.Error(err))
		return
	}
	s.log.Debug("s1ap: Create Bearer Response sent",
		zap.String("peer", peer),
		zap.Uint32("response_teid", teid),
		zap.Uint32("sequence_number", seq),
		zap.Int("bearer_count", len(bearers)),
		zap.Uint8("response_cause", cause))
}

func (s *Server) sendUpdateBearerResponse(peer string, teid uint32, seq uint32, cause uint8, bearers []gtpv2.UpdateBearerBearer) {
	responder, ok := s.s11.(S11BearerResponder)
	if !ok {
		s.log.Warn("s1ap: S11 client cannot send Update Bearer Response")
		return
	}
	var meta *gtpv2.UpdateBearerResponseMeta
	if ue, _ := s.findUEByLocalS11TEID(teid, 0); ue != nil {
		meta = updateBearerResponseMetaFromUE(ue, s.buildPLMN())
	}
	if err := responder.SendUpdateBearerResponse(peer, teid, seq, cause, bearers, meta); err != nil {
		s.log.Warn("s1ap: Update Bearer Response send failed", zap.String("peer", peer), zap.Uint32("seq", seq), zap.Error(err))
	}
}

func (s *Server) sendDeleteBearerResponse(peer string, teid uint32, seq uint32, cause uint8, ebis []uint8) {
	responder, ok := s.s11.(S11BearerResponder)
	if !ok {
		s.log.Warn("s1ap: S11 client cannot send Delete Bearer Response")
		return
	}
	var meta *gtpv2.DeleteBearerResponseMeta
	if ue, _ := s.findUEByLocalS11TEID(teid, 0); ue != nil {
		meta = deleteBearerResponseMetaFromUE(ue, s.buildPLMN())
	}
	if err := responder.SendDeleteBearerResponse(peer, teid, seq, cause, ebis, meta); err != nil {
		s.log.Warn("s1ap: Delete Bearer Response send failed", zap.String("peer", peer), zap.Uint32("seq", seq), zap.Error(err))
	}
}

func arpPriority(raw uint8) uint8 {
	pl := (raw & 0x3c) >> 2
	if pl == 0 {
		return 8
	}
	return pl
}

func applyUpdateBearerRequestToDedicatedBearer(next *uecontext.DedicatedBearerContext, req gtpv2.UpdateBearerBearer) {
	if next == nil {
		return
	}
	if len(req.BearerQoS) > 0 {
		next.BearerQoS = append([]byte(nil), req.BearerQoS...)
	}
	if req.QCI != 0 {
		next.QCI = req.QCI
	}
	if req.ARP != 0 {
		next.ARP = req.ARP
	}
	if len(req.TFT) > 0 {
		next.TFT = append([]byte(nil), req.TFT...)
	}
	if len(req.PCO) > 0 {
		next.PCO = append([]byte(nil), req.PCO...)
	}
}

func findPendingBearerTransactionForResponseLocked(ue *uecontext.Context, resp *esm.BearerProcedureResponse) (string, *uecontext.DedicatedBearerTransaction, bool) {
	if ue == nil || resp == nil {
		return "", nil, false
	}
	var preferredKinds []string
	switch resp.MessageType {
	case esm.MsgActivateDedicatedEPSBearerContextAccept, esm.MsgActivateDedicatedEPSBearerContextReject:
		preferredKinds = []string{bearerTxCreate}
	case esm.MsgModifyEPSBearerContextAccept, esm.MsgModifyEPSBearerContextReject:
		preferredKinds = []string{bearerTxUpdate, bearerTxLocalUpdate}
	case esm.MsgDeactivateEPSBearerContextAccept:
		preferredKinds = []string{bearerTxDelete}
	default:
		return "", nil, false
	}
	for _, kind := range preferredKinds {
		for key, tx := range ue.PendingBearerTransactions {
			if tx == nil || tx.Kind != kind {
				continue
			}
			if tx.Bearers[resp.EPSBearerID] != nil {
				return key, tx, true
			}
		}
	}
	return "", nil, false
}

func pendingBearerTransactionSummariesLocked(ue *uecontext.Context) []string {
	if ue == nil {
		return nil
	}
	out := make([]string, 0, len(ue.PendingBearerTransactions))
	for key, tx := range ue.PendingBearerTransactions {
		if tx == nil {
			continue
		}
		ebis := sortedTxBearerEBIs(tx)
		out = append(out, fmt.Sprintf("%s:%s:%v", key, tx.Kind, ebis))
	}
	sort.Strings(out)
	return out
}

func findConflictingPendingNetworkUpdateLocked(ue *uecontext.Context, bearers []gtpv2.UpdateBearerBearer) (*uecontext.DedicatedBearerTransaction, uint8, bool) {
	if ue == nil {
		return nil, 0, false
	}
	for _, bearer := range bearers {
		for _, tx := range ue.PendingBearerTransactions {
			if tx == nil {
				continue
			}
			if tx.Kind != bearerTxUpdate {
				continue
			}
			if tx.Bearers[bearer.EBI] != nil {
				return tx, bearer.EBI, true
			}
		}
	}
	return nil, 0, false
}

func preemptionCapability(raw uint8) bool {
	return raw&0x40 == 0
}

func preemptionVulnerability(raw uint8) bool {
	return raw&0x01 == 0
}

func protectNASLocked(ue *uecontext.Context, plain []byte) ([]byte, uint32, error) {
	dlCount := uint32(ue.DLNASCount)
	var protected []byte
	var err error
	if ue.EncAlg != security.AlgIDEEA0 {
		protected, err = nas.EncodeIntegrityAndCiphered(plain, ue.IntAlg, ue.EncAlg, ue.KNASint, ue.KNASenc, dlCount)
	} else {
		protected, err = nas.EncodeIntegrityProtected(plain, ue.IntAlg, ue.KNASint, dlCount)
	}
	if err != nil {
		return nil, dlCount, fmt.Errorf("protect NAS: %w", err)
	}
	return protected, dlCount, nil
}
