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
	"github.com/vectorcore/mme/internal/uecontext"
)

const (
	bearerTxCreate = "create"
	bearerTxUpdate = "update"
	bearerTxDelete = "delete"

	createBearerOverallTimeout   = 30 * time.Second
	maxPendingCreateBearersPerUE = 4
)

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
	for _, existing := range ue.PendingBearerTransactions {
		if existing.Kind != bearerTxCreate || existing.Fingerprint != fingerprint || isCreateBearerTerminal(existing.CreateState) {
			continue
		}
		if createBearerCanSupersedeTransport(existing.CreateState) {
			existing.PeerAddress = peer
			existing.LocalTEID = req.TEID
			existing.SequenceNum = req.SeqNum
			for i := range req.Bearers {
				if i >= len(existing.EBIs) {
					break
				}
				if proc := existing.Bearers[existing.EBIs[i]]; proc != nil {
					proc.SGWS1UTEID = req.Bearers[i].SGWS1UTEID
					proc.SGWS1UIP = append(net.IP(nil), req.Bearers[i].SGWS1UIP...)
				}
			}
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
		s.log.Info("s1ap: Create Bearer procedure started",
			zap.String("imsi", ue.IMSI),
			zap.Uint32("mme_ue_id", ue.MMEUES1APID),
			zap.Uint32("sequence_number", req.SeqNum),
			zap.Uint8("linked_ebi", req.LinkedEBI),
			zap.Uint8("requested_ebi", b.RequestedEBI),
			zap.Uint8("assigned_ebi", assigned),
			zap.Uint8("qci", qci),
			zap.Uint8("arp", b.ARP),
			zap.String("tft_hex", hex.EncodeToString(b.TFT)),
			zap.String("sgw_s1u_ip", net.IP(b.SGWS1UIP).String()),
			zap.Uint32("sgw_s1u_teid", b.SGWS1UTEID),
			zap.String("transaction_state", tx.State))
	}
	sort.Slice(tx.EBIs, func(i, j int) bool { return tx.EBIs[i] < tx.EBIs[j] })
	ue.PendingBearerTransactions[key] = tx
	mmeID := ue.MMEUES1APID
	imsi := ue.IMSI
	emmState := ue.EMMState
	ecmState := ue.ECMState
	activeS1 := hasActiveS1BindingLocked(ue)
	if !activeS1 && emmState == emm.StateRegistered && ecmState == emm.ECMIdle {
		tx.CreateState = uecontext.CreateBearerWaitingForUE
		tx.State = string(tx.CreateState)
		pageIMSI = imsi
		shouldPage = ue.PagingAttempts == 0
		tx.PagingAttempts = ue.PagingAttempts
		s.log.Info("s11: Create Bearer Request held for idle UE",
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
		case uecontext.CreateBearerWaitingForUE, uecontext.CreateBearerPaging:
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
		plain := esm.EncodeActivateDedicatedEPSBearerContextRequest(proc.AssignedEBI, proc.LinkedEBI, proc.PTI, proc.QCI, proc.TFT, proc.PCO)
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

	s.log.Info("s1ap: resuming pending Create Bearer after S1 binding restored",
		zap.String("imsi", imsi),
		zap.Uint32("mme_ue_id", mmeID),
		zap.String("transaction_id", transactionID),
		zap.Uint32("sequence_number", sequence),
		zap.Uint8s("assigned_ebis", assignedEBIs))
	if err := s.SendERABSetupRequest(mmeID, erabItems); err != nil {
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
	tx := &uecontext.DedicatedBearerTransaction{
		Kind:        bearerTxUpdate,
		PeerAddress: peer,
		LocalTEID:   req.TEID,
		SequenceNum: req.SeqNum,
		Bearers:     map[uint8]*uecontext.DedicatedBearerContext{},
		State:       "modifying",
	}
	mmeID := ue.MMEUES1APID
	var nasToSend [][]byte
	for _, b := range req.Bearers {
		active := ue.DedicatedBearers[b.EBI]
		if active == nil {
			continue
		}
		next := *active
		if len(b.BearerQoS) > 0 {
			next.BearerQoS = append([]byte(nil), b.BearerQoS...)
			next.QCI = b.QCI
			next.ARP = b.ARP
		}
		if len(b.TFT) > 0 {
			next.TFT = append([]byte(nil), b.TFT...)
		}
		if len(b.PCO) > 0 {
			next.PCO = append([]byte(nil), b.PCO...)
		}
		tx.Bearers[b.EBI] = &next
		plain := esm.EncodeModifyEPSBearerContextRequest(b.EBI, next.PTI, next.QCI, b.BearerQoS, b.TFT, b.PCO)
		protected, _, err := protectNASLocked(ue, plain)
		if err != nil {
			ue.Unlock()
			s.sendUpdateBearerResponse(peer, req.TEID, req.SeqNum, gtpv2.CauseRequestDenied, req.Bearers)
			return
		}
		ue.DLNASCount.Increment()
		nasToSend = append(nasToSend, protected)
		s.log.Info("s1ap: Update Bearer NAS Modify sent",
			zap.String("imsi", ue.IMSI),
			zap.Uint32("mme_ue_id", mmeID),
			zap.Uint32("sequence_number", req.SeqNum),
			zap.Uint8("assigned_ebi", b.EBI),
			zap.Uint8("qci", next.QCI),
			zap.String("tft_hex", hex.EncodeToString(b.TFT)))
	}
	if len(tx.Bearers) == 0 {
		ue.Unlock()
		s.sendUpdateBearerResponse(peer, req.TEID, req.SeqNum, gtpv2.CauseContextNotFound, req.Bearers)
		return
	}
	ue.PendingBearerTransactions[key] = tx
	ue.LastDownlinkNASMessage = "Modify EPS Bearer Context Request"
	ue.Unlock()
	for _, protected := range nasToSend {
		if err := s.SendDownlinkNAS(mmeID, protected); err != nil {
			s.sendUpdateBearerResponse(peer, req.TEID, req.SeqNum, gtpv2.CauseRequestDenied, req.Bearers)
			return
		}
	}
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
		Kind:        bearerTxDelete,
		PeerAddress: peer,
		LocalTEID:   req.TEID,
		SequenceNum: req.SeqNum,
		EBIs:        append([]uint8(nil), req.EBIs...),
		Bearers:     map[uint8]*uecontext.DedicatedBearerContext{},
		State:       "deleting",
	}
	mmeID := ue.MMEUES1APID
	var nasToSend [][]byte
	for _, ebi := range req.EBIs {
		active := ue.DedicatedBearers[ebi]
		if active == nil {
			continue
		}
		copyBearer := *active
		tx.Bearers[ebi] = &copyBearer
		plain := esm.EncodeDeactivateEPSBearerContextRequest(ebi, copyBearer.PTI, esm.ESMCauseRegularDeactivation)
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
	for key, tx := range ue.PendingBearerTransactions {
		proc := tx.Bearers[resp.EPSBearerID]
		if proc == nil {
			continue
		}
		switch resp.MessageType {
		case esm.MsgActivateDedicatedEPSBearerContextAccept:
			res, ok := ue.EBIReservations[resp.EPSBearerID]
			if !ok || res.TransactionID != tx.ID || proc.TransactionID != tx.ID {
				log.Warn("s1ap: stale Activate Dedicated EPS Bearer Context Accept ignored",
					zap.Uint8("assigned_ebi", resp.EPSBearerID),
					zap.String("transaction_id", tx.ID))
				return
			}
			proc.NASAccepted = true
			log.Info("s1ap: Activate Dedicated EPS Bearer Context Accept received",
				zap.Uint8("assigned_ebi", resp.EPSBearerID),
				zap.Uint8("linked_ebi", proc.LinkedEBI),
				zap.Uint8("pti", resp.ProcedureTransactionID))
			s.maybeCompleteCreateBearerLocked(ue, key, tx)
		case esm.MsgActivateDedicatedEPSBearerContextReject:
			res, ok := ue.EBIReservations[resp.EPSBearerID]
			if !ok || res.TransactionID != tx.ID || proc.TransactionID != tx.ID {
				log.Warn("s1ap: stale Activate Dedicated EPS Bearer Context Reject ignored",
					zap.Uint8("assigned_ebi", resp.EPSBearerID),
					zap.String("transaction_id", tx.ID))
				return
			}
			proc.NASRejected = true
			proc.FailureCause = resp.Cause
			s.maybeCompleteCreateBearerLocked(ue, key, tx)
		case esm.MsgModifyEPSBearerContextAccept:
			ue.DedicatedBearers[resp.EPSBearerID] = proc
			delete(ue.PendingBearerTransactions, key)
			go s.sendUpdateBearerResponse(tx.PeerAddress, tx.LocalTEID, tx.SequenceNum, gtpv2.CauseRequestAccepted, updateBearersFromTx(tx))
		case esm.MsgModifyEPSBearerContextReject:
			delete(ue.PendingBearerTransactions, key)
			go s.sendUpdateBearerResponse(tx.PeerAddress, tx.LocalTEID, tx.SequenceNum, gtpv2.CauseRequestDenied, updateBearersFromTx(tx))
		case esm.MsgDeactivateEPSBearerContextAccept:
			delete(ue.DedicatedBearers, resp.EPSBearerID)
			delete(tx.Bearers, resp.EPSBearerID)
			if len(tx.Bearers) == 0 {
				delete(ue.PendingBearerTransactions, key)
				go s.sendDeleteBearerResponse(tx.PeerAddress, tx.LocalTEID, tx.SequenceNum, gtpv2.CauseRequestAccepted, deleteEBIsFromTx(tx, resp.EPSBearerID))
			}
		}
		return
	}
	log.Warn("s1ap: bearer NAS response for unknown EBI",
		zap.Uint8("assigned_ebi", resp.EPSBearerID),
		zap.Uint8("message_type", resp.MessageType))
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
		log.Info("s1ap: dedicated E-RAB Setup Response item",
			zap.Uint8("assigned_ebi", result.EBI),
			zap.Uint8("qci", proc.QCI),
			zap.Uint32("sgw_s1u_teid", proc.SGWS1UTEID),
			zap.Uint32("enb_s1u_teid", result.ENBS1UTEID),
			zap.Bool("success", result.Success),
			zap.Uint8("cause", result.Cause))
		s.maybeCompleteCreateBearerLocked(ue, key, tx)
		return true
	}
	return false
}

func (s *Server) maybeCompleteCreateBearerLocked(ue *uecontext.Context, key string, tx *uecontext.DedicatedBearerTransaction) {
	if tx.Kind != bearerTxCreate {
		return
	}
	allDone := true
	anySuccess := false
	for _, proc := range tx.Bearers {
		if proc.NASRejected || proc.ERABFailed {
			continue
		}
		if !(proc.NASAccepted && proc.ERABEstablished) {
			allDone = false
			break
		}
		anySuccess = true
	}
	if !allDone {
		return
	}
	bearers := createBearersFromTx(tx)
	for _, proc := range tx.Bearers {
		if proc.NASAccepted && proc.ERABEstablished {
			proc.State = "active"
			ue.DedicatedBearers[proc.AssignedEBI] = proc
		}
		delete(ue.EBIReservations, proc.AssignedEBI)
	}
	ue.StopTimer(uecontext.TimerCreateBearerPrefix + key)
	delete(ue.PendingBearerTransactions, key)
	cause := gtpv2.CauseRequestDenied
	if anySuccess {
		cause = gtpv2.CauseRequestAccepted
	}
	tx.CreateState = uecontext.CreateBearerCompleted
	tx.State = string(tx.CreateState)
	duration := time.Since(tx.CreatedAt)
	successful := 0
	for _, proc := range tx.Bearers {
		if proc.NASAccepted && proc.ERABEstablished {
			successful++
		}
	}
	failed := len(tx.Bearers) - successful
	go s.sendFinalCreateBearerResponse(tx, cause, bearers, duration, successful, failed)
}

func (s *Server) failCreateBearerTransaction(ue *uecontext.Context, key string, cause uint8) {
	ue.Lock()
	tx := ue.PendingBearerTransactions[key]
	if tx != nil {
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

func (s *Server) sendFinalCreateBearerResponse(tx *uecontext.DedicatedBearerTransaction, cause uint8, bearers []gtpv2.CreateBearerBearer, duration time.Duration, successful int, failed int) {
	if !tx.TryMarkResponseSent() {
		return
	}
	s.sendCreateBearerResponse(tx.PeerAddress, tx.LocalTEID, tx.SequenceNum, cause, bearers)
	s.log.Info("s11: Create Bearer transaction completed",
		zap.String("transaction_id", tx.ID),
		zap.Duration("duration", duration),
		zap.Int("bearer_count", len(bearers)),
		zap.Int("successful_bearers", successful),
		zap.Int("failed_bearers", failed),
		zap.Uint8("response_cause", cause),
		zap.Bool("response_sent", true))
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

func linkedBearerActiveLocked(ue *uecontext.Context, linkedEBI uint8) bool {
	if linkedEBI == 0 {
		return true
	}
	if ue.DefaultEBI == linkedEBI {
		return true
	}
	for _, pdn := range ue.PDNs {
		if pdn.DefaultEBI == linkedEBI {
			return true
		}
	}
	return false
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

func isCreateBearerTerminal(state uecontext.CreateBearerState) bool {
	switch state {
	case uecontext.CreateBearerCompleted, uecontext.CreateBearerFailed, uecontext.CreateBearerTimedOut:
		return true
	default:
		return false
	}
}

func createBearerCanSupersedeTransport(state uecontext.CreateBearerState) bool {
	switch state {
	case uecontext.CreateBearerReceived, uecontext.CreateBearerWaitingForUE, uecontext.CreateBearerPaging:
		return true
	default:
		return false
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
		out = append(out, gtpv2.CreateBearerBearer{
			RequestedEBI: proc.RequestedEBI,
			AssignedEBI:  proc.AssignedEBI,
			EBI:          proc.AssignedEBI,
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

func (s *Server) sendCreateBearerResponse(peer string, teid uint32, seq uint32, cause uint8, bearers []gtpv2.CreateBearerBearer) {
	responder, ok := s.s11.(S11BearerResponder)
	if !ok {
		s.log.Warn("s1ap: S11 client cannot send Create Bearer Response")
		return
	}
	if err := responder.SendCreateBearerResponse(peer, teid, seq, cause, bearers); err != nil {
		s.log.Warn("s1ap: Create Bearer Response send failed", zap.String("peer", peer), zap.Uint32("seq", seq), zap.Error(err))
		return
	}
	s.log.Info("s1ap: Create Bearer Response sent",
		zap.String("peer", peer),
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
	if err := responder.SendUpdateBearerResponse(peer, teid, seq, cause, bearers); err != nil {
		s.log.Warn("s1ap: Update Bearer Response send failed", zap.String("peer", peer), zap.Uint32("seq", seq), zap.Error(err))
	}
}

func (s *Server) sendDeleteBearerResponse(peer string, teid uint32, seq uint32, cause uint8, ebis []uint8) {
	responder, ok := s.s11.(S11BearerResponder)
	if !ok {
		s.log.Warn("s1ap: S11 client cannot send Delete Bearer Response")
		return
	}
	if err := responder.SendDeleteBearerResponse(peer, teid, seq, cause, ebis); err != nil {
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
