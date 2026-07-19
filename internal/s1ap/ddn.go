package s1ap

import (
	"fmt"
	"net"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/gtpv2"
	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/uecontext"
)

const (
	ddnPagingRetryTimerName   = "DDNPagingRetry"
	ddnPagingTimeoutTimerName = "DDNPagingTimeout"
)

func (s *Server) HandleDownlinkDataNotification(peer string, req *gtpv2.DownlinkDataNotification) {
	if req == nil {
		return
	}

	var ebi uint8
	if req.EBI != nil {
		ebi = *req.EBI
	}
	var arp uint8
	if req.ARP != nil {
		arp = *req.ARP
	}

	ue, pdn := s.findUEByLocalS11TEID(req.TEID, ebi)
	if ue == nil {
		s.log.Warn("s11: Downlink Data Notification UE lookup miss",
			zap.String("event", "ddn_received"),
			zap.String("peer", peer),
			zap.Uint32("header_teid", req.TEID),
			zap.Uint32("sequence", req.SeqNum),
			zap.Uint8("ebi", ebi),
			zap.Uint8("arp", arp))
		s.sendDDNAck(peer, req.TEID, req.SeqNum, gtpv2.CauseContextNotFound, nil)
		return
	}

	var (
		cause         uint8
		shouldPage    bool
		targets       []string
		txID          string
		attempt       uint8
		imsi          string
		emmState      emm.EMMState
		ecmState      emm.ECMState
		bindingGen    uint64
		duplicateType string
		joined        bool
		noENB         bool
	)

	now := time.Now()
	ue.Lock()
	imsi = ue.IMSI
	emmState = ue.EMMState
	ecmState = ue.ECMState
	bindingGen = ue.S1BindingGeneration
	cause = s.validateDDNLocked(ue, pdn, peer, req)
	if cause == gtpv2.CauseRequestAccepted && ecmState == emm.ECMConnected {
		cause = gtpv2.CauseRequestAccepted
	}
	if cause == gtpv2.CauseRequestAccepted && emmState != emm.StateRegistered {
		cause = gtpv2.CauseContextNotFound
	}
	if cause == gtpv2.CauseRequestAccepted && ecmState == emm.ECMIdle && s.pagingCfg.DDNEnabled {
		tx := ue.DDNPaging
		key := ddnDuplicateKey(peer, req.TEID, req.SeqNum, ebi)
		if tx != nil && tx.DedupKeys != nil {
			if _, ok := tx.DedupKeys[key]; ok {
				duplicateType = "exact"
				tx.LastDDNAt = now
				tx.LastAckCause = gtpv2.CauseRequestAccepted
				txID = tx.ID
				attempt = tx.PagingAttemptCount
				ue.Unlock()
				s.log.Info("s11: duplicate DDN suppressed",
					zap.String("event", "ddn_duplicate"),
					zap.String("peer", peer),
					zap.Uint32("header_teid", req.TEID),
					zap.Uint32("sequence", req.SeqNum),
					zap.Uint8("ebi", ebi),
					zap.String("duplicate_type", duplicateType),
					zap.String("existing_transaction_id", txID),
					zap.String("paging_status", string(tx.Status)))
				s.sendDDNAck(peer, req.TEID, req.SeqNum, gtpv2.CauseRequestAccepted, nil)
				return
			}
		}
		if tx != nil && !ddnPagingTerminal(tx.Status) {
			duplicateType = "joined"
			joined = true
			tx.LastDDNAt = now
			tx.LastAckCause = gtpv2.CauseRequestAccepted
			if tx.DedupKeys == nil {
				tx.DedupKeys = make(map[string]time.Time)
			}
			tx.DedupKeys[key] = now
			if tx.JoinedBearers == nil {
				tx.JoinedBearers = make(map[uint8]struct{})
			}
			if ebi != 0 {
				tx.JoinedBearers[ebi] = struct{}{}
			}
			if arp != 0 {
				tx.ARPRaw = arp
			}
			txID = tx.ID
			attempt = tx.PagingAttemptCount
		} else {
			targets = s.findStrictENBsForTAILocked(ue)
			if len(targets) == 0 {
				noENB = true
				cause = gtpv2.CauseUnableToPageUE
			} else {
				tx = newDDNPagingTransactionLocked(ue, peer, req, now)
				ue.DDNPaging = tx
				ue.PagingAttempts = 1
				txID = tx.ID
				tx.Status = uecontext.DDNPagingPagingSent
				tx.PagingAttemptCount = 1
				tx.LastPagingAt = now
				attempt = 1
				shouldPage = true
			}
		}
	}
	ue.Unlock()

	s.log.Info("s11: Downlink Data Notification received",
		zap.String("event", "ddn_received"),
		zap.String("peer", peer),
		zap.Uint32("header_teid", req.TEID),
		zap.Uint32("sequence", req.SeqNum),
		zap.Uint8("ebi", ebi),
		zap.Uint8("arp", arp),
		zap.Uint32("mme_ue_id", ue.MMEUES1APID),
		zap.String("imsi", imsi),
		zap.Stringer("emm_state", emmState),
		zap.Stringer("ecm_state", ecmState))

	s.sendDDNAck(peer, req.TEID, req.SeqNum, cause, nil)
	if cause != gtpv2.CauseRequestAccepted {
		s.log.Info("s11: Downlink Data Notification response sent",
			zap.String("event", "ddn_response_sent"),
			zap.String("response_type", "ack"),
			zap.Uint8("cause", cause),
			zap.String("cause_name", gtpv2.CauseName(cause)),
			zap.Uint32("sequence", req.SeqNum),
			zap.Uint32("header_teid", req.TEID))
		if noENB {
			s.failDDNPaging(ue, txID, cause, "no_matching_enb")
		}
		return
	}

	if ecmState == emm.ECMConnected {
		s.log.Info("s11: DDN paging suppressed because UE is already connected",
			zap.String("event", "ddn_response_sent"),
			zap.String("response_type", "ack"),
			zap.Uint8("cause", cause),
			zap.String("cause_name", gtpv2.CauseName(cause)),
			zap.Uint32("sequence", req.SeqNum),
			zap.Uint32("header_teid", req.TEID))
		return
	}
	if joined {
		s.log.Info("s11: DDN joined existing paging transaction",
			zap.String("event", "ddn_duplicate"),
			zap.String("duplicate_type", duplicateType),
			zap.String("existing_transaction_id", txID),
			zap.Uint8("paging_attempt", attempt))
		return
	}
	if !shouldPage {
		return
	}

	s.log.Info("s1ap: DDN paging started",
		zap.String("event", "ddn_paging_started"),
		zap.Uint32("mme_ue_id", ue.MMEUES1APID),
		zap.String("imsi", imsi),
		zap.String("transaction_id", txID),
		zap.Uint64("binding_generation", bindingGen),
		zap.Uint8("attempt", attempt),
		zap.Int("target_enb_count", len(targets)))
	for _, addr := range targets {
		s.log.Info("s1ap: DDN paging target",
			zap.String("event", "ddn_paging_started"),
			zap.String("transaction_id", txID),
			zap.Uint8("attempt", attempt),
			zap.String("target_enb", addr))
		s.sendPaging(addr, ue, s.log.With(
			zap.String("transaction_id", txID),
			zap.Uint8("paging_attempt", attempt),
		))
	}
	metrics.PagingTotal.WithLabelValues("sent").Inc()
	s.startDDNPagingTimers(ue, txID)
}

func (s *Server) validateDDNLocked(ue *uecontext.Context, pdn *uecontext.PDNContext, peer string, req *gtpv2.DownlinkDataNotification) uint8 {
	if ue == nil || pdn == nil {
		return gtpv2.CauseContextNotFound
	}
	if req.EBI != nil && *req.EBI == 0 {
		return gtpv2.CauseMandatoryIEIncorrect
	}
	if !sameGTPCPeer(peer, pdn.SGWAddress) {
		return gtpv2.CauseContextNotFound
	}
	if strings.Contains(pdn.State, "delete") || strings.Contains(pdn.State, "disconnect") {
		return gtpv2.CauseContextNotFound
	}
	if req.EBI != nil && *req.EBI != pdn.DefaultEBI {
		db := ue.DedicatedBearers[*req.EBI]
		if db == nil || db.LinkedEBI != pdn.DefaultEBI {
			return gtpv2.CauseContextNotFound
		}
	}
	return gtpv2.CauseRequestAccepted
}

func newDDNPagingTransactionLocked(ue *uecontext.Context, peer string, req *gtpv2.DownlinkDataNotification, now time.Time) *uecontext.DDNPagingTransaction {
	var ebi uint8
	if req.EBI != nil {
		ebi = *req.EBI
	}
	var arp uint8
	if req.ARP != nil {
		arp = *req.ARP
	}
	tx := &uecontext.DDNPagingTransaction{
		ID:                fmt.Sprintf("ddn-%d-%08x-%06x", ue.MMEUES1APID, req.TEID, req.SeqNum),
		SourcePeer:        peer,
		MMEControlTEID:    req.TEID,
		OriginalSequence:  req.SeqNum,
		InitialBearerEBI:  ebi,
		ARPRaw:            arp,
		FirstDDNAt:        now,
		LastDDNAt:         now,
		Status:            uecontext.DDNPagingPending,
		BindingGeneration: ue.S1BindingGeneration,
		LastAckCause:      gtpv2.CauseRequestAccepted,
		JoinedBearers:     make(map[uint8]struct{}),
		DedupKeys:         make(map[string]time.Time),
	}
	if ebi != 0 {
		tx.JoinedBearers[ebi] = struct{}{}
	}
	tx.DedupKeys[ddnDuplicateKey(peer, req.TEID, req.SeqNum, ebi)] = now
	return tx
}

func (s *Server) startDDNPagingTimers(ue *uecontext.Context, txID string) {
	ue.Lock()
	retry := s.pagingCfg.RetryInterval
	timeout := s.pagingCfg.TransactionTimeout
	ue.StartTimer(ddnPagingRetryTimerName, retry, func() {
		s.onDDNPagingRetry(ue, txID)
	})
	ue.StartTimer(ddnPagingTimeoutTimerName, timeout, func() {
		s.onDDNPagingTimeout(ue, txID)
	})
	ue.Unlock()
}

func (s *Server) onDDNPagingRetry(ue *uecontext.Context, txID string) {
	ue.Lock()
	tx := ue.DDNPaging
	if tx == nil || tx.ID != txID || ddnPagingTerminal(tx.Status) || tx.Status == uecontext.DDNPagingServiceRequest || tx.Status == uecontext.DDNPagingResumeInProgress {
		ue.Unlock()
		return
	}
	if tx.PagingAttemptCount >= s.pagingCfg.MaxAttempts {
		ue.Unlock()
		return
	}
	targets := s.findStrictENBsForTAILocked(ue)
	if len(targets) == 0 {
		tx.Status = uecontext.DDNPagingFailed
		tx.FailureCause = gtpv2.CauseUnableToPageUE
		tx.FailureReason = "no_matching_enb"
		ue.PagingAttempts = 0
		ue.StopTimer(ddnPagingRetryTimerName)
		ue.Unlock()
		s.failDDNPaging(ue, txID, gtpv2.CauseUnableToPageUE, "no_matching_enb")
		return
	}
	tx.PagingAttemptCount++
	tx.LastPagingAt = time.Now()
	tx.Status = uecontext.DDNPagingPagingSent
	ue.PagingAttempts = tx.PagingAttemptCount
	attempt := tx.PagingAttemptCount
	imsi := ue.IMSI
	ue.Unlock()

	s.log.Info("s1ap: DDN paging retry",
		zap.String("event", "ddn_paging_started"),
		zap.String("transaction_id", txID),
		zap.String("imsi", imsi),
		zap.Uint8("attempt", attempt),
		zap.Int("target_enb_count", len(targets)))
	for _, addr := range targets {
		s.sendPaging(addr, ue, s.log.With(
			zap.String("transaction_id", txID),
			zap.Uint8("paging_attempt", attempt),
		))
	}
	metrics.PagingTotal.WithLabelValues("retry").Inc()

	ue.Lock()
	if ue.DDNPaging != nil && ue.DDNPaging.ID == txID && !ddnPagingTerminal(ue.DDNPaging.Status) &&
		ue.DDNPaging.Status != uecontext.DDNPagingServiceRequest && ue.DDNPaging.Status != uecontext.DDNPagingResumeInProgress {
		ue.StartTimer(ddnPagingRetryTimerName, s.pagingCfg.RetryInterval, func() {
			s.onDDNPagingRetry(ue, txID)
		})
	}
	ue.Unlock()
}

func (s *Server) onDDNPagingTimeout(ue *uecontext.Context, txID string) {
	s.failDDNPaging(ue, txID, gtpv2.CauseUnableToPageUE, "paging_timeout")
}

func (s *Server) failDDNPaging(ue *uecontext.Context, txID string, cause uint8, reason string) {
	ue.Lock()
	tx := ue.DDNPaging
	if tx == nil || tx.ID != txID || ddnPagingTerminal(tx.Status) {
		ue.Unlock()
		return
	}
	tx.Status = uecontext.DDNPagingFailed
	if reason == "paging_timeout" {
		tx.Status = uecontext.DDNPagingTimedOut
	}
	tx.FailureCause = cause
	tx.FailureReason = reason
	attempts := tx.PagingAttemptCount
	elapsed := time.Since(tx.FirstDDNAt)
	ue.PagingAttempts = 0
	ue.StopTimer(ddnPagingRetryTimerName)
	ue.StopTimer(ddnPagingTimeoutTimerName)
	ue.Unlock()

	s.log.Warn("s1ap: DDN paging failed",
		zap.String("event", "ddn_paging_failed"),
		zap.String("transaction_id", txID),
		zap.String("reason", reason),
		zap.Uint8("attempts", attempts),
		zap.Int64("elapsed_ms", elapsed.Milliseconds()))
}

func (s *Server) noteDDNServiceRequest(ue *uecontext.Context, enbUEID uint32, bindingGeneration uint64) {
	ue.Lock()
	tx := ue.DDNPaging
	if tx == nil || ddnPagingTerminal(tx.Status) {
		ue.Unlock()
		return
	}
	tx.Status = uecontext.DDNPagingServiceRequest
	tx.BindingGeneration = bindingGeneration
	tx.LastDDNAt = time.Now()
	txID := tx.ID
	mmeUEID := ue.MMEUES1APID
	ue.StopTimer(ddnPagingRetryTimerName)
	ue.Unlock()

	s.log.Info("s1ap: DDN paging correlated with Service Request",
		zap.String("event", "ddn_paging_service_request"),
		zap.String("transaction_id", txID),
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.Uint32("new_enb_ue_id", enbUEID),
		zap.Uint64("binding_generation", bindingGeneration))
}

func (s *Server) noteDDNResumeInProgress(ue *uecontext.Context) {
	ue.Lock()
	if ue.DDNPaging != nil && !ddnPagingTerminal(ue.DDNPaging.Status) {
		ue.DDNPaging.Status = uecontext.DDNPagingResumeInProgress
	}
	ue.Unlock()
}

func (s *Server) completeDDNPagingIfPending(ue *uecontext.Context, trigger string, resumeEBIs []uint8) {
	ue.Lock()
	tx := ue.DDNPaging
	if tx == nil || ddnPagingTerminal(tx.Status) {
		ue.Unlock()
		return
	}
	tx.Status = uecontext.DDNPagingCompleted
	tx.LastDDNAt = time.Now()
	txID := tx.ID
	elapsed := time.Since(tx.FirstDDNAt)
	ue.PagingAttempts = 0
	ue.StopTimer(ddnPagingRetryTimerName)
	ue.StopTimer(ddnPagingTimeoutTimerName)
	ue.Unlock()

	s.log.Info("s1ap: DDN paging completed",
		zap.String("event", "ddn_paging_completed"),
		zap.String("transaction_id", txID),
		zap.Int64("elapsed_ms", elapsed.Milliseconds()),
		zap.Any("resume_ics_ebis", resumeEBIs),
		zap.String("trigger", trigger))
}

func (s *Server) failDDNPagingIfPending(ue *uecontext.Context, reason string) {
	if ue == nil {
		return
	}
	s.failDDNPaging(ue, currentDDNTransactionID(ue), gtpv2.CauseSystemFailure, reason)
}

func currentDDNTransactionID(ue *uecontext.Context) string {
	ue.Lock()
	defer ue.Unlock()
	if ue.DDNPaging == nil {
		return ""
	}
	return ue.DDNPaging.ID
}

func (s *Server) sendDDNAck(peer string, teid uint32, seq uint32, cause uint8, delayValue *uint8) {
	resp, ok := s.s11.(S11DDNResponder)
	if !ok {
		s.log.Warn("s11: DDN responder unavailable",
			zap.String("peer", peer),
			zap.Uint32("header_teid", teid),
			zap.Uint32("sequence", seq),
			zap.Uint8("cause", cause))
		return
	}
	if err := resp.SendDDNAck(peer, teid, seq, cause, delayValue); err != nil {
		s.log.Warn("s11: failed to send DDN Ack",
			zap.String("peer", peer),
			zap.Uint32("header_teid", teid),
			zap.Uint32("sequence", seq),
			zap.Uint8("cause", cause),
			zap.Error(err))
		return
	}
	s.log.Info("s11: Downlink Data Notification response sent",
		zap.String("event", "ddn_response_sent"),
		zap.String("response_type", "ack"),
		zap.Uint8("cause", cause),
		zap.String("cause_name", gtpv2.CauseName(cause)),
		zap.Uint32("sequence", seq),
		zap.Uint32("header_teid", teid))
}

func sameGTPCPeer(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	aa, errA := net.ResolveUDPAddr("udp", a)
	bb, errB := net.ResolveUDPAddr("udp", b)
	if errA != nil || errB != nil {
		return false
	}
	return aa.IP.Equal(bb.IP) && aa.Port == bb.Port
}

func ddnDuplicateKey(peer string, teid uint32, seq uint32, ebi uint8) string {
	return fmt.Sprintf("%s|%08x|%06x|%02x", peer, teid, seq, ebi)
}

func ddnPagingTerminal(status uecontext.DDNPagingStatus) bool {
	switch status {
	case uecontext.DDNPagingCompleted, uecontext.DDNPagingTimedOut, uecontext.DDNPagingFailed:
		return true
	default:
		return false
	}
}

func (s *Server) findStrictENBsForTAILocked(ue *uecontext.Context) []string {
	if ue == nil || ue.TAI == nil {
		return nil
	}
	var matched []string
	s.enbs.Range(func(_, val any) bool {
		enb := val.(*ENBContext)
		enb.mu.Lock()
		defer enb.mu.Unlock()
		for _, sta := range enb.SupportedTAs {
			if sta.TAC != ue.TAI.TAC {
				continue
			}
			for _, bp := range sta.BroadcastPLMNs {
				plmn, err := ies.EncodePLMN(bp.MCC, bp.MNC)
				if err != nil {
					continue
				}
				if len(plmn) == 3 && plmn[0] == ue.TAI.PLMN[0] && plmn[1] == ue.TAI.PLMN[1] && plmn[2] == ue.TAI.PLMN[2] {
					matched = append(matched, enb.RemoteAddr)
					return true
				}
			}
		}
		return true
	})
	return matched
}
