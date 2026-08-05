package s1ap

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/vectorcore/mme/internal/diameter/sgd"
	"github.com/vectorcore/mme/internal/metrics"
	nas "github.com/vectorcore/mme/internal/nas"
	"github.com/vectorcore/mme/internal/nas/emm"
	nassms "github.com/vectorcore/mme/internal/nas/sms"
	"github.com/vectorcore/mme/internal/uecontext"
	"go.uber.org/zap"
)

type mtSMSResult struct {
	resultCode uint32
	rpui       []byte
}

type pendingMTSMS struct {
	ti          uint8
	rpReference uint8
	result      chan mtSMSResult
	request     *sgd.MTRequest
	state       string
}

type moSMSState string

const (
	moSMSWaitingSGdAnswer  moSMSState = "waiting_for_sgd_answer"
	moSMSWaitingFinalCPAck moSMSState = "waiting_for_final_cp_ack"
	moSMSCompleted         moSMSState = "completed"
	moSMSFailed            moSMSState = "failed"
	moSMSFinalCPRetries               = 2
)

// pendingMOSMS remains present after the SGd answer.  The CP transaction is
// only complete when the UE acknowledges the MME-originated CP-DATA carrying
// RP-ACK/RP-ERROR (TS 24.011 CP procedure).
type pendingMOSMS struct {
	mu                sync.Mutex
	rpdu              []byte
	ti                uint8
	ueTransactionFlag bool
	rpReference       uint8
	state             moSMSState
	downlinkCP        []byte
	retries           int
	timer             *time.Timer
}

// processUplinkSMS accepts a protected UL NAS Transport SMS container and
// submits the MO RPDU to the transport-neutral SMS service.
func (s *Server) processUplinkSMS(ue *uecontext.Context, payload []byte) error {
	cpdu, err := nassms.DecodeNASContainer(payload)
	if err != nil {
		ue.Lock()
		mmeUEID, imsi := ue.MMEUES1APID, ue.IMSI
		ue.Unlock()
		declared, available := -1, -1
		if len(payload) > 0 {
			declared, available = int(payload[0]), len(payload)-1
		}
		s.log.Warn("sms: invalid uplink NAS transport container length",
			zap.Uint32("mme_ue_id", mmeUEID),
			zap.String("imsi", imsi),
			zap.Uint8("nas_message_type", emm.MsgUplinkNASTransport),
			zap.Int("pdu_length", len(payload)+2),
			zap.Int("declared_container_length", declared),
			zap.Int("available_container_length", available),
			zap.Int("container_offset", 3),
			zap.Error(err))
		// Raw NAS can contain SMS content, so retain it only at debug level.
		s.log.Debug("sms: invalid uplink NAS transport raw payload",
			zap.String("plain_nas_hex", fmt.Sprintf("0763%x", payload)))
		return err
	}
	if s.selectSMSPath(ue) == "sgs" {
		// SMS over SGs is a transparent NAS-message-container relay (TS
		// 29.118 §9.4.15): the VLR/MSC owns the CP/RP protocol, so unlike
		// SGd below, the MME never parses CP-DATA/CP-ACK/CP-ERROR itself -
		// it forwards every uplink container as-is.
		return s.relayUplinkSMSToSGs(ue, cpdu)
	}
	cp, err := nassms.DecodeCP(cpdu)
	if err != nil {
		return fmt.Errorf("sms: invalid MO CP-DATA: %w", err)
	}
	ue.Lock()
	mmeUEID, ueIMSI := ue.MMEUES1APID, ue.IMSI
	ue.Unlock()
	s.log.Debug("sms: uplink NAS transport decoded",
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.Int("container_length", len(cpdu)),
		zap.Uint8("inner_protocol_discriminator", cpdu[0]&0x0f),
		zap.Uint8("sms_transaction_id", cp.TI))
	if cp.Type == nassms.CPError {
		ue.Lock()
		imsi, mmeUEID := ue.IMSI, ue.MMEUES1APID
		ue.Unlock()
		cause := uint8(0)
		if cp.Cause != nil {
			cause = *cp.Cause
		}
		s.log.Info("sms: uplink CP-ERROR received",
			zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi),
			zap.Uint8("cp_transaction_id", cp.TI), zap.Uint8("cp_cause", cause),
			zap.Bool("network_originated_transaction", cp.TransactionIDFlag))
		if v, ok := s.pendingMTSMS.Load(imsi); ok {
			pending := v.(*pendingMTSMS)
			if cp.TransactionIDFlag && cp.TI == pending.ti {
				select {
				case pending.result <- mtSMSResult{resultCode: diam.UnableToDeliver}:
				default:
				}
				return nil
			}
		}
		if tx := s.findPendingMOSMS(imsi, cp.TI, cp.TransactionIDFlag); tx != nil {
			tx.mu.Lock()
			state := tx.state
			rpReference := tx.rpReference
			tx.state = moSMSFailed
			tx.mu.Unlock()
			s.log.Warn("sms: MO SMS final CP-ERROR received",
				zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi),
				zap.Uint8("cp_transaction_id", cp.TI),
				zap.Bool("transaction_identifier_flag", cp.TransactionIDFlag),
				zap.Uint8("rp_reference", rpReference), zap.Uint8("cp_cause", cause),
				zap.String("state", string(state)),
				zap.String("raw_cp_hex", fmt.Sprintf("%x", cpdu)))
			s.finishMOSMS(imsi, cp.TI, tx)
			return nil
		}
		// A late CP-ERROR can follow a local transaction timeout or a Diameter
		// failure. It is valid NAS input and must not be reinterpreted as
		// CP-DATA or cause a second protocol error.
		return nil
	}
	if cp.Type == nassms.CPAck {
		if tx := s.findPendingMOSMS(ueIMSI, cp.TI, cp.TransactionIDFlag); tx != nil {
			tx.mu.Lock()
			if tx.state != moSMSWaitingFinalCPAck {
				state := tx.state
				tx.mu.Unlock()
				s.log.Debug("sms: MO CP-ACK received outside final acknowledgement state",
					zap.Uint32("mme_ue_id", mmeUEID), zap.Uint8("cp_transaction_id", cp.TI), zap.String("state", string(state)))
				return nil
			}
			tx.state = moSMSCompleted
			rpReference := tx.rpReference
			tx.mu.Unlock()
			s.log.Info("sms: MO SMS final CP-ACK received",
				zap.Uint32("mme_ue_id", mmeUEID), zap.Uint8("cp_transaction_id", cp.TI), zap.Uint8("rp_reference", rpReference))
			s.finishMOSMS(ueIMSI, cp.TI, tx)
			s.log.Info("sms: MO SMS transaction completed", zap.Uint32("mme_ue_id", mmeUEID), zap.Uint8("cp_transaction_id", cp.TI), zap.Uint8("rp_reference", rpReference))
		}
		return nil
	}
	if cp.Type != nassms.CPData {
		return fmt.Errorf("sms: unexpected uplink CP type")
	}
	ue.Lock()
	registered := ue.SMSRegistrationState == uecontext.SMSRegistrationRegistered
	imsi, msisdn := ue.IMSI, ue.MSISDN
	ue.Unlock()
	if ref, rpui, ackErr := nassms.DecodeRPAckMO(cp.RPDU); ackErr == nil {
		if v, ok := s.pendingMTSMS.Load(imsi); ok {
			pending := v.(*pendingMTSMS)
			if !cp.TransactionIDFlag || cp.TI != pending.ti || ref != pending.rpReference {
				return fmt.Errorf("sms: unmatched MT RP-ACK")
			}
			ack, _ := nassms.EncodeCPAckWithDirection(cp.TI, !cp.TransactionIDFlag)
			_ = s.sendSMSCP(ue, ack)
			select {
			case pending.result <- mtSMSResult{resultCode: diam.Success, rpui: rpui}:
			default:
			}
			return nil
		}
		s.log.Debug("sms: late or unsolicited uplink RP-ACK", zap.Uint32("mme_ue_id", mmeUEID), zap.Uint8("rp_reference", ref), zap.Int("rp_user_data_length", len(rpui)))
		return nil
	}
	if ref, _, rpErr := nassms.DecodeRPErrorMO(cp.RPDU); rpErr == nil {
		if v, ok := s.pendingMTSMS.Load(imsi); ok {
			pending := v.(*pendingMTSMS)
			if !cp.TransactionIDFlag || cp.TI != pending.ti || ref != pending.rpReference {
				return fmt.Errorf("sms: unmatched MT RP-ERROR")
			}
			ack, _ := nassms.EncodeCPAckWithDirection(cp.TI, !cp.TransactionIDFlag)
			_ = s.sendSMSCP(ue, ack)
			select {
			case pending.result <- mtSMSResult{resultCode: diam.UnableToDeliver}:
			default:
			}
			return nil
		}
		s.log.Debug("sms: late or unsolicited uplink RP-ERROR", zap.Uint32("mme_ue_id", mmeUEID), zap.Uint8("rp_reference", ref))
		return nil
	}
	if !registered || s.sms == nil {
		return fmt.Errorf("sms: service unavailable")
	}
	if _, err := nassms.DecodeRPDataMO(cp.RPDU); err != nil {
		return err
	}
	key := moSMSKey(imsi, cp.TI)
	rp, _ := nassms.DecodeRPDataMO(cp.RPDU)
	transaction := &pendingMOSMS{
		rpdu:              append([]byte(nil), cp.RPDU...),
		ti:                cp.TI,
		ueTransactionFlag: cp.TransactionIDFlag,
		rpReference:       rp.Reference,
		state:             moSMSWaitingSGdAnswer,
	}
	if prior, loaded := s.pendingMOSMS.LoadOrStore(key, transaction); loaded {
		if !bytes.Equal(prior.(*pendingMOSMS).rpdu, cp.RPDU) {
			return fmt.Errorf("sms: CP transaction identifier reused with different MO RPDU")
		}
		metrics.SMSDuplicateMessagesTotal.WithLabelValues("mo_cp_data").Inc()
		priorTx := prior.(*pendingMOSMS)
		priorTx.mu.Lock()
		state := priorTx.state
		priorTx.mu.Unlock()
		s.log.Info("sms: MO transaction reused after duplicate CP-DATA",
			zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi),
			zap.Uint8("cp_transaction_id", cp.TI), zap.Bool("transaction_identifier_flag", cp.TransactionIDFlag),
			zap.Uint8("rp_reference", rp.Reference), zap.String("state", string(state)))
		ack, _ := nassms.EncodeCPAckWithDirection(cp.TI, !cp.TransactionIDFlag)
		return s.sendSMSCP(ue, ack)
	}
	s.log.Info("sms: MO CP-DATA received",
		zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi),
		zap.Uint8("cp_transaction_id", cp.TI), zap.Bool("transaction_identifier_flag", cp.TransactionIDFlag),
		zap.Uint8("rp_reference", rp.Reference), zap.String("state", string(transaction.state)))
	// A CP-ACK is sent immediately.  It acknowledges CP-DATA reception, not
	// SGd delivery, and is encoded in the MME-to-UE direction (opposite TIO).
	ack, _ := nassms.EncodeCPAckWithDirection(cp.TI, !cp.TransactionIDFlag)
	s.log.Debug("sms: MO immediate CP-ACK encoded",
		zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi), zap.Uint8("cp_transaction_id", cp.TI),
		zap.Bool("transaction_identifier_flag", !cp.TransactionIDFlag))
	if err := s.sendSMSCP(ue, ack); err != nil {
		s.pendingMOSMS.Delete(key)
		return err
	}
	s.log.Info("sms: MO immediate CP-ACK transmitted",
		zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi), zap.Uint8("cp_transaction_id", cp.TI))
	metrics.SMSActiveTransactions.Inc()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), smsTransactionTimeout(s))
		defer cancel()
		result, sendErr := s.sms.HandleMO(ctx, imsi, msisdn, cp.RPDU)
		if sendErr == nil {
			s.log.Info("sms: received SGd MO-Forward-Short-Message-Answer",
				zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi), zap.Uint8("cp_transaction_id", cp.TI))
		} else {
			metrics.SMSMORequestsTotal.WithLabelValues("failure").Inc()
			s.log.Warn("sms: MO SMS transaction failed",
				zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi), zap.Uint8("cp_transaction_id", cp.TI), zap.Error(sendErr))
		}
		var response []byte
		if sendErr == nil {
			response, _ = nassms.EncodeRPAckToMS(rp.Reference, result.SMRPUI)
			s.log.Debug("sms: MO RP-ACK generated", zap.Uint32("mme_ue_id", mmeUEID), zap.Uint8("rp_reference", rp.Reference))
		} else {
			// RP cause #111: protocol error, unspecified. SGd-specific errors are
			// deliberately not exposed to the UE.
			response = []byte{nassms.RPErrorNetwork, rp.Reference, 1, 111}
		}
		answer, _ := nassms.EncodeCPDataWithDirection(cp.TI, !cp.TransactionIDFlag, response)
		s.log.Debug("sms: MO RP-ACK encoded in CP-DATA", zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi), zap.Uint8("cp_transaction_id", cp.TI), zap.Uint8("rp_reference", rp.Reference), zap.Bool("transaction_identifier_flag", !cp.TransactionIDFlag))
		transaction.mu.Lock()
		if transaction.state != moSMSWaitingSGdAnswer {
			transaction.mu.Unlock()
			return
		}
		transaction.downlinkCP = append([]byte(nil), answer...)
		transaction.state = moSMSWaitingFinalCPAck
		transaction.mu.Unlock()
		if err := s.sendSMSCP(ue, answer); err != nil {
			metrics.SMSMORequestsTotal.WithLabelValues("failure").Inc()
			s.log.Warn("sms: MO downlink NAS response failed", zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi), zap.Error(err))
			transaction.mu.Lock()
			transaction.state = moSMSFailed
			transaction.mu.Unlock()
			s.finishMOSMS(imsi, cp.TI, transaction)
			return
		}
		if sendErr == nil {
			metrics.SMSMORequestsTotal.WithLabelValues("success").Inc()
			s.log.Info("sms: MO RP-ACK sent in CP-DATA", zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi), zap.Uint8("cp_transaction_id", cp.TI), zap.Uint8("rp_reference", rp.Reference))
		}
		s.log.Info("sms: MO SMS waiting for final CP-ACK", zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi), zap.Uint8("cp_transaction_id", cp.TI))
		s.armMOFinalCPAckTimer(ue, imsi, cp.TI, transaction)
	}()
	return nil
}

func moSMSKey(imsi string, ti uint8) string { return fmt.Sprintf("%s:%d", imsi, ti) }

// findPendingMOSMS matches the UE-originated CP transaction identifier.  The
// MME sends its CP messages with the inverse TIO; the UE's final CP-ACK uses
// the original UE direction again, as in the Cisco trace (29 ... -> a9 ... ->
// 29 04).
func (s *Server) findPendingMOSMS(imsi string, ti uint8, ueTransactionFlag bool) *pendingMOSMS {
	v, ok := s.pendingMOSMS.Load(moSMSKey(imsi, ti))
	if !ok {
		return nil
	}
	tx := v.(*pendingMOSMS)
	tx.mu.Lock()
	matches := tx.ueTransactionFlag == ueTransactionFlag
	tx.mu.Unlock()
	if !matches {
		return nil
	}
	return tx
}

func (s *Server) finishMOSMS(imsi string, ti uint8, tx *pendingMOSMS) {
	key := moSMSKey(imsi, ti)
	if !s.pendingMOSMS.CompareAndDelete(key, tx) {
		return
	}
	s.pendingMOSMS.Delete(key)
	tx.mu.Lock()
	if tx.timer != nil {
		tx.timer.Stop()
		tx.timer = nil
	}
	tx.mu.Unlock()
	metrics.SMSActiveTransactions.Dec()
}

// armMOFinalCPAckTimer retains and retransmits the exact network CP-DATA. It
// never re-submits the MO SMS to SGd; CP retransmission is strictly UE-facing.
func (s *Server) armMOFinalCPAckTimer(ue *uecontext.Context, imsi string, ti uint8, tx *pendingMOSMS) {
	tx.mu.Lock()
	tx.timer = time.AfterFunc(smsTransactionTimeout(s), func() {
		s.retryMOFinalCPData(ue, imsi, ti, tx)
	})
	tx.mu.Unlock()
}

func (s *Server) retryMOFinalCPData(ue *uecontext.Context, imsi string, ti uint8, tx *pendingMOSMS) {
	tx.mu.Lock()
	if tx.state != moSMSWaitingFinalCPAck {
		tx.mu.Unlock()
		return
	}
	if tx.retries >= moSMSFinalCPRetries {
		tx.state = moSMSFailed
		tx.mu.Unlock()
		metrics.SMSTimerExpirationsTotal.WithLabelValues("mo_final_cp_ack").Inc()
		s.log.Warn("sms: MO SMS final CP-ACK timed out", zap.String("imsi", imsi), zap.Uint8("cp_transaction_id", ti))
		s.finishMOSMS(imsi, ti, tx)
		return
	}
	tx.retries++
	retry := tx.retries
	cp := append([]byte(nil), tx.downlinkCP...)
	tx.mu.Unlock()
	if err := s.sendSMSCP(ue, cp); err != nil {
		s.log.Warn("sms: MO CP-DATA retransmission failed", zap.String("imsi", imsi), zap.Uint8("cp_transaction_id", ti), zap.Error(err))
		tx.mu.Lock()
		tx.state = moSMSFailed
		tx.mu.Unlock()
		s.finishMOSMS(imsi, ti, tx)
		return
	}
	s.log.Info("sms: MO CP-DATA retransmitted awaiting final CP-ACK", zap.String("imsi", imsi), zap.Uint8("cp_transaction_id", ti), zap.Int("retry", retry))
	tx.mu.Lock()
	if tx.state == moSMSWaitingFinalCPAck {
		tx.timer.Reset(smsTransactionTimeout(s))
	}
	tx.mu.Unlock()
}

// HandleSGdMT delivers connected UEs immediately and queues ECM-IDLE UEs
// before invoking the existing paging coordinator.
func (s *Server) HandleSGdMT(req *sgd.MTRequest) (uint32, []byte) {
	metrics.SMSMTRequestsTotal.WithLabelValues("received").Inc()
	if req == nil || s.sms == nil {
		return diam.UnableToComply, nil
	}
	ue, ok := s.ueManager.GetByIMSI(req.IMSI)
	if !ok {
		return diam.UnableToDeliver, nil
	}
	ue.Lock()
	registered := ue.SMSRegistrationState == uecontext.SMSRegistrationRegistered
	connected := ue.ECMState == emm.ECMConnected
	ue.Unlock()
	if !registered {
		return diam.UnableToDeliver, nil
	}
	ti := s.allocateMTSMSTI(req.IMSI)
	pending := &pendingMTSMS{ti: ti, rpReference: ti, result: make(chan mtSMSResult, 1), request: req, state: "mt_received"}
	if _, loaded := s.pendingMTSMS.LoadOrStore(req.IMSI, pending); loaded {
		metrics.SMSDuplicateMessagesTotal.WithLabelValues("mt_tfr").Inc()
		return diam.TooBusy, nil
	}
	defer s.pendingMTSMS.Delete(req.IMSI)
	metrics.SMSActiveTransactions.Inc()
	defer metrics.SMSActiveTransactions.Dec()
	s.log.Info("sms: MT transaction created", zap.String("imsi", req.IMSI), zap.String("session_id", req.SessionID), zap.Uint8("cp_transaction_id", ti), zap.Uint8("rp_reference", ti), zap.String("state", pending.state))

	if !connected {
		if err := s.PageUE(req.IMSI); err != nil {
			metrics.SMSMTPagingTotal.WithLabelValues("failure").Inc()
			return diam.UnableToDeliver, nil
		}
		pending.state = "paging"
		metrics.SMSMTPagingTotal.WithLabelValues("started").Inc()
		s.log.Info("sms: MT paging started", zap.String("imsi", req.IMSI), zap.String("session_id", req.SessionID), zap.String("state", pending.state))
	} else if err := s.deliverMTPending(ue, pending); err != nil {
		return diam.UnableToDeliver, nil
	}
	timer := time.NewTimer(smsTransactionTimeout(s))
	defer timer.Stop()
	select {
	case result := <-pending.result:
		metrics.SMSMTRequestsTotal.WithLabelValues("delivered").Inc()
		return result.resultCode, result.rpui
	case <-timer.C:
		metrics.SMSMTRequestsTotal.WithLabelValues("timeout").Inc()
		metrics.SMSTimerExpirationsTotal.WithLabelValues("mt").Inc()
		return diam.UnableToDeliver, nil
	}
}

// deliverMTPending is invoked either immediately for an ECM-CONNECTED UE or
// after the Service Request's Initial Context Setup response. It completes
// the original TFR rather than asking the SMSC to submit a new transaction.
func (s *Server) deliverMTPending(ue *uecontext.Context, pending *pendingMTSMS) error {
	if pending == nil || pending.request == nil {
		return fmt.Errorf("sms: missing MT transaction")
	}
	rpdu, err := nassms.EncodeRPDataMT(pending.rpReference, pending.request.SCAddress, pending.request.SMRPUI)
	if err != nil {
		return err
	}
	// A network-originated CP transaction starts with TIO=0. The UE replies
	// with TIO=1 and the MME's final CP-ACK returns to TIO=0.
	cp, err := nassms.EncodeCPDataWithDirection(pending.ti, false, rpdu)
	if err != nil {
		return err
	}
	pending.state = "waiting_for_rp_ack"
	if err := s.sendSMSCP(ue, cp); err != nil {
		pending.state = "failed"
		return err
	}
	s.log.Info("sms: MT RP-DATA transmitted", zap.String("imsi", pending.request.IMSI), zap.String("session_id", pending.request.SessionID), zap.Uint8("cp_transaction_id", pending.ti), zap.Uint8("rp_reference", pending.rpReference), zap.String("state", pending.state))
	return nil
}

func smsTransactionTimeout(s *Server) time.Duration {
	if s.smsTimeout > 0 {
		return s.smsTimeout
	}
	return 30 * time.Second
}

func (s *Server) allocateMTSMSTI(imsi string) uint8 {
	s.smsMu.Lock()
	defer s.smsMu.Unlock()
	ti := s.nextMTSMSTI[imsi] & 0x07
	s.nextMTSMSTI[imsi] = (ti + 1) & 0x07
	return ti
}

func (s *Server) sendSMSCP(ue *uecontext.Context, cp []byte) error {
	// A Service Request is first decoded on a temporary context. Always route
	// SMS downlink traffic through the canonical IMSI context so a stale
	// temporary/released binding cannot produce remote="" / eNB-UE-ID=0 after
	// S1 resumption.
	if ue != nil && s.ueManager != nil {
		ue.Lock()
		imsi := ue.IMSI
		ue.Unlock()
		if imsi != "" {
			if current, ok := s.ueManager.GetByIMSI(imsi); ok {
				ue = current
			}
		}
	}
	if ue == nil {
		return fmt.Errorf("sms: nil UE context")
	}
	container, err := nassms.EncodeNASContainer(cp)
	if err != nil {
		return err
	}
	plain := append([]byte{emm.PDEPSMobilityMgmt, emm.MsgDownlinkNASTransport}, container...)
	ue.Lock()
	mmeID, enbID, enbAddr := ue.MMEUES1APID, ue.ENBS1APID, ue.ENBGlobalID
	protected, err := nas.EncodeIntegrityAndCiphered(plain, ue.IntAlg, ue.EncAlg, ue.KNASint, ue.KNASenc, uint32(ue.DLNASCount))
	if err == nil {
		ue.DLNASCount.Increment()
	}
	ue.Unlock()
	if err == nil {
		return s.sendDownlinkNASTransport(enbAddr, mmeID, enbID, protected)
	}
	return err
}

// deliverPendingMTSMS runs only after a Service Request's ICS response has
// made the S1 context usable. It resumes the original Diameter TFR transaction
// that is waiting in HandleSGdMT.
func (s *Server) deliverPendingMTSMS(ue *uecontext.Context) {
	if s.sms == nil || ue == nil {
		return
	}
	ue.Lock()
	imsi := ue.IMSI
	registered := ue.SMSRegistrationState == uecontext.SMSRegistrationRegistered
	ue.Unlock()
	if !registered {
		return
	}
	v, ok := s.pendingMTSMS.Load(imsi)
	if !ok {
		return
	}
	pending := v.(*pendingMTSMS)
	if pending.state != "paging" {
		return
	}
	pending.state = "resumed"
	s.log.Info("sms: MT UE resumed after paging", zap.String("imsi", imsi), zap.String("session_id", pending.request.SessionID), zap.String("state", pending.state))
	if err := s.deliverMTPending(ue, pending); err != nil {
		pending.state = "failed"
		select {
		case pending.result <- mtSMSResult{resultCode: diam.UnableToDeliver}:
		default:
		}
		s.log.Warn("sms: MT delivery after paging failed", zap.String("imsi", imsi), zap.Error(err))
	}
}
