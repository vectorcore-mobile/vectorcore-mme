package s1ap

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/vectorcore/mme/internal/diameter/sgd"
	"github.com/vectorcore/mme/internal/metrics"
	nas "github.com/vectorcore/mme/internal/nas"
	"github.com/vectorcore/mme/internal/nas/emm"
	nassms "github.com/vectorcore/mme/internal/nas/sms"
	"github.com/vectorcore/mme/internal/roaming"
	smsservice "github.com/vectorcore/mme/internal/sms"
	"github.com/vectorcore/mme/internal/uecontext"
	"go.uber.org/zap"
)

type pendingMTSMS struct {
	ti          uint8
	rpReference uint8
	result      chan sgd.MTOutcome
	request     *sgd.MTRequest
	state       string
	// cpDataSent is set once the downlink CP-DATA has gone to the eNB, so a
	// timeout can tell "paging unanswered" from "UE did not answer RP-DATA".
	cpDataSent atomic.Bool

	// TC1M retransmission state (TS 24.011 §5.3.2.1), guarded by cpMu.
	cpMu       sync.Mutex
	downlinkCP []byte
	cpAcked    bool
	finished   bool
	cpRetries  int
	tc1m       *time.Timer
}

// mtCPDataRetries is the maximum number of MT CP-DATA retransmissions,
// matching the MO path (moSMSFinalCPRetries).
const mtCPDataRetries = 2

// mtTC1M spaces the initial transmission and its retransmissions evenly
// inside the transaction timeout, so all of them fit before the TFA is due.
func mtTC1M(s *Server) time.Duration {
	return smsTransactionTimeout(s) / (mtCPDataRetries + 1)
}

// armMTRetransmission keeps the exact CP-DATA and starts TC1M.
func (s *Server) armMTRetransmission(ue *uecontext.Context, p *pendingMTSMS, cp []byte) {
	p.cpMu.Lock()
	defer p.cpMu.Unlock()
	if p.finished || p.cpAcked {
		return
	}
	p.downlinkCP = append([]byte(nil), cp...)
	p.tc1m = time.AfterFunc(mtTC1M(s), func() { s.retransmitMTCPData(ue, p) })
}

// retransmitMTCPData runs on TC1M expiry: resend the identical CP-DATA until
// the UE's CP-ACK arrives or the retransmission budget is used. Giving up
// leaves the outcome to the transaction timer.
func (s *Server) retransmitMTCPData(ue *uecontext.Context, p *pendingMTSMS) {
	p.cpMu.Lock()
	if p.finished || p.cpAcked {
		p.cpMu.Unlock()
		return
	}
	if p.cpRetries >= mtCPDataRetries {
		p.cpMu.Unlock()
		metrics.SMSTimerExpirationsTotal.WithLabelValues("mt_tc1m").Inc()
		s.log.Warn("sms: MT CP-ACK not received after retransmissions", zap.String("imsi", p.request.IMSI), zap.Uint8("cp_transaction_id", p.ti))
		return
	}
	p.cpRetries++
	retry := p.cpRetries
	cp := append([]byte(nil), p.downlinkCP...)
	p.cpMu.Unlock()
	if err := s.sendSMSCP(ue, cp); err != nil {
		s.log.Warn("sms: MT CP-DATA retransmission failed", zap.String("imsi", p.request.IMSI), zap.Uint8("cp_transaction_id", p.ti), zap.Error(err))
		return
	}
	s.log.Info("sms: MT CP-DATA retransmitted", zap.String("imsi", p.request.IMSI), zap.Uint8("cp_transaction_id", p.ti), zap.Int("retry", retry))
	p.cpMu.Lock()
	if !p.finished && !p.cpAcked {
		p.tc1m.Reset(mtTC1M(s))
	}
	p.cpMu.Unlock()
}

// ackMTCPData records the UE's CP-ACK for the MT CP-DATA and stops TC1M.
func (p *pendingMTSMS) ackMTCPData() {
	p.cpMu.Lock()
	defer p.cpMu.Unlock()
	p.cpAcked = true
	if p.tc1m != nil {
		p.tc1m.Stop()
	}
}

// finishMTRetransmission stops TC1M for good when the transaction ends.
func (p *pendingMTSMS) finishMTRetransmission() {
	p.cpMu.Lock()
	defer p.cpMu.Unlock()
	p.finished = true
	if p.tc1m != nil {
		p.tc1m.Stop()
	}
}

// TS 24.011 §8.1.4.2 CP-Cause and §8.2.5.4 RP-Cause values used for MT.
const (
	cpCauseCongestion             = 22
	rpCauseMemoryCapacityExceeded = 22
)

// mtRPErrorOutcome maps a UE RP-ERROR for an MT transfer to the TFA
// (TS 29.338 §5.3.2.4). Memory full waits for the memory-available alert;
// every other cause is the handset rejecting the message.
func mtRPErrorOutcome(cause uint8, userData []byte) sgd.MTOutcome {
	if cause == rpCauseMemoryCapacityExceeded {
		return sgd.MTDeliveryFailure(sgd.DeliveryFailureMemoryCapacityExceeded, userData)
	}
	return sgd.MTDeliveryFailure(sgd.DeliveryFailureEquipmentProtocolError, userData)
}

// mtTimeoutOutcome reports an MT transaction timer expiry as absent user:
// "no paging response" if the CP-DATA never reached the UE, otherwise
// "temporarily unavailable" (the UE did not answer the RP-DATA).
func mtTimeoutOutcome(pending *pendingMTSMS) sgd.MTOutcome {
	if !pending.cpDataSent.Load() {
		return sgd.MTAbsentUser(sgd.AbsentDiagNoPagingResponse)
	}
	return sgd.MTAbsentUser(sgd.AbsentDiagTemporarilyUnavailable)
}

// mtCPErrorOutcome maps a UE CP-ERROR for an MT transfer. Congestion means
// the UE cannot take another CP transaction now, so it is reported as busy
// (short retry); other causes are CP protocol errors in the handset.
func mtCPErrorOutcome(cause uint8) sgd.MTOutcome {
	if cause == cpCauseCongestion {
		return sgd.MTUserBusy()
	}
	return sgd.MTDeliveryFailure(sgd.DeliveryFailureEquipmentProtocolError, nil)
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
				case pending.result <- mtCPErrorOutcome(cause):
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
		// A CP-ACK with the TI flag set answers a network-originated
		// transaction: the MT CP-DATA (TS 24.011 §5.3.2.1). MO final CP-ACKs
		// carry the flag clear and are matched below.
		if cp.TransactionIDFlag {
			if v, ok := s.pendingMTSMS.Load(ueIMSI); ok {
				if pending := v.(*pendingMTSMS); pending.ti == cp.TI {
					pending.ackMTCPData()
					s.log.Debug("sms: MT CP-ACK received", zap.Uint32("mme_ue_id", mmeUEID), zap.Uint8("cp_transaction_id", cp.TI))
					return nil
				}
			}
		}
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
			case pending.result <- sgd.MTDelivered(rpui):
			default:
			}
			return nil
		}
		s.log.Debug("sms: late or unsolicited uplink RP-ACK", zap.Uint32("mme_ue_id", mmeUEID), zap.Uint8("rp_reference", ref), zap.Int("rp_user_data_length", len(rpui)))
		return nil
	}
	if ref, rpCause, rpUserData, rpErr := nassms.DecodeRPErrorMO(cp.RPDU); rpErr == nil {
		if v, ok := s.pendingMTSMS.Load(imsi); ok {
			pending := v.(*pendingMTSMS)
			if !cp.TransactionIDFlag || cp.TI != pending.ti || ref != pending.rpReference {
				return fmt.Errorf("sms: unmatched MT RP-ERROR")
			}
			ack, _ := nassms.EncodeCPAckWithDirection(cp.TI, !cp.TransactionIDFlag)
			_ = s.sendSMSCP(ue, ack)
			s.log.Info("sms: MT RP-ERROR received",
				zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi),
				zap.Uint8("rp_reference", ref), zap.Uint8("rp_cause", rpCause),
				zap.Int("rp_user_data_length", len(rpUserData)))
			select {
			case pending.result <- mtRPErrorOutcome(rpCause, rpUserData):
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
	// An MO CP transaction carries either RP-DATA (an SMS, relayed as SGd
	// OFR) or RP-SMMA (memory available, relayed as S6a NOR). Both share the
	// CP handling below; only the core-side request differs.
	var rpReference uint8
	smmaRef, smmaErr := nassms.DecodeRPSMMA(cp.RPDU)
	isSMMA := smmaErr == nil
	if isSMMA {
		rpReference = smmaRef
	} else {
		rp, err := nassms.DecodeRPDataMO(cp.RPDU)
		if err != nil {
			return err
		}
		rpReference = rp.Reference
	}
	key := moSMSKey(imsi, cp.TI)
	transaction := &pendingMOSMS{
		rpdu:              append([]byte(nil), cp.RPDU...),
		ti:                cp.TI,
		ueTransactionFlag: cp.TransactionIDFlag,
		rpReference:       rpReference,
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
			zap.Uint8("rp_reference", rpReference), zap.String("state", string(state)))
		ack, _ := nassms.EncodeCPAckWithDirection(cp.TI, !cp.TransactionIDFlag)
		return s.sendSMSCP(ue, ack)
	}
	s.log.Info("sms: MO CP-DATA received",
		zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi),
		zap.Uint8("cp_transaction_id", cp.TI), zap.Bool("transaction_identifier_flag", cp.TransactionIDFlag),
		zap.Uint8("rp_reference", rpReference), zap.String("state", string(transaction.state)))
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
		var response []byte
		var sendErr error
		if isSMMA {
			response, sendErr = s.relayMemoryAvailable(ctx, ue, imsi, rpReference)
		} else {
			var result *smsservice.MOResult
			result, sendErr = s.sms.HandleMO(ctx, imsi, msisdn, cp.RPDU)
			if sendErr == nil {
				s.log.Info("sms: received SGd MO-Forward-Short-Message-Answer",
					zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi), zap.Uint8("cp_transaction_id", cp.TI))
				response, _ = nassms.EncodeRPAckToMS(rpReference, result.SMRPUI)
				s.log.Debug("sms: MO RP-ACK generated", zap.Uint32("mme_ue_id", mmeUEID), zap.Uint8("rp_reference", rpReference))
			} else {
				metrics.SMSMORequestsTotal.WithLabelValues("failure").Inc()
				s.log.Warn("sms: MO SMS transaction failed",
					zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi), zap.Uint8("cp_transaction_id", cp.TI), zap.Error(sendErr))
				// RP cause #111: protocol error, unspecified. SGd-specific errors are
				// deliberately not exposed to the UE.
				response = []byte{nassms.RPErrorNetwork, rpReference, 1, 111}
			}
		}
		answer, _ := nassms.EncodeCPDataWithDirection(cp.TI, !cp.TransactionIDFlag, response)
		s.log.Debug("sms: MO RP-ACK encoded in CP-DATA", zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi), zap.Uint8("cp_transaction_id", cp.TI), zap.Uint8("rp_reference", rpReference), zap.Bool("transaction_identifier_flag", !cp.TransactionIDFlag))
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
		if sendErr == nil && !isSMMA {
			metrics.SMSMORequestsTotal.WithLabelValues("success").Inc()
			s.log.Info("sms: MO RP-ACK sent in CP-DATA", zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi), zap.Uint8("cp_transaction_id", cp.TI), zap.Uint8("rp_reference", rpReference))
		}
		s.log.Info("sms: MO SMS waiting for final CP-ACK", zap.Uint32("mme_ue_id", mmeUEID), zap.String("imsi", imsi), zap.Uint8("cp_transaction_id", cp.TI))
		s.armMOFinalCPAckTimer(ue, imsi, cp.TI, transaction)
	}()
	return nil
}

// TS 24.011 §8.2.5.4 RP-Cause values returned to the UE for RP-SMMA.
const (
	rpCauseUnknownSubscriber = 30
	rpCauseTemporaryFailure  = 41
)

// notifyS6aClient is implemented by the S6a Diameter handlers.
type notifyS6aClient interface {
	SendNotifyAlert(ctx context.Context, dest roaming.S6aRequest, alertReason int32) (uint32, error)
}

const (
	// alertReasonUEMemoryAvailable is TS 29.272 Alert-Reason UE_MEMORY_AVAILABLE.
	alertReasonUEMemoryAvailable int32 = 1
	// diameterErrorUserUnknown is TS 29.272 Experimental-Result
	// DIAMETER_ERROR_USER_UNKNOWN.
	diameterErrorUserUnknown uint32 = 5001
)

// relayMemoryAvailable forwards a UE's RP-SMMA to its HSS as an S6a
// Notify-Request with Alert-Reason UE_MEMORY_AVAILABLE (TS 29.272 §5.2.5.1),
// so the HSS clears MCEF and alerts the SMS-SC. It returns the RP-ACK or
// RP-ERROR to send to the UE (TS 24.011 §7.3.3/§7.3.4).
func (s *Server) relayMemoryAvailable(ctx context.Context, ue *uecontext.Context, imsi string, rpReference uint8) ([]byte, error) {
	notifier, ok := s.s6a.(notifyS6aClient)
	if !ok {
		s.log.Warn("sms: RP-SMMA received but S6a Notify is unavailable", zap.String("imsi", imsi))
		return []byte{nassms.RPErrorNetwork, rpReference, 1, rpCauseTemporaryFailure}, fmt.Errorf("sms: S6a Notify unavailable")
	}
	dest, routed := s.routedS6aRequest(ue)
	if !routed {
		dest = roaming.S6aRequest{SubscriberIMSI: imsi}
	}
	code, err := notifier.SendNotifyAlert(ctx, dest, alertReasonUEMemoryAvailable)
	switch {
	case err == nil && code == diam.Success:
		s.log.Info("sms: RP-SMMA relayed to HSS", zap.String("imsi", imsi), zap.Uint8("rp_reference", rpReference))
		ack, _ := nassms.EncodeRPAckToMS(rpReference, nil)
		return ack, nil
	case err == nil && code == diameterErrorUserUnknown:
		s.log.Warn("sms: HSS rejected RP-SMMA notify: user unknown", zap.String("imsi", imsi))
		return []byte{nassms.RPErrorNetwork, rpReference, 1, rpCauseUnknownSubscriber}, fmt.Errorf("sms: NOA result %d", code)
	default:
		if err == nil {
			err = fmt.Errorf("sms: NOA result %d", code)
		}
		s.log.Warn("sms: RP-SMMA notify failed", zap.String("imsi", imsi), zap.Error(err))
		return []byte{nassms.RPErrorNetwork, rpReference, 1, rpCauseTemporaryFailure}, err
	}
}

// alertReasonUEPresent is TS 29.272 Alert-Reason UE_PRESENT.
const alertReasonUEPresent int32 = 0

// markNotReachableForSMS sets MNRF after an MT SMS was answered absent-user,
// so the next UE activity tells the HSS (and through it the SMS-SC) that the
// UE can be reached. Without a UE context there is nothing to flag: a new
// attach (ULR) already makes the HSS alert the SMS-SC.
func (s *Server) markNotReachableForSMS(imsi string, outcome sgd.MTOutcome) {
	if outcome.ExperimentalResultCode != sgd.ResultErrorAbsentUser || imsi == "" || s.ueManager == nil {
		return
	}
	ue, ok := s.ueManager.GetByIMSI(imsi)
	if !ok {
		return
	}
	ue.Lock()
	ue.SMSNotReachableFlag = true
	ue.Unlock()
	s.log.Info("sms: MNRF set after absent-user MT", zap.String("imsi", imsi))
}

// notifyUEPresentIfNotReachable is called on UE activity. When MNRF is set it
// clears it and sends an S6a Notify-Request with Alert-Reason UE_PRESENT
// (TS 29.272 §5.2.5.1) to the subscriber's HSS, asynchronously. A failed
// notify sets MNRF again so the next activity retries.
func (s *Server) notifyUEPresentIfNotReachable(ue *uecontext.Context) {
	if ue == nil {
		return
	}
	notifier, ok := s.s6a.(notifyS6aClient)
	if !ok {
		return
	}
	ue.Lock()
	if !ue.SMSNotReachableFlag {
		ue.Unlock()
		return
	}
	ue.SMSNotReachableFlag = false
	imsi := ue.IMSI
	ue.Unlock()
	dest, routed := s.routedS6aRequest(ue)
	if !routed {
		dest = roaming.S6aRequest{SubscriberIMSI: imsi}
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), smsTransactionTimeout(s))
		defer cancel()
		code, err := notifier.SendNotifyAlert(ctx, dest, alertReasonUEPresent)
		switch {
		case err == nil && code == diam.Success:
			s.log.Info("sms: MNRF cleared, HSS notified UE present", zap.String("imsi", imsi))
		case err == nil && code == diameterErrorUserUnknown:
			s.log.Warn("sms: HSS rejected UE-present notify: user unknown", zap.String("imsi", imsi))
		default:
			if err == nil {
				err = fmt.Errorf("sms: NOA result %d", code)
			}
			ue.Lock()
			ue.SMSNotReachableFlag = true
			ue.Unlock()
			s.log.Warn("sms: UE-present notify failed; MNRF kept for retry", zap.String("imsi", imsi), zap.Error(err))
		}
	}()
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
//
// Failures are reported with TS 29.338 Experimental-Result codes: absent user
// (with Absent-User-Diagnostic-SM) when the UE cannot be reached, busy when
// another MT is in progress, and SM delivery failure when the UE rejects it.
func (s *Server) HandleSGdMT(req *sgd.MTRequest) sgd.MTOutcome {
	outcome := s.handleSGdMT(req)
	if req != nil {
		s.markNotReachableForSMS(req.IMSI, outcome)
	}
	return outcome
}

func (s *Server) handleSGdMT(req *sgd.MTRequest) sgd.MTOutcome {
	metrics.SMSMTRequestsTotal.WithLabelValues("received").Inc()
	if req == nil || s.sms == nil {
		return sgd.MTBaseResult(diam.UnableToComply)
	}
	// The whole TFR, including any wait for an earlier MT to the same UE,
	// is bounded by one transaction timeout so the TFA beats the SMS-SC's
	// own TFA timer.
	deadline := time.Now().Add(smsTransactionTimeout(s))
	if outcome, ok := s.mtUEUnreachable(req.IMSI); !ok {
		return outcome
	}
	release, outcome, ok := s.acquireMTTurn(req, deadline)
	if !ok {
		return outcome
	}
	defer release()
	// Re-read the UE: it may have detached, deregistered or gone idle while
	// this TFR was queued.
	ue, ok := s.ueManager.GetByIMSI(req.IMSI)
	if !ok {
		return sgd.MTAbsentUser(sgd.AbsentDiagIMSIDetached)
	}
	ue.Lock()
	registered := ue.SMSRegistrationState == uecontext.SMSRegistrationRegistered
	connected := ue.ECMState == emm.ECMConnected
	ue.Unlock()
	if !registered {
		return sgd.MTAbsentUser(sgd.AbsentDiagIMSIDetached)
	}
	ti := s.allocateMTSMSTI(req.IMSI)
	pending := &pendingMTSMS{ti: ti, rpReference: ti, result: make(chan sgd.MTOutcome, 1), request: req, state: "mt_received"}
	if _, loaded := s.pendingMTSMS.LoadOrStore(req.IMSI, pending); loaded {
		// acquireMTTurn serialises MTs per IMSI, so this is only reachable if
		// a transaction was left behind; never run two at once.
		metrics.SMSDuplicateMessagesTotal.WithLabelValues("mt_tfr").Inc()
		return sgd.MTUserBusy()
	}
	defer s.pendingMTSMS.Delete(req.IMSI)
	defer pending.finishMTRetransmission()
	metrics.SMSActiveTransactions.Inc()
	defer metrics.SMSActiveTransactions.Dec()
	s.log.Info("sms: MT transaction created", zap.String("imsi", req.IMSI), zap.String("session_id", req.SessionID), zap.Uint8("cp_transaction_id", ti), zap.Uint8("rp_reference", ti), zap.String("state", pending.state))

	if !connected {
		if err := s.PageUE(req.IMSI); err != nil {
			metrics.SMSMTPagingTotal.WithLabelValues("failure").Inc()
			return sgd.MTAbsentUser(sgd.AbsentDiagTemporarilyUnavailable)
		}
		pending.state = "paging"
		metrics.SMSMTPagingTotal.WithLabelValues("started").Inc()
		s.log.Info("sms: MT paging started", zap.String("imsi", req.IMSI), zap.String("session_id", req.SessionID), zap.String("state", pending.state))
	} else if err := s.deliverMTPending(ue, pending); err != nil {
		return sgd.MTAbsentUser(sgd.AbsentDiagTemporarilyUnavailable)
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case outcome := <-pending.result:
		metrics.SMSMTRequestsTotal.WithLabelValues("delivered").Inc()
		return outcome
	case <-timer.C:
		metrics.SMSMTRequestsTotal.WithLabelValues("timeout").Inc()
		metrics.SMSTimerExpirationsTotal.WithLabelValues("mt").Inc()
		return mtTimeoutOutcome(pending)
	}
}

// mtUEUnreachable fails fast, before queueing, for a TFR that cannot be
// delivered whatever happens to earlier MTs.
func (s *Server) mtUEUnreachable(imsi string) (sgd.MTOutcome, bool) {
	ue, ok := s.ueManager.GetByIMSI(imsi)
	if !ok {
		return sgd.MTAbsentUser(sgd.AbsentDiagIMSIDetached), false
	}
	ue.Lock()
	registered := ue.SMSRegistrationState == uecontext.SMSRegistrationRegistered
	ue.Unlock()
	if !registered {
		return sgd.MTAbsentUser(sgd.AbsentDiagIMSIDetached), false
	}
	return sgd.MTOutcome{}, true
}

// maxQueuedMTPerIMSI bounds the TFRs that may wait behind a running MT for
// the same UE; more are answered busy at once.
const maxQueuedMTPerIMSI = 8

// mtQueue serialises MT transactions for one IMSI. TS 24.011 allows one MT
// CP transaction per UE at a time, so later TFRs wait their turn (FIFO)
// instead of being rejected.
type mtQueue struct {
	waiters []chan struct{}
}

// acquireMTTurn waits until no other MT is running for req.IMSI. A queue entry
// in s.mtQueues means an MT is running; its waiters get the turn in order.
// If the deadline passes while queued the TFR is answered busy
// (DIAMETER_ERROR_USER_BUSY_FOR_MT_SMS), which the SMS-SC retries shortly.
func (s *Server) acquireMTTurn(req *sgd.MTRequest, deadline time.Time) (release func(), outcome sgd.MTOutcome, ok bool) {
	imsi := req.IMSI
	release = func() { s.releaseMTTurn(imsi) }
	s.smsMu.Lock()
	if s.mtQueues == nil {
		s.mtQueues = make(map[string]*mtQueue)
	}
	q, running := s.mtQueues[imsi]
	if !running {
		s.mtQueues[imsi] = &mtQueue{}
		s.smsMu.Unlock()
		return release, sgd.MTOutcome{}, true
	}
	if len(q.waiters) >= maxQueuedMTPerIMSI {
		s.smsMu.Unlock()
		metrics.SMSDuplicateMessagesTotal.WithLabelValues("mt_tfr_queue_full").Inc()
		s.log.Warn("sms: MT queue full, answering busy", zap.String("imsi", imsi), zap.String("session_id", req.SessionID))
		return nil, sgd.MTUserBusy(), false
	}
	turn := make(chan struct{})
	q.waiters = append(q.waiters, turn)
	position := len(q.waiters)
	s.smsMu.Unlock()
	s.log.Info("sms: MT queued behind running transaction", zap.String("imsi", imsi), zap.String("session_id", req.SessionID), zap.Int("position", position))

	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-turn:
		return release, sgd.MTOutcome{}, true
	case <-timer.C:
	}
	s.smsMu.Lock()
	for i, w := range q.waiters {
		if w == turn {
			q.waiters = append(q.waiters[:i], q.waiters[i+1:]...)
			s.smsMu.Unlock()
			s.log.Warn("sms: MT timed out in queue, answering busy", zap.String("imsi", imsi), zap.String("session_id", req.SessionID))
			return nil, sgd.MTUserBusy(), false
		}
	}
	s.smsMu.Unlock()
	// The turn was handed over just as the deadline fired; pass it on.
	<-turn
	s.releaseMTTurn(imsi)
	return nil, sgd.MTUserBusy(), false
}

// releaseMTTurn hands the IMSI's MT turn to the next waiter, or ends the
// queue when nobody is waiting.
func (s *Server) releaseMTTurn(imsi string) {
	s.smsMu.Lock()
	defer s.smsMu.Unlock()
	q, ok := s.mtQueues[imsi]
	if !ok {
		return
	}
	if len(q.waiters) == 0 {
		delete(s.mtQueues, imsi)
		return
	}
	next := q.waiters[0]
	q.waiters = q.waiters[1:]
	close(next)
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
	pending.cpDataSent.Store(true)
	s.armMTRetransmission(ue, pending, cp)
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
		case pending.result <- sgd.MTAbsentUser(sgd.AbsentDiagTemporarilyUnavailable):
		default:
		}
		s.log.Warn("sms: MT delivery after paging failed", zap.String("imsi", imsi), zap.Error(err))
	}
}
