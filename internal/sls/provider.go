package sls

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/metrics"
)

// lcsClientTypeRootCount is the number of root values in the LCS-AP
// LCS-Client-Type ENUMERATED (TS 29.171 lcs-ap-ies.asn1): emergency-Services,
// value-Added-Services, pLMN-Operator-Services, lawful-Intercept-Services,
// pLMN-Operator-broadcast-Services, pLMN-Operator-OM,
// pLMN-Operator-Anonymous-Statistics, pLMN-Operator-Target-MS-Service-Support.
// The Diameter SLg LCS-Client-Type AVP (TS 29.173) only defines the first 4
// (0-3), and its numeric values are identical to these root indices, so the
// Diameter enumerated value can be forwarded unchanged.
const lcsClientTypeRootCount = 8

// accuracyFulfilmentRootCount is the number of root values in the LCS-AP
// Accuracy-Fulfillment-Indicator ENUMERATED (TS 29.171 lcs-ap-ies.asn1):
// requested-accuracy-fulfilled(0), requested-accuracy-not-fulfilled(1). The
// Diameter Accuracy-Fulfilment-Indicator AVP (code 2513) uses the identical
// numeric mapping, so the decoded index can be forwarded unchanged.
const accuracyFulfilmentRootCount = 2

func encodeLCSClientType(clientType uint32) []byte {
	w := aper.NewBitWriter()
	aper.EncodeEnumeratedExt(w, int(clientType), lcsClientTypeRootCount)
	return w.Bytes()
}

// encodeUEPositioningCapability encodes the LCS-AP UE-Positioning-Capability
// IE (TS 29.171 lcs-ap-ies.asn1: "UE-Positioning-Capability ::= SEQUENCE {
// lPP BOOLEAN, ... }"). The SEQUENCE is extensible with no root OPTIONAL
// components, so its preamble is a single extension-marker bit (matching the
// pattern in internal/s1ap/pdu/procedure_body.go's EncodeProcedureIEContainer)
// followed directly by the lPP field.
//
// The MME has no per-UE signal for LPP support today; EPS Rel-9+ devices
// that participate in control-plane LCS at all overwhelmingly support LPP,
// so this is sent unconditionally true rather than left unsent.
func encodeUEPositioningCapability(lppSupport bool) []byte {
	w := aper.NewBitWriter()
	w.WriteBit(0) // UE-Positioning-Capability SEQUENCE extension marker: no extensions
	aper.EncodeBoolean(w, lppSupport)
	return w.Bytes()
}

var (
	ErrUnavailable = errors.New("sls: E-SMLC unavailable")
	ErrMalformed   = errors.New("sls: malformed LCS-AP")
	ErrCapacity    = errors.New("sls: transaction capacity reached")
	ErrLate        = errors.New("sls: stale or unknown transaction")
)

type Transport interface {
	Available() bool
	Send(context.Context, []byte) error
}
type transaction struct {
	key       string
	mmeUEID   uint32
	routingID uint8
	done      chan result
}
type PositioningRelay interface {
	SendDownlinkLPPa(uint32, uint8, []byte) error
	// SendDownlinkLPP's second argument is the SLs Correlation ID (TS
	// 29.171) for the owning transaction, carried to the UE as the NAS
	// Routing Identifier per TS 24.171 §5.3.2.1.1.
	SendDownlinkLPP(uint32, []byte, []byte) error
}

// pendingLPPCleaner is deliberately optional: a relay may keep a bounded
// ECM-idle delivery queue, but the SLs provider remains the owner of the
// positioning transaction and tells that relay when the transaction ends.
// Keeping this as a narrow optional interface preserves the existing relay
// surface for callers that do not need deferred NAS delivery.
type pendingLPPCleaner interface {
	ClearPendingLPP(uint32)
}
type result struct {
	estimate                    []byte
	positioningData             []byte
	accuracyFulfilmentIndicator uint32
	accuracyFulfilmentPresent   bool
	err                         error
}

// PositionResult is the outcome of a completed RequestPosition call. The raw
// LCS-AP Positioning-Data bytes are forwarded unchanged: TS 29.172's
// EUTRAN-Positioning-Data AVP states its "internal structure and encoding is
// defined in 3GPP TS 29.171", i.e. the GMLC is expected to decode the same
// LCS-AP wire encoding, so no MME-side reinterpretation is needed or correct.
type PositionResult struct {
	Estimate                    []byte
	PositioningData             []byte
	AccuracyFulfilmentIndicator uint32
	AccuracyFulfilmentPresent   bool
}

// Provider owns terminal completion. Every waiter defers remove, therefore a
// response, cancellation, timeout, association loss and Close remove once.
type Provider struct {
	timeout time.Duration
	max     int
	t       Transport
	log     *zap.Logger
	mu      sync.Mutex
	tx      map[string]*transaction
	next    uint32
	closed  bool
	relay   PositioningRelay
}

func NewProvider(timeout time.Duration, max int, t Transport, l *zap.Logger) *Provider {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if max < 1 {
		max = 1
	}
	if l == nil {
		l = zap.NewNop()
	}
	return &Provider{timeout: timeout, max: max, t: t, log: l, tx: map[string]*transaction{}}
}
func (p *Provider) RequestPosition(ctx context.Context, key string, mmeUEID uint32, ecgi []byte, clientType uint32) (PositionResult, error) {
	if len(ecgi) != 7 {
		p.log.Warn("sls: RequestPosition rejected", zap.String("key", key), zap.Uint32("mme_ue_id", mmeUEID), zap.String("reason", "invalid ECGI length"))
		return PositionResult{}, ErrUnavailable
	}
	if p.t == nil || !p.t.Available() {
		p.log.Warn("sls: RequestPosition rejected", zap.String("key", key), zap.Uint32("mme_ue_id", mmeUEID), zap.String("reason", "transport unavailable"))
		return PositionResult{}, ErrUnavailable
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		p.log.Warn("sls: RequestPosition rejected", zap.String("key", key), zap.Uint32("mme_ue_id", mmeUEID), zap.String("reason", "provider closed"))
		return PositionResult{}, ErrUnavailable
	}
	if len(p.tx) >= p.max {
		p.mu.Unlock()
		p.log.Warn("sls: RequestPosition rejected", zap.String("key", key), zap.Uint32("mme_ue_id", mmeUEID), zap.String("reason", "transaction capacity reached"), zap.Int("max", p.max))
		return PositionResult{}, ErrCapacity
	}
	// EPS Generic NAS Transport carries no SLs correlation identifier. Keep one
	// active LPP-capable positioning session per authenticated UE so uplink LPP
	// is never routed ambiguously to a different E-SMLC transaction.
	for _, active := range p.tx {
		if active.mmeUEID == mmeUEID {
			p.mu.Unlock()
			p.log.Warn("sls: RequestPosition rejected", zap.String("key", key), zap.Uint32("mme_ue_id", mmeUEID), zap.String("reason", "positioning already active for this UE"))
			return PositionResult{}, ErrCapacity
		}
	}
	p.next++
	if p.next == 0 {
		p.next++
	}
	var id [4]byte
	binary.BigEndian.PutUint32(id[:], p.next)
	k := string(id[:])
	route := uint8(p.next)
	if route == 0 {
		route = 1
	}
	x := &transaction{key: key, mmeUEID: mmeUEID, routingID: route, done: make(chan result, 1)}
	p.tx[k] = x
	metrics.PositioningRequestsTotal.Inc()
	metrics.PositioningActiveTransactions.Inc()
	p.mu.Unlock()
	defer p.remove(k, x)
	w, err := Encode(PDU{Category: Initiating, Procedure: ProcedureLocationRequest, Criticality: aperReject, IEs: []IE{{IECorrelationID, aperReject, id[:], true}, {IELocationType, aperReject, []byte{0}, true}, {IEECGI, aperIgnore, append([]byte(nil), ecgi...), true}, {IELCSClientType, aperReject, encodeLCSClientType(clientType), true}, {IEUEPositioningCapability, aperReject, encodeUEPositioningCapability(true), true}}})
	if err != nil {
		p.log.Warn("sls: LCS-AP encode failed", zap.String("key", key), zap.Uint32("mme_ue_id", mmeUEID), zap.Error(err))
		return PositionResult{}, err
	}
	if err = p.t.Send(ctx, w); err != nil {
		p.log.Warn("sls: Location Request send failed", zap.String("key", key), zap.Uint32("mme_ue_id", mmeUEID), zap.Error(err))
		return PositionResult{}, err
	}
	p.log.Info("sls: Location Request sent", zap.String("key", key), zap.Uint32("mme_ue_id", mmeUEID), zap.Uint8("routing_id", route), zap.Uint32("lcs_client_type", clientType))
	wctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	select {
	case r := <-x.done:
		if r.err != nil {
			p.log.Warn("sls: positioning failed", zap.String("key", key), zap.Uint32("mme_ue_id", mmeUEID), zap.Error(r.err))
		} else {
			p.log.Info("sls: positioning succeeded", zap.String("key", key), zap.Uint32("mme_ue_id", mmeUEID), zap.Int("estimate_len", len(r.estimate)))
		}
		return PositionResult{Estimate: r.estimate, PositioningData: r.positioningData, AccuracyFulfilmentIndicator: r.accuracyFulfilmentIndicator, AccuracyFulfilmentPresent: r.accuracyFulfilmentPresent}, r.err
	case <-wctx.Done():
		p.log.Warn("sls: positioning timed out", zap.String("key", key), zap.Uint32("mme_ue_id", mmeUEID), zap.Duration("timeout", p.timeout))
		metrics.PositioningFailureTotal.WithLabelValues("timeout").Inc()
		return PositionResult{}, wctx.Err()
	}
}

// lcsCauseMiscUnspecified encodes the LCS-Cause IE (TS 29.171 lcs-ap-ies.asn1:
// "LCS-Cause ::= CHOICE { radio-Network-Layer, transport-Layer, protocol,
// misc }", a non-extensible CHOICE — no leading extension-marker bit, unlike
// the extensible types elsewhere in this file) as misc(3)/unspecified(3).
// "Misc-Cause ::= ENUMERATED { processing-Overload, hardware-Failure,
// o-And-M-Intervention, unspecified, ..., ciphering-key-data-lost }" is
// itself extensible. This is the only cause AbortPosition currently has a
// reason to send (UE detach / transaction superseded — not a technical
// positioning failure), so no richer cause taxonomy is exposed yet.
func lcsCauseMiscUnspecified() []byte {
	w := aper.NewBitWriter()
	aper.EncodeEnumerated(w, 3, 4)    // LCS-Cause CHOICE index 3 = misc (non-extensible)
	aper.EncodeEnumeratedExt(w, 3, 4) // Misc-Cause value 3 = unspecified
	return w.Bytes()
}

// AbortPosition sends a Location-Abort-Request (TS 29.171 §7.3.3: "sent by
// the MME to abort the positioning attempt... Direction: MME → E-SMLC") for
// every transaction active for mmeUEID, then locally completes each waiting
// RequestPosition call with context.Canceled rather than leaving it to run
// out its full timeout. Called on UE lifecycle events (detach, superseded
// transaction) where the MME has already given up locally.
func (p *Provider) AbortPosition(mmeUEID uint32) {
	type active struct {
		id []byte // 4-byte correlation ID, the p.tx map key
		x  *transaction
	}
	p.mu.Lock()
	var found []active
	for k, x := range p.tx {
		if x.mmeUEID == mmeUEID {
			found = append(found, active{id: []byte(k), x: x})
		}
	}
	p.mu.Unlock()
	if len(found) == 0 {
		return
	}
	cause := lcsCauseMiscUnspecified()
	for _, a := range found {
		w, err := Encode(PDU{Category: Initiating, Procedure: ProcedureLocationAbort, Criticality: aperReject, IEs: []IE{{IECorrelationID, aperReject, a.id, true}, {IELCSCause, aperIgnore, cause, true}}})
		if err != nil {
			p.log.Warn("sls: Location Abort encode failed", zap.String("key", a.x.key), zap.Uint32("mme_ue_id", mmeUEID), zap.Error(err))
		} else if p.t == nil {
			// no transport configured; nothing to notify the E-SMLC with
		} else if err := p.t.Send(context.Background(), w); err != nil {
			p.log.Warn("sls: Location Abort send failed", zap.String("key", a.x.key), zap.Uint32("mme_ue_id", mmeUEID), zap.Error(err))
		} else {
			p.log.Info("sls: Location Abort sent", zap.String("key", a.x.key), zap.Uint32("mme_ue_id", mmeUEID))
		}
		select {
		case a.x.done <- result{err: context.Canceled}:
		default:
		}
	}
}

// payloadTypeRootCount is the number of root values in the LCS-AP
// Payload-Type ENUMERATED (TS 29.171 §7.4.17): LPP(0), LPPa(1).
const payloadTypeRootCount = 2
const (
	payloadTypeLPP  = 0
	payloadTypeLPPa = 1
)

// encodePayloadType/decodePayloadType are the proper APER encoding for the
// Payload-Type IE, matching every other extensible ENUMERATED in this
// package (e.g. encodeLCSClientType). A prior version of this file used
// hardcoded raw bytes (0x00/0x80) instead: the correctly APER-encoded LPPa
// value is 0x40 (extension-marker bit 0, value bit 1, zero-padded to the
// byte), not 0x80, which silently misclassified every LPPa Connection
// Oriented Information message as LPP.
func encodePayloadType(v int) []byte {
	w := aper.NewBitWriter()
	aper.EncodeEnumeratedExt(w, v, payloadTypeRootCount)
	return w.Bytes()
}
func decodePayloadType(b []byte) (int, error) {
	return aper.DecodeEnumeratedExt(aper.NewBitReader(b), payloadTypeRootCount)
}

func (p *Provider) SetLPPaRelay(relay PositioningRelay) { p.mu.Lock(); p.relay = relay; p.mu.Unlock() }
func (p *Provider) HandleUplinkLPP(mmeUEID uint32, payload []byte) error {
	if len(payload) == 0 {
		return ErrMalformed
	}
	p.mu.Lock()
	var id string
	for key, tx := range p.tx {
		if tx.mmeUEID == mmeUEID {
			id = key
			break
		}
	}
	p.mu.Unlock()
	if id == "" {
		return ErrLate
	}
	metrics.PositioningLPPUplinkTotal.Inc()
	w, err := Encode(PDU{Category: Initiating, Procedure: ProcedureConnectionOrientedInformation, Criticality: aperIgnore, IEs: []IE{{ID: IECorrelationID, Criticality: aperReject, Value: []byte(id), Known: true}, {ID: IEPayloadType, Criticality: aperReject, Value: encodePayloadType(payloadTypeLPP), Known: true}, {ID: IEAPDU, Criticality: aperReject, Value: append([]byte(nil), payload...), Known: true}}})
	if err != nil {
		return err
	}
	return p.t.Send(context.Background(), w)
}
func (p *Provider) HandleUplinkLPPa(mmeUEID uint32, routingID uint8, payload []byte) error {
	if len(payload) == 0 {
		return ErrMalformed
	}
	p.mu.Lock()
	var id string
	for key, tx := range p.tx {
		if tx.mmeUEID == mmeUEID && tx.routingID == routingID {
			id = key
			break
		}
	}
	p.mu.Unlock()
	if id == "" {
		return ErrLate
	}
	w, err := Encode(PDU{Category: Initiating, Procedure: ProcedureConnectionOrientedInformation, Criticality: aperIgnore, IEs: []IE{{ID: IECorrelationID, Criticality: aperReject, Value: []byte(id), Known: true}, {ID: IEPayloadType, Criticality: aperReject, Value: encodePayloadType(payloadTypeLPPa), Known: true}, {ID: IEAPDU, Criticality: aperReject, Value: append([]byte(nil), payload...), Known: true}}})
	if err != nil {
		return err
	}
	return p.t.Send(context.Background(), w)
}

// aliases avoid leaking the APER package into call-sites.
const aperReject = 0
const aperIgnore = 1

func (p *Provider) HandleInbound(w []byte) error {
	pdu, err := Decode(w)
	if err != nil {
		return err
	}
	if pdu.Procedure == ProcedureReset {
		if pdu.Category != Initiating {
			return ErrMalformed
		}
		p.log.Warn("sls: E-SMLC Reset received", zap.Int("active_transactions", p.activeCount()))
		p.AssociationLost(ErrUnavailable)
		ack, e := Encode(PDU{Category: Successful, Procedure: ProcedureReset, Criticality: aperReject})
		if e != nil {
			return e
		}
		return p.t.Send(context.Background(), ack)
	}
	if pdu.Procedure == ProcedureLocationAbort && pdu.Category == Initiating {
		id, e := correlation(pdu)
		if e != nil {
			return e
		}
		p.mu.Lock()
		x := p.tx[string(id)]
		p.mu.Unlock()
		if x == nil {
			return ErrLate
		}
		p.log.Info("sls: Location Abort received", zap.String("key", x.key), zap.Uint32("mme_ue_id", x.mmeUEID))
		select {
		case x.done <- result{err: context.Canceled}:
			return nil
		default:
			return ErrLate
		}
	}
	if pdu.Procedure == ProcedureConnectionOrientedInformation && pdu.Category == Initiating {
		id, e := correlation(pdu)
		if e != nil {
			return e
		}
		var payload, payloadType []byte
		for _, ie := range pdu.IEs {
			if ie.ID == IEAPDU {
				payload = append([]byte(nil), ie.Value...)
			}
			if ie.ID == IEPayloadType {
				payloadType = append([]byte(nil), ie.Value...)
			}
		}
		if len(payload) == 0 {
			return ErrMalformed
		}
		p.mu.Lock()
		tx := p.tx[string(id)]
		relay := p.relay
		p.mu.Unlock()
		if tx == nil || relay == nil {
			return ErrLate
		}
		if len(payloadType) == 0 {
			return ErrMalformed
		}
		pt, e := decodePayloadType(payloadType)
		if e != nil {
			return ErrMalformed
		}
		if pt == payloadTypeLPP {
			p.log.Debug("sls: downlink LPP relayed", zap.String("key", tx.key), zap.Uint32("mme_ue_id", tx.mmeUEID), zap.Int("payload_len", len(payload)))
			return relay.SendDownlinkLPP(tx.mmeUEID, id, payload)
		}
		p.log.Debug("sls: downlink LPPa relayed", zap.String("key", tx.key), zap.Uint32("mme_ue_id", tx.mmeUEID), zap.Uint8("routing_id", tx.routingID), zap.Int("payload_len", len(payload)))
		return relay.SendDownlinkLPPa(tx.mmeUEID, tx.routingID, payload)
	}
	if pdu.Procedure != ProcedureLocationRequest || (pdu.Category != Successful && pdu.Category != Unsuccessful) {
		return ErrMalformed
	}
	id, err := correlation(pdu)
	if err != nil {
		return err
	}
	seen := map[uint16]bool{}
	var estimate, positioningData []byte
	var cause bool
	var accuracyFulfilmentIndicator uint32
	var accuracyFulfilmentPresent bool
	for _, ie := range pdu.IEs {
		if seen[ie.ID] {
			return ErrMalformed
		}
		seen[ie.ID] = true
		if !ie.Known && ie.Criticality == aperReject {
			return ErrMalformed
		}
		switch ie.ID {
		case IELocationEstimate:
			estimate = append([]byte(nil), ie.Value...)
		case IELCSCause:
			cause = true
		case IEPositioningData:
			positioningData = append([]byte(nil), ie.Value...)
		case IEAccuracyFulfilmentIndicator:
			v, e := aper.DecodeEnumeratedExt(aper.NewBitReader(ie.Value), accuracyFulfilmentRootCount)
			if e != nil {
				return ErrMalformed
			}
			accuracyFulfilmentIndicator = uint32(v)
			accuracyFulfilmentPresent = true
		}
	}
	if pdu.Category == Unsuccessful && !cause {
		return ErrMalformed
	}
	p.mu.Lock()
	x := p.tx[string(id)]
	p.mu.Unlock()
	if x == nil {
		return ErrLate
	}
	r := result{estimate: estimate, positioningData: positioningData, accuracyFulfilmentIndicator: accuracyFulfilmentIndicator, accuracyFulfilmentPresent: accuracyFulfilmentPresent}
	if pdu.Category == Unsuccessful || len(estimate) == 0 {
		r.err = ErrUnavailable
	}
	if r.err != nil {
		p.log.Warn("sls: Location Response received", zap.String("key", x.key), zap.Uint32("mme_ue_id", x.mmeUEID), zap.Bool("successful", pdu.Category == Successful), zap.Bool("cause_present", cause))
	} else {
		p.log.Info("sls: Location Response received", zap.String("key", x.key), zap.Uint32("mme_ue_id", x.mmeUEID), zap.Bool("successful", true), zap.Int("estimate_len", len(estimate)))
	}
	select {
	case x.done <- r:
		if r.err == nil {
			metrics.PositioningSuccessTotal.Inc()
		} else {
			metrics.PositioningFailureTotal.WithLabelValues("esmlc").Inc()
		}
		return nil
	default:
		return ErrLate
	}
}
func (p *Provider) activeCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.tx)
}
func (p *Provider) AssociationLost(err error) {
	if err == nil {
		err = ErrUnavailable
	}
	p.mu.Lock()
	all := make([]*transaction, 0, len(p.tx))
	for _, x := range p.tx {
		all = append(all, x)
	}
	p.mu.Unlock()
	if len(all) > 0 {
		p.log.Warn("sls: association lost, aborting active transactions", zap.Int("count", len(all)), zap.Error(err))
	}
	for _, x := range all {
		select {
		case x.done <- result{err: err}:
		default:
		}
	}
}
func (p *Provider) Close() {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	p.AssociationLost(context.Canceled)
}
func (p *Provider) remove(k string, x *transaction) {
	p.mu.Lock()
	if p.tx[k] == x {
		delete(p.tx, k)
		metrics.PositioningActiveTransactions.Dec()
	}
	relay := p.relay
	p.mu.Unlock()
	if cleaner, ok := relay.(pendingLPPCleaner); ok {
		cleaner.ClearPendingLPP(x.mmeUEID)
	}
}
