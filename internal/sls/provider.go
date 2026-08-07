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

func encodeLCSClientType(clientType uint32) []byte {
	w := aper.NewBitWriter()
	aper.EncodeEnumeratedExt(w, int(clientType), lcsClientTypeRootCount)
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
	SendDownlinkLPP(uint32, []byte) error
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
	estimate []byte
	err      error
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
func (p *Provider) RequestPosition(ctx context.Context, key string, mmeUEID uint32, ecgi []byte, clientType uint32) ([]byte, error) {
	if len(ecgi) != 7 {
		p.log.Warn("sls: RequestPosition rejected", zap.String("key", key), zap.Uint32("mme_ue_id", mmeUEID), zap.String("reason", "invalid ECGI length"))
		return nil, ErrUnavailable
	}
	if p.t == nil || !p.t.Available() {
		p.log.Warn("sls: RequestPosition rejected", zap.String("key", key), zap.Uint32("mme_ue_id", mmeUEID), zap.String("reason", "transport unavailable"))
		return nil, ErrUnavailable
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		p.log.Warn("sls: RequestPosition rejected", zap.String("key", key), zap.Uint32("mme_ue_id", mmeUEID), zap.String("reason", "provider closed"))
		return nil, ErrUnavailable
	}
	if len(p.tx) >= p.max {
		p.mu.Unlock()
		p.log.Warn("sls: RequestPosition rejected", zap.String("key", key), zap.Uint32("mme_ue_id", mmeUEID), zap.String("reason", "transaction capacity reached"), zap.Int("max", p.max))
		return nil, ErrCapacity
	}
	// EPS Generic NAS Transport carries no SLs correlation identifier. Keep one
	// active LPP-capable positioning session per authenticated UE so uplink LPP
	// is never routed ambiguously to a different E-SMLC transaction.
	for _, active := range p.tx {
		if active.mmeUEID == mmeUEID {
			p.mu.Unlock()
			p.log.Warn("sls: RequestPosition rejected", zap.String("key", key), zap.Uint32("mme_ue_id", mmeUEID), zap.String("reason", "positioning already active for this UE"))
			return nil, ErrCapacity
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
	w, err := Encode(PDU{Category: Initiating, Procedure: ProcedureLocationRequest, Criticality: aperReject, IEs: []IE{{IECorrelationID, aperReject, id[:], true}, {IELocationType, aperReject, []byte{0}, true}, {IEECGI, aperIgnore, append([]byte(nil), ecgi...), true}, {IELCSClientType, aperReject, encodeLCSClientType(clientType), true}}})
	if err != nil {
		p.log.Warn("sls: LCS-AP encode failed", zap.String("key", key), zap.Uint32("mme_ue_id", mmeUEID), zap.Error(err))
		return nil, err
	}
	if err = p.t.Send(ctx, w); err != nil {
		p.log.Warn("sls: Location Request send failed", zap.String("key", key), zap.Uint32("mme_ue_id", mmeUEID), zap.Error(err))
		return nil, err
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
		return r.estimate, r.err
	case <-wctx.Done():
		p.log.Warn("sls: positioning timed out", zap.String("key", key), zap.Uint32("mme_ue_id", mmeUEID), zap.Duration("timeout", p.timeout))
		metrics.PositioningFailureTotal.WithLabelValues("timeout").Inc()
		return nil, wctx.Err()
	}
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
	w, err := Encode(PDU{Category: Initiating, Procedure: 1, Criticality: aperIgnore, IEs: []IE{{ID: IECorrelationID, Criticality: aperReject, Value: []byte(id), Known: true}, {ID: 15, Criticality: aperReject, Value: []byte{0}, Known: true}, {ID: 1, Criticality: aperReject, Value: append([]byte(nil), payload...), Known: true}}})
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
	w, err := Encode(PDU{Category: Initiating, Procedure: 1, Criticality: aperIgnore, IEs: []IE{{ID: IECorrelationID, Criticality: aperReject, Value: []byte(id), Known: true}, {ID: 15, Criticality: aperReject, Value: []byte{0x80}, Known: true}, {ID: 1, Criticality: aperReject, Value: append([]byte(nil), payload...), Known: true}}})
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
	if pdu.Procedure == 1 && pdu.Category == Initiating {
		id, e := correlation(pdu)
		if e != nil {
			return e
		}
		var payload, payloadType []byte
		for _, ie := range pdu.IEs {
			if ie.ID == 1 {
				payload = append([]byte(nil), ie.Value...)
			}
			if ie.ID == 15 {
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
		if payloadType[0]&0x80 == 0 {
			p.log.Debug("sls: downlink LPP relayed", zap.String("key", tx.key), zap.Uint32("mme_ue_id", tx.mmeUEID), zap.Int("payload_len", len(payload)))
			return relay.SendDownlinkLPP(tx.mmeUEID, payload)
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
	var estimate []byte
	var cause bool
	for _, ie := range pdu.IEs {
		if seen[ie.ID] {
			return ErrMalformed
		}
		seen[ie.ID] = true
		if !ie.Known && ie.Criticality == aperReject {
			return ErrMalformed
		}
		if ie.ID == IELocationEstimate {
			estimate = append([]byte(nil), ie.Value...)
		}
		if ie.ID == IELCSCause {
			cause = true
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
	r := result{estimate: estimate}
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
