package sls

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/vectorcore/mme/internal/metrics"
)

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
	mu      sync.Mutex
	tx      map[string]*transaction
	next    uint32
	closed  bool
	relay   PositioningRelay
}

func NewProvider(timeout time.Duration, max int, t Transport) *Provider {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if max < 1 {
		max = 1
	}
	return &Provider{timeout: timeout, max: max, t: t, tx: map[string]*transaction{}}
}
func (p *Provider) RequestPosition(ctx context.Context, key string, mmeUEID uint32, ecgi []byte) ([]byte, error) {
	if len(ecgi) != 7 {
		return nil, ErrUnavailable
	}
	if p.t == nil || !p.t.Available() {
		return nil, ErrUnavailable
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, ErrUnavailable
	}
	if len(p.tx) >= p.max {
		p.mu.Unlock()
		return nil, ErrCapacity
	}
	// EPS Generic NAS Transport carries no SLs correlation identifier. Keep one
	// active LPP-capable positioning session per authenticated UE so uplink LPP
	// is never routed ambiguously to a different E-SMLC transaction.
	for _, active := range p.tx {
		if active.mmeUEID == mmeUEID {
			p.mu.Unlock()
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
	w, err := Encode(PDU{Category: Initiating, Procedure: ProcedureLocationRequest, Criticality: aperReject, IEs: []IE{{IECorrelationID, aperReject, id[:], true}, {IELocationType, aperReject, []byte{0}, true}, {IEECGI, aperIgnore, append([]byte(nil), ecgi...), true}}})
	if err != nil {
		return nil, err
	}
	if err = p.t.Send(ctx, w); err != nil {
		return nil, err
	}
	wctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	select {
	case r := <-x.done:
		return r.estimate, r.err
	case <-wctx.Done():
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
			return relay.SendDownlinkLPP(tx.mmeUEID, payload)
		}
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
