package sls

import (
	"bytes"
	"context"
	"errors"
	"github.com/vectorcore/mme/internal/asn1/aper"
	"sync"
	"testing"
	"time"
)

const timeSecond = time.Second

type testTransport struct {
	mu   sync.Mutex
	sent [][]byte
	ok   bool
}

func (t *testTransport) Available() bool { return t.ok }
func (t *testTransport) Send(_ context.Context, b []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sent = append(t.sent, append([]byte(nil), b...))
	return nil
}
func TestProviderCorrelatesAndCleansUp(t *testing.T) {
	tr := &testTransport{ok: true}
	p := NewProvider(time.Second, 1, tr, nil)
	done := make(chan error, 1)
	go func() {
		_, e := p.RequestPosition(context.Background(), "plr", 1, []byte{0, 0xf1, 0x10, 0, 0, 0, 1}, 0)
		done <- e
	}()
	for {
		tr.mu.Lock()
		n := len(tr.sent)
		tr.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	r, err := Encode(PDU{Category: Successful, Procedure: ProcedureLocationRequest, Criticality: aper.CriticalityReject, IEs: []IE{{ID: IECorrelationID, Criticality: aper.CriticalityReject, Value: []byte{0, 0, 0, 1}, Known: true}, {ID: IELocationEstimate, Criticality: aper.CriticalityReject, Value: []byte{0, 0, 0, 0, 0, 0, 0}, Known: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = p.HandleInbound(r); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := p.HandleInbound(r); !errors.Is(err, ErrLate) {
		t.Fatalf("want late, got %v", err)
	}
}
func TestProviderCapturesPositioningDataAndAccuracyIndicator(t *testing.T) {
	tr := &testTransport{ok: true}
	p := NewProvider(time.Second, 1, tr, nil)
	done := make(chan PositionResult, 1)
	go func() {
		r, _ := p.RequestPosition(context.Background(), "plr", 1, []byte{0, 0xf1, 0x10, 0, 0, 0, 1}, 0)
		done <- r
	}()
	for {
		tr.mu.Lock()
		n := len(tr.sent)
		tr.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	positioningData := []byte{0x01, 0x02, 0x03}
	r, err := Encode(PDU{Category: Successful, Procedure: ProcedureLocationRequest, Criticality: aper.CriticalityReject, IEs: []IE{
		{ID: IECorrelationID, Criticality: aper.CriticalityReject, Value: []byte{0, 0, 0, 1}, Known: true},
		{ID: IELocationEstimate, Criticality: aper.CriticalityReject, Value: []byte{0, 0, 0, 0, 0, 0, 0}, Known: true},
		{ID: IEPositioningData, Criticality: aper.CriticalityReject, Value: positioningData, Known: true},
		{ID: IEAccuracyFulfilmentIndicator, Criticality: aper.CriticalityReject, Value: []byte{0x00}, Known: true}, // ext=0, value=0 (requested-accuracy-fulfilled)
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err = p.HandleInbound(r); err != nil {
		t.Fatal(err)
	}
	got := <-done
	if !bytes.Equal(got.PositioningData, positioningData) {
		t.Errorf("PositioningData: got %x, want %x", got.PositioningData, positioningData)
	}
	if !got.AccuracyFulfilmentPresent {
		t.Error("AccuracyFulfilmentPresent: want true")
	}
	if got.AccuracyFulfilmentIndicator != 0 {
		t.Errorf("AccuracyFulfilmentIndicator: got %d, want 0", got.AccuracyFulfilmentIndicator)
	}
}

func TestAbortPositionCancelsWaiterAndSendsLocationAbort(t *testing.T) {
	tr := &testTransport{ok: true}
	p := NewProvider(time.Second, 1, tr, nil)
	done := make(chan error, 1)
	go func() {
		_, e := p.RequestPosition(context.Background(), "plr", 42, []byte{0, 0xf1, 0x10, 0, 0, 0, 1}, 0)
		done <- e
	}()
	for {
		tr.mu.Lock()
		n := len(tr.sent)
		tr.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	// AbortPosition for an unrelated UE must not touch this transaction.
	p.AbortPosition(999)
	select {
	case err := <-done:
		t.Fatalf("RequestPosition completed early after unrelated abort: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	p.AbortPosition(42)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	tr.mu.Lock()
	sent := len(tr.sent)
	last := append([]byte(nil), tr.sent[len(tr.sent)-1]...)
	tr.mu.Unlock()
	if sent != 2 {
		t.Fatalf("want 2 messages sent (Location Request + Location Abort), got %d", sent)
	}
	pdu, err := Decode(last)
	if err != nil {
		t.Fatalf("decode Location Abort: %v", err)
	}
	if pdu.Procedure != ProcedureLocationAbort || pdu.Category != Initiating {
		t.Fatalf("want Location-Abort-Request, got procedure=%d category=%v", pdu.Procedure, pdu.Category)
	}
}

func TestProviderAssociationLossAndTimeout(t *testing.T) {
	tr := &testTransport{ok: true}
	p := NewProvider(time.Second, 1, tr, nil)
	done := make(chan error, 1)
	go func() {
		_, e := p.RequestPosition(context.Background(), "plr", 1, []byte{0, 0xf1, 0x10, 0, 0, 0, 1}, 0)
		done <- e
	}()
	for {
		tr.mu.Lock()
		n := len(tr.sent)
		tr.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	p.AssociationLost(nil)
	if err := <-done; !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want unavailable, %v", err)
	}
	_, err := NewProvider(time.Millisecond, 1, tr, nil).RequestPosition(context.Background(), "timeout", 1, []byte{0, 0xf1, 0x10, 0, 0, 0, 1}, 0)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want timeout %v", err)
	}
}

// TestPayloadTypeWireBytes locks in the exact APER-encoded byte values for
// the LCS-AP Payload-Type IE (TS 29.171 §7.4.17: ENUMERATED{LPP, LPPa, ...}).
// LPPa's correct wire byte is 0x40 (extension-marker bit 0, value-bit 1,
// zero-padded), not 0x80 - the earlier bug this test guards against.
func TestPayloadTypeWireBytes(t *testing.T) {
	if got := encodePayloadType(payloadTypeLPP); len(got) != 1 || got[0] != 0x00 {
		t.Fatalf("LPP encoding = %x, want 00", got)
	}
	if got := encodePayloadType(payloadTypeLPPa); len(got) != 1 || got[0] != 0x40 {
		t.Fatalf("LPPa encoding = %x, want 40", got)
	}
	for _, v := range []int{payloadTypeLPP, payloadTypeLPPa} {
		got, err := decodePayloadType(encodePayloadType(v))
		if err != nil || got != v {
			t.Fatalf("round-trip v=%d: got=%d err=%v", v, got, err)
		}
	}
}

type fakeRelay struct {
	lppCalls  []fakeRelayLPPCall
	lppaCalls []fakeRelayLPPaCall
}
type fakeRelayLPPCall struct {
	mme     uint32
	routing []byte
	payload []byte
}
type fakeRelayLPPaCall struct {
	mme     uint32
	route   uint8
	payload []byte
}

func (f *fakeRelay) SendDownlinkLPP(mme uint32, routing, payload []byte) error {
	f.lppCalls = append(f.lppCalls, fakeRelayLPPCall{mme, append([]byte(nil), routing...), append([]byte(nil), payload...)})
	return nil
}
func (f *fakeRelay) SendDownlinkLPPa(mme uint32, route uint8, payload []byte) error {
	f.lppaCalls = append(f.lppaCalls, fakeRelayLPPaCall{mme, route, append([]byte(nil), payload...)})
	return nil
}

// TestHandleInboundDispatchesLPPvsLPPaByPayloadType is the regression test
// for the LPP/LPPa misclassification bug: a real, properly APER-encoded
// LPPa Payload-Type IE (0x40) must dispatch to SendDownlinkLPPa, not
// SendDownlinkLPP (which is what the old 0x80-bitmask check produced).
func TestHandleInboundDispatchesLPPvsLPPaByPayloadType(t *testing.T) {
	for _, tc := range []struct {
		name        string
		payloadType int
		wantLPP     bool
	}{
		{"LPP", payloadTypeLPP, true},
		{"LPPa", payloadTypeLPPa, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := NewProvider(time.Second, 1, &testTransport{ok: true}, nil)
			id := []byte{0, 0, 0, 1}
			tx := &transaction{key: "k", mmeUEID: 7, routingID: 3, done: make(chan result, 1)}
			p.tx[string(id)] = tx
			fake := &fakeRelay{}
			p.SetLPPaRelay(fake)

			apdu := []byte{0xAA, 0xBB, 0xCC}
			pdu, err := Encode(PDU{Category: Initiating, Procedure: ProcedureConnectionOrientedInformation, Criticality: aperReject, IEs: []IE{
				{ID: IECorrelationID, Criticality: aperReject, Value: id, Known: true},
				{ID: IEPayloadType, Criticality: aperReject, Value: encodePayloadType(tc.payloadType), Known: true},
				{ID: IEAPDU, Criticality: aperReject, Value: apdu, Known: true},
			}})
			if err != nil {
				t.Fatal(err)
			}
			if err := p.HandleInbound(pdu); err != nil {
				t.Fatal(err)
			}
			if tc.wantLPP {
				if len(fake.lppCalls) != 1 || len(fake.lppaCalls) != 0 {
					t.Fatalf("got lppCalls=%d lppaCalls=%d, want LPP dispatch", len(fake.lppCalls), len(fake.lppaCalls))
				}
				if fake.lppCalls[0].mme != 7 || !bytes.Equal(fake.lppCalls[0].payload, apdu) || !bytes.Equal(fake.lppCalls[0].routing, id) {
					t.Fatalf("unexpected LPP call: %+v, want routing=%x", fake.lppCalls[0], id)
				}
			} else {
				if len(fake.lppaCalls) != 1 || len(fake.lppCalls) != 0 {
					t.Fatalf("got lppCalls=%d lppaCalls=%d, want LPPa dispatch", len(fake.lppCalls), len(fake.lppaCalls))
				}
				if fake.lppaCalls[0].mme != 7 || fake.lppaCalls[0].route != 3 || !bytes.Equal(fake.lppaCalls[0].payload, apdu) {
					t.Fatalf("unexpected LPPa call: %+v", fake.lppaCalls[0])
				}
			}
		})
	}
}

// TestUplinkRelayEncodesCorrectPayloadType is the mirrored regression test
// for the MME->E-SMLC direction: HandleUplinkLPP/HandleUplinkLPPa must
// encode a Payload-Type an E-SMLC doing a spec-correct APER decode will
// read back as LPP/LPPa respectively.
func TestUplinkRelayEncodesCorrectPayloadType(t *testing.T) {
	tr := &testTransport{ok: true}
	p := NewProvider(time.Second, 4, tr, nil)
	id := []byte{0, 0, 0, 9}
	p.tx[string(id)] = &transaction{key: "k", mmeUEID: 42, routingID: 5, done: make(chan result, 1)}

	if err := p.HandleUplinkLPP(42, []byte{0x01}); err != nil {
		t.Fatal(err)
	}
	if err := p.HandleUplinkLPPa(42, 5, []byte{0x02}); err != nil {
		t.Fatal(err)
	}
	tr.mu.Lock()
	sent := append([][]byte(nil), tr.sent...)
	tr.mu.Unlock()
	if len(sent) != 2 {
		t.Fatalf("want 2 sent messages, got %d", len(sent))
	}
	for i, want := range []int{payloadTypeLPP, payloadTypeLPPa} {
		pdu, err := Decode(sent[i])
		if err != nil {
			t.Fatal(err)
		}
		var pt []byte
		for _, ie := range pdu.IEs {
			if ie.ID == IEPayloadType {
				pt = ie.Value
			}
		}
		got, err := decodePayloadType(pt)
		if err != nil || got != want {
			t.Fatalf("message %d: decoded payload type = %d, want %d (err=%v)", i, got, want, err)
		}
	}
}

func TestProviderAcksReset(t *testing.T) {
	tr := &testTransport{ok: true}
	p := NewProvider(time.Second, 1, tr, nil)
	w, err := Encode(PDU{Category: Initiating, Procedure: ProcedureReset, Criticality: aper.CriticalityIgnore, IEs: []IE{{ID: IELCSCause, Criticality: aper.CriticalityIgnore, Value: []byte{0}, Known: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.HandleInbound(w); err != nil {
		t.Fatal(err)
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if len(tr.sent) != 1 {
		t.Fatalf("reset ack count=%d", len(tr.sent))
	}
	ack, err := Decode(tr.sent[0])
	if err != nil {
		t.Fatal(err)
	}
	if ack.Category != Successful || ack.Procedure != ProcedureReset {
		t.Fatalf("unexpected reset ack: %#v", ack)
	}
}
