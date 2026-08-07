package sls

import (
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
