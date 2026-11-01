package s1ap

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/vectorcore/mme/internal/roaming"
)

// fakeNotifyS6a records NOR requests and answers with a fixed result.
type fakeNotifyS6a struct {
	NoopS6aClient
	mu     sync.Mutex
	calls  []roaming.S6aRequest
	reason int32
	code   uint32
	err    error
}

func (f *fakeNotifyS6a) SendNotifyAlert(_ context.Context, dest roaming.S6aRequest, alertReason int32) (uint32, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, dest)
	f.reason = alertReason
	return f.code, f.err
}

// waitDownlinkContaining waits for a downlink S1AP message whose (null
// ciphered) NAS carries want.
func waitDownlinkContaining(t *testing.T, downlink chan []byte, want []byte, what string) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case b := <-downlink:
			if bytes.Contains(b, want) {
				return
			}
		case <-deadline:
			t.Fatalf("%s (%x) not sent to the UE", what, want)
		}
	}
}

func TestRPSMMAIsRelayedAsNotifyMemoryAvailable(t *testing.T) {
	const ref = 0x2a
	// UE CP-DATA, TI 0 (UE-originated), RPDU = RP-SMMA (MTI 6, reference).
	smma := []byte{5, 0x09, 0x01, 2, 0x06, ref}
	cases := []struct {
		name     string
		s6a      S6aClient
		wantRP   []byte // RPDU expected inside the downlink CP-DATA
		wantNORs int
	}{
		{"HSS accepts", &fakeNotifyS6a{code: 2001}, []byte{0x03, ref}, 1},
		{"HSS user unknown", &fakeNotifyS6a{code: 5001}, []byte{0x05, ref, 1, 30}, 1},
		{"HSS unreachable", &fakeNotifyS6a{err: errors.New("no peer")}, []byte{0x05, ref, 1, 41}, 1},
		{"no Notify support", NoopS6aClient{}, []byte{0x05, ref, 1, 41}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, ue, downlink := newMTOutcomeServer(t, true)
			s.s6a = tc.s6a
			if err := s.processUplinkSMS(ue, smma); err != nil {
				t.Fatalf("RP-SMMA rejected: %v", err)
			}
			// Immediate CP-ACK (network direction, TI flag set): 89 04.
			waitDownlinkContaining(t, downlink, []byte{0x89, 0x04}, "CP-ACK")
			// CP-DATA 89 01 <len> <RPDU>.
			waitDownlinkContaining(t, downlink, append([]byte{0x89, 0x01, byte(len(tc.wantRP))}, tc.wantRP...), "RP answer")

			if f, ok := tc.s6a.(*fakeNotifyS6a); ok {
				f.mu.Lock()
				calls, reason := append([]roaming.S6aRequest(nil), f.calls...), f.reason
				f.mu.Unlock()
				if len(calls) != tc.wantNORs || calls[0].SubscriberIMSI != mtOutcomeIMSI || reason != alertReasonUEMemoryAvailable {
					t.Fatalf("NOR calls = %+v reason %d, want one for %s with UE_MEMORY_AVAILABLE", calls, reason, mtOutcomeIMSI)
				}
			}

			// UE final CP-ACK (TI 0, UE direction) closes the transaction.
			if err := s.processUplinkSMS(ue, []byte{2, 0x09, 0x04}); err != nil {
				t.Fatalf("final CP-ACK: %v", err)
			}
			if _, ok := s.pendingMOSMS.Load(moSMSKey(mtOutcomeIMSI, 0)); ok {
				t.Fatal("RP-SMMA transaction still pending after final CP-ACK")
			}
		})
	}
}

func TestDuplicateRPSMMASendsOneNotify(t *testing.T) {
	s, ue, downlink := newMTOutcomeServer(t, true)
	block := make(chan struct{})
	f := &blockingNotifyS6a{release: block, calls: make(chan struct{}, 4)}
	s.s6a = f
	smma := []byte{5, 0x09, 0x01, 2, 0x06, 0x07}
	if err := s.processUplinkSMS(ue, smma); err != nil {
		t.Fatal(err)
	}
	<-f.calls
	// The UE retransmits CP-DATA while the NOR is outstanding.
	if err := s.processUplinkSMS(ue, smma); err != nil {
		t.Fatal(err)
	}
	close(block)
	waitDownlinkContaining(t, downlink, []byte{0x89, 0x01, 2, 0x03, 0x07}, "RP-ACK")
	select {
	case <-f.calls:
		t.Fatal("duplicate RP-SMMA produced a second NOR")
	case <-time.After(50 * time.Millisecond):
	}
}

type blockingNotifyS6a struct {
	NoopS6aClient
	release chan struct{}
	calls   chan struct{}
}

func (b *blockingNotifyS6a) SendNotifyAlert(context.Context, roaming.S6aRequest, int32) (uint32, error) {
	b.calls <- struct{}{}
	<-b.release
	return 2001, nil
}
