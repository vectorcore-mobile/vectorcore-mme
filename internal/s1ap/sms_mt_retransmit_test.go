package s1ap

import (
	"bytes"
	"testing"
	"time"

	"github.com/fiorix/go-diameter/v4/diam"

	"github.com/vectorcore/mme/internal/diameter/sgd"
)

// mtCPDataMarker is the start of the MT CP-DATA the MME sends for
// mtRequest(): TI flag clear, CP-DATA, then RP-DATA (MT) with reference = TI.
func mtCPDataMarker(ti uint8) []byte {
	return []byte{ti<<4 | 0x09, 0x01}
}

// collectCPData counts downlink messages that carry the MT CP-DATA within d.
func collectCPData(downlink chan []byte, marker []byte, d time.Duration) (count int, frames [][]byte) {
	deadline := time.After(d)
	for {
		select {
		case b := <-downlink:
			if bytes.Contains(b, marker) {
				count++
				frames = append(frames, b)
			}
		case <-deadline:
			return count, frames
		}
	}
}

func startMT(t *testing.T, s *Server) (chan sgd.MTOutcome, *pendingMTSMS) {
	t.Helper()
	done := make(chan sgd.MTOutcome, 1)
	go func() { done <- s.HandleSGdMT(mtRequest()) }()
	var p *pendingMTSMS
	waitFor(t, "MT transaction", func() bool {
		v, ok := s.pendingMTSMS.Load(mtOutcomeIMSI)
		if ok {
			p = v.(*pendingMTSMS)
		}
		return ok && p.cpDataSent.Load()
	})
	return done, p
}

func TestMTCPDataRetransmittedOnTC1MExpiry(t *testing.T) {
	s, _, downlink := newMTOutcomeServer(t, true)
	s.smsTimeout = 300 * time.Millisecond // TC1M = 100ms
	done, p := startMT(t, s)

	n, frames := collectCPData(downlink, mtCPDataMarker(p.ti), 400*time.Millisecond)
	if n != 1+mtCPDataRetries {
		t.Fatalf("MT CP-DATA sent %d times, want %d (initial + %d retransmissions)", n, 1+mtCPDataRetries, mtCPDataRetries)
	}
	// Each retransmission carries the identical CP-DATA. The NAS security
	// header (COUNT, MAC) differs per message, so compare the CP PDU only:
	// TI/PD, CP-DATA, RPDU length, RPDU.
	cpPDU := func(f []byte) []byte {
		i := bytes.Index(f, mtCPDataMarker(p.ti))
		if i < 0 || i+3 > len(f) || i+3+int(f[i+2]) > len(f) {
			t.Fatalf("CP-DATA not found in downlink %x", f)
		}
		return f[i : i+3+int(f[i+2])]
	}
	want := cpPDU(frames[0])
	if !bytes.Equal(want, p.downlinkCP) {
		t.Fatalf("sent CP-DATA %x, retained %x", want, p.downlinkCP)
	}
	for i, f := range frames[1:] {
		if got := cpPDU(f); !bytes.Equal(got, want) {
			t.Fatalf("retransmission %d = %x, want %x", i+1, got, want)
		}
	}
	assertAbsentUser(t, "no answer", <-done, sgd.AbsentDiagTemporarilyUnavailable)
}

func TestMTCPAckStopsRetransmission(t *testing.T) {
	s, ue, downlink := newMTOutcomeServer(t, true)
	s.smsTimeout = 300 * time.Millisecond
	done, p := startMT(t, s)
	_, _ = collectCPData(downlink, mtCPDataMarker(p.ti), 10*time.Millisecond) // drain the initial CP-DATA

	// UE CP-ACK for the network-originated transaction: TI flag set.
	if err := s.processUplinkSMS(ue, []byte{2, 0x80 | p.ti<<4 | 0x09, 0x04}); err != nil {
		t.Fatalf("MT CP-ACK: %v", err)
	}
	if n, _ := collectCPData(downlink, mtCPDataMarker(p.ti), 250*time.Millisecond); n != 0 {
		t.Fatalf("CP-DATA retransmitted %d times after the UE's CP-ACK", n)
	}
	// The RP-ACK still completes the transaction.
	if err := s.processUplinkSMS(ue, rpAckFor(p)); err != nil {
		t.Fatalf("RP-ACK: %v", err)
	}
	if got := <-done; got.ResultCode != diam.Success {
		t.Fatalf("outcome = %+v, want 2001", got)
	}
}

func TestMTRetransmissionStopsWhenTransactionEnds(t *testing.T) {
	s, ue, downlink := newMTOutcomeServer(t, true)
	s.smsTimeout = 300 * time.Millisecond
	done, p := startMT(t, s)
	// RP-ACK without a separate CP-ACK (the CP-ACK was lost).
	if err := s.processUplinkSMS(ue, rpAckFor(p)); err != nil {
		t.Fatalf("RP-ACK: %v", err)
	}
	if got := <-done; got.ResultCode != diam.Success {
		t.Fatalf("outcome = %+v, want 2001", got)
	}
	_, _ = collectCPData(downlink, mtCPDataMarker(p.ti), 10*time.Millisecond)
	if n, _ := collectCPData(downlink, mtCPDataMarker(p.ti), 250*time.Millisecond); n != 0 {
		t.Fatalf("CP-DATA retransmitted %d times after the transaction ended", n)
	}
}
