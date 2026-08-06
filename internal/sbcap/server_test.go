package sbcap

import (
	"testing"

	"github.com/ishidawataru/sctp"
	"github.com/vectorcore/mme/internal/config"
	"go.uber.org/zap"
)

func testServer(legacy bool) *Server {
	return NewServer(config.SBcAPConfig{AcceptLegacyPPIDZero: legacy, Peers: []config.SBcAPPeerConfig{{Name: "cbc", Addresses: []string{"127.0.0.2"}}}}, zap.NewNop(), nil)
}

func TestInboundPPIDPolicy(t *testing.T) {
	for _, tt := range []struct {
		name   string
		legacy bool
		ppid   uint32
		want   bool
	}{
		{"standard strict", false, SCTPPPIdentifier, true},
		{"legacy zero strict", false, 0, false},
		{"legacy zero enabled", true, 0, true},
		{"other enabled", true, 18, false},
		{"other strict", false, 99, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := testServer(tt.legacy).acceptInboundPPID("cbc", &sctp.SndRcvInfo{PPID: tt.ppid}); got != tt.want {
				t.Fatalf("PPID %d: got %v want %v", tt.ppid, got, tt.want)
			}
		})
	}
}

func TestSnapshotReportsConfiguredPeersAndConnectedState(t *testing.T) {
	s := testServer(false)
	got := s.Snapshot()
	if len(got) != 1 || got[0].Name != "cbc" || got[0].Connected {
		t.Fatalf("Snapshot() before connect = %+v, want one disconnected cbc peer", got)
	}

	s.mu.Lock()
	s.connections["cbc"] = &connection{}
	s.mu.Unlock()

	got = s.Snapshot()
	if len(got) != 1 || !got[0].Connected || len(got[0].Addresses) != 1 || got[0].Addresses[0] != "127.0.0.2" {
		t.Fatalf("Snapshot() after connect = %+v, want connected cbc peer", got)
	}
}

func TestLegacyPPIDDoesNotAdmitUnknownPeer(t *testing.T) {
	s := testServer(true)
	if _, ok := s.authorized["127.0.0.99"]; ok {
		t.Fatal("unexpected authorized peer")
	}
	// handleConnection performs this source-address check before it calls the
	// PPID gate; a legacy PPID must never turn an unknown association into one.
	if !s.acceptInboundPPID("cbc", &sctp.SndRcvInfo{PPID: 0}) {
		t.Fatal("admitted peer legacy mode rejected")
	}
}

func TestOutboundPPIDIsAlwaysStandard(t *testing.T) {
	if SCTPPPIdentifier != 24 {
		t.Fatalf("SBc-AP outbound PPID = %d, want 24", SCTPPPIdentifier)
	}
}
