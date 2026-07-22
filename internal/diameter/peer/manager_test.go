package peer

import (
	"context"
	"crypto/tls"
	"net"
	"testing"

	"github.com/fiorix/go-diameter/v4/diam/dict"
	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/config"
)

type testConn struct{}

func (testConn) Write([]byte) (int, error)             { return 0, nil }
func (testConn) WriteStream([]byte, uint) (int, error) { return 0, nil }
func (testConn) Close()                                {}
func (testConn) LocalAddr() net.Addr                   { return &net.TCPAddr{} }
func (testConn) RemoteAddr() net.Addr                  { return &net.TCPAddr{} }
func (testConn) TLS() *tls.ConnectionState             { return nil }
func (testConn) Dictionary() *dict.Parser              { return dict.Default }
func (testConn) Context() context.Context              { return context.Background() }
func (testConn) SetContext(context.Context)            {}
func (testConn) Connection() net.Conn                  { return nil }

type closeTrackingConn struct {
	testConn
	closed bool
}

func (c *closeTrackingConn) Close() { c.closed = true }

func readyManager(peers ...config.DiameterPeerConfig) *Manager {
	m := New(config.DiameterConfig{Peers: peers}, zap.NewNop(), nil)
	for _, p := range m.peers {
		p.state, p.conn = Ready, testConn{}
	}
	return m
}

func apps(p *record, ids ...uint32) {
	for _, id := range ids {
		p.apps[id] = true
	}
}
func priority(v int) *int { return &v }

func TestSelectPeerSingleRelaySupportsAllApplications(t *testing.T) {
	m := readyManager(config.DiameterPeerConfig{Name: "dra-1", Address: "a"})
	apps(m.peers[0], RelayApplicationID)
	for _, app := range []uint32{16777251, 16777252, 16777255} {
		got, err := m.SelectPeer(app, "example.net")
		if err != nil || got.Name != "dra-1" || got.SelectionType != "relay" {
			t.Fatalf("app %d: got %#v, %v", app, got, err)
		}
	}
}

func TestSelectPeerRelayOrderAndFailover(t *testing.T) {
	m := readyManager(config.DiameterPeerConfig{Name: "dra-1", Address: "a"}, config.DiameterPeerConfig{Name: "dra-2", Address: "b"})
	apps(m.peers[0], RelayApplicationID)
	apps(m.peers[1], RelayApplicationID)
	got, _ := m.SelectPeer(1, "r")
	if got.Name != "dra-1" {
		t.Fatalf("got %s, want dra-1", got.Name)
	}
	m.peers[0].state = Down
	got, _ = m.SelectPeer(1, "r")
	if got.Name != "dra-2" {
		t.Fatalf("got %s, want dra-2", got.Name)
	}
}

func TestSelectPeerPriorityWithinClass(t *testing.T) {
	m := readyManager(config.DiameterPeerConfig{Name: "dra-1", Address: "a", Priority: priority(20)}, config.DiameterPeerConfig{Name: "dra-2", Address: "b", Priority: priority(10)})
	apps(m.peers[0], RelayApplicationID)
	apps(m.peers[1], RelayApplicationID)
	got, _ := m.SelectPeer(1, "r")
	if got.Name != "dra-2" {
		t.Fatalf("got %s, want dra-2", got.Name)
	}
}

func TestSelectPeerDirectBeatsRelayRegardlessOfPriority(t *testing.T) {
	m := readyManager(config.DiameterPeerConfig{Name: "dra", Address: "a", Priority: priority(1)}, config.DiameterPeerConfig{Name: "hss", Address: "b", Priority: priority(20)})
	apps(m.peers[0], RelayApplicationID)
	apps(m.peers[1], 16777251)
	got, _ := m.SelectPeer(16777251, "r")
	if got.Name != "hss" || got.SelectionType != "direct" || got.DestinationHost != "" {
		t.Fatalf("got %#v", got)
	}
	got, _ = m.SelectPeer(16777252, "r")
	if got.Name != "dra" {
		t.Fatalf("got %s, want dra", got.Name)
	}
}

func TestSelectPeerDirectPriorityAndRelayFallback(t *testing.T) {
	m := readyManager(config.DiameterPeerConfig{Name: "hss-1", Address: "a", Priority: priority(20)}, config.DiameterPeerConfig{Name: "hss-2", Address: "b", Priority: priority(10)}, config.DiameterPeerConfig{Name: "dra", Address: "c", Priority: priority(1)})
	apps(m.peers[0], 16777251)
	apps(m.peers[1], 16777251)
	apps(m.peers[2], RelayApplicationID)
	got, _ := m.SelectPeer(16777251, "r")
	if got.Name != "hss-2" {
		t.Fatalf("got %s, want hss-2", got.Name)
	}
	m.peers[1].state = Down
	m.peers[0].state = Down
	got, _ = m.SelectPeer(16777251, "r")
	if got.Name != "dra" || got.SelectionType != "relay" {
		t.Fatalf("got %#v", got)
	}
}

func TestSelectPeerNoRoute(t *testing.T) {
	m := readyManager(config.DiameterPeerConfig{Name: "other", Address: "a"})
	apps(m.peers[0], 99)
	if _, err := m.SelectPeer(16777251, "r"); err == nil {
		t.Fatal("expected no peer available error")
	}
}

func TestReportTransactionFailureInvalidatesStaleConnection(t *testing.T) {
	m := readyManager(config.DiameterPeerConfig{Name: "dra-1", Address: "a"})
	apps(m.peers[0], RelayApplicationID)
	conn := &closeTrackingConn{}
	m.peers[0].conn = conn
	m.ReportTransactionFailure("dra-1")
	if !conn.closed || m.peers[0].conn != nil || m.peers[0].state != Suspect {
		t.Fatalf("peer not invalidated: %+v", m.peers[0])
	}
	if _, err := m.SelectPeer(16777313, "example.net"); err == nil {
		t.Fatal("stale connection remained selectable")
	}
}

func TestRouteLocalAddressUsesSingleRouteSelectedIP(t *testing.T) {
	addr, err := routeLocalAddress("127.0.0.1:3868")
	if err != nil {
		t.Fatalf("routeLocalAddress: %v", err)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host != "127.0.0.1" || port != "0" {
		t.Fatalf("got %q, want 127.0.0.1:0", addr)
	}
}
