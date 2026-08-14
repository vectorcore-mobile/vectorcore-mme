package sbcap

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ishidawataru/sctp"
	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/transportqos"
	"go.uber.org/zap"
)

// MessageHandler receives only authenticated, PPID-validated SBc-AP payloads.
// It must return promptly; the SCTP read loop remains owned by Server.
type MessageHandler func(peer string, payload []byte)

// Server is a CBC-initiated SCTP listener. SBc-AP has no setup procedure, so
// peer admission is based on configured source addresses.
type Server struct {
	cfg          config.SBcAPConfig
	log          *zap.Logger
	onMessage    MessageHandler
	authorized   map[string]string
	mu           sync.RWMutex
	listener     *sctp.SCTPListener
	connections  map[string]*connection
	legacyWarned map[string]time.Time
}

type connection struct {
	conn *sctp.SCTPConn
	send chan []byte
	done chan struct{}
}

func NewServer(cfg config.SBcAPConfig, log *zap.Logger, onMessage MessageHandler) *Server {
	authorized := make(map[string]string)
	for _, peer := range cfg.Peers {
		for _, address := range peer.Addresses {
			authorized[address] = peer.Name
		}
	}
	initMessageMetrics()
	return &Server{cfg: cfg, log: log, onMessage: onMessage, authorized: authorized, connections: make(map[string]*connection), legacyWarned: make(map[string]time.Time)}
}

// initMessageMetrics pre-registers the mme_sbcap_messages_total label
// combinations seen in normal operation. A CounterVec exposes no series at
// all until WithLabelValues is called, so without this the metric is absent
// from /metrics (and from the web UI's metrics table) until the first CBC
// message of each kind actually occurs.
func initMessageMetrics() {
	for _, p := range []uint8{ProcedureWriteReplaceWarning, ProcedureStopWarning, ProcedureErrorIndication} {
		metrics.SBcAPMessagesTotal.WithLabelValues("rx", strconv.Itoa(int(p)), "received")
	}
	for _, p := range []uint8{ProcedureWriteReplaceWarningIndication, ProcedureStopWarningIndication, ProcedureErrorIndication, ProcedurePWSRestartIndication, ProcedurePWSFailureIndication} {
		metrics.SBcAPMessagesTotal.WithLabelValues("tx", strconv.Itoa(int(p)), "sent")
	}
}

func (s *Server) Listen() error {
	addr := &sctp.SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP(s.cfg.BindAddress)}}, Port: s.cfg.Port}
	socketCfg := &sctp.SocketConfig{Control: func(network, address string, raw syscall.RawConn) error {
		return transportqos.Control(s.cfg.QoS.DSCP)(network, address, raw)
	}}
	ln, err := socketCfg.Listen("sctp", addr)
	if err != nil {
		return fmt.Errorf("sbcap: listen %s:%d: %w", s.cfg.BindAddress, s.cfg.Port, err)
	}
	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()
	defer func() {
		_ = ln.Close()
		s.mu.Lock()
		if s.listener == ln {
			s.listener = nil
		}
		s.mu.Unlock()
	}()
	s.log.Info("sbcap: SCTP listening", zap.String("address", fmt.Sprintf("%s:%d", s.cfg.BindAddress, s.cfg.Port)), zap.Uint32("ppid", SCTPPPIdentifier), zap.Bool("accept_legacy_ppid_zero", s.cfg.AcceptLegacyPPIDZero))
	if tos, configured, _ := transportqos.TOS(s.cfg.QoS.DSCP); configured {
		s.log.Info("sbcap: outbound QoS configured", zap.Int("dscp", *s.cfg.QoS.DSCP), zap.String("tos", fmt.Sprintf("0x%02x", tos)))
	}
	for {
		accepted, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("sbcap: accept: %w", err)
		}
		conn, ok := accepted.(*sctp.SCTPConn)
		if !ok {
			_ = accepted.Close()
			continue
		}
		if err := transportqos.Apply(s.cfg.QoS.DSCP, conn); err != nil {
			_ = conn.Close()
			s.log.Warn("sbcap: accepted association QoS failed", zap.Error(err))
			continue
		}
		go s.handleConnection(conn)
	}
}

// Close stops accepting CBC associations and closes active associations. It
// does not persist or replay warning state across shutdown.
func (s *Server) Close() error {
	s.mu.Lock()
	ln := s.listener
	connections := make([]*connection, 0, len(s.connections))
	for _, c := range s.connections {
		connections = append(connections, c)
	}
	s.mu.Unlock()
	for _, c := range connections {
		_ = c.conn.Close()
	}
	if ln != nil {
		return ln.Close()
	}
	return nil
}

// authorizedPeer resolves the configured peer name for a CBC's remote host.
// SCTP associations may be multi-homed: conn.RemoteAddr().String() then
// joins every bound address with "/" (e.g. "127.0.0.1/10.0.0.5/172.17.0.1"),
// which never equals a single configured peer address even when one of the
// bound addresses is authorized. Accept the association if any one of them
// matches.
func authorizedPeer(authorized map[string]string, host string) (string, bool) {
	for _, candidate := range strings.Split(host, "/") {
		if peer, ok := authorized[candidate]; ok {
			return peer, true
		}
	}
	return "", false
}

func (s *Server) handleConnection(conn *sctp.SCTPConn) {
	// SCTPRead exposes PPID through ancillary data only when DATA_IO events
	// are enabled. Without this subscription the Go SCTP adapter returns nil
	// metadata, making standards PPID enforcement impossible.
	if err := conn.SubscribeEvents(sctp.SCTP_EVENT_DATA_IO); err != nil {
		s.log.Warn("sbcap: unable to subscribe to SCTP DATA_IO events", zap.Error(err))
		_ = conn.Close()
		return
	}
	remote := conn.RemoteAddr().String()
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	peer, allowed := authorizedPeer(s.authorized, host)
	if !allowed {
		s.log.Warn("sbcap: rejected unauthorized CBC association", zap.String("remote", remote))
		_ = conn.Close()
		return
	}
	c := &connection{conn: conn, send: make(chan []byte, 64), done: make(chan struct{})}
	s.mu.Lock()
	s.connections[peer] = c
	s.mu.Unlock()
	s.log.Info("sbcap: CBC association up", zap.String("peer", peer), zap.String("remote", remote))
	metrics.SBcAPAssociations.Inc()
	defer func() {
		s.mu.Lock()
		if s.connections[peer] == c {
			delete(s.connections, peer)
		}
		s.mu.Unlock()
		close(c.done)
		_ = conn.Close()
		metrics.SBcAPAssociations.Dec()
		s.log.Info("sbcap: CBC association down", zap.String("peer", peer), zap.String("remote", remote))
	}()
	go func() {
		for {
			select {
			case <-c.done:
				return
			case payload := <-c.send:
				if _, err := conn.SCTPWrite(payload, &sctp.SndRcvInfo{PPID: SCTPPPIdentifier}); err != nil {
					s.log.Debug("sbcap: SCTP write failed", zap.String("peer", peer), zap.Error(err))
					return
				}
				if p, err := Decode(payload); err == nil {
					metrics.SBcAPMessagesTotal.WithLabelValues("tx", strconv.Itoa(int(p.ProcedureCode)), "sent").Inc()
				}
			}
		}
	}()
	buf := make([]byte, 65536)
	for {
		n, info, err := conn.SCTPRead(buf)
		if err != nil {
			s.log.Debug("sbcap: SCTP read ended", zap.String("peer", peer), zap.Error(err))
			return
		}
		if n == 0 {
			continue
		}
		if !s.acceptInboundPPID(peer, info) {
			metrics.SBcAPPPIDRejectedTotal.WithLabelValues(strconv.FormatUint(uint64(ppid(info)), 10)).Inc()
			s.log.Warn("sbcap: discarded payload with invalid PPID", zap.String("peer", peer), zap.Uint32("ppid", ppid(info)), zap.Bool("accept_legacy_ppid_zero", s.cfg.AcceptLegacyPPIDZero))
			continue
		}
		payload := append([]byte(nil), buf[:n]...)
		if s.onMessage != nil {
			s.onMessage(peer, payload)
		}
	}
}

// acceptInboundPPID accepts only the registered SBc-AP PPID, except for the
// narrowly scoped legacy OsmoCBC compatibility switch.  Peer admission is
// completed before this function is reachable, so PPID 0 never authenticates
// an otherwise unknown SCTP association.
func (s *Server) acceptInboundPPID(peer string, info *sctp.SndRcvInfo) bool {
	if info != nil && info.PPID == SCTPPPIdentifier {
		return true
	}
	if info == nil || info.PPID != 0 || !s.cfg.AcceptLegacyPPIDZero {
		return false
	}
	metrics.SBcAPLegacyPPIDZeroTotal.Inc()
	s.mu.Lock()
	last := s.legacyWarned[peer]
	if time.Since(last) >= time.Minute {
		s.legacyWarned[peer] = time.Now()
		s.mu.Unlock()
		s.log.Warn("sbcap: accepting non-standard SCTP PPID 0 due to compatibility configuration", zap.String("peer", peer))
	} else {
		s.mu.Unlock()
	}
	return true
}

func ppid(info *sctp.SndRcvInfo) uint32 {
	if info == nil {
		return 0
	}
	return info.PPID
}

// PeerStatus is a point-in-time snapshot of one configured CBC peer, for
// OAM/API reporting.
type PeerStatus struct {
	Name      string
	Addresses []string
	Connected bool
}

// Snapshot returns the current status of every configured CBC peer, in
// configured order.
func (s *Server) Snapshot() []PeerStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]PeerStatus, 0, len(s.cfg.Peers))
	for _, p := range s.cfg.Peers {
		_, connected := s.connections[p.Name]
		out = append(out, PeerStatus{Name: p.Name, Addresses: p.Addresses, Connected: connected})
	}
	return out
}

// Send delivers an SBc-AP PDU to the currently active association for peer.
// It does not queue warning state across an association loss.
func (s *Server) Send(peer string, payload []byte) error {
	s.mu.RLock()
	c := s.connections[peer]
	s.mu.RUnlock()
	if c == nil {
		return fmt.Errorf("sbcap: no active association for peer %q", peer)
	}
	select {
	case <-c.done:
		return fmt.Errorf("sbcap: association closed for peer %q", peer)
	case c.send <- append([]byte(nil), payload...):
		return nil
	default:
		return fmt.Errorf("sbcap: outbound queue full for peer %q", peer)
	}
}

// Broadcast sends a transient indication to every currently active CBC
// association. It intentionally does not queue it for disconnected peers.
func (s *Server) Broadcast(payload []byte) {
	s.mu.RLock()
	peers := make([]string, 0, len(s.connections))
	for peer := range s.connections {
		peers = append(peers, peer)
	}
	s.mu.RUnlock()
	for _, peer := range peers {
		_ = s.Send(peer, payload)
	}
}
