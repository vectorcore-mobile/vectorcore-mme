// Package sctp provides the SCTP transport layer for S1AP.
// Each SCTP association corresponds to one eNodeB connection.
package sctp

import (
	"fmt"
	"net"
	"sync"
	"syscall"

	"github.com/ishidawataru/sctp"
	"github.com/vectorcore/mme/internal/transportqos"
	"go.uber.org/zap"
)

const s1apPPID uint32 = 18

// MessageHandler is called for each received SCTP message (one complete S1AP PDU).
// remoteAddr identifies the sending eNB. sendCh is the channel for sending replies to this eNB.
type MessageHandler func(remoteAddr string, data []byte)

// ConnectHandler is called when a new SCTP association is established.
// sendCh is a channel the caller can write S1AP PDUs to; the server drains it to the wire.
type ConnectHandler func(remoteAddr string, sendCh chan<- []byte)

// DisconnectHandler is called when an SCTP association is closed.
type DisconnectHandler func(remoteAddr string)

// Server listens on an SCTP address for incoming S1AP connections.
type Server struct {
	bindAddr     string
	port         int
	dscp         *int
	log          *zap.Logger
	onMessage    MessageHandler
	onConnect    ConnectHandler
	onDisconnect DisconnectHandler

	mu       sync.Mutex
	listener net.Listener
	conns    map[*sctp.SCTPConn]struct{}
	closed   bool
}

// NewServer creates an SCTP server that will call onMessage for each S1AP PDU received.
func NewServer(bindAddr string, port int, dscp *int, log *zap.Logger,
	onConnect ConnectHandler, onMessage MessageHandler, onDisconnect DisconnectHandler) *Server {
	return &Server{
		bindAddr:     bindAddr,
		port:         port,
		dscp:         dscp,
		log:          log,
		onMessage:    onMessage,
		onConnect:    onConnect,
		onDisconnect: onDisconnect,
		conns:        make(map[*sctp.SCTPConn]struct{}),
	}
}

// Listen starts the SCTP listener (blocking). Returns on fatal error.
func (s *Server) Listen() error {
	addr := &sctp.SCTPAddr{
		IPAddrs: []net.IPAddr{{IP: net.ParseIP(s.bindAddr)}},
		Port:    s.port,
	}
	socketCfg := &sctp.SocketConfig{Control: func(network, address string, raw syscall.RawConn) error {
		return transportqos.Control(s.dscp)(network, address, raw)
	}}
	ln, err := socketCfg.Listen("sctp", addr)
	if err != nil {
		return fmt.Errorf("sctp: listen %s:%d: %w", s.bindAddr, s.port, err)
	}
	defer ln.Close()
	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()
	s.log.Info("s1ap: SCTP listening", zap.String("addr", fmt.Sprintf("%s:%d", s.bindAddr, s.port)))
	if tos, configured, _ := transportqos.TOS(s.dscp); configured {
		s.log.Info("s1ap: outbound QoS configured", zap.Int("dscp", *s.dscp), zap.String("tos", fmt.Sprintf("0x%02x", tos)))
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			return fmt.Errorf("sctp: accept: %w", err)
		}
		sctpConn := conn.(*sctp.SCTPConn)
		if err := transportqos.Apply(s.dscp, sctpConn); err != nil {
			_ = sctpConn.Close()
			s.log.Warn("s1ap: SCTP accepted association QoS failed", zap.Error(err))
			continue
		}
		go s.handleConn(sctpConn)
	}
}

// Close stops the listener and closes every active eNB SCTP association,
// unblocking Listen's Accept loop and each handleConn's Read loop so the
// server shuts down without leaking sockets or goroutines.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	ln := s.listener
	conns := make([]*sctp.SCTPConn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()

	var err error
	if ln != nil {
		err = ln.Close()
	}
	for _, c := range conns {
		_ = c.Close()
	}
	return err
}

func (s *Server) handleConn(conn *sctp.SCTPConn) {
	remote := conn.RemoteAddr().String()
	s.log.Info("s1ap: new SCTP connection", zap.String("remote", remote))

	s.mu.Lock()
	s.conns[conn] = struct{}{}
	s.mu.Unlock()

	// Create send channel and notify caller
	sendCh := make(chan []byte, 64)
	if s.onConnect != nil {
		s.onConnect(remote, sendCh)
	}

	// Writer goroutine drains sendCh to the SCTP connection
	go func() {
		for data := range sendCh {
			_, _ = conn.SCTPWrite(data, &sctp.SndRcvInfo{PPID: s1apPPID})
		}
	}()

	defer func() {
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
		close(sendCh)
		conn.Close()
		s.log.Info("s1ap: SCTP connection closed", zap.String("remote", remote))
		if s.onDisconnect != nil {
			s.onDisconnect(remote)
		}
	}()

	buf := make([]byte, 65536)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			s.log.Debug("s1ap: SCTP read error", zap.String("remote", remote), zap.Error(err))
			return
		}
		if n == 0 {
			continue
		}
		// Copy into a new slice so the goroutine holds a safe reference
		msg := make([]byte, n)
		copy(msg, buf[:n])
		s.onMessage(remote, msg)
	}
}

// Conn wraps an SCTP connection with a send mutex.
type Conn struct {
	conn *sctp.SCTPConn
	done chan struct{}
	send chan []byte
}

// NewConn wraps an existing SCTPConn and starts a send goroutine.
func NewConn(sctpConn *sctp.SCTPConn) *Conn {
	c := &Conn{
		conn: sctpConn,
		done: make(chan struct{}),
		send: make(chan []byte, 64),
	}
	go c.writer()
	return c
}

// Send enqueues an S1AP PDU for delivery. Non-blocking.
func (c *Conn) Send(data []byte) {
	select {
	case c.send <- data:
	case <-c.done:
	}
}

func (c *Conn) writer() {
	for {
		select {
		case data := <-c.send:
			_, _ = c.conn.SCTPWrite(data, &sctp.SndRcvInfo{PPID: s1apPPID})
		case <-c.done:
			return
		}
	}
}

// Close signals the send goroutine to stop.
func (c *Conn) Close() {
	close(c.done)
}

// RemoteAddr returns the remote address string.
func (c *Conn) RemoteAddr() string {
	return c.conn.RemoteAddr().String()
}
