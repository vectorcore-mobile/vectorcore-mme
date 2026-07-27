package s10

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/gtpv2"
	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/transportqos"
)

// ContextRequestHandler is implemented by the s1ap.Server (both MME roles).
type ContextRequestHandler interface {
	// HandleContextRequest is called on the old MME when a Context Request arrives.
	// Returns (response, mmeUEID of the found UE, found). If not found, response has
	// Cause=ContextNotFound; mmeUEID is 0.
	HandleContextRequest(srcAddr string, req *ContextRequest) (*ContextResponse, uint32, bool)
	// HandleContextAcknowledge is called on the old MME when a Context Acknowledge arrives.
	HandleContextAcknowledge(mmeUEID uint32, cause uint8)
}

// ContextResult is delivered to the new MME goroutine waiting for Context Response.
type ContextResult struct {
	Resp *ContextResponse
	Err  error
}

// pendingEntry is stored in pendingCTX keyed by sequence number.
type pendingEntry struct {
	localTEID uint32
	ch        chan ContextResult
}

// Server is the S10 GTPv2-C UDP server. It handles both roles:
//   - New MME: sends Context Requests, receives Context Responses.
//   - Old MME: receives Context Requests, sends Context Responses.
type Server struct {
	cfg     config.S10Config
	log     *zap.Logger
	conn    *net.UDPConn
	handler ContextRequestHandler

	seq  atomic.Uint32
	teid atomic.Uint32

	// New MME role: pending Context Requests, keyed by sequence number.
	pendingCTX sync.Map // seqNum uint32 → pendingEntry

	// Old MME role: pending Context Acknowledges, keyed by local TEID.
	pendingAck sync.Map // localTEID uint32 → mmeUEID uint32
}

// NewServer creates an S10 Server. Call SetHandler before Start.
func NewServer(cfg config.S10Config, log *zap.Logger) (*Server, error) {
	return &Server{cfg: cfg, log: log}, nil
}

// SetHandler wires the result callback. Must be called before Start.
func (s *Server) SetHandler(h ContextRequestHandler) { s.handler = h }

// Start binds the UDP socket and begins the receive loop. Blocks until the socket closes.
func (s *Server) Start() error {
	address := net.JoinHostPort(s.cfg.BindAddress, strconv.Itoa(s.cfg.BindPort))
	lc := net.ListenConfig{Control: transportqos.Control(s.cfg.QoS.DSCP)}
	packetConn, err := lc.ListenPacket(context.Background(), "udp", address)
	if err != nil {
		return fmt.Errorf("s10: bind UDP %s: %w", address, err)
	}
	conn, ok := packetConn.(*net.UDPConn)
	if !ok {
		_ = packetConn.Close()
		return fmt.Errorf("s10: bind UDP %s: unexpected socket type %T", address, packetConn)
	}
	s.conn = conn
	s.log.Info("s10: listening", zap.String("addr", conn.LocalAddr().String()))
	if tos, configured, _ := transportqos.TOS(s.cfg.QoS.DSCP); configured {
		s.log.Info("s10: outbound QoS configured", zap.Int("dscp", *s.cfg.QoS.DSCP), zap.String("tos", fmt.Sprintf("0x%02x", tos)))
	}
	s.recvLoop()
	return nil
}

// LocalAddr returns "ip:port" for use in Sender F-TEID IEs. Valid after Start.
func (s *Server) LocalAddr() string {
	if s.conn == nil {
		return fmt.Sprintf("%s:%d", s.cfg.BindAddress, s.cfg.BindPort)
	}
	return s.conn.LocalAddr().String()
}

// SendContextRequest sends a Context Request to peerAddr and returns a channel on which
// the caller must select (with a timeout). The channel receives exactly one ContextResult.
func (s *Server) SendContextRequest(peerAddr string, req *ContextRequest) (<-chan ContextResult, error) {
	localTEID := AllocateTEID()
	req.SenderFTEID.TEID = localTEID
	if req.SenderFTEID.IP == nil {
		if s.conn != nil {
			req.SenderFTEID.IP = s.conn.LocalAddr().(*net.UDPAddr).IP.To4()
		}
	}

	seq := s.nextSeq()
	ch := make(chan ContextResult, 1)
	s.pendingCTX.Store(seq, pendingEntry{localTEID: localTEID, ch: ch})

	peer, err := net.ResolveUDPAddr("udp4", peerAddr)
	if err != nil {
		s.pendingCTX.Delete(seq)
		return nil, fmt.Errorf("s10: resolve peer %q: %w", peerAddr, err)
	}

	buf := EncodeContextRequest(req, seq, 0) // TEID=0 first contact
	if _, err := s.conn.WriteToUDP(buf, peer); err != nil {
		s.pendingCTX.Delete(seq)
		metrics.S10MessagesTotal.WithLabelValues("ctx_request", "send_error").Inc()
		return nil, fmt.Errorf("s10: send ContextRequest: %w", err)
	}
	metrics.S10MessagesTotal.WithLabelValues("ctx_request", "sent").Inc()
	s.log.Info("s10: Context Request sent", zap.String("peer", peerAddr), zap.Uint32("seq", seq))
	return ch, nil
}

// SendContextAcknowledge sends a Context Acknowledge to peerAddr using the old MME's
// TEID in the GTPv2 header.
func (s *Server) SendContextAcknowledge(peerAddr string, peerTEID uint32, cause uint8) error {
	peer, err := net.ResolveUDPAddr("udp4", peerAddr)
	if err != nil {
		return fmt.Errorf("s10: resolve peer %q: %w", peerAddr, err)
	}
	buf := EncodeContextAcknowledge(cause, s.nextSeq(), peerTEID)
	if _, err := s.conn.WriteToUDP(buf, peer); err != nil {
		metrics.S10MessagesTotal.WithLabelValues("ctx_acknowledge", "send_error").Inc()
		return fmt.Errorf("s10: send ContextAcknowledge: %w", err)
	}
	metrics.S10MessagesTotal.WithLabelValues("ctx_acknowledge", "sent").Inc()
	s.log.Info("s10: Context Acknowledge sent", zap.String("peer", peerAddr), zap.Uint8("cause", cause))
	return nil
}

func (s *Server) nextSeq() uint32 { return s.seq.Add(1) }

func (s *Server) recvLoop() {
	buf := make([]byte, 65535)
	for {
		n, remoteAddr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			s.log.Warn("s10: recv error", zap.Error(err))
			return
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go s.dispatch(pkt, remoteAddr.String())
	}
}

func (s *Server) dispatch(pkt []byte, srcAddr string) {
	msg, err := gtpv2.Decode(pkt)
	if err != nil {
		s.log.Warn("s10: decode error", zap.String("src", srcAddr), zap.Error(err))
		return
	}

	switch msg.Type {
	case gtpv2.MsgContextRequest:
		s.handleIncomingContextRequest(msg, srcAddr)

	case gtpv2.MsgContextResponse:
		v, ok := s.pendingCTX.LoadAndDelete(msg.SeqNum)
		if !ok {
			s.log.Warn("s10: ContextResponse for unknown seq", zap.Uint32("seq", msg.SeqNum))
			return
		}
		e := v.(pendingEntry)
		resp, decErr := DecodeContextResponse(msg)
		if decErr != nil {
			metrics.S10MessagesTotal.WithLabelValues("ctx_response", "decode_error").Inc()
			e.ch <- ContextResult{Err: decErr}
			return
		}
		s.log.Info("s10: Context Response received", zap.String("src", srcAddr),
			zap.Uint8("cause", resp.Cause), zap.String("imsi", resp.IMSI))
		metrics.S10MessagesTotal.WithLabelValues("ctx_response", "received").Inc()
		e.ch <- ContextResult{Resp: resp}

	case gtpv2.MsgContextAcknowledge:
		// msg.TEID is the old MME's local TEID stored in pendingAck.
		v, ok := s.pendingAck.LoadAndDelete(msg.TEID)
		if !ok {
			s.log.Warn("s10: ContextAck for unknown TEID", zap.Uint32("teid", msg.TEID))
			return
		}
		mmeUEID := v.(uint32)
		ack, decErr := DecodeContextAcknowledge(msg)
		if decErr != nil {
			metrics.S10MessagesTotal.WithLabelValues("ctx_acknowledge", "decode_error").Inc()
			s.log.Warn("s10: ContextAck decode error", zap.Error(decErr))
			return
		}
		s.log.Info("s10: Context Acknowledge received", zap.String("src", srcAddr),
			zap.Uint8("cause", ack.Cause))
		metrics.S10MessagesTotal.WithLabelValues("ctx_acknowledge", "received").Inc()
		if s.handler != nil {
			s.handler.HandleContextAcknowledge(mmeUEID, ack.Cause)
		}

	default:
		s.log.Debug("s10: unexpected message type", zap.Uint8("type", msg.Type))
	}
}

func (s *Server) handleIncomingContextRequest(msg *gtpv2.Message, srcAddr string) {
	req, err := DecodeContextRequest(msg)
	if err != nil {
		s.log.Warn("s10: decode ContextRequest failed", zap.String("src", srcAddr), zap.Error(err))
		metrics.S10MessagesTotal.WithLabelValues("ctx_request", "decode_error").Inc()
		return
	}
	s.log.Info("s10: Context Request received", zap.String("src", srcAddr))
	metrics.S10MessagesTotal.WithLabelValues("ctx_request", "received").Inc()

	if s.handler == nil {
		s.log.Warn("s10: no handler, ignoring Context Request")
		return
	}

	resp, mmeUEID, found := s.handler.HandleContextRequest(srcAddr, req)

	// Allocate local TEID for this context transfer session.
	localTEID := AllocateTEID()
	// Register a pendingAck entry only when the UE was found. A not-found response
	// carries Cause=ContextNotFound and will never be followed by a CTX-Ack from the
	// new MME, so storing mmeUEID=0 would accumulate dead map entries indefinitely.
	if found {
		s.pendingAck.Store(localTEID, mmeUEID)
	}

	// The Sender F-TEID in the response uses our local S10 address.
	resp.SenderFTEID = gtpv2.FTEID{
		InterfaceType: gtpv2.IFTypeS10MME,
		TEID:          localTEID,
	}
	if s.conn != nil {
		resp.SenderFTEID.IP = s.conn.LocalAddr().(*net.UDPAddr).IP.To4()
	}

	// peerTEID in the response header = new MME's local TEID (req.SenderFTEID.TEID)
	peerTEID := req.SenderFTEID.TEID
	buf := EncodeContextResponse(resp, msg.SeqNum, peerTEID)

	peer, err := net.ResolveUDPAddr("udp4", srcAddr)
	if err != nil {
		s.log.Warn("s10: cannot resolve src for CTX-Resp", zap.String("src", srcAddr), zap.Error(err))
		s.pendingAck.Delete(localTEID)
		return
	}
	if _, err := s.conn.WriteToUDP(buf, peer); err != nil {
		s.log.Warn("s10: send ContextResponse failed", zap.Error(err))
		s.pendingAck.Delete(localTEID)
		metrics.S10MessagesTotal.WithLabelValues("ctx_response", "send_error").Inc()
		return
	}
	metrics.S10MessagesTotal.WithLabelValues("ctx_response", "sent").Inc()
	s.log.Info("s10: Context Response sent", zap.String("dst", srcAddr),
		zap.Uint8("cause", resp.Cause))
}
