// Package s11 implements the GTPv2-C S11 interface (MME ↔ S-GW).
// The MME is the originator: it sends CSR/MBR/DSR and receives the responses.
package s11

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/gtpv2"
	"github.com/vectorcore/mme/internal/metrics"
)

// ResultHandler receives decoded GTPv2-C responses asynchronously.
// Implementations must be safe to call from any goroutine.
type ResultHandler interface {
	HandleCSRResult(mmeUEID uint32, resp *gtpv2.CreateSessionResponse, err error)
	HandleMBRResult(mmeUEID uint32, err error)
	HandleDSRResult(mmeUEID uint32, err error)
}

// pending is stored in the correlation maps.
type pending struct{ mmeUEID uint32 }

// Client is the S11 GTPv2-C UDP client. One per MME process.
type Client struct {
	cfg     config.S11Config
	log     *zap.Logger
	conn    *net.UDPConn
	sgwAddr *net.UDPAddr
	handler ResultHandler

	seq        atomic.Uint32
	pendingCSR sync.Map // seqNum uint32 → pending
	pendingMBR sync.Map // seqNum uint32 → pending
	pendingDSR sync.Map // seqNum uint32 → pending
}

// NewClient creates a Client. Call SetHandler before Start to wire up the result callbacks.
func NewClient(cfg config.S11Config, log *zap.Logger) (*Client, error) {
	sgwAddr, err := net.ResolveUDPAddr("udp4", cfg.SGWAddress)
	if err != nil {
		return nil, fmt.Errorf("s11: resolve sgw address %q: %w", cfg.SGWAddress, err)
	}
	return &Client{
		cfg:     cfg,
		log:     log,
		sgwAddr: sgwAddr,
	}, nil
}

// SetHandler wires the result callback. Must be called before Start.
func (c *Client) SetHandler(h ResultHandler) { c.handler = h }

// Start binds the UDP socket and starts the receive loop. Blocks until the
// socket is closed; call in a goroutine.
func (c *Client) Start() error {
	bindAddr := &net.UDPAddr{
		IP:   net.ParseIP(c.cfg.BindAddress),
		Port: c.cfg.BindPort,
	}
	conn, err := net.ListenUDP("udp4", bindAddr)
	if err != nil {
		return fmt.Errorf("s11: bind UDP %v: %w", bindAddr, err)
	}
	c.conn = conn
	c.log.Info("s11: listening", zap.String("addr", conn.LocalAddr().String()),
		zap.String("sgw", c.sgwAddr.String()))
	c.recvLoop()
	return nil
}

// LocalIP returns the locally bound IP (for use as the MME S11 source IP in F-TEID IEs).
// Valid after Start has been called and the socket is bound.
func (c *Client) LocalIP() net.IP {
	if c.conn == nil {
		return net.ParseIP(c.cfg.BindAddress)
	}
	return c.conn.LocalAddr().(*net.UDPAddr).IP
}

// Close shuts down the S11 UDP socket. The receive loop exits when the socket closes.
// Call after Shutdown has sent all outstanding DSRs.
func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// SendCSR sends a Create Session Request and records the pending correlation.
func (c *Client) SendCSR(mmeUEID uint32, req *gtpv2.CreateSessionRequest) error {
	seq := c.nextSeq()
	buf := req.Encode(seq)
	c.pendingCSR.Store(seq, pending{mmeUEID: mmeUEID})
	if err := c.send(buf); err != nil {
		c.pendingCSR.Delete(seq)
		metrics.S11MessagesTotal.WithLabelValues("csr", "send_error").Inc()
		return err
	}
	c.log.Info("s11: CSR sent", zap.Uint32("mme_ue_id", mmeUEID), zap.Uint32("seq", seq))
	metrics.S11MessagesTotal.WithLabelValues("csr", "sent").Inc()
	return nil
}

// SendMBR sends a Modify Bearer Request.
func (c *Client) SendMBR(mmeUEID uint32, req *gtpv2.ModifyBearerRequest) error {
	seq := c.nextSeq()
	buf := req.Encode(seq)
	c.pendingMBR.Store(seq, pending{mmeUEID: mmeUEID})
	if err := c.send(buf); err != nil {
		c.pendingMBR.Delete(seq)
		metrics.S11MessagesTotal.WithLabelValues("mbr", "send_error").Inc()
		return err
	}
	c.log.Info("s11: MBR sent", zap.Uint32("mme_ue_id", mmeUEID), zap.Uint32("seq", seq))
	metrics.S11MessagesTotal.WithLabelValues("mbr", "sent").Inc()
	return nil
}

// SendDSR sends a Delete Session Request.
func (c *Client) SendDSR(mmeUEID uint32, req *gtpv2.DeleteSessionRequest) error {
	seq := c.nextSeq()
	buf := req.Encode(seq)
	c.pendingDSR.Store(seq, pending{mmeUEID: mmeUEID})
	if err := c.send(buf); err != nil {
		c.pendingDSR.Delete(seq)
		metrics.S11MessagesTotal.WithLabelValues("dsr", "send_error").Inc()
		return err
	}
	c.log.Info("s11: DSR sent", zap.Uint32("mme_ue_id", mmeUEID), zap.Uint32("seq", seq))
	metrics.S11MessagesTotal.WithLabelValues("dsr", "sent").Inc()
	return nil
}

func (c *Client) send(buf []byte) error {
	_, err := c.conn.WriteToUDP(buf, c.sgwAddr)
	return err
}

func (c *Client) nextSeq() uint32 {
	return c.seq.Add(1)
}

func (c *Client) recvLoop() {
	buf := make([]byte, 65535)
	for {
		n, _, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			c.log.Warn("s11: recv error", zap.Error(err))
			return
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go c.dispatch(pkt)
	}
}

func (c *Client) dispatch(pkt []byte) {
	msg, err := gtpv2.Decode(pkt)
	if err != nil {
		c.log.Warn("s11: decode error", zap.Error(err))
		return
	}

	switch msg.Type {
	case gtpv2.MsgCreateSessionResponse:
		v, ok := c.pendingCSR.LoadAndDelete(msg.SeqNum)
		if !ok {
			c.log.Warn("s11: CSRsp for unknown seq", zap.Uint32("seq", msg.SeqNum))
			return
		}
		p := v.(pending)
		resp, decErr := gtpv2.DecodeCreateSessionResponse(msg)
		if decErr != nil {
			metrics.S11MessagesTotal.WithLabelValues("csr", "decode_error").Inc()
			c.handler.HandleCSRResult(p.mmeUEID, nil, decErr)
			return
		}
		c.log.Info("s11: CSRsp received", zap.Uint32("mme_ue_id", p.mmeUEID),
			zap.Uint8("cause", resp.Cause))
		if resp.Cause == gtpv2.CauseRequestAccepted {
			metrics.S11MessagesTotal.WithLabelValues("csr", "accepted").Inc()
		} else {
			metrics.S11MessagesTotal.WithLabelValues("csr", "rejected").Inc()
		}
		c.handler.HandleCSRResult(p.mmeUEID, resp, nil)

	case gtpv2.MsgModifyBearerResponse:
		v, ok := c.pendingMBR.LoadAndDelete(msg.SeqNum)
		if !ok {
			c.log.Warn("s11: MBRsp for unknown seq", zap.Uint32("seq", msg.SeqNum))
			return
		}
		p := v.(pending)
		cause, decErr := gtpv2.DecodeModifyBearerResponse(msg)
		if decErr != nil {
			metrics.S11MessagesTotal.WithLabelValues("mbr", "decode_error").Inc()
			c.handler.HandleMBRResult(p.mmeUEID, decErr)
			return
		}
		c.log.Info("s11: MBRsp received", zap.Uint32("mme_ue_id", p.mmeUEID),
			zap.Uint8("cause", cause))
		if cause == gtpv2.CauseRequestAccepted {
			metrics.S11MessagesTotal.WithLabelValues("mbr", "accepted").Inc()
			c.handler.HandleMBRResult(p.mmeUEID, nil)
		} else {
			metrics.S11MessagesTotal.WithLabelValues("mbr", "rejected").Inc()
			c.handler.HandleMBRResult(p.mmeUEID,
				fmt.Errorf("s11: MBRsp cause %d", cause))
		}

	case gtpv2.MsgDeleteSessionResponse:
		v, ok := c.pendingDSR.LoadAndDelete(msg.SeqNum)
		if !ok {
			c.log.Warn("s11: DSRsp for unknown seq", zap.Uint32("seq", msg.SeqNum))
			return
		}
		p := v.(pending)
		cause, decErr := gtpv2.DecodeDeleteSessionResponse(msg)
		if decErr != nil {
			metrics.S11MessagesTotal.WithLabelValues("dsr", "decode_error").Inc()
			c.handler.HandleDSRResult(p.mmeUEID, decErr)
			return
		}
		c.log.Info("s11: DSRsp received", zap.Uint32("mme_ue_id", p.mmeUEID),
			zap.Uint8("cause", cause))
		metrics.S11MessagesTotal.WithLabelValues("dsr", "received").Inc()
		if cause != gtpv2.CauseRequestAccepted {
			c.handler.HandleDSRResult(p.mmeUEID, fmt.Errorf("s11: DSRsp cause %d", cause))
			return
		}
		c.handler.HandleDSRResult(p.mmeUEID, nil)

	default:
		c.log.Debug("s11: unexpected message type", zap.Uint8("type", msg.Type))
	}
}
