// Package s11 implements the GTPv2-C S11 interface (MME ↔ S-GW).
// The MME is the originator: it sends CSR/MBR/DSR and receives the responses.
package s11

import (
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/gtpv2"
	"github.com/vectorcore/mme/internal/metrics"
)

// ResultHandler receives decoded GTPv2-C responses asynchronously.
// Implementations must be safe to call from any goroutine.
type ResultHandler interface {
	HandleCSRResult(mmeUEID uint32, resp *gtpv2.CreateSessionResponse, err error)
	HandleMBRResult(mmeUEID uint32, correlationID string, resp *gtpv2.ModifyBearerResponse, err error)
	HandleDSRResult(mmeUEID uint32, linkedEBI uint8, err error)
	HandleRABRResult(mmeUEID uint32, result *gtpv2.ReleaseAccessBearersResult, err error)
	HandleDownlinkDataNotification(peer string, req *gtpv2.DownlinkDataNotification)
	HandleCreateBearerRequest(peer string, req *gtpv2.CreateBearerRequest)
	HandleUpdateBearerRequest(peer string, req *gtpv2.UpdateBearerRequest)
	HandleDeleteBearerRequest(peer string, req *gtpv2.DeleteBearerRequest)
}

// pending is stored in the correlation maps.
type pending struct {
	mmeUEID       uint32
	linkedEBI     uint8
	correlationID string
	peer          string
	requestTEID   uint32
	mmeS11TEID    uint32
	apn           string
	defaultEBI    uint8
	sessionState  string
	lastS11Proc   string
	transactionID string
	sentAt        time.Time
}

// Client is the S11 GTPv2-C UDP client. One per MME process.
type Client struct {
	cfg     config.S11Config
	log     *zap.Logger
	conn    *net.UDPConn
	handler ResultHandler

	seq        atomic.Uint32
	pendingCSR sync.Map // seqNum uint32 → pending
	pendingMBR sync.Map // seqNum uint32 → pending
	pendingDSR sync.Map // seqNum uint32 → pending
	pendingRAB sync.Map // seqNum uint32 → pending
}

// NewClient creates a Client. Call SetHandler before Start to wire up the result callbacks.
func NewClient(cfg config.S11Config, log *zap.Logger) (*Client, error) {
	return &Client{
		cfg: cfg,
		log: log,
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
	c.log.Info("s11: listening", zap.String("addr", conn.LocalAddr().String()))
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
	if msg, err := gtpv2.Decode(buf); err == nil {
		c.log.Debug("s11: CSR encoded",
			zap.Uint32("mme_ue_id", mmeUEID),
			zap.Uint32("seq", seq),
			zap.Int("csr_len", len(buf)),
			zap.Strings("csr_ie_list", ieListSummary(msg.IEs)),
			zap.Strings("csr_ie_details", gtpv2.DetailedIESummary(msg.IEs)))
	}
	c.pendingCSR.Store(seq, pending{mmeUEID: mmeUEID})
	if err := c.send(buf, req.SGWAddress); err != nil {
		c.pendingCSR.Delete(seq)
		metrics.S11MessagesTotal.WithLabelValues("csr", "send_error").Inc()
		return err
	}
	c.log.Debug("s11: CSR sent", zap.Uint32("mme_ue_id", mmeUEID), zap.Uint32("seq", seq))
	metrics.S11MessagesTotal.WithLabelValues("csr", "sent").Inc()
	return nil
}

// SendMBR sends a Modify Bearer Request.
func (c *Client) SendMBR(mmeUEID uint32, req *gtpv2.ModifyBearerRequest) error {
	seq := c.nextSeq()
	buf := req.Encode(seq)
	if msg, err := gtpv2.Decode(buf); err == nil {
		c.log.Debug("s11: MBR encoded",
			zap.Uint32("mme_ue_id", mmeUEID),
			zap.Uint32("seq", seq),
			zap.Uint32("sgwc_teid", req.SGWC_TEID),
			zap.Uint8("ebi", req.EBI),
			zap.Uint32("enb_s1u_teid", req.ENBU_TEID),
			zap.String("enb_s1u_ipv4", req.ENBU_IP.String()),
			zap.Int("mbr_len", len(buf)),
			zap.Strings("mbr_ie_list", ieListSummary(msg.IEs)),
			zap.Strings("mbr_ie_details", gtpv2.DetailedIESummary(msg.IEs)))
	}
	c.pendingMBR.Store(seq, pending{mmeUEID: mmeUEID, correlationID: req.CorrelationID})
	if err := c.send(buf, req.SGWAddress); err != nil {
		c.pendingMBR.Delete(seq)
		metrics.S11MessagesTotal.WithLabelValues("mbr", "send_error").Inc()
		return err
	}
	c.log.Debug("s11: MBR sent", zap.Uint32("mme_ue_id", mmeUEID), zap.Uint32("seq", seq))
	metrics.S11MessagesTotal.WithLabelValues("mbr", "sent").Inc()
	return nil
}

// SendDSR sends a Delete Session Request.
func (c *Client) SendDSR(mmeUEID uint32, req *gtpv2.DeleteSessionRequest) error {
	seq := c.nextSeq()
	buf := req.Encode(seq)
	c.pendingDSR.Store(seq, pending{mmeUEID: mmeUEID, linkedEBI: req.EBI})
	if err := c.send(buf, req.SGWAddress); err != nil {
		c.pendingDSR.Delete(seq)
		metrics.S11MessagesTotal.WithLabelValues("dsr", "send_error").Inc()
		return err
	}
	c.log.Info("s11: DSR sent", zap.Uint32("mme_ue_id", mmeUEID), zap.Uint32("seq", seq))
	metrics.S11MessagesTotal.WithLabelValues("dsr", "sent").Inc()
	return nil
}

// SendRABR sends a Release Access Bearers Request.
func (c *Client) SendRABR(mmeUEID uint32, req *gtpv2.ReleaseAccessBearersRequest) (uint32, error) {
	seq := c.nextSeq()
	buf := req.Encode(seq)
	sentAt := time.Now()
	c.pendingRAB.Store(seq, pending{
		mmeUEID:       mmeUEID,
		peer:          req.SGWAddress,
		requestTEID:   req.SGWC_TEID,
		mmeS11TEID:    req.MMES11TEID,
		apn:           req.APN,
		defaultEBI:    req.DefaultEBI,
		sessionState:  req.SessionState,
		lastS11Proc:   req.LastS11Procedure,
		transactionID: req.TransactionID,
		sentAt:        sentAt,
	})
	if err := c.send(buf, req.SGWAddress); err != nil {
		c.pendingRAB.Delete(seq)
		metrics.S11MessagesTotal.WithLabelValues("rabr", "send_error").Inc()
		return 0, err
	}
	c.log.Info("s11: RABR sent",
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.String("event", "rabr_sent"),
		zap.String("peer", req.SGWAddress),
		zap.String("apn", req.APN),
		zap.Uint8("default_ebi", req.DefaultEBI),
		zap.Uint32("mme_s11_teid", req.MMES11TEID),
		zap.Uint32("sgw_s11_teid", req.SGWC_TEID),
		zap.Uint32("sequence", seq),
		zap.Uint8("originating_node", req.OriginatingNode),
		zap.String("session_state", req.SessionState),
		zap.String("last_s11_procedure", req.LastS11Procedure),
		zap.String("transaction_id", req.TransactionID))
	metrics.S11MessagesTotal.WithLabelValues("rabr", "sent").Inc()
	return seq, nil
}

func (c *Client) SendCreateBearerResponse(peer string, teid uint32, seq uint32, cause uint8, bearers []gtpv2.CreateBearerBearer, meta *gtpv2.CreateBearerResponseMeta) error {
	buf := gtpv2.EncodeCreateBearerResponseWithMeta(teid, seq, cause, bearers, meta)
	return c.sendResponse(buf, peer)
}

func (c *Client) SendDDNAck(peer string, teid uint32, seq uint32, cause uint8, delayValue *uint8) error {
	buf := gtpv2.EncodeDownlinkDataNotificationAck(teid, seq, cause, delayValue)
	return c.sendResponse(buf, peer)
}

func (c *Client) SendDDNFailureIndication(peer string, teid uint32, seq uint32, cause uint8, imsi string) error {
	buf := gtpv2.EncodeDownlinkDataNotificationFailureIndication(teid, seq, cause, imsi)
	return c.sendResponse(buf, peer)
}

func (c *Client) SendCreateBearerResponseWithPiggybackMBR(peer string, teid uint32, seq uint32, cause uint8, bearers []gtpv2.CreateBearerBearer, meta *gtpv2.CreateBearerResponseMeta, mmeUEID uint32, mbr *gtpv2.ModifyBearerRequest) (uint32, error) {
	cbResp := gtpv2.EncodeCreateBearerResponseWithMeta(teid, seq, cause, bearers, meta)
	mbrSeq := c.nextSeq()
	mbrRaw := mbr.Encode(mbrSeq)
	piggy, err := gtpv2.EncodePiggybacked(cbResp, mbrRaw)
	if err != nil {
		return 0, err
	}
	c.pendingMBR.Store(mbrSeq, pending{mmeUEID: mmeUEID})
	if err := c.sendResponse(piggy, peer); err != nil {
		c.pendingMBR.Delete(mbrSeq)
		metrics.S11MessagesTotal.WithLabelValues("mbr", "send_error").Inc()
		return 0, err
	}
	c.log.Info("s11: Create Bearer Response with piggybacked MBR sent",
		zap.Uint32("mme_ue_id", mmeUEID),
		zap.Uint32("create_bearer_seq", seq),
		zap.Uint32("mbr_seq", mbrSeq),
		zap.Int("mbr_len", len(mbrRaw)))
	metrics.S11MessagesTotal.WithLabelValues("mbr", "sent").Inc()
	return mbrSeq, nil
}

func (c *Client) SendUpdateBearerResponse(peer string, teid uint32, seq uint32, cause uint8, bearers []gtpv2.UpdateBearerBearer, meta *gtpv2.UpdateBearerResponseMeta) error {
	buf := gtpv2.EncodeUpdateBearerResponseWithMeta(teid, seq, cause, bearers, meta)
	return c.sendResponse(buf, peer)
}

func (c *Client) SendDeleteBearerResponse(peer string, teid uint32, seq uint32, cause uint8, ebis []uint8, meta *gtpv2.DeleteBearerResponseMeta) error {
	buf := gtpv2.EncodeDeleteBearerResponseWithMeta(teid, seq, cause, ebis, meta)
	return c.sendResponse(buf, peer)
}

func (c *Client) send(buf []byte, remote string) error {
	if remote == "" {
		return fmt.Errorf("s11: missing selected SGW address")
	}
	sgwAddr, err := net.ResolveUDPAddr("udp", remote)
	if err != nil {
		return fmt.Errorf("s11: resolve selected SGW address %q: %w", remote, err)
	}
	_, err = c.conn.WriteToUDP(buf, sgwAddr)
	return err
}

func (c *Client) sendResponse(buf []byte, remote string) error {
	sgwAddr, err := net.ResolveUDPAddr("udp", remote)
	if err != nil {
		return fmt.Errorf("s11: resolve response peer %q: %w", remote, err)
	}
	_, err = c.conn.WriteToUDP(buf, sgwAddr)
	return err
}

func (c *Client) nextSeq() uint32 {
	return c.seq.Add(1)
}

func (c *Client) buildEchoResponse(seq uint32) []byte {
	return gtpv2.EncodeNoTEID(&gtpv2.Message{
		Type:   gtpv2.MsgEchoResponse,
		SeqNum: seq,
		IEs:    []gtpv2.IE{gtpv2.EncodeRecovery(c.cfg.RecoveryRestartCounter)},
	})
}

func (c *Client) recvLoop() {
	buf := make([]byte, 65535)
	for {
		n, remote, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			c.log.Warn("s11: recv error", zap.Error(err))
			return
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go c.dispatch(pkt, remote)
	}
}

func (c *Client) dispatch(pkt []byte, remote *net.UDPAddr) {
	msgs, err := gtpv2.DecodeAll(pkt)
	if err != nil {
		c.log.Warn("s11: decode error", zap.String("raw_hex", hex.EncodeToString(pkt)), zap.Error(err))
		return
	}
	for _, msg := range msgs {
		c.dispatchMessage(msg, pkt, remote)
	}
}

func (c *Client) dispatchMessage(msg *gtpv2.Message, pkt []byte, remote *net.UDPAddr) {
	switch msg.Type {
	case gtpv2.MsgEchoRequest:
		resp := c.buildEchoResponse(msg.SeqNum)
		if _, err := c.conn.WriteToUDP(resp, remote); err != nil {
			c.log.Warn("s11: Echo Response send error", zap.String("remote", remote.String()), zap.Error(err))
			return
		}
		c.log.Debug("s11: Echo Request handled", zap.String("remote", remote.String()), zap.Uint32("seq", msg.SeqNum))

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
		causeDetails, _ := gtpv2.DecodeCauseDetails(gtpv2.FindIE(msg.IEs, gtpv2.IETypeCause, 0))
		if causeDetails == nil {
			causeDetails = &gtpv2.CauseDetails{}
		}
		c.log.Debug("s11: CSRsp received", zap.Uint32("mme_ue_id", p.mmeUEID),
			zap.Uint8("cause", resp.Cause),
			zap.String("cause_name", gtpv2.CauseName(resp.Cause)),
			zap.Int("raw_csrsp_len", len(pkt)),
			zap.Strings("csrsp_ie_list", ieListSummary(msg.IEs)),
			zap.Strings("csrsp_ie_details", gtpv2.DetailedIESummary(msg.IEs)),
			zap.Uint8("cause_flags", causeDetails.Flags),
			zap.Uint8("offending_ie_type", causeDetails.OffendingIEType),
			zap.Uint8("offending_ie_instance", causeDetails.OffendingIEInstance))
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
		resp, decErr := gtpv2.DecodeModifyBearerResponse(msg)
		if decErr != nil {
			metrics.S11MessagesTotal.WithLabelValues("mbr", "decode_error").Inc()
			c.handler.HandleMBRResult(p.mmeUEID, p.correlationID, nil, decErr)
			return
		}
		c.log.Debug("s11: MBRsp received", zap.Uint32("mme_ue_id", p.mmeUEID),
			zap.Uint8("cause", resp.Cause),
			zap.String("cause_name", gtpv2.CauseName(resp.Cause)),
			zap.Int("modified_bearers", len(resp.ModifiedBearers)),
			zap.Int("removed_bearers", len(resp.RemovedBearers)))
		if resp.Cause == gtpv2.CauseRequestAccepted || resp.Cause == gtpv2.CauseRequestAcceptedPartially {
			metrics.S11MessagesTotal.WithLabelValues("mbr", "accepted").Inc()
			c.handler.HandleMBRResult(p.mmeUEID, p.correlationID, resp, nil)
		} else {
			metrics.S11MessagesTotal.WithLabelValues("mbr", "rejected").Inc()
			c.handler.HandleMBRResult(p.mmeUEID, p.correlationID, resp,
				fmt.Errorf("s11: MBRsp cause %d", resp.Cause))
		}

	case gtpv2.MsgCreateBearerRequest:
		req, decErr := gtpv2.DecodeCreateBearerRequest(msg)
		if decErr != nil {
			c.log.Warn("s11: Create Bearer Request decode error",
				zap.String("remote", remote.String()),
				zap.Uint32("seq", msg.SeqNum),
				zap.Uint32("teid", msg.TEID),
				zap.String("raw_hex", hex.EncodeToString(pkt)),
				zap.Error(decErr))
			cause := gtpv2.DecodeErrorCause(decErr)
			resp := gtpv2.EncodeCreateBearerResponse(msg.TEID, msg.SeqNum, cause, nil)
			_, _ = c.conn.WriteToUDP(resp, remote)
			return
		}
		fields := []zap.Field{
			zap.String("remote", remote.String()),
			zap.Uint32("seq", req.SeqNum),
			zap.Uint32("teid", req.TEID),
			zap.Uint8("linked_ebi", req.LinkedEBI),
			zap.Int("bearer_count", len(req.Bearers)),
		}
		for i, b := range req.Bearers {
			fields = append(fields,
				zap.Uint8(fmt.Sprintf("bearer_%d_ebi", i), b.EBI),
				zap.Uint8(fmt.Sprintf("bearer_%d_qci", i), b.QCI),
				zap.Uint32(fmt.Sprintf("bearer_%d_sgw_s1u_teid", i), b.SGWS1UTEID),
				zap.String(fmt.Sprintf("bearer_%d_tft_hex", i), hex.EncodeToString(b.TFT)))
		}
		c.log.Debug("s11: Create Bearer Request received", fields...)
		if c.handler == nil {
			resp := gtpv2.EncodeCreateBearerResponse(req.TEID, req.SeqNum, gtpv2.CauseServiceNotSupported, req.Bearers)
			_, _ = c.conn.WriteToUDP(resp, remote)
			metrics.S11MessagesTotal.WithLabelValues("create_bearer", "rejected").Inc()
			return
		}
		c.handler.HandleCreateBearerRequest(remote.String(), req)

	case gtpv2.MsgDownlinkDataNotification:
		req, decErr := gtpv2.DecodeDownlinkDataNotification(msg)
		if decErr != nil {
			c.log.Warn("s11: Downlink Data Notification decode error",
				zap.String("remote", remote.String()),
				zap.Uint32("seq", msg.SeqNum),
				zap.Uint32("teid", msg.TEID),
				zap.String("raw_hex", hex.EncodeToString(pkt)),
				zap.Error(decErr))
			if c.handler != nil {
				c.handler.HandleDownlinkDataNotification(remote.String(), &gtpv2.DownlinkDataNotification{
					TEID:   msg.TEID,
					SeqNum: msg.SeqNum,
				})
			}
			return
		}
		fields := []zap.Field{
			zap.String("remote", remote.String()),
			zap.Uint32("seq", req.SeqNum),
			zap.Uint32("teid", req.TEID),
		}
		if req.EBI != nil {
			fields = append(fields, zap.Uint8("ebi", *req.EBI))
		}
		if req.ARP != nil {
			fields = append(fields, zap.Uint8("arp", *req.ARP))
		}
		if req.IMSI != "" {
			fields = append(fields, zap.String("imsi", req.IMSI))
		}
		if req.SenderFTEID != nil {
			fields = append(fields,
				zap.Uint32("sender_fteid_teid", req.SenderFTEID.TEID),
				zap.String("sender_fteid_ip", req.SenderFTEID.IP.String()))
		}
		if req.DelayValue != nil {
			fields = append(fields, zap.Uint8("delay_value", *req.DelayValue))
		}
		fields = append(fields,
			zap.Bool("paging_service_info_present", len(req.PagingServiceInfo) > 0),
			zap.Int("unknown_ie_count", len(req.LowPriorityRawIEs)+len(req.AdditionalEBIRawIE)))
		c.log.Info("s11: Downlink Data Notification received", fields...)
		metrics.S11MessagesTotal.WithLabelValues("ddn", "received").Inc()
		if c.handler != nil {
			c.handler.HandleDownlinkDataNotification(remote.String(), req)
		}

	case gtpv2.MsgUpdateBearerRequest:
		req, decErr := gtpv2.DecodeUpdateBearerRequest(msg)
		if decErr != nil {
			c.log.Warn("s11: Update Bearer Request decode error",
				zap.String("remote", remote.String()),
				zap.Uint32("seq", msg.SeqNum),
				zap.Uint32("teid", msg.TEID),
				zap.String("raw_hex", hex.EncodeToString(pkt)),
				zap.Error(decErr))
			resp := gtpv2.EncodeUpdateBearerResponse(msg.TEID, msg.SeqNum, gtpv2.DecodeErrorCause(decErr), nil)
			_, _ = c.conn.WriteToUDP(resp, remote)
			return
		}
		fields := []zap.Field{
			zap.String("remote", remote.String()),
			zap.Uint32("seq", req.SeqNum),
			zap.Uint32("teid", req.TEID),
			zap.Int("bearer_count", len(req.Bearers)),
		}
		for i, b := range req.Bearers {
			fields = append(fields,
				zap.Uint8(fmt.Sprintf("bearer_%d_ebi", i), b.EBI),
				zap.Uint8(fmt.Sprintf("bearer_%d_qci", i), b.QCI),
				zap.String(fmt.Sprintf("bearer_%d_tft_hex", i), hex.EncodeToString(b.TFT)))
		}
		c.log.Debug("s11: Update Bearer Request received", fields...)
		if c.handler == nil {
			resp := gtpv2.EncodeUpdateBearerResponse(req.TEID, req.SeqNum, gtpv2.CauseServiceNotSupported, req.Bearers)
			_, _ = c.conn.WriteToUDP(resp, remote)
			metrics.S11MessagesTotal.WithLabelValues("update_bearer", "rejected").Inc()
			return
		}
		c.handler.HandleUpdateBearerRequest(remote.String(), req)

	case gtpv2.MsgDeleteBearerRequest:
		req, decErr := gtpv2.DecodeDeleteBearerRequest(msg)
		if decErr != nil {
			c.log.Warn("s11: Delete Bearer Request decode error",
				zap.String("remote", remote.String()),
				zap.Uint32("seq", msg.SeqNum),
				zap.Uint32("teid", msg.TEID),
				zap.String("raw_hex", hex.EncodeToString(pkt)),
				zap.Error(decErr))
			resp := gtpv2.EncodeDeleteBearerResponse(msg.TEID, msg.SeqNum, gtpv2.DecodeErrorCause(decErr), nil)
			_, _ = c.conn.WriteToUDP(resp, remote)
			return
		}
		c.log.Debug("s11: Delete Bearer Request received",
			zap.String("remote", remote.String()),
			zap.Uint32("seq", req.SeqNum),
			zap.Uint32("teid", req.TEID),
			zap.Uint8s("ebis", req.EBIs))
		if c.handler == nil {
			resp := gtpv2.EncodeDeleteBearerResponse(req.TEID, req.SeqNum, gtpv2.CauseServiceNotSupported, req.EBIs)
			_, _ = c.conn.WriteToUDP(resp, remote)
			metrics.S11MessagesTotal.WithLabelValues("delete_bearer", "rejected").Inc()
			return
		}
		c.handler.HandleDeleteBearerRequest(remote.String(), req)

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
			c.handler.HandleDSRResult(p.mmeUEID, p.linkedEBI, decErr)
			return
		}
		c.log.Debug("s11: DSRsp received", zap.Uint32("mme_ue_id", p.mmeUEID),
			zap.Uint8("linked_ebi", p.linkedEBI),
			zap.Uint8("cause", cause), zap.String("cause_name", gtpv2.CauseName(cause)))
		metrics.S11MessagesTotal.WithLabelValues("dsr", "received").Inc()
		if cause != gtpv2.CauseRequestAccepted {
			c.handler.HandleDSRResult(p.mmeUEID, p.linkedEBI, fmt.Errorf("s11: DSRsp cause %d", cause))
			return
		}
		c.handler.HandleDSRResult(p.mmeUEID, p.linkedEBI, nil)

	case gtpv2.MsgReleaseAccessBearersResponse:
		v, ok := c.pendingRAB.LoadAndDelete(msg.SeqNum)
		if !ok {
			c.log.Warn("s11: RABRsp for unknown seq", zap.Uint32("seq", msg.SeqNum))
			return
		}
		p := v.(pending)
		resp, decErr := gtpv2.DecodeReleaseAccessBearersResponse(msg)
		if decErr != nil {
			metrics.S11MessagesTotal.WithLabelValues("rabr", "decode_error").Inc()
			c.handler.HandleRABRResult(p.mmeUEID, nil, decErr)
			return
		}
		result := &gtpv2.ReleaseAccessBearersResult{
			Peer:                       remote.String(),
			SeqNum:                     msg.SeqNum,
			RequestedSGWCTEID:          p.requestTEID,
			RequestedMMES11TEID:        p.mmeS11TEID,
			ResponseHeaderTEID:         msg.TEID,
			APN:                        p.apn,
			DefaultEBI:                 p.defaultEBI,
			SessionState:               p.sessionState,
			LastSuccessfulS11Procedure: p.lastS11Proc,
			TransactionID:              p.transactionID,
			SentAt:                     p.sentAt,
			Elapsed:                    time.Since(p.sentAt),
			Cause:                      resp.Cause,
		}
		c.log.Info("s11: RABRsp received",
			zap.Uint32("mme_ue_id", p.mmeUEID),
			zap.String("event", "rabr_response"),
			zap.String("peer", remote.String()),
			zap.String("apn", p.apn),
			zap.Uint8("default_ebi", p.defaultEBI),
			zap.Uint32("sequence", msg.SeqNum),
			zap.Uint32("requested_sgw_s11_teid", p.requestTEID),
			zap.Uint32("response_header_teid", msg.TEID),
			zap.Uint8("cause", resp.Cause),
			zap.String("cause_name", gtpv2.CauseName(resp.Cause)),
			zap.Int64("elapsed_ms", result.Elapsed.Milliseconds()))
		if resp.Cause == gtpv2.CauseRequestAccepted {
			metrics.S11MessagesTotal.WithLabelValues("rabr", "accepted").Inc()
			c.handler.HandleRABRResult(p.mmeUEID, result, nil)
			return
		}
		metrics.S11MessagesTotal.WithLabelValues("rabr", "rejected").Inc()
		c.handler.HandleRABRResult(p.mmeUEID, result, fmt.Errorf("s11: RABRsp cause %d", resp.Cause))

	default:
		c.log.Debug("s11: unexpected message type", zap.Uint8("type", msg.Type))
	}
}

func ieListSummary(ies []gtpv2.IE) []string {
	out := make([]string, 0, len(ies))
	for _, ie := range ies {
		out = append(out, fmt.Sprintf("type=%d instance=%d len=%d", ie.Type, ie.Instance, len(ie.Value)))
	}
	return out
}
