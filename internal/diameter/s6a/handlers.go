// Package s6a implements the S6a Diameter interface (3GPP TS 29.272).
// The MME is the Diameter client; it connects outbound to the HSS.
package s6a

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/fiorix/go-diameter/v4/diam/avp"
	"github.com/fiorix/go-diameter/v4/diam/datatype"
	"github.com/fiorix/go-diameter/v4/diam/dict"
	"github.com/fiorix/go-diameter/v4/diam/sm"
	"github.com/fiorix/go-diameter/v4/diam/sm/smpeer"
	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/gateway"
	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/uecontext"
)

const (
	vendor3GPP    = 10415
	appIDS6a      = diam.TGPP_S6A_APP_ID
	ratTypeEUTRAN = 1004
)

// ResultHandler is the callback interface that s1ap.Server implements.
// S6a calls these methods asynchronously when Diameter answers arrive.
type ResultHandler interface {
	HandleAIAResult(mmeUEID uint32, rand, xres, autn, kasme []byte, err error)
	HandleULAResultWithSubscriberProfile(mmeUEID uint32, msisdn string, profile *gateway.SubscriberProfile, err error)
}

// Handlers is the S6a Diameter client.
// It implements the s1ap.S6aClient interface (SendAIR, SendULR, SendPUR).
type Handlers struct {
	cfg       config.S6aConfig
	nfCfg     config.NFConfig
	ueManager *uecontext.Manager
	nas       ResultHandler
	detachFn  func(ue *uecontext.Context) // optional; wired from S1AP for CLR cleanup
	log       *zap.Logger

	settings *sm.Settings

	connMu sync.RWMutex
	conn   diam.Conn

	pendingAIR sync.Map // sessionID string → uint32 (mmeUEID)
	pendingULR sync.Map // sessionID string → uint32 (mmeUEID)

	sessionSeq atomic.Uint64
}

// NewHandlers creates a new S6a handler set.
func NewHandlers(
	cfg config.S6aConfig,
	nfCfg config.NFConfig,
	ueManager *uecontext.Manager,
	nas ResultHandler,
	log *zap.Logger,
) *Handlers {
	settings := &sm.Settings{
		OriginHost:       datatype.DiameterIdentity(nfCfg.OriginHost),
		OriginRealm:      datatype.DiameterIdentity(nfCfg.OriginRealm),
		VendorID:         vendor3GPP,
		ProductName:      "VectorCore MME",
		FirmwareRevision: 1,
	}
	return &Handlers{
		cfg:       cfg,
		nfCfg:     nfCfg,
		ueManager: ueManager,
		nas:       nas,
		log:       log,
		settings:  settings,
	}
}

// SetResultHandler wires the NAS result callback after construction.
// Call this before Start().
func (h *Handlers) SetResultHandler(nas ResultHandler) {
	h.nas = nas
}

// SetDetachFn wires the network-triggered detach callback (called on CLR).
// The fn should send DSR to the S-GW and clean up S1AP resources.
func (h *Handlers) SetDetachFn(fn func(ue *uecontext.Context)) {
	h.detachFn = fn
}

// Start runs the Diameter layer. Two modes:
//   - If s6a.bind_address is set: listen for inbound connections (DRA or HSS connects to us).
//   - Otherwise: connect outbound to s6a.peer_address and reconnect on failure.
//
// Blocking in both cases.
func (h *Handlers) Start() error {
	if h.cfg.BindAddress != "" {
		return h.listen()
	}
	for {
		if err := h.connect(); err != nil {
			h.log.Warn("s6a: connection failed, retrying",
				zap.String("peer", h.cfg.PeerAddress), zap.Error(err))
		}
		time.Sleep(h.retryDelay())
	}
}

func (h *Handlers) retryDelay() time.Duration {
	if h.cfg.RetryDelay > 0 {
		return h.cfg.RetryDelay
	}
	return 5 * time.Second
}

func (h *Handlers) addDestinationRouting(m *diam.Message, host, realm string) {
	if h.cfg.Routing.SendDestinationHost && host != "" {
		m.NewAVP(avp.DestinationHost, avp.Mbit, 0, datatype.DiameterIdentity(host))
	}
	m.NewAVP(avp.DestinationRealm, avp.Mbit, 0, datatype.DiameterIdentity(realm))
}

func boolToUint32(v bool) uint32 {
	if v {
		return 1
	}
	return 0
}

// buildMux constructs the sm.StateMachine and registers all S6a message handlers.
func (h *Handlers) buildMux() *sm.StateMachine {
	mux := sm.New(h.settings)
	mux.HandleIdx(
		diam.CommandIndex{AppID: appIDS6a, Code: diam.AuthenticationInformation, Request: false},
		diam.HandlerFunc(h.handleAIA))
	mux.HandleIdx(
		diam.CommandIndex{AppID: appIDS6a, Code: diam.UpdateLocation, Request: false},
		diam.HandlerFunc(h.handleULA))
	mux.HandleIdx(
		diam.CommandIndex{AppID: appIDS6a, Code: diam.CancelLocation, Request: true},
		diam.HandlerFunc(h.handleCLR))
	mux.HandleIdx(
		diam.CommandIndex{AppID: appIDS6a, Code: diam.InsertSubscriberData, Request: true},
		diam.HandlerFunc(h.handleIDR))
	mux.HandleIdx(
		diam.CommandIndex{AppID: appIDS6a, Code: diam.PurgeUE, Request: false},
		diam.HandlerFunc(h.handlePUA))
	mux.HandleFunc("DPR", diam.HandlerFunc(h.handleDPR))
	mux.HandleFunc("ALL", diam.HandlerFunc(func(c diam.Conn, m *diam.Message) {
		h.log.Debug("s6a: unhandled message",
			zap.String("cmd", fmt.Sprintf("%d", m.Header.CommandCode)))
	}))
	go func() {
		for er := range mux.ErrorReports() {
			h.log.Warn("s6a: mux error", zap.Error(er.Error))
		}
	}()
	return mux
}

// connCapture wraps a diam.Handler so every incoming message records the peer connection.
// Used in server/listen mode so we can send requests on the DRA-initiated connection.
type connCapture struct {
	h    *Handlers
	next diam.Handler
}

func (cc *connCapture) ServeDIAM(c diam.Conn, m *diam.Message) {
	cc.next.ServeDIAM(c, m) // sm processes CER first, setting smpeer on the context
	cc.h.storeConn(c)       // now peerMeta(c) returns the populated Origin-Host/Realm
}

// storeConn records c as the active connection and starts a goroutine that nils it on close.
func (h *Handlers) storeConn(c diam.Conn) {
	h.connMu.Lock()
	if h.conn == c {
		h.connMu.Unlock()
		return
	}
	h.conn = c
	h.connMu.Unlock()

	host, realm, _ := peerMeta(c)
	h.log.Info("s6a: Diameter peer connected",
		zap.String("origin_host", host),
		zap.String("origin_realm", realm),
		zap.String("remote_addr", c.RemoteAddr().String()))
	metrics.S6aRequestsTotal.WithLabelValues("connect", "ok").Inc()

	if cn, ok := c.(diam.CloseNotifier); ok {
		go func() {
			<-cn.CloseNotify()
			h.connMu.Lock()
			if h.conn == c {
				h.conn = nil
			}
			h.connMu.Unlock()
			h.log.Warn("s6a: Diameter peer disconnected",
				zap.String("origin_host", host), zap.String("origin_realm", realm))
		}()
	}
}

// listen starts a Diameter server so the DRA (or HSS directly) can connect inbound.
func (h *Handlers) listen() error {
	mux := h.buildMux()
	port := h.cfg.BindPort
	if port == 0 {
		port = 3868
	}
	addr := fmt.Sprintf("%s:%d", h.cfg.BindAddress, port)
	h.log.Info("s6a: listening for Diameter connections", zap.String("addr", addr))
	return diam.ListenAndServe(addr, &connCapture{h: h, next: mux}, dict.Default)
}

// connect establishes one outbound Diameter connection to the HSS or DRA.
func (h *Handlers) connect() error {
	mux := h.buildMux()

	cli := &sm.Client{
		Dict:               dict.Default,
		Handler:            mux,
		MaxRetransmits:     3,
		RetransmitInterval: time.Second,
		EnableWatchdog:     true,
		WatchdogInterval:   5 * time.Second,
		SupportedVendorID: []*diam.AVP{
			diam.NewAVP(avp.SupportedVendorID, avp.Mbit, 0, datatype.Unsigned32(vendor3GPP)),
		},
		VendorSpecificApplicationID: []*diam.AVP{
			diam.NewAVP(avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{
				AVP: []*diam.AVP{
					diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(appIDS6a)),
					diam.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(vendor3GPP)),
				},
			}),
		},
	}

	conn, err := cli.DialNetwork("tcp", h.cfg.PeerAddress)
	if err != nil {
		return fmt.Errorf("s6a: dial %s: %w", h.cfg.PeerAddress, err)
	}

	h.connMu.Lock()
	h.conn = conn
	h.connMu.Unlock()

	h.log.Info("s6a: connected to peer", zap.String("peer", h.cfg.PeerAddress))
	metrics.S6aRequestsTotal.WithLabelValues("connect", "ok").Inc()

	<-conn.(diam.CloseNotifier).CloseNotify()
	h.connMu.Lock()
	h.conn = nil
	h.connMu.Unlock()
	h.log.Warn("s6a: peer connection lost", zap.String("peer", h.cfg.PeerAddress))
	return nil
}

// Connected reports whether a Diameter peer is currently connected.
func (h *Handlers) Connected() bool {
	h.connMu.RLock()
	defer h.connMu.RUnlock()
	return h.conn != nil
}

// getConn returns the current Diameter connection, or an error if not connected.
func (h *Handlers) getConn() (diam.Conn, error) {
	h.connMu.RLock()
	defer h.connMu.RUnlock()
	if h.conn == nil {
		return nil, fmt.Errorf("s6a: not connected to HSS")
	}
	return h.conn, nil
}

// handleDPR handles Disconnect-Peer-Request from the remote end.
// We send a DPA and close the connection; per RFC 6733 §5.4 the connection
// must be torn down after the DPA is sent.
func (h *Handlers) handleDPR(c diam.Conn, m *diam.Message) {
	var req struct {
		OriginHost  datatype.DiameterIdentity `avp:"Origin-Host"`
		OriginRealm datatype.DiameterIdentity `avp:"Origin-Realm"`
	}
	_ = m.Unmarshal(&req)
	h.log.Info("s6a: peer disconnecting (DPR)",
		zap.String("origin_host", string(req.OriginHost)),
		zap.String("origin_realm", string(req.OriginRealm)),
		zap.String("remote_addr", c.RemoteAddr().String()))

	ans := m.Answer(diam.Success)
	ans.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity(h.nfCfg.OriginHost))
	ans.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity(h.nfCfg.OriginRealm))
	if _, err := ans.WriteTo(c); err != nil {
		h.log.Warn("s6a: DPA write failed", zap.Error(err))
	}
	c.Close()
}

// peerMeta retrieves the HSS peer metadata from the connection context.
func peerMeta(c diam.Conn) (host, realm string, ok bool) {
	meta, found := smpeer.FromContext(c.Context())
	if !found {
		return "", "", false
	}
	return string(meta.OriginHost), string(meta.OriginRealm), true
}

// newSessionID generates a unique Session-ID.
func (h *Handlers) newSessionID(imsi string) string {
	seq := h.sessionSeq.Add(1)
	return fmt.Sprintf("%s;%s;%d", h.nfCfg.OriginHost, imsi, seq)
}
