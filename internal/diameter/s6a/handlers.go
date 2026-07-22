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
	"github.com/fiorix/go-diameter/v4/diam/sm"
	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/diameter/peer"
	"github.com/vectorcore/mme/internal/diameter/s13"
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
	cfg         config.S6aConfig
	diameterCfg config.DiameterConfig
	nfCfg       config.NFConfig
	ueManager   *uecontext.Manager
	nas         ResultHandler
	detachFn    func(ue *uecontext.Context) // optional; wired from S1AP for CLR cleanup
	log         *zap.Logger

	settings *sm.Settings

	peers *peer.Manager

	pendingAIR sync.Map // sessionID string → uint32 (mmeUEID)
	pendingULR sync.Map // sessionID string → uint32 (mmeUEID)
	pendingS13 sync.Map // sessionID string → pendingS13
	s13Cfg     config.S13Config

	sessionSeq atomic.Uint64
}

type pendingS13 struct {
	mmeUEID uint32
	timer   *time.Timer
	imei    string
	imeisv  string
}

// NewHandlers creates a new S6a handler set.
func NewHandlers(
	cfg config.S6aConfig,
	diameterCfg config.DiameterConfig,
	nfCfg config.NFConfig,
	ueManager *uecontext.Manager,
	nas ResultHandler,
	log *zap.Logger,
) *Handlers {
	settings := &sm.Settings{
		OriginHost:       datatype.DiameterIdentity(diameterCfg.OriginHost),
		OriginRealm:      datatype.DiameterIdentity(diameterCfg.OriginRealm),
		VendorID:         vendor3GPP,
		ProductName:      "VectorCore MME",
		FirmwareRevision: 1,
	}
	h := &Handlers{
		cfg:         cfg,
		diameterCfg: diameterCfg,
		nfCfg:       nfCfg,
		ueManager:   ueManager,
		nas:         nas,
		log:         log,
		settings:    settings,
	}
	h.peers = peer.New(diameterCfg, log, h.buildMux)
	return h
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

// SetS13Enabled controls S13 capability advertisement on the shared Diameter
// connections. It must be called before Start.
func (h *Handlers) SetS13Enabled(enabled bool) { h.peers.SetS13Enabled(enabled) }

// SetS13Config installs the top-level S13 policy before Start.
func (h *Handlers) SetS13Config(cfg config.S13Config) { h.s13Cfg = cfg }

// S13Enabled reports whether the equipment-check client is enabled for attach.
func (h *Handlers) S13Enabled() bool { return h.s13Cfg.Enabled && h.s13Cfg.CheckOnAttach }

func (h *Handlers) S13FailurePolicy() string { return h.s13Cfg.FailurePolicy }

// Start runs the shared Diameter peer manager. It maintains every configured
// outbound peer and any configured TCP/SCTP listeners concurrently.
func (h *Handlers) Start() error {
	return h.peers.Start()
}

func (h *Handlers) addDestinationRouting(m *diam.Message, host, realm string) {
	if host != "" {
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
func (h *Handlers) buildMux(onCER diam.HandlerFunc) *sm.StateMachine {
	settings := *h.settings
	settings.OnCER = onCER
	mux := sm.New(&settings)
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
	if h.s13Cfg.Enabled {
		mux.HandleIdx(diam.CommandIndex{AppID: s13.ApplicationID, Code: s13.CommandCode, Request: false}, diam.HandlerFunc(h.handleECA))
	}
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

// SendEquipmentCheck sends an asynchronous ECR through the same
// application-aware peer manager used by S6a. No request is sent without a
// validated equipment identity.
func (h *Handlers) SendEquipmentCheck(imsi, identity string, mmeUEID uint32) error {
	if !h.S13Enabled() {
		return fmt.Errorf("s13: disabled")
	}
	selected, err := h.peers.SelectPeer(s13.ApplicationID, h.diameterCfg.OriginRealm)
	if err != nil {
		return fmt.Errorf("s13: route ECR: %w", err)
	}
	sessionID := h.newSessionID(imsi)
	normalizedIMEI, _, err := s13.NormalizeIdentity(identity)
	if err != nil {
		return err
	}
	// Preserve common routing semantics: direct S13 peers get their learned
	// Origin-Host as Destination-Host; DRA/relay routes use realm-only routing.
	m, err := s13.BuildECR(sessionID, h.diameterCfg.OriginHost, h.diameterCfg.OriginRealm, selected.OriginRealm, selected.DestinationHost, imsi, identity)
	if err != nil {
		return err
	}
	pending := &pendingS13{mmeUEID: mmeUEID, imei: normalizedIMEI}
	if len(identity) == 16 {
		pending.imeisv = identity
	}
	pending.timer = time.AfterFunc(h.s13Cfg.Timeout, func() {
		if value, ok := h.pendingS13.LoadAndDelete(sessionID); ok {
			p := value.(*pendingS13)
			result := s13.Result{Err: fmt.Errorf("s13: ECA timeout"), IMEI: p.imei, IMEISV: p.imeisv}
			result.Allowed = s13.Allow(h.s13Cfg, result)
			h.log.Warn("s13: transaction removed", zap.String("session_id", sessionID), zap.Uint32("mme_ue_id", p.mmeUEID), zap.String("reason", "timeout"))
			h.deliverS13Result(p.mmeUEID, result)
		}
	})
	h.pendingS13.Store(sessionID, pending)
	if _, err = m.WriteTo(selected.Connection); err != nil {
		if value, ok := h.pendingS13.LoadAndDelete(sessionID); ok {
			value.(*pendingS13).timer.Stop()
		}
		h.reportTransactionFailure(selected)
		return fmt.Errorf("s13: ECR write: %w", err)
	}
	h.log.Info("s13: ECR sent", zap.String("session_id", sessionID), zap.Uint32("mme_ue_id", mmeUEID), zap.String("masked_imei", s13.MaskIMEI(normalizedIMEI)))
	h.log.Debug("s13: ECR identity", zap.String("session_id", sessionID), zap.Uint32("mme_ue_id", mmeUEID), zap.String("imei", normalizedIMEI), zap.String("imeisv", pending.imeisv))
	return nil
}

func (h *Handlers) handleECA(_ diam.Conn, m *diam.Message) {
	sessionAVP, err := m.FindAVP(avp.SessionID, 0)
	if err != nil {
		h.log.Warn("s13: ECA without Session-Id", zap.Error(err))
		return
	}
	sessionID, ok := sessionAVP.Data.(datatype.UTF8String)
	if !ok {
		h.log.Warn("s13: ECA invalid Session-Id")
		return
	}
	pending, ok := h.pendingS13.LoadAndDelete(string(sessionID))
	if !ok {
		h.log.Warn("s13: late or duplicate ECA", zap.String("session_id", string(sessionID)))
		return
	}
	p := pending.(*pendingS13)
	p.timer.Stop()
	result := s13.DecodeECA(m)
	result.IMEI, result.IMEISV = p.imei, p.imeisv
	result.Allowed = s13.Allow(h.s13Cfg, result)
	metrics.S13ECAsTotal.Inc()
	statusName := "unknown"
	if result.Verified {
		statusName = result.Status.String()
	}
	h.log.Info("s13: ECA received", zap.Uint32("mme_ue_id", p.mmeUEID), zap.String("session_id", string(sessionID)), zap.Uint32("result_code", result.DiameterResult), zap.Uint32("equipment_status", uint32(result.Status)), zap.String("equipment_status_name", statusName), zap.String("masked_imei", s13.MaskIMEI(p.imei)))
	h.log.Debug("s13: ECA identity correlation", zap.Uint32("mme_ue_id", p.mmeUEID), zap.String("session_id", string(sessionID)), zap.String("imei", p.imei), zap.String("imeisv", p.imeisv))
	if result.Verified {
		metrics.S13ChecksTotal.WithLabelValues(statusName).Inc()
	} else {
		metrics.S13ChecksTotal.WithLabelValues("diameter_error").Inc()
	}
	h.log.Debug("s13: transaction removed", zap.String("session_id", string(sessionID)), zap.Uint32("mme_ue_id", p.mmeUEID), zap.String("reason", statusName))
	h.deliverS13Result(p.mmeUEID, result)
}

func (h *Handlers) deliverS13Result(mmeUEID uint32, result s13.Result) {
	if receiver, ok := h.nas.(interface{ HandleS13Result(uint32, s13.Result) }); ok {
		receiver.HandleS13Result(mmeUEID, result)
	}
}

func (h *Handlers) selectPeer(realm string) (*peer.Peer, error) {
	return h.peers.SelectPeer(appIDS6a, realm)
}

func (h *Handlers) reportTransactionFailure(selected *peer.Peer) {
	h.peers.ReportTransactionFailure(selected.Name)
}

// Connected reports whether an S6a-capable or relay Diameter peer is ready.
func (h *Handlers) Connected() bool {
	_, err := h.selectPeer(h.diameterCfg.OriginRealm)
	return err == nil
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

// newSessionID generates a unique Session-ID.
func (h *Handlers) newSessionID(imsi string) string {
	seq := h.sessionSeq.Add(1)
	return fmt.Sprintf("%s;%s;%d", h.nfCfg.OriginHost, imsi, seq)
}
