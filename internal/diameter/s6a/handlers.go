// Package s6a implements the S6a Diameter interface (3GPP TS 29.272).
// The MME is the Diameter client; it connects outbound to the HSS.
package s6a

import (
	"context"
	"crypto/sha256"
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
	"github.com/vectorcore/mme/internal/diameter/sgd"
	"github.com/vectorcore/mme/internal/diameter/slg"
	"github.com/vectorcore/mme/internal/gateway"
	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/nas/lcsnotify"
	"github.com/vectorcore/mme/internal/sls"
	smsservice "github.com/vectorcore/mme/internal/sms"
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

	pendingAIR  sync.Map // sessionID string → uint32 (mmeUEID)
	pendingULR  sync.Map // sessionID string → uint32 (mmeUEID)
	pendingS13  sync.Map // sessionID string → pendingS13
	pendingOFR  sync.Map // sessionID string → chan sgd.MOAnswer
	pendingALR  sync.Map // sessionID string → chan uint32
	mtResults   sync.Map // exact inbound TFR identity -> cachedMTResult
	s13Cfg      config.S13Config
	sgdCfg      config.SGdConfig
	slgCfg      config.SLgConfig
	slgTx       *slgTransactions
	pendingLRA  sync.Map // Session-Id -> chan error
	slsProvider interface {
		RequestPosition(context.Context, string, uint32, []byte, uint32, bool) (sls.PositionResult, error)
		AbortPosition(uint32)
	}
	// lcsNotifier sends the TS 23.271 §9.1.15 step 4 LCS location-notification
	// over NAS (s1ap.Server implements this). Nil-safe: handlePLR treats a
	// missing notifier as "cannot notify", failing closed for
	// RESTRICTED_IF_NO_RESPONSE and open for ALLOWED_IF_NO_RESPONSE, matching
	// each value's no-response rule.
	lcsNotifier interface {
		SendLocationNotification(mme uint32, notificationType lcsnotify.NotificationType, wait bool, timeout time.Duration) (bool, error)
	}

	sessionSeq atomic.Uint64
}

const mtResultCacheTTL = 2 * time.Minute

type cachedMTResult struct {
	result    uint32
	rpui      []byte
	expiresAt time.Time
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
		slgTx:       newSLgTransactions(1024),
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

// SetSGdEnabled controls SGd capability advertisement on the shared Diameter
// connections. Request handlers are installed by the SMS service when enabled.
func (h *Handlers) SetSGdEnabled(enabled bool) { h.peers.SetSGdEnabled(enabled) }

// SetSLgEnabled controls SLg capability advertisement and request handling.
func (h *Handlers) SetSLgEnabled(enabled bool) { h.peers.SetSLgEnabled(enabled) }

// DiameterPeers reports the current status of every configured Diameter
// peer (shared by S6a, S13, SGd, and SLg), for OAM reporting.
func (h *Handlers) DiameterPeers() []peer.PeerStatus { return h.peers.Snapshot() }

// SetS13Config installs the top-level S13 policy before Start.
func (h *Handlers) SetS13Config(cfg config.S13Config) { h.s13Cfg = cfg }

// SetSGdConfig installs SMS-in-MME settings before Start.
func (h *Handlers) SetSGdConfig(cfg config.SGdConfig) { h.sgdCfg = cfg }

// SetSLgConfig installs bounded SLg procedure policy before Start.
func (h *Handlers) SetSLgConfig(cfg config.SLgConfig) {
	h.slgCfg = cfg
	h.slgTx = newSLgTransactions(cfg.TransactionCapacity)
}

// SetSLsProvider installs the optional E-SMLC transaction boundary before
// Diameter starts. Nil restores explicit positioning-unavailable behaviour.
func (h *Handlers) SetSLsProvider(provider interface {
	RequestPosition(context.Context, string, uint32, []byte, uint32, bool) (sls.PositionResult, error)
	AbortPosition(uint32)
}) {
	h.slsProvider = provider
}

// SetLCSNotifier installs the NAS transport used to send TS 23.271 §9.1.15
// step 4 LCS location-notifications (s1ap.Server). Nil restores the
// "notification unavailable" fallback behaviour in handlePLR.
func (h *Handlers) SetLCSNotifier(notifier interface {
	SendLocationNotification(mme uint32, notificationType lcsnotify.NotificationType, wait bool, timeout time.Duration) (bool, error)
}) {
	h.lcsNotifier = notifier
}

// ShutdownSLg deterministically cancels outstanding no-state transactions.
func (h *Handlers) ShutdownSLg() { h.slgTx.Close() }

// Close stops the Diameter peer manager: it closes the inbound listener (if
// any), every established peer connection, and signals connect loops to stop
// retrying.
func (h *Handlers) Close() error { return h.peers.Close() }

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
	if h.sgdCfg.Enabled {
		mux.HandleIdx(diam.CommandIndex{AppID: sgd.ApplicationID, Code: sgd.CommandMOForwardShortMessage, Request: false}, diam.HandlerFunc(h.handleOFA))
		mux.HandleIdx(diam.CommandIndex{AppID: sgd.ApplicationID, Code: sgd.CommandMTForwardShortMessage, Request: true}, diam.HandlerFunc(h.handleTFR))
		mux.HandleIdx(diam.CommandIndex{AppID: sgd.ApplicationID, Code: sgd.CommandAlertServiceCentre, Request: true}, diam.HandlerFunc(h.handleALR))
		mux.HandleIdx(diam.CommandIndex{AppID: sgd.ApplicationID, Code: sgd.CommandAlertServiceCentre, Request: false}, diam.HandlerFunc(h.handleALA))
	}
	if h.s13Cfg.Enabled {
		mux.HandleIdx(diam.CommandIndex{AppID: s13.ApplicationID, Code: s13.CommandCode, Request: false}, diam.HandlerFunc(h.handleECA))
	}
	if h.slgCfg.Enabled {
		mux.HandleIdx(diam.CommandIndex{AppID: slg.ApplicationID, Code: slg.CommandProvideLocation, Request: true}, diam.HandlerFunc(h.handlePLR))
		mux.HandleIdx(diam.CommandIndex{AppID: slg.ApplicationID, Code: slg.CommandLocationReport, Request: false}, diam.HandlerFunc(h.handleLRA))
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

// handleALR acknowledges an unsolicited deployed-peer ALR defensively. Normal
// MME Alert Service Centre processing originates ALR through
// SendAlertServiceCentre and waits for ALA; this handler prevents an
// unexpected peer request from disrupting the shared Diameter connection.
func (h *Handlers) handleALR(c diam.Conn, m *diam.Message) {
	ans := m.Answer(diam.Success)
	ans.NewAVP(avp.AuthSessionState, avp.Mbit, 0, datatype.Enumerated(1))
	ans.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity(h.diameterCfg.OriginHost))
	ans.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity(h.diameterCfg.OriginRealm))
	if _, err := ans.WriteTo(c); err != nil {
		h.log.Warn("sgd: ALA write", zap.Error(err))
	}
}

func (h *Handlers) handleALA(_ diam.Conn, m *diam.Message) {
	sid := findSessionID(m)
	if sid == "" {
		h.log.Warn("sgd: ALA missing Session-Id")
		return
	}
	code, err := sgd.DecodeALA(m)
	if err != nil {
		h.log.Warn("sgd: invalid ALA", zap.Error(err))
		return
	}
	v, ok := h.pendingALR.Load(sid)
	if !ok {
		h.log.Warn("sgd: late or duplicate ALA", zap.String("session_id", sid))
		return
	}
	select {
	case v.(chan uint32) <- code:
	default:
	}
}

func (h *Handlers) handleTFR(c diam.Conn, m *diam.Message) {
	req, err := sgd.DecodeTFR(m)
	if err != nil {
		h.log.Warn("sgd: invalid TFR", zap.Error(err))
		return
	}
	h.log.Info("sgd: MT-FSM request received", zap.String("imsi", req.IMSI), zap.String("session_id", req.SessionID), zap.Uint32("hop_by_hop", m.Header.HopByHopID), zap.Uint32("end_to_end", m.Header.EndToEndID))
	cacheKey := mtTFRCacheKey(m, req)
	result, rpui, duplicate := h.lookupMTResult(cacheKey)
	if duplicate {
		h.log.Info("sgd: duplicate MT-FSM request detected",
			zap.String("imsi", req.IMSI), zap.String("session_id", req.SessionID),
			zap.Uint32("hop_by_hop", m.Header.HopByHopID), zap.Uint32("end_to_end", m.Header.EndToEndID))
	} else {
		result = uint32(diam.UnableToComply)
		if receiver, ok := h.nas.(interface {
			HandleSGdMT(*sgd.MTRequest) (uint32, []byte)
		}); ok {
			result, rpui = receiver.HandleSGdMT(req)
		}
	}
	ans, err := sgd.BuildTFA(m, h.diameterCfg.OriginHost, h.diameterCfg.OriginRealm, result, rpui)
	if err != nil {
		h.log.Warn("sgd: build TFA", zap.Error(err))
		return
	}
	h.log.Debug("sgd: MT-FSM answer encoded", zap.String("imsi", req.IMSI), zap.String("session_id", req.SessionID), zap.Uint32("hop_by_hop", m.Header.HopByHopID), zap.Uint32("end_to_end", m.Header.EndToEndID), zap.Uint32("result_code", result))
	if _, err := ans.WriteTo(c); err != nil {
		h.log.Warn("sgd: TFA write failed", zap.String("imsi", req.IMSI), zap.String("session_id", req.SessionID), zap.Uint32("hop_by_hop", m.Header.HopByHopID), zap.Uint32("end_to_end", m.Header.EndToEndID), zap.Error(err))
		return
	}
	if !duplicate {
		h.storeMTResult(cacheKey, result, rpui)
	}
	h.log.Info("sgd: MT-FSM answer transmitted", zap.String("imsi", req.IMSI), zap.String("session_id", req.SessionID), zap.Uint32("hop_by_hop", m.Header.HopByHopID), zap.Uint32("end_to_end", m.Header.EndToEndID), zap.Uint32("result_code", result), zap.Bool("duplicate", duplicate))
}

// mtTFRCacheKey intentionally includes Diameter transaction identity. A new
// Session-Id is a new SMSC transaction even when its TPDU is byte-identical;
// only retransmission of the same TFR is suppressed here.
func mtTFRCacheKey(m *diam.Message, req *sgd.MTRequest) string {
	payload := sha256.Sum256(req.SMRPUI)
	return fmt.Sprintf("%s:%08x:%08x:%s:%x", req.SessionID, m.Header.HopByHopID, m.Header.EndToEndID, req.IMSI, payload[:])
}

func (h *Handlers) lookupMTResult(key string) (uint32, []byte, bool) {
	v, ok := h.mtResults.Load(key)
	if !ok {
		return 0, nil, false
	}
	cached := v.(cachedMTResult)
	if !cached.expiresAt.After(time.Now()) {
		h.mtResults.Delete(key)
		return 0, nil, false
	}
	return cached.result, append([]byte(nil), cached.rpui...), true
}

func (h *Handlers) storeMTResult(key string, result uint32, rpui []byte) {
	h.mtResults.Store(key, cachedMTResult{result: result, rpui: append([]byte(nil), rpui...), expiresAt: time.Now().Add(mtResultCacheTTL)})
}

// SendMobileOriginatedSMS implements the transport-neutral SMS service's SGd
// adapter using the existing direct-peer/DRA application selection.
func (h *Handlers) SendMobileOriginatedSMS(ctx context.Context, req *smsservice.MORequest) (*smsservice.MOResult, error) {
	if !h.sgdCfg.Enabled {
		return nil, fmt.Errorf("sgd: disabled")
	}
	if req == nil {
		return nil, fmt.Errorf("sgd: nil MO request")
	}
	selected, err := h.peers.SelectPeer(sgd.ApplicationID, h.diameterCfg.OriginRealm)
	if err != nil {
		return nil, err
	}
	h.log.Info("sgd: peer selected for MO SMS", zap.String("peer", selected.Name), zap.String("destination_host", selected.DestinationHost))
	sid := h.newSessionID(req.IMSI)
	m, err := sgd.BuildOFR(sgd.MORequest{SessionID: sid, OriginHost: h.diameterCfg.OriginHost, OriginRealm: h.diameterCfg.OriginRealm, DestinationHost: selected.DestinationHost, DestinationRealm: h.diameterCfg.OriginRealm, IMSI: req.IMSI, MSISDN: req.MSISDN, SCAddress: h.sgdCfg.SMSCAddress, SCAddressEncoding: h.sgdCfg.SGdSCAddressEncoding, SMRPUI: req.SMRPUI})
	if err != nil {
		return nil, err
	}
	ch := make(chan sgd.MOAnswer, 1)
	h.pendingOFR.Store(sid, ch)
	defer h.pendingOFR.Delete(sid)
	if _, err = m.WriteTo(selected.Connection); err != nil {
		h.reportTransactionFailure(selected)
		return nil, fmt.Errorf("sgd: OFR write: %w", err)
	}
	h.log.Info("sgd: MO-Forward-Short-Message-Request sent", zap.String("session_id", sid), zap.String("peer", selected.Name))
	h.log.Info("sgd: waiting for MO-Forward-Short-Message-Answer", zap.String("session_id", sid), zap.String("peer", selected.Name))
	select {
	case answer := <-ch:
		h.log.Info("sgd: MO-Forward-Short-Message-Answer received", zap.String("session_id", sid), zap.Uint32("diameter_result_code", answer.ResultCode))
		if answer.ResultCode < 2000 || answer.ResultCode >= 3000 {
			return nil, fmt.Errorf("sgd: OFA result %d", answer.ResultCode)
		}
		return &smsservice.MOResult{SMRPUI: answer.SMRPUI}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// SendAlertServiceCentre implements the optional core-side alert transport.
// It reuses the same SGd-capable direct peer or DRA selection as OFR.
func (h *Handlers) SendAlertServiceCentre(ctx context.Context, req *smsservice.AlertRequest) error {
	if !h.sgdCfg.Enabled || req == nil || req.IMSI == "" {
		return fmt.Errorf("sgd: Alert Service Centre unavailable")
	}
	selected, err := h.peers.SelectPeer(sgd.ApplicationID, h.diameterCfg.OriginRealm)
	if err != nil {
		return fmt.Errorf("sgd: route ALR: %w", err)
	}
	sid := h.newSessionID(req.IMSI)
	m, err := sgd.BuildALR(sgd.AlertRequest{SessionID: sid, OriginHost: h.diameterCfg.OriginHost, OriginRealm: h.diameterCfg.OriginRealm, DestinationHost: selected.DestinationHost, DestinationRealm: h.diameterCfg.OriginRealm, IMSI: req.IMSI, MSISDN: req.MSISDN, SCAddress: h.sgdCfg.SMSCAddress, SCAddressEncoding: h.sgdCfg.SGdSCAddressEncoding})
	if err != nil {
		return err
	}
	ch := make(chan uint32, 1)
	h.pendingALR.Store(sid, ch)
	defer h.pendingALR.Delete(sid)
	if _, err = m.WriteTo(selected.Connection); err != nil {
		h.reportTransactionFailure(selected)
		return fmt.Errorf("sgd: ALR write: %w", err)
	}
	select {
	case code := <-ch:
		if code < 2000 || code >= 3000 {
			return fmt.Errorf("sgd: ALA result %d", code)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *Handlers) handleOFA(_ diam.Conn, m *diam.Message) {
	sid := findSessionID(m)
	if sid == "" {
		h.log.Warn("sgd: OFA missing Session-Id")
		return
	}
	answer, err := sgd.DecodeOFA(m)
	if err != nil {
		h.log.Warn("sgd: invalid OFA", zap.Error(err))
		return
	}
	v, ok := h.pendingOFR.Load(sid)
	if !ok {
		h.log.Warn("sgd: late or duplicate OFA", zap.String("session_id", sid))
		return
	}
	select {
	case v.(chan sgd.MOAnswer) <- *answer:
		h.log.Debug("sgd: OFA correlated", zap.String("session_id", sid), zap.Uint32("result_code", answer.ResultCode), zap.Uint32("hop_by_hop_id", m.Header.HopByHopID), zap.Uint32("end_to_end_id", m.Header.EndToEndID))
	default:
	}
}

func findSessionID(m *diam.Message) string {
	if m == nil {
		return ""
	}
	for _, a := range m.AVP {
		if a.Code == avp.SessionID && a.VendorID == 0 {
			if v, ok := a.Data.(datatype.UTF8String); ok {
				return string(v)
			}
		}
	}
	return ""
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
// This is a health/readiness probe, not a route selection, so it must not
// go through selectPeer/SelectPeer: that path logs a "selected peer" line
// on every call, and Connected() is polled far more often (e.g. by the
// OAM health endpoint) than actual S6a requests are sent.
func (h *Handlers) Connected() bool {
	return h.peers.HasReadyPeer(appIDS6a)
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
