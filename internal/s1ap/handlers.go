package s1ap

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/gateway"
	"github.com/vectorcore/mme/internal/gtpv2"
	"github.com/vectorcore/mme/internal/gtpv2/s10"
	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/models"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/peertracker"
	"github.com/vectorcore/mme/internal/repository"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	s1sctp "github.com/vectorcore/mme/internal/s1ap/sctp"
	"github.com/vectorcore/mme/internal/uecontext"
)

// NASTransport is the interface the S6a layer uses to send NAS messages back
// to a UE via an eNB. This breaks the circular dependency between s1ap and s6a.
type NASTransport interface {
	SendDownlinkNAS(mmeUEID uint32, nasPDU []byte) error
	SendInitialContextSetup(mmeUEID uint32, nasPDU []byte, bearer *BearerInfo) error
}

// S11Client is the interface the S1AP layer uses to drive GTPv2-C S11 sessions.
// Implemented by internal/gtpv2/s11.Client. NoopS11Client is retained for unit tests.
type S11Client interface {
	SendCSR(mmeUEID uint32, req *gtpv2.CreateSessionRequest) error
	SendMBR(mmeUEID uint32, req *gtpv2.ModifyBearerRequest) error
	SendDSR(mmeUEID uint32, req *gtpv2.DeleteSessionRequest) error
}

type S11BearerResponder interface {
	SendCreateBearerResponse(peer string, teid uint32, seq uint32, cause uint8, bearers []gtpv2.CreateBearerBearer) error
	SendUpdateBearerResponse(peer string, teid uint32, seq uint32, cause uint8, bearers []gtpv2.UpdateBearerBearer) error
	SendDeleteBearerResponse(peer string, teid uint32, seq uint32, cause uint8, ebis []uint8) error
}

// BearerInfo carries the default EPS bearer parameters needed for the ICS Request E-RAB list.
type BearerInfo struct {
	EBI       uint8
	SGWU_TEID uint32
	SGWU_IP   []byte // 4-byte IPv4
}

// NoopS6aClient is retained for unit tests. Runtime MME always starts S6a.
type NoopS6aClient struct{}

func (NoopS6aClient) SendAIR(_ string, _ [3]byte, _ uint32) error { return nil }
func (NoopS6aClient) SendULR(_ string, _ [3]byte, _ uint32) error { return nil }
func (NoopS6aClient) SendPUR(_ string) error                      { return nil }

// NoopS11Client is retained for unit tests. Runtime MME always starts S11.
type NoopS11Client struct{}

func (NoopS11Client) SendCSR(_ uint32, _ *gtpv2.CreateSessionRequest) error { return nil }
func (NoopS11Client) SendMBR(_ uint32, _ *gtpv2.ModifyBearerRequest) error  { return nil }
func (NoopS11Client) SendDSR(_ uint32, _ *gtpv2.DeleteSessionRequest) error { return nil }
func (NoopS11Client) SendCreateBearerResponse(_ string, _ uint32, _ uint32, _ uint8, _ []gtpv2.CreateBearerBearer) error {
	return nil
}
func (NoopS11Client) SendUpdateBearerResponse(_ string, _ uint32, _ uint32, _ uint8, _ []gtpv2.UpdateBearerBearer) error {
	return nil
}
func (NoopS11Client) SendDeleteBearerResponse(_ string, _ uint32, _ uint32, _ uint8, _ []uint8) error {
	return nil
}

// S10Client is the interface the S1AP layer uses for S10 inter-MME context transfer.
// Implemented by s10.Server; NoopS10Client used when S10 is disabled.
type S10Client interface {
	// SendContextRequest sends a Context Request to peerAddr and returns a channel for the response.
	SendContextRequest(peerAddr string, req *s10.ContextRequest) (<-chan s10.ContextResult, error)
	// SendContextAcknowledge sends a Context Acknowledge to the old MME.
	SendContextAcknowledge(peerAddr string, peerTEID uint32, cause uint8) error
	// LocalAddr returns "ip:port" for constructing the Sender F-TEID IE.
	LocalAddr() string
}

// NoopS10Client is used when S10 is disabled.
type NoopS10Client struct{}

func (NoopS10Client) SendContextRequest(_ string, _ *s10.ContextRequest) (<-chan s10.ContextResult, error) {
	return nil, errors.New("s10: disabled")
}
func (NoopS10Client) SendContextAcknowledge(_ string, _ uint32, _ uint8) error { return nil }
func (NoopS10Client) LocalAddr() string                                        { return "" }

// Server is the S1AP layer: manages eNB connections and dispatches messages.
type Server struct {
	cfg          config.S1APConfig
	nfCfg        config.NFConfig
	secCfg       config.SecurityConfig
	s10Cfg       config.S10Config
	nasCfg       config.NASConfig
	operCfg      config.OperatorConfig
	store        repository.Repository
	ueManager    *uecontext.Manager
	enbTracker   *peertracker.Tracker
	gutiAlloc    *uecontext.GUTIAllocator
	s6a          S6aClient
	s10          S10Client
	s11          S11Client
	s11LocalIP   []byte // 4-byte IPv4 used as the MME S11 source IP in F-TEID IEs
	pgwIP        []byte // 4-byte IPv4 of the PGW/SMF-C S5/S8 GTP-C endpoint
	gatewaySel   *gateway.Selector
	restartEpoch string
	log          *zap.Logger

	enbs  sync.Map // string (remoteAddr) → *ENBContext
	sends sync.Map // string (remoteAddr) → chan<- []byte
}

// NewServer creates a new S1AP Server.
func NewServer(
	cfg config.S1APConfig,
	nfCfg config.NFConfig,
	secCfg config.SecurityConfig,
	s10Cfg config.S10Config,
	nasCfg config.NASConfig,
	operCfg config.OperatorConfig,
	store repository.Repository,
	ueManager *uecontext.Manager,
	enbTracker *peertracker.Tracker,
	s6a S6aClient,
	s10 S10Client,
	s11 S11Client,
	s11LocalIP []byte,
	pgwIP []byte,
	log *zap.Logger,
) *Server {
	gutiAlloc, err := uecontext.NewGUTIAllocator(nfCfg.MCC, nfCfg.MNC, nfCfg.MMEGI, nfCfg.MMEC)
	if err != nil {
		log.Warn("s1ap: GUTI allocator init failed, GUTI will not be assigned", zap.Error(err))
	}
	return &Server{
		cfg:          cfg,
		nfCfg:        nfCfg,
		secCfg:       secCfg,
		s10Cfg:       s10Cfg,
		nasCfg:       nasCfg,
		operCfg:      operCfg,
		store:        store,
		ueManager:    ueManager,
		enbTracker:   enbTracker,
		gutiAlloc:    gutiAlloc,
		s6a:          s6a,
		s10:          s10,
		s11:          s11,
		s11LocalIP:   s11LocalIP,
		pgwIP:        pgwIP,
		restartEpoch: fmt.Sprintf("%d", time.Now().UnixNano()),
		log:          log,
	}
}

func (s *Server) SetRecoveryEpoch(epoch string) {
	s.restartEpoch = epoch
}

func (s *Server) SetGatewaySelector(selector *gateway.Selector) {
	s.gatewaySel = selector
}

// HandleNetworkDetach is called by the S6a layer (CLR) to trigger cleanup for a HSS-initiated detach.
func (s *Server) HandleNetworkDetach(ue *uecontext.Context) {
	s.sendDeleteSession(ue)
}

// Start starts the SCTP listener. Blocking — returns only on fatal error.
func (s *Server) Start() error {
	srv := s1sctp.NewServer(
		s.cfg.BindAddress,
		s.cfg.BindPort,
		s.log,
		func(remoteAddr string, sendCh chan<- []byte) {
			s.sends.Store(remoteAddr, sendCh)
		},
		s.handleMessage,
		s.handleDisconnect,
	)
	return srv.Listen()
}

// handleMessage is called by the SCTP layer for each received PDU.
func (s *Server) handleMessage(remoteAddr string, data []byte) {
	p, err := pdu.Decode(data)
	if err != nil {
		s.log.Warn("s1ap: PDU decode error",
			zap.String("remote", remoteAddr),
			zap.Error(err))
		return
	}

	switch p.Type {
	case pdu.PDUTypeInitiatingMessage:
		s.dispatchInitiating(remoteAddr, p)
	case pdu.PDUTypeSuccessfulOutcome:
		s.dispatchSuccessful(remoteAddr, p)
	case pdu.PDUTypeUnsuccessfulOutcome:
		s.dispatchUnsuccessful(remoteAddr, p)
	default:
		s.log.Warn("s1ap: unknown PDU type", zap.Uint8("type", uint8(p.Type)))
	}
}

func (s *Server) dispatchInitiating(remoteAddr string, p *pdu.PDU) {
	ies, err := decodeProcedureIEsCompat(p.Value)
	if err != nil {
		s.log.Warn("s1ap: IE decode error", zap.String("remote", remoteAddr), zap.Error(err))
		return
	}

	switch p.ProcedureCode {
	case pdu.ProcS1Setup:
		s.handleS1SetupRequest(remoteAddr, p, ies)
	case pdu.ProcPathSwitchRequest:
		s.handlePathSwitchRequest(remoteAddr, p, ies)
	case pdu.ProcInitialUEMessage:
		s.handleInitialUEMessage(remoteAddr, p, ies)
	case pdu.ProcUplinkNASTransport:
		s.handleUplinkNASTransport(remoteAddr, p, ies)
	case pdu.ProcUEContextReleaseRequest:
		s.handleUEContextReleaseRequest(remoteAddr, p, ies)
	case pdu.ProcUECapabilityInfoIndication:
		s.handleUECapabilityInfoIndication(remoteAddr, p, ies)
	case pdu.ProcErrorIndication:
		s.handleErrorIndication(remoteAddr, p, ies)
	case pdu.ProcReset:
		s.handleReset(remoteAddr, p, ies)
	case pdu.ProcHandoverPreparation:
		s.handleHandoverRequired(remoteAddr, p, ies)
	case pdu.ProcHandoverNotification:
		s.handleHandoverNotify(remoteAddr, p, ies)
	default:
		s.log.Warn("s1ap: unhandled initiating procedure",
			zap.Uint8("code", p.ProcedureCode),
			zap.String("remote", remoteAddr))
	}
}

func (s *Server) dispatchSuccessful(remoteAddr string, p *pdu.PDU) {
	ies, err := decodeProcedureIEsCompat(p.Value)
	if err != nil {
		s.log.Warn("s1ap: IE decode error (success)", zap.String("remote", remoteAddr), zap.Error(err))
		return
	}
	switch p.ProcedureCode {
	case pdu.ProcInitialContextSetup:
		s.handleInitialContextSetupResponse(remoteAddr, p, ies)
	case pdu.ProcERABSetup:
		s.handleERABSetupResponse(remoteAddr, p, ies)
	case pdu.ProcUEContextRelease:
		s.handleUEContextReleaseComplete(remoteAddr, p, ies)
	case pdu.ProcHandoverResourceAllocation:
		s.handleHandoverRequestAck(remoteAddr, p, ies)
	default:
		s.log.Debug("s1ap: unhandled successful outcome",
			zap.Uint8("code", p.ProcedureCode),
			zap.String("remote", remoteAddr))
	}
}

func (s *Server) dispatchUnsuccessful(remoteAddr string, p *pdu.PDU) {
	ies, err := decodeProcedureIEsCompat(p.Value)
	if err != nil {
		s.log.Warn("s1ap: IE decode error (unsuccessful)", zap.String("remote", remoteAddr), zap.Error(err))
		return
	}
	switch p.ProcedureCode {
	case pdu.ProcInitialContextSetup:
		s.handleInitialContextSetupFailure(remoteAddr, p, ies)
	case pdu.ProcHandoverResourceAllocation:
		s.handleHandoverRequestFailure(remoteAddr, p, ies)
	default:
		s.log.Debug("s1ap: unhandled unsuccessful outcome",
			zap.Uint8("code", p.ProcedureCode),
			zap.String("remote", remoteAddr))
	}
}

func decodeProcedureIEsCompat(data []byte) ([]pdu.ProtocolIE, error) {
	ies, err := pdu.DecodeProcedureIEContainer(data)
	if err == nil {
		return ies, nil
	}
	return pdu.DecodeIEContainer(data)
}

// handleDisconnect is called when an SCTP association is closed.
func (s *Server) handleDisconnect(remoteAddr string) {
	s.sends.Delete(remoteAddr)
	v, ok := s.enbs.LoadAndDelete(remoteAddr)
	if !ok {
		return
	}
	enb := v.(*ENBContext)
	s.enbTracker.Remove(remoteAddr)
	metrics.S1APConnectedENBs.Dec()

	evicted := 0
	preserved := 0
	for _, ue := range s.ueManager.List() {
		ue.Lock()
		if ue.ENBGlobalID != remoteAddr {
			ue.Unlock()
			continue
		}
		emmState := ue.EMMState
		preserveEPS := emmState == emm.StateRegistered ||
			emmState == emm.StateTrackingAreaUpdating ||
			emmState == emm.StateServiceRequestInitiated
		if preserveEPS {
			mmeID := ue.MMEUES1APID
			enbUEID := ue.ENBS1APID
			imsi := ue.IMSI
			apn := ue.APN
			ue.SetECMState(emm.ECMIdle)
			ue.ENBS1APID = 0
			ue.ENBGlobalID = ""
			ue.S1BindingState = uecontext.S1BindingReleased
			ue.ENBU_TEID = 0
			ue.ENBU_IP = nil
			ue.Unlock()
			s.log.Info("s1ap: preserving UE EPS context on eNB disconnect",
				zap.String("imsi", imsi),
				zap.Uint32("mme_ue_id", mmeID),
				zap.Uint32("old_enb_ue_id", enbUEID),
				zap.String("apn", apn),
				zap.String("remote", remoteAddr),
				zap.String("emm_state", emmState.String()),
				zap.String("ecm_state", emm.ECMIdle.String()),
				zap.String("delete_reason", "s1_only_disconnect"),
				zap.Bool("s11_delete_required", false))
			s.persistUERecoverySnapshot(ue, models.RecoveryStateDisconnected, "ENB_DISCONNECT")
			preserved++
			continue
		}
		mmeID := ue.MMEUES1APID
		imsi := ue.IMSI
		apn := ue.APN
		ue.StopAllTimers()
		ue.Unlock()

		s.log.Info("s1ap: evicting UE on eNB disconnect",
			zap.String("imsi", imsi),
			zap.Uint32("mme_ue_id", mmeID),
			zap.String("apn", apn),
			zap.String("remote", remoteAddr))

		s.sendDeleteSession(ue) // idempotent: no-op if SGWC_TEID == 0
		s.persistUERecoverySnapshot(ue, models.RecoveryStateDisconnected, "ENB_DISCONNECT")
		s.ueManager.Remove(ue)
		evicted++
	}

	s.log.Info("s1ap: eNB disconnected",
		zap.String("remote", remoteAddr),
		zap.String("global_enb_id", enb.GlobalENBID.Serialise()),
		zap.Int("preserved_ues", preserved),
		zap.Int("evicted_ues", evicted))
}

// Shutdown drains active UE sessions by sending Delete Session Requests for all UEs
// that have an established S11 session, then removes them from the in-memory manager.
// Intended for graceful MME shutdown on SIGTERM. DSRs are fire-and-forget UDP so they
// are delivered even if we return before the DSRsp arrives. The ctx deadline is checked
// between UEs to bound how long shutdown can block.
func (s *Server) Shutdown(ctx context.Context) {
	ues := s.ueManager.List()
	s.log.Info("s1ap: graceful shutdown: draining sessions", zap.Int("ues", len(ues)))
	drained := 0
	for _, ue := range ues {
		select {
		case <-ctx.Done():
			s.log.Warn("s1ap: shutdown deadline reached, abandoning remaining sessions",
				zap.Int("remaining", len(ues)-drained))
			return
		default:
		}
		ue.Lock()
		wasAttached := ue.EMMState == emm.StateRegistered ||
			(ue.EMMState == emm.StateTrackingAreaUpdating && ue.SGWC_TEID != 0)
		ue.StopAllTimers()
		ue.Unlock()

		s.sendDeleteSession(ue)
		s.ueManager.Remove(ue)
		if wasAttached {
			metrics.AttachedUEs.Dec()
		}
		drained++
	}
	s.log.Info("s1ap: graceful shutdown complete", zap.Int("drained", drained))
}

// getENB returns the ENBContext for a remote address, or nil.
func (s *Server) getENB(remoteAddr string) *ENBContext {
	v, ok := s.enbs.Load(remoteAddr)
	if !ok {
		return nil
	}
	return v.(*ENBContext)
}

// getUEAndENB looks up UE context by MME UE S1AP ID and its associated eNB.
func (s *Server) getUEAndENB(mmeUEID uint32) (*uecontext.Context, *ENBContext) {
	ue, ok := s.ueManager.GetByMMEID(mmeUEID)
	if !ok {
		return nil, nil
	}
	ue.Lock()
	enbAddr := ue.ENBGlobalID // stored as remote addr in Phase 1 for simplicity
	ue.Unlock()

	enb := s.getENB(enbAddr)
	return ue, enb
}
