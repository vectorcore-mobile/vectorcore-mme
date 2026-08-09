package s1ap

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/fiorix/go-diameter/v4/diam"
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
	"github.com/vectorcore/mme/internal/sgsap"
	smsservice "github.com/vectorcore/mme/internal/sms"
	"github.com/vectorcore/mme/internal/uecontext"
)

// NASTransport is the interface the S6a layer uses to send NAS messages back
// to a UE via an eNB. This breaks the circular dependency between s1ap and s6a.
type NASTransport interface {
	SendDownlinkNAS(mmeUEID uint32, nasPDU []byte) error
	SendInitialContextSetup(mmeUEID uint32, nasPDU []byte, bearer *BearerInfo) error
}

type LPPaSink interface {
	HandleUplinkLPPa(uint32, uint8, []byte) error
}
type LPPSink interface{ HandleUplinkLPP(uint32, []byte) error }

// S11Client is the interface the S1AP layer uses to drive GTPv2-C S11 sessions.
// Implemented by internal/gtpv2/s11.Client. NoopS11Client is retained for unit tests.
type S11Client interface {
	SendCSR(mmeUEID uint32, req *gtpv2.CreateSessionRequest) error
	SendMBR(mmeUEID uint32, req *gtpv2.ModifyBearerRequest) error
	SendDSR(mmeUEID uint32, req *gtpv2.DeleteSessionRequest) error
}

type S11DDNResponder interface {
	SendDDNAck(peer string, teid uint32, seq uint32, cause uint8, delayValue *uint8) error
	SendDDNFailureIndication(peer string, teid uint32, seq uint32, cause uint8, imsi string) error
}

type S11RABClient interface {
	SendRABR(mmeUEID uint32, req *gtpv2.ReleaseAccessBearersRequest) (uint32, error)
}

type S11BearerResponder interface {
	SendCreateBearerResponse(peer string, teid uint32, seq uint32, cause uint8, bearers []gtpv2.CreateBearerBearer, meta *gtpv2.CreateBearerResponseMeta) error
	SendUpdateBearerResponse(peer string, teid uint32, seq uint32, cause uint8, bearers []gtpv2.UpdateBearerBearer, meta *gtpv2.UpdateBearerResponseMeta) error
	SendDeleteBearerResponse(peer string, teid uint32, seq uint32, cause uint8, ebis []uint8, meta *gtpv2.DeleteBearerResponseMeta) error
}

type S11PiggybackResponder interface {
	SendCreateBearerResponseWithPiggybackMBR(peer string, teid uint32, seq uint32, cause uint8, bearers []gtpv2.CreateBearerBearer, meta *gtpv2.CreateBearerResponseMeta, mmeUEID uint32, mbr *gtpv2.ModifyBearerRequest) (uint32, error)
}

// BearerInfo carries the default EPS bearer parameters needed for the ICS Request E-RAB list.
type BearerInfo struct {
	EBI                     uint8
	QCI                     uint8
	ARPPriority             uint8
	PreemptionCapability    bool
	PreemptionVulnerability bool
	BearerQoS               []byte
	SGWU_TEID               uint32
	SGWU_IP                 []byte // 4-byte IPv4
}

// NoopS6aClient is retained for unit tests. Runtime MME always starts S6a.
type NoopS6aClient struct{}

func (NoopS6aClient) SendAIR(_ string, _ [3]byte, _ uint32) error { return nil }
func (NoopS6aClient) SendULR(_ string, _ [3]byte, _ uint32) error { return nil }
func (NoopS6aClient) SendPUR(_ string) error                      { return nil }
func (NoopS6aClient) AbortSLgPositioning(_ uint32)                {}

// NoopS11Client is retained for unit tests. Runtime MME always starts S11.
type NoopS11Client struct{}

func (NoopS11Client) SendCSR(_ uint32, _ *gtpv2.CreateSessionRequest) error { return nil }
func (NoopS11Client) SendMBR(_ uint32, _ *gtpv2.ModifyBearerRequest) error  { return nil }
func (NoopS11Client) SendDSR(_ uint32, _ *gtpv2.DeleteSessionRequest) error { return nil }
func (NoopS11Client) SendDDNAck(_ string, _ uint32, _ uint32, _ uint8, _ *uint8) error {
	return nil
}
func (NoopS11Client) SendDDNFailureIndication(_ string, _ uint32, _ uint32, _ uint8, _ string) error {
	return nil
}
func (NoopS11Client) SendRABR(_ uint32, _ *gtpv2.ReleaseAccessBearersRequest) (uint32, error) {
	return 0, nil
}
func (NoopS11Client) SendCreateBearerResponse(_ string, _ uint32, _ uint32, _ uint8, _ []gtpv2.CreateBearerBearer, _ *gtpv2.CreateBearerResponseMeta) error {
	return nil
}
func (NoopS11Client) SendUpdateBearerResponse(_ string, _ uint32, _ uint32, _ uint8, _ []gtpv2.UpdateBearerBearer, _ *gtpv2.UpdateBearerResponseMeta) error {
	return nil
}
func (NoopS11Client) SendDeleteBearerResponse(_ string, _ uint32, _ uint32, _ uint8, _ []uint8, _ *gtpv2.DeleteBearerResponseMeta) error {
	return nil
}
func (NoopS11Client) SendCreateBearerResponseWithPiggybackMBR(_ string, _ uint32, _ uint32, _ uint8, _ []gtpv2.CreateBearerBearer, _ *gtpv2.CreateBearerResponseMeta, _ uint32, _ *gtpv2.ModifyBearerRequest) (uint32, error) {
	return 0, nil
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

// VLRManager is the interface the S1AP layer uses to reach the SGs-AP VLR
// association layer. Implemented by vlr.Manager; NoopVLRManager is used
// when SGs is disabled. Breaks the circular dependency between s1ap and vlr
// (vlr.Handler is implemented on *Server), the same pattern as S6a/S10/S11.
type VLRManager interface {
	Available(vlrName string) bool
	LookupVLR(mcc, mnc string, tac uint16) (config.SGsTAILAIMapItem, bool)

	SendLocationUpdateRequest(vlrName string, r sgsap.LocationUpdateRequest) error
	SendUplinkUnitdata(vlrName string, u sgsap.UplinkUnitdata) error
	SendServiceRequest(vlrName string, r sgsap.ServiceRequest) error
	SendTMSIReallocationComplete(vlrName, imsi string) error
	SendEPSDetachIndication(vlrName string, d sgsap.EPSDetachIndication) error
	SendIMSIDetachIndication(vlrName string, d sgsap.IMSIDetachIndication) error
	SendPagingReject(vlrName, imsi string, cause sgsap.Cause) error
	SendAlertAck(vlrName, imsi string) error
	SendAlertReject(vlrName, imsi string, cause sgsap.Cause) error
	SendUEUnreachable(vlrName string, u sgsap.UEUnreachable) error
	SendUEActivityIndication(vlrName, imsi string) error
	SendMOCSFBIndication(vlrName string, ind sgsap.MOCSFBIndication) error
}

// NoopVLRManager is used when SGs is disabled.
type NoopVLRManager struct{}

func (NoopVLRManager) Available(string) bool { return false }
func (NoopVLRManager) LookupVLR(string, string, uint16) (config.SGsTAILAIMapItem, bool) {
	return config.SGsTAILAIMapItem{}, false
}
func (NoopVLRManager) SendLocationUpdateRequest(string, sgsap.LocationUpdateRequest) error {
	return errors.New("sgs: disabled")
}
func (NoopVLRManager) SendUplinkUnitdata(string, sgsap.UplinkUnitdata) error {
	return errors.New("sgs: disabled")
}
func (NoopVLRManager) SendServiceRequest(string, sgsap.ServiceRequest) error {
	return errors.New("sgs: disabled")
}
func (NoopVLRManager) SendTMSIReallocationComplete(string, string) error {
	return errors.New("sgs: disabled")
}
func (NoopVLRManager) SendEPSDetachIndication(string, sgsap.EPSDetachIndication) error {
	return errors.New("sgs: disabled")
}
func (NoopVLRManager) SendIMSIDetachIndication(string, sgsap.IMSIDetachIndication) error {
	return errors.New("sgs: disabled")
}
func (NoopVLRManager) SendPagingReject(string, string, sgsap.Cause) error {
	return errors.New("sgs: disabled")
}
func (NoopVLRManager) SendAlertAck(string, string) error { return errors.New("sgs: disabled") }
func (NoopVLRManager) SendAlertReject(string, string, sgsap.Cause) error {
	return errors.New("sgs: disabled")
}
func (NoopVLRManager) SendUEUnreachable(string, sgsap.UEUnreachable) error {
	return errors.New("sgs: disabled")
}
func (NoopVLRManager) SendUEActivityIndication(string, string) error {
	return errors.New("sgs: disabled")
}
func (NoopVLRManager) SendMOCSFBIndication(string, sgsap.MOCSFBIndication) error {
	return errors.New("sgs: disabled")
}

// Server is the S1AP layer: manages eNB connections and dispatches messages.
type Server struct {
	cfg                config.S1APConfig
	nfCfg              config.NFConfig
	secCfg             config.SecurityConfig
	s10Cfg             config.S10Config
	nasCfg             config.NASConfig
	emmTimersCfg       config.EMMTimersConfig
	pagingCfg          config.PagingConfig
	operCfg            config.OperatorConfig
	sgdCfg             config.SGdConfig
	sgsCfg             config.SGsConfig
	smsCfg             config.SMSConfig
	vlr                VLRManager
	roamingCfg         config.RoamingConfig
	roamingConfigured  bool
	store              repository.Repository
	ueManager          *uecontext.Manager
	enbTracker         *peertracker.Tracker
	gutiAlloc          *uecontext.GUTIAllocator
	s6a                S6aClient
	s10                S10Client
	s11                S11Client
	s11LocalIP         []byte // 4-byte IPv4 used as the MME S11 source IP in F-TEID IEs
	pgwIP              []byte // 4-byte IPv4 of the PGW/SMF-C S5/S8 GTP-C endpoint
	gatewaySel         *gateway.Selector
	restartEpoch       string
	recoveryPersistent bool
	log                *zap.Logger
	sms                *smsservice.Service
	smsTimeout         time.Duration
	pendingMTSMS       sync.Map // IMSI -> *pendingMTSMS
	pendingSGsMT       sync.Map // IMSI -> *pendingSGsMTSMS
	pendingMOSMS       sync.Map // imsi:cp-ti -> *pendingMOSMS
	smsMu              sync.Mutex
	nextMTSMSTI        map[string]uint8

	enbs  sync.Map // string (remoteAddr) → *ENBContext
	sends sync.Map // string (remoteAddr) → chan<- []byte

	completedCreateBearerResponses sync.Map // string bearerTxKey -> *cachedCreateBearerResponse
	pendingERABModificationInds    sync.Map // string correlationID -> *pendingERABModificationIndication
	pwsTransactions                sync.Map // string -> *pwsTransaction
	pwsTransactionMu               sync.Mutex
	pwsTransactionBases            map[string]struct{} // in-flight CBC/procedure/warning identities
	pwsIndication                  func(peer string, payload []byte)
	pwsForward                     func(procedure uint8, ies []pdu.ProtocolIE)
	lppaSink                       LPPaSink
	lppSink                        LPPSink
	lppPendingMu                   sync.Mutex
	lppPending                     map[uint32][]pendingGenericNAS
	// lppaPending mirrors lppPending's queue-and-page behavior for the
	// LPPa/S1AP delivery path (see SendDownlinkLPPa) — a separate map since
	// LPPa Initiation Requests are delivered over Downlink UE Associated
	// LPPa Transport, not Generic NAS Transport, once the S1 binding is
	// restored. Guarded by the same lppPendingMu: both queues key off the
	// identical ECM-IDLE/paging lifecycle, so one mutex is enough and avoids
	// a second lock-ordering concern.
	lppaPending      map[uint32][]pendingLPPa
	lcsNotifyMu      sync.Mutex
	lcsNotifyPending map[uint32]chan lcsNotifyResult

	transportMu sync.Mutex
	sctpSrv     *s1sctp.Server
}

// NewServer creates a new S1AP Server.
func NewServer(
	cfg config.S1APConfig,
	nfCfg config.NFConfig,
	secCfg config.SecurityConfig,
	s10Cfg config.S10Config,
	nasCfg config.NASConfig,
	emmTimersCfg config.EMMTimersConfig,
	pagingCfg config.PagingConfig,
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
	server := &Server{
		cfg:                 cfg,
		nfCfg:               nfCfg,
		secCfg:              secCfg,
		s10Cfg:              s10Cfg,
		nasCfg:              nasCfg,
		emmTimersCfg:        emmTimersCfg,
		pagingCfg:           pagingCfg,
		operCfg:             operCfg,
		lppPending:          make(map[uint32][]pendingGenericNAS),
		lppaPending:         make(map[uint32][]pendingLPPa),
		store:               store,
		ueManager:           ueManager,
		enbTracker:          enbTracker,
		gutiAlloc:           gutiAlloc,
		s6a:                 s6a,
		s10:                 s10,
		s11:                 s11,
		s11LocalIP:          s11LocalIP,
		pgwIP:               pgwIP,
		restartEpoch:        fmt.Sprintf("%d", time.Now().UnixNano()),
		log:                 log,
		vlr:                 NoopVLRManager{},
		nextMTSMSTI:         make(map[string]uint8),
		pwsTransactionBases: make(map[string]struct{}),
	}
	return server
}

func (s *Server) SetRecoveryEpoch(epoch string) {
	s.restartEpoch = epoch
}

// SetPersistentRecovery gates durable UE deadline snapshots. In-memory mode
// deliberately keeps the historical restart semantics: all UE state is lost.
func (s *Server) SetPersistentRecovery(enabled bool) { s.recoveryPersistent = enabled }

func (s *Server) SetGatewaySelector(selector *gateway.Selector) {
	s.gatewaySel = selector
}

func (s *Server) SetSMSService(service *smsservice.Service) { s.sms = service }
func (s *Server) SetSGdConfig(cfg config.SGdConfig)         { s.sgdCfg = cfg }
func (s *Server) SetSGsConfig(cfg config.SGsConfig)         { s.sgsCfg = cfg }
func (s *Server) SetSMSConfig(cfg config.SMSConfig)         { s.smsCfg = cfg }
func (s *Server) SetVLRManager(m VLRManager) {
	if m == nil {
		m = NoopVLRManager{}
	}
	s.vlr = m
}
func (s *Server) SetRoamingConfig(cfg config.RoamingConfig) {
	s.roamingCfg, s.roamingConfigured = cfg, true
}
func (s *Server) SetSMSTransactionTimeout(timeout time.Duration) {
	if timeout > 0 {
		s.smsTimeout = timeout
	}
}

// HandleNetworkDetach is called by the S6a layer (CLR) to trigger cleanup for a HSS-initiated detach.
func (s *Server) HandleNetworkDetach(ue *uecontext.Context) {
	if s.sms != nil {
		ue.Lock()
		imsi := ue.IMSI
		ue.Unlock()
		s.sms.RemovePendingMT(imsi)
		if value, ok := s.pendingMTSMS.LoadAndDelete(imsi); ok {
			pending := value.(*pendingMTSMS)
			select {
			case pending.result <- mtSMSResult{resultCode: diam.UnableToDeliver}:
			default:
			}
		}
		prefix := imsi + ":"
		s.pendingMOSMS.Range(func(key, entry any) bool {
			if mapKey, ok := key.(string); ok && len(mapKey) >= len(prefix) && mapKey[:len(prefix)] == prefix {
				if tx, ok := entry.(*pendingMOSMS); ok {
					ti := tx.ti
					s.finishMOSMS(imsi, ti, tx)
				}
			}
			return true
		})
	}
	s.sendDeleteSession(ue)
}

// Start starts the SCTP listener. Blocking — returns only on fatal error.
func (s *Server) Start() error {
	srv := s1sctp.NewServer(
		s.cfg.BindAddress,
		s.cfg.BindPort,
		s.cfg.QoS.DSCP,
		s.log,
		func(remoteAddr string, sendCh chan<- []byte) {
			s.sends.Store(remoteAddr, sendCh)
		},
		s.handleMessage,
		s.handleDisconnect,
	)
	s.transportMu.Lock()
	s.sctpSrv = srv
	s.transportMu.Unlock()
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

	if !s.allowInboundProcedure(remoteAddr, p) {
		return
	}

	s.logInboundPDU(remoteAddr, p)

	switch p.Type {
	case pdu.PDUTypeInitiatingMessage:
		s.dispatchInitiating(remoteAddr, p)
	case pdu.PDUTypeSuccessfulOutcome:
		s.dispatchSuccessful(remoteAddr, p, data)
	case pdu.PDUTypeUnsuccessfulOutcome:
		s.dispatchUnsuccessful(remoteAddr, p, data)
	default:
		s.log.Warn("s1ap: unknown PDU type", zap.Uint8("type", uint8(p.Type)))
	}
}

func (s *Server) logInboundPDU(remoteAddr string, p *pdu.PDU) {
	if p == nil {
		return
	}
	s.log.Debug("s1ap: inbound eNB PDU",
		zap.String("remote", remoteAddr),
		zap.String("pdu_type", p.Type.String()),
		zap.Uint8("procedure_code", p.ProcedureCode),
		zap.String("procedure_name", s1apProcedureName(p.ProcedureCode)),
		zap.String("criticality", p.Criticality.String()))
}

func s1apProcedureName(code uint8) string {
	switch code {
	case pdu.ProcHandoverPreparation:
		return "HandoverPreparation"
	case pdu.ProcHandoverResourceAllocation:
		return "HandoverResourceAllocation"
	case pdu.ProcPathSwitchRequest:
		return "PathSwitchRequest"
	case pdu.ProcERABSetup:
		return "ERABSetup"
	case pdu.ProcERABModify:
		return "ERABModify"
	case pdu.ProcERABRelease:
		return "ERABRelease"
	case pdu.ProcInitialContextSetup:
		return "InitialContextSetup"
	case pdu.ProcPaging:
		return "Paging"
	case pdu.ProcDownlinkNASTransport:
		return "DownlinkNASTransport"
	case pdu.ProcInitialUEMessage:
		return "InitialUEMessage"
	case pdu.ProcUplinkNASTransport:
		return "UplinkNASTransport"
	case pdu.ProcReset:
		return "Reset"
	case pdu.ProcErrorIndication:
		return "ErrorIndication"
	case pdu.ProcNASNonDeliveryIndication:
		return "NASNonDeliveryIndication"
	case pdu.ProcS1Setup:
		return "S1Setup"
	case pdu.ProcUEContextReleaseRequest:
		return "UEContextReleaseRequest"
	case pdu.ProcDownlinkS1CDMA:
		return "DownlinkS1CDMA"
	case pdu.ProcUplinkS1CDMA:
		return "UplinkS1CDMA"
	case pdu.ProcUEContextModification:
		return "UEContextModification"
	case pdu.ProcUECapabilityInfoIndication:
		return "UECapabilityInfoIndication"
	case pdu.ProcUEContextRelease:
		return "UEContextRelease"
	case pdu.ProcENBStatusTransfer:
		return "ENBStatusTransfer"
	case pdu.ProcMMEStatusTransfer:
		return "MMEStatusTransfer"
	case pdu.ProcDeactivateTrace:
		return "DeactivateTrace"
	case pdu.ProcTraceStart:
		return "TraceStart"
	case pdu.ProcTraceFailureIndication:
		return "TraceFailureIndication"
	case pdu.ProcENBConfigurationUpdate:
		return "ENBConfigurationUpdate"
	case pdu.ProcMMEConfigurationUpdate:
		return "MMEConfigurationUpdate"
	case pdu.ProcLocationReportingControl:
		return "LocationReportingControl"
	case pdu.ProcLocationReportFailure:
		return "LocationReportFailure"
	case pdu.ProcLocationReport:
		return "LocationReport"
	case pdu.ProcOverloadStart:
		return "OverloadStart"
	case pdu.ProcOverloadStop:
		return "OverloadStop"
	case pdu.ProcWriteReplaceWarning:
		return "WriteReplaceWarning"
	case pdu.ProcENBDirectInformationTransfer:
		return "ENBDirectInformationTransfer"
	case pdu.ProcMMEDirectInformationTransfer:
		return "MMEDirectInformationTransfer"
	case pdu.ProcPrivateMessage:
		return "PrivateMessage"
	case pdu.ProcENBConfigurationTransfer:
		return "ENBConfigurationTransfer"
	case pdu.ProcMMEConfigurationTransfer:
		return "MMEConfigurationTransfer"
	case pdu.ProcCellTrafficTrace:
		return "CellTrafficTrace"
	case pdu.ProcKill:
		return "Kill"
	case pdu.ProcPWSRestartIndication:
		return "PWSRestartIndication"
	case pdu.ProcERABModificationIndication:
		return "ERABModificationIndication"
	case pdu.ProcHandoverNotification:
		return "HandoverNotification"
	case pdu.ProcHandoverCancel:
		return "HandoverCancel"
	case pdu.ProcERABReleaseIndication:
		return "ERABReleaseIndication"
	default:
		return "unknown"
	}
}

func (s *Server) allowInboundProcedure(remoteAddr string, p *pdu.PDU) bool {
	if p == nil {
		return false
	}
	if p.Type == pdu.PDUTypeInitiatingMessage && p.ProcedureCode == pdu.ProcS1Setup {
		return true
	}
	v, ok := s.enbs.Load(remoteAddr)
	if !ok {
		s.log.Warn("s1ap: dropping procedure before S1Setup",
			zap.String("remote", remoteAddr),
			zap.Uint8("procedure_code", p.ProcedureCode),
			zap.String("pdu_type", p.Type.String()),
			zap.String("reason", "missing_enb_context"))
		return false
	}
	enb, ok := v.(*ENBContext)
	if !ok || enb == nil || !enb.SetupComplete {
		s.log.Warn("s1ap: dropping procedure before S1Setup completion",
			zap.String("remote", remoteAddr),
			zap.Uint8("procedure_code", p.ProcedureCode),
			zap.String("pdu_type", p.Type.String()))
		return false
	}
	return true
}

func (s *Server) dispatchInitiating(remoteAddr string, p *pdu.PDU) {
	ies, err := decodeProcedureIEsCompat(p.Value)
	if err != nil {
		s.log.Warn("s1ap: IE decode error", zap.String("remote", remoteAddr), zap.Error(err))
		return
	}
	if !s.validateInboundProcedureIEs(remoteAddr, p, ies) {
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
	case pdu.ProcUplinkUEAssociatedLPPaTransport:
		s.handleUplinkLPPa(remoteAddr, ies)
	case pdu.ProcUEContextReleaseRequest:
		s.handleUEContextReleaseRequest(remoteAddr, p, ies)
	case pdu.ProcUECapabilityInfoIndication:
		s.handleUECapabilityInfoIndication(remoteAddr, p, ies)
	case pdu.ProcErrorIndication:
		s.handleErrorIndication(remoteAddr, p, ies)
	case pdu.ProcERABModificationIndication:
		s.handleERABModificationIndication(remoteAddr, p, ies)
	case pdu.ProcReset:
		s.handleReset(remoteAddr, p, ies)
	case pdu.ProcENBConfigurationUpdate:
		s.handleENBConfigurationUpdate(remoteAddr, p, ies)
	case pdu.ProcHandoverPreparation:
		s.handleHandoverRequired(remoteAddr, p, ies)
	case pdu.ProcHandoverNotification:
		s.handleHandoverNotify(remoteAddr, p, ies)
	case pdu.ProcPWSRestartIndication:
		s.handlePWSForward(p.ProcedureCode, ies)
	case pdu.ProcPWSFailureIndication:
		s.handlePWSForward(p.ProcedureCode, ies)
	default:
		s.log.Warn("s1ap: unhandled initiating procedure",
			zap.Uint8("code", p.ProcedureCode),
			zap.String("remote", remoteAddr))
	}
}

func (s *Server) dispatchSuccessful(remoteAddr string, p *pdu.PDU, raw []byte) {
	ies, err := decodeProcedureIEsCompat(p.Value)
	if err != nil {
		s.log.Warn("s1ap: IE decode error (success)", zap.String("remote", remoteAddr), zap.Error(err))
		return
	}
	if !s.validateInboundProcedureIEs(remoteAddr, p, ies) {
		return
	}
	switch p.ProcedureCode {
	case pdu.ProcInitialContextSetup:
		s.handleInitialContextSetupResponse(remoteAddr, p, ies)
	case pdu.ProcERABSetup:
		s.handleERABSetupResponse(remoteAddr, p, raw, ies)
	case pdu.ProcERABModify:
		s.handleERABModifyResponse(remoteAddr, p, raw, ies)
	case pdu.ProcERABRelease:
		s.handleERABReleaseComplete(remoteAddr, p, raw, ies)
	case pdu.ProcUEContextRelease:
		s.handleUEContextReleaseComplete(remoteAddr, p, ies)
	case pdu.ProcUEContextModification:
		s.handleUEContextModificationResponse(remoteAddr, p, ies)
	case pdu.ProcHandoverResourceAllocation:
		s.handleHandoverRequestAck(remoteAddr, p, ies)
	case pdu.ProcWriteReplaceWarning, pdu.ProcKill:
		s.handlePWSResponse(remoteAddr, p.ProcedureCode, ies)
	default:
		s.log.Debug("s1ap: unhandled successful outcome",
			zap.Uint8("code", p.ProcedureCode),
			zap.String("remote", remoteAddr))
	}
}

func (s *Server) dispatchUnsuccessful(remoteAddr string, p *pdu.PDU, raw []byte) {
	ies, err := decodeProcedureIEsCompat(p.Value)
	if err != nil {
		s.log.Warn("s1ap: IE decode error (unsuccessful)", zap.String("remote", remoteAddr), zap.Error(err))
		return
	}
	if !s.validateInboundProcedureIEs(remoteAddr, p, ies) {
		return
	}
	switch p.ProcedureCode {
	case pdu.ProcInitialContextSetup:
		s.handleInitialContextSetupFailure(remoteAddr, p, ies)
	case pdu.ProcERABSetup:
		s.log.Warn("s1ap: unsuccessful E-RAB Setup outcome received",
			zap.String("remote", remoteAddr),
			zap.Uint8("procedure_code", p.ProcedureCode),
			zap.String("pdu_choice", p.Type.String()),
			zap.String("criticality", p.Criticality.String()),
			zap.String("raw_s1ap_hex", hex.EncodeToString(raw)))
	case pdu.ProcERABModify:
		s.handleERABModifyFailure(remoteAddr, p, ies)
	case pdu.ProcHandoverResourceAllocation:
		s.handleHandoverRequestFailure(remoteAddr, p, ies)
	case pdu.ProcUEContextModification:
		s.handleUEContextModificationFailure(remoteAddr, p, ies)
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
			if isResumeICSAttachStep(ue.AttachStep) {
				ue.AttachStep = uecontext.AttachStepNone
				ue.SetEMMState(emm.StateRegistered)
			}
			ue.SetECMState(emm.ECMIdle)
			ue.ENBS1APID = 0
			ue.ENBGlobalID = ""
			ue.S1BindingState = uecontext.S1BindingReleased
			ue.ENBU_TEID = 0
			ue.ENBU_IP = nil
			ue.Unlock()
			// The old S1 binding is gone. A pending LPP NAS PDU (or LPPa
			// Initiation Request) must not be delivered through a later,
			// unrelated service resumption.
			s.ClearPendingLPP(mmeID)
			s.ClearPendingLPPa(mmeID)
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
			s.armReachabilityForIdle(ue, "enb-disconnect")
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
		s.ClearPendingLPP(mmeID)
		s.ClearPendingLPPa(mmeID)
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
	deadlineReached := false
	for _, ue := range ues {
		select {
		case <-ctx.Done():
			s.log.Warn("s1ap: shutdown deadline reached, abandoning remaining sessions",
				zap.Int("remaining", len(ues)-drained))
			deadlineReached = true
		default:
		}
		if deadlineReached {
			break
		}
		ue.Lock()
		mmeUEID := ue.MMEUES1APID
		wasAttached := ue.EMMState == emm.StateRegistered ||
			(ue.EMMState == emm.StateTrackingAreaUpdating && ue.SGWC_TEID != 0)
		ue.StopAllTimers()
		ue.Unlock()
		s.ClearPendingLPP(mmeUEID)
		s.ClearPendingLPPa(mmeUEID)

		s.sendDeleteSession(ue)
		s.ueManager.Remove(ue)
		if wasAttached {
			metrics.AttachedUEs.Dec()
		}
		drained++
	}
	s.log.Info("s1ap: graceful shutdown complete", zap.Int("drained", drained))

	s.transportMu.Lock()
	sctpSrv := s.sctpSrv
	s.transportMu.Unlock()
	if sctpSrv != nil {
		if err := sctpSrv.Close(); err != nil {
			s.log.Warn("s1ap: SCTP transport close error", zap.Error(err))
		} else {
			s.log.Info("s1ap: SCTP transport closed")
		}
	}
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
