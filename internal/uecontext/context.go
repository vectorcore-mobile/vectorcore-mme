// Package uecontext manages the per-UE EMM state machine and security context.
package uecontext

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/security"
)

type S1BindingState uint8

// SMSRegistrationState is per UE: enabling SGd at node level does not
// register every subscriber for SMS in MME.
type SMSRegistrationState string

const (
	SMSRegistrationNotRequested SMSRegistrationState = "not-requested"
	SMSRegistrationPending      SMSRegistrationState = "pending"
	SMSRegistrationRegistered   SMSRegistrationState = "registered"
	SMSRegistrationRejected     SMSRegistrationState = "rejected"
	SMSRegistrationRemoved      SMSRegistrationState = "removed"
)

const (
	S1BindingReleased S1BindingState = iota
	S1BindingActive
	S1BindingReleasePending
)

func (s S1BindingState) String() string {
	switch s {
	case S1BindingReleased:
		return "S1_RELEASED"
	case S1BindingActive:
		return "S1_ACTIVE"
	case S1BindingReleasePending:
		return "S1_RELEASE_PENDING"
	default:
		return "S1_UNKNOWN"
	}
}

type DDNPagingStatus string

const (
	DDNPagingPending          DDNPagingStatus = "pending"
	DDNPagingPagingSent       DDNPagingStatus = "paging-sent"
	DDNPagingServiceRequest   DDNPagingStatus = "service-request-received"
	DDNPagingResumeInProgress DDNPagingStatus = "resume-in-progress"
	DDNPagingCompleted        DDNPagingStatus = "completed"
	DDNPagingTimedOut         DDNPagingStatus = "timed-out"
	DDNPagingFailed           DDNPagingStatus = "failed"
)

type DDNPagingTransaction struct {
	ID                 string
	SourcePeer         string
	MMEControlTEID     uint32
	OriginalSequence   uint32
	InitialBearerEBI   uint8
	ARPRaw             uint8
	FirstDDNAt         time.Time
	LastDDNAt          time.Time
	PagingAttemptCount uint8
	LastPagingAt       time.Time
	Status             DDNPagingStatus
	BindingGeneration  uint64
	LastAckCause       uint8
	FailureCause       uint8
	FailureReason      string
	JoinedBearers      map[uint8]struct{}
	DedupKeys          map[string]time.Time
}

type RABRSessionResult string

const (
	RABRSessionPending               RABRSessionResult = "pending"
	RABRSessionAccepted              RABRSessionResult = "accepted"
	RABRSessionContextNotFound       RABRSessionResult = "context-not-found"
	RABRSessionTimedOut              RABRSessionResult = "timed-out"
	RABRSessionLocalValidationFailed RABRSessionResult = "local-validation-failed"
	RABRSessionPeerError             RABRSessionResult = "peer-error"
)

type S1ReleaseRABRSession struct {
	Key                        string
	APN                        string
	DefaultEBI                 uint8
	MMES11TEID                 uint32
	SGWS11TEID                 uint32
	SGWS11Addr                 string
	SessionState               string
	LastSuccessfulS11Procedure string
	Sequence                   uint32
	SentAt                     time.Time
	ResponseAt                 time.Time
	ResponseHeaderTEID         uint32
	Cause                      uint8
	Result                     RABRSessionResult
}

type S1ReleaseRABRTransaction struct {
	ID            string
	StartedAt     time.Time
	ReleaseCause  string
	CommandSent   bool
	PolicyApplied string
	Sessions      map[string]*S1ReleaseRABRSession
}

// Context holds all runtime state for a single attached UE.
// It is protected by mu; all fields must be accessed under mu.
type Context struct {
	mu sync.Mutex

	// S1AP identifiers
	MMEUES1APID         uint32
	ENBS1APID           uint32
	ENBGlobalID         string // serialised GlobalENBID
	S1BindingGeneration uint64
	S1BindingState      S1BindingState

	// S1 release in progress for the previous access context. Kept separate
	// from the current ENBS1APID so a fast Service Request can rebind the UE
	// before the old UE Context Release Complete arrives.
	S1ReleasePending    bool
	S1ReleaseENBID      uint32
	S1ReleaseENBAddr    string
	S1ReleaseGeneration uint64
	S1ReleaseCauseGroup uint8
	S1ReleaseCauseValue uint8

	// Identity
	IMSI   string
	IMEI   string
	IMEISV string
	// PendingIdentityType records why an Identity Request was sent. It keeps
	// an equipment response from ever being mistaken for an IMSI.
	PendingIdentityType uint8

	// Runtime-only SMS state. Transactions and timers are never restored after
	// restart; normal S6a registration refresh establishes availability again.
	SMSRegistrationState SMSRegistrationState
	SMSRegistrationCause string
	SMSRegistrationAt    time.Time

	// GUTI
	GUTI *emm.GUTI

	// GUTI reallocation state. During TAU/GUTI reallocation, both the old GUTI
	// and pending new GUTI must resolve until TAU Complete commits the change.
	PendingOldGUTI       *emm.GUTI
	PendingGUTI          *emm.GUTI
	GUTIReallocPending   bool
	GUTIReallocRetry     int
	GUTIReallocStartedAt time.Time
	PendingTAUAcceptNAS  []byte

	// EMM state
	EMMState emm.EMMState
	ECMState emm.ECMState

	// Security context
	KASME   []byte
	KNASint []byte
	KNASenc []byte
	IntAlg  uint8 // selected EIA (0,1,2)
	EncAlg  uint8 // selected EEA (0,1,2)
	NASKSI  uint8 // 0..6 valid, 7 means "no key available"

	// NAS COUNTs
	ULNASCount security.NASCount
	DLNASCount security.NASCount

	// Access-stratum security context snapshot used for the next resume ICS.
	// KeNB must remain tied to the UL NAS COUNT that triggered the resume.
	KeNB                   []byte
	KeNBULCount            uint32
	KeNBSnapshotGeneration uint64

	// UE network capability (raw bytes from Attach Request)
	UENetworkCapability []byte
	MSNetworkCapability []byte
	AttachType          uint8

	// UE radio capability (raw S1AP UERadioCapability OCTET STRING).
	UERadioCapability []byte

	// Original unprotected Attach Request NAS PDU, as received in S1AP NAS-PDU.
	InitialAttachRequestNAS []byte

	// Last protected downlink NAS message name, for correlating EMM Status reports.
	LastDownlinkNASMessage string

	// Temporary identity candidate from an unverified Attach Request GUTI.
	// This is diagnostic/collision state only; it is not confirmed identity.
	CandidateGUTI string
	CandidateIMSI string

	// Authentication challenge in flight
	RAND []byte
	XRES []byte
	AUTN []byte

	// Last known TAI
	TAI *emm.TAI

	// ECGI from Initial UE Message (for ULI IE in GTPv2 CSR)
	ECGIPLMN [3]byte
	ECGIECI  uint32 // 28-bit E-UTRAN Cell Identifier

	// Subscription data (from HSS via S6a ULR/ULA)
	MSISDN               string
	APN                  string
	UEAMBRDown           uint32
	UEAMBRUp             uint32
	SubscriberAPNs       []string
	SubscriberAPNConfigs map[string]SubscriberAPNConfig

	LastReleaseCause string

	// Attach flow sub-step (0=none; see AttachStep* constants)
	AttachStep    uint8
	PDNRequestPTI uint8 // PTI from ESM PDN Connectivity Request
	ESMContainer  []byte
	PDNRequest    []byte
	PCO           []byte // UE-requested PCO from PDN Connectivity Request
	PGWPCO        []byte // P-GW returned PCO from Create Session Response

	// S11 GTPv2-C bearer state (populated after CSRsp)
	LocalS11TEID              uint32
	SGWAddress                string
	SGWC_TEID                 uint32
	SGWC_IP                   net.IP
	SGWU_TEID                 uint32
	SGWU_IP                   net.IP
	ENBU_TEID                 uint32 // from ICS Response
	ENBU_IP                   net.IP
	DefaultEBI                uint8
	UEIPv4                    net.IP
	PDNs                      map[string]*PDNContext
	PendingPDN                *PDNContext
	DedicatedBearers          map[uint8]*DedicatedBearerContext
	PendingBearerTransactions map[string]*DedicatedBearerTransaction
	PendingERABProcedures     map[string]*PendingERABProcedure
	EBIReservations           map[uint8]EBIReservation

	// Handover security state (TS 33.401 §7.2.8)
	NH  []byte // 32-byte Next Hop key; nil until first ICS sent
	NCC uint8  // Next hop Chaining Counter 0..7

	// Short debug watch after successful ICS to catch post-restore mutations.
	PostICSDebugUntil      time.Time
	PostICSDebugGeneration uint64

	// S1 handover state (transient, not persisted to DB)
	HOState             HOState
	HOSrcENBAddr        string // source eNB remote addr (preserved during HO)
	HOSrcENBS1APID      uint32 // source eNB UE S1AP ID (preserved during HO)
	HOTargetENBAddr     string
	HOTargetENBUEID     uint32
	HOTargetENBU_TEID   uint32 // from E-RABAdmittedList
	HOTargetENBU_IP     net.IP
	HOSrcToTgtContainer []byte // forwarded opaquely to target eNB

	// S10 inter-MME TAU transient state (cleared after Context Acknowledge is sent)
	S10OldMMEAddr string // old MME UDP addr ("ip:port") for sending Context Acknowledge
	S10OldMMETEID uint32 // old MME's S10 local TEID (goes in CTX-Ack header)

	// Paging state
	PagingAttempts   uint8 // 0 = not paging; >0 = paging cycle active
	DDNPaging        *DDNPagingTransaction
	DefaultPagingDRX uint8
	S1ReleaseRABR    *S1ReleaseRABRTransaction

	// Active timers
	timers map[string]*time.Timer

	// MME-side reachability state. These fields are protected by mu; generations
	// make a queued time.AfterFunc harmless after refresh, removal, or ID reuse.
	ReachabilityState                string
	MobileReachableGeneration        uint64
	MobileReachableDeadline          time.Time
	MobileReachableTimerActive       bool
	ImplicitDetachGeneration         uint64
	ImplicitDetachDeadline           time.Time
	ImplicitDetachTimerActive        bool
	LastReachabilityRefresh          time.Time
	LastReachabilityReason           string
	ImplicitDetachCleanupStarted     bool
	ImplicitDetachCleanupGeneration  uint64
	ImplicitDetachCleanupDeadline    time.Time
	ImplicitDetachCleanupTimerActive bool

	// Created / last updated
	CreatedAt time.Time
	UpdatedAt time.Time
}

type SubscriberAPNConfig struct {
	ContextIdentifier       uint32
	ServiceSelection        string
	MIPHomeAgentAddress     net.IP
	MIPHomeAgentHost        string
	PDNGWAllocationType     *int32
	PDNType                 uint8
	PDNTypePolicy           uint8
	QCI                     uint8
	ARPPriority             uint8
	PreemptionCapability    bool
	PreemptionVulnerability bool
	APNAMBRDown             uint32
	APNAMBRUp               uint32
}

type PDNContext struct {
	APN                     string
	ProcedureTransactionID  uint8
	DisconnectPTI           uint8
	PDNType                 uint8
	RequestedPDNType        uint8
	SubscribedPDNType       uint8
	SubscribedPDNTypePolicy uint8
	NetworkPDNType          uint8
	DefaultEBI              uint8
	QCI                     uint8
	ARPPriority             uint8
	PreemptionCapability    bool
	PreemptionVulnerability bool
	// APN AMBR is retained with the PDN so that every access-side encoding
	// uses the same subscribed policy as the S11 Create Session request.
	APNAMBRDown  uint32
	APNAMBRUp    uint32
	LocalS11TEID uint32
	SGWAddress   string
	SGWC_TEID    uint32
	SGWC_IP      net.IP
	SGWU_TEID    uint32
	SGWU_IP      net.IP
	ENBU_TEID    uint32
	ENBU_IP      net.IP
	UEIPv4       net.IP
	UEPCO        []byte
	PGWPCO       []byte
	// InitialERABAggregationPending holds the already protected IMS default
	// bearer activation briefly while a linked Create Bearer Request can join
	// the same initial E-RAB Setup procedure.
	InitialERABAggregationPending bool
	InitialERABActivationNAS      []byte
	// InitialERABAggregationGeneration invalidates a timer callback after the
	// staged activation has been aggregated, sent as fallback, or superseded.
	InitialERABAggregationGeneration uint64
	// ActivationNAS and the T3485 fields retain the exact network-initiated
	// activation PDU until the UE accepts, rejects, or the procedure aborts.
	ActivationNAS              []byte
	ActivationPlainNAS         []byte
	ActivationRetryCount       uint8
	ActivationTimerGeneration  uint64
	ActivationTimerActive      bool
	ActivationTimedOut         bool
	NASAccepted                bool
	ERABEstablished            bool
	ModifyBearerSent           bool
	ModifyBearerAccepted       bool
	ModifyBearerFailed         bool
	ModifyBearerDeferred       bool
	ModifyBearerFallbackSent   bool
	ModifyBearerRetryAttempts  uint8
	DisconnectRequested        bool
	DisconnectNASAccepted      bool
	State                      string
	SessionCreatedAt           time.Time
	LastSuccessfulS11Procedure string
}

type CreateBearerState string

const (
	CreateBearerReceived       CreateBearerState = "received"
	CreateBearerWaitingForUE   CreateBearerState = "waiting_for_ue"
	CreateBearerWaitingForLink CreateBearerState = "waiting_for_linked_bearer"
	CreateBearerPaging         CreateBearerState = "paging"
	CreateBearerActivatingNAS  CreateBearerState = "activating_nas"
	CreateBearerSettingUpERAB  CreateBearerState = "setting_up_erab"
	CreateBearerWaitingResults CreateBearerState = "waiting_results"
	CreateBearerCleaningUpERAB CreateBearerState = "cleaning_up_erab"
	CreateBearerCompleted      CreateBearerState = "completed"
	CreateBearerFailed         CreateBearerState = "failed"
	CreateBearerTimedOut       CreateBearerState = "timed_out"
)

type EBIReservation struct {
	EBI           uint8
	TransactionID string
	ReservedAt    time.Time
}

type DedicatedBearerContext struct {
	TransactionID string
	RequestedEBI  uint8
	AssignedEBI   uint8
	LinkedEBI     uint8
	PTI           uint8
	// LegacyTransactionIdentifier is retained for the optional TS 24.301
	// Transaction identifier IE while this network-initiated procedure lives.
	LegacyTransactionIdentifier uint8

	QCI       uint8
	ARP       uint8
	BearerQoS []byte
	TFT       []byte
	PCO       []byte

	SGWS1UTEID uint32
	SGWS1UIP   net.IP
	ENBS1UTEID uint32
	ENBS1UIP   net.IP

	NASAccepted     bool
	NASRejected     bool
	ERABEstablished bool
	ERABFailed      bool
	// ActivationNAS is the protected NAS PDU that was actually delivered in
	// the E-RAB Setup. T3485 retransmits this stable procedure payload.
	ActivationNAS             []byte
	ActivationRetryCount      uint8
	ActivationTimerGeneration uint64
	ActivationTimerActive     bool
	ActivationTimedOut        bool

	State        string
	FailureCause uint8
}

type DedicatedBearerTransaction struct {
	ID             string
	Kind           string
	PeerAddress    string
	LocalTEID      uint32
	SequenceNum    uint32
	LinkedEBI      uint8
	EBIs           []uint8
	Fingerprint    string
	Bearers        map[uint8]*DedicatedBearerContext
	ResponseCause  uint8
	CreateState    CreateBearerState
	State          string
	CreatedAt      time.Time
	PagingAt       time.Time
	Deadline       time.Time
	PagingAttempts uint8
	responseSent   atomic.Bool
}

func (t *DedicatedBearerTransaction) TryMarkResponseSent() bool {
	if t == nil {
		return false
	}
	return t.responseSent.CompareAndSwap(false, true)
}

type PendingERABProcedure struct {
	TransactionID       string
	ProcedureKind       string
	ExpectedEBIs        map[uint8]struct{}
	S1BindingGeneration uint64
	CreatedAt           time.Time
	Deadline            time.Time
}

// NewContext creates a new UE context with an MME UE S1AP ID.
func NewContext(mmeID uint32) *Context {
	return &Context{
		MMEUES1APID:               mmeID,
		SMSRegistrationState:      SMSRegistrationNotRequested,
		EMMState:                  emm.StateDeregistered,
		ECMState:                  emm.ECMIdle,
		PDNs:                      make(map[string]*PDNContext),
		DedicatedBearers:          make(map[uint8]*DedicatedBearerContext),
		PendingBearerTransactions: make(map[string]*DedicatedBearerTransaction),
		PendingERABProcedures:     make(map[string]*PendingERABProcedure),
		EBIReservations:           make(map[uint8]EBIReservation),
		timers:                    make(map[string]*time.Timer),
		CreatedAt:                 time.Now(),
		UpdatedAt:                 time.Now(),
		NASKSI:                    0x07,
		ReachabilityState:         "reachable",
	}
}

// Lock acquires the context mutex.
func (c *Context) Lock() { c.mu.Lock() }

// Unlock releases the context mutex.
func (c *Context) Unlock() { c.mu.Unlock() }

// SetEMMState transitions the EMM state.
func (c *Context) SetEMMState(s emm.EMMState) {
	c.EMMState = s
	c.UpdatedAt = time.Now()
}

// SetECMState transitions the ECM state.
func (c *Context) SetECMState(s emm.ECMState) {
	c.ECMState = s
	c.UpdatedAt = time.Now()
}

// StoreAuthChallenge stores the AKA vectors for the pending authentication.
func (c *Context) StoreAuthChallenge(rand, xres, autn, kasme []byte) {
	c.RAND = rand
	c.XRES = xres
	c.AUTN = autn
	c.KASME = kasme
	if c.NASKSI < 6 {
		c.NASKSI++
	} else {
		c.NASKSI = 0
	}
	c.UpdatedAt = time.Now()
}

// ActivateSecurityContext derives NAS keys from KASME and stores them.
func (c *Context) ActivateSecurityContext(intAlg, encAlg uint8) error {
	knasInt, knasEnc, err := security.DeriveNASKeys(c.KASME, intAlg, encAlg)
	if err != nil {
		return err
	}
	c.KNASint = knasInt
	c.KNASenc = knasEnc
	c.IntAlg = intAlg
	c.EncAlg = encAlg
	c.UpdatedAt = time.Now()
	return nil
}

// IncrementULCount increments the uplink NAS COUNT and returns the new value.
func (c *Context) IncrementULCount() uint32 {
	c.ULNASCount.Increment()
	return uint32(c.ULNASCount)
}

// IncrementDLCount increments the downlink NAS COUNT and returns the new value.
func (c *Context) IncrementDLCount() uint32 {
	c.DLNASCount.Increment()
	return uint32(c.DLNASCount)
}

// StartTimer starts a named NAS timer. If the timer already exists it is cancelled first.
func (c *Context) StartTimer(name string, d time.Duration, f func()) {
	if t, ok := c.timers[name]; ok {
		t.Stop()
	}
	c.timers[name] = time.AfterFunc(d, f)
}

// StopTimer cancels a named NAS timer.
func (c *Context) StopTimer(name string) {
	if t, ok := c.timers[name]; ok {
		t.Stop()
		delete(c.timers, name)
	}
}

// StopAllTimers cancels all active NAS timers.
func (c *Context) StopAllTimers() {
	for name, t := range c.timers {
		t.Stop()
		delete(c.timers, name)
	}
}

// CancelActivationTimers invalidates every network-initiated ESM activation
// callback before terminal UE or PDN state is removed. The caller must hold
// c.Lock(); this complements StopAllTimers because an AfterFunc callback may
// already be queued when its timer is stopped.
func (c *Context) CancelActivationTimers() {
	for _, pdn := range c.PDNs {
		if pdn == nil {
			continue
		}
		pdn.ActivationTimerActive = false
		pdn.ActivationTimerGeneration++
		c.StopTimer(fmt.Sprintf("T3485:%d", pdn.DefaultEBI))
	}
	for _, proc := range c.DedicatedBearers {
		if proc == nil {
			continue
		}
		proc.ActivationTimerActive = false
		proc.ActivationTimerGeneration++
		c.StopTimer(fmt.Sprintf("T3485:%d", proc.AssignedEBI))
	}
	for _, tx := range c.PendingBearerTransactions {
		for _, proc := range tx.Bearers {
			if proc == nil {
				continue
			}
			proc.ActivationTimerActive = false
			proc.ActivationTimerGeneration++
			c.StopTimer(fmt.Sprintf("T3485:%d", proc.AssignedEBI))
		}
	}
}

// HOState represents the S1 handover preparation/execution state.
type HOState uint8

const (
	HOStateNone      HOState = 0
	HOStatePreparing HOState = 1 // HO Required received, HO Request sent to target
	HOStateExecuting HOState = 2 // HO Command sent, awaiting HO Notify
)

// AttachStep sub-states within EMM-REGISTERED-INITIATED.
const (
	AttachStepNone                     uint8 = 0
	AttachStepWaitingAIA               uint8 = 1  // AIR sent, waiting Authentication-Information-Answer
	AttachStepWaitingAuthResp          uint8 = 2  // Auth Request sent, waiting Auth Response
	AttachStepWaitingSMCCplt           uint8 = 3  // Security Mode Command sent, waiting SMC Complete
	AttachStepWaitingULA               uint8 = 4  // ULR sent, waiting Update-Location-Answer
	AttachStepWaitingCSRsp             uint8 = 5  // CSR sent to S-GW, waiting Create Session Response
	AttachStepWaitingICSResp           uint8 = 6  // ICS Request sent, waiting ICS Response
	AttachStepWaitingAttachCplt        uint8 = 7  // Attach Accept delivered, waiting Attach Complete
	AttachStepWaitingTAUComplete       uint8 = 8  // TAU Accept sent, waiting TAU Complete
	AttachStepWaitingICSRespSR         uint8 = 9  // ICS Request sent for Service Request re-establishment
	AttachStepWaitingICSRespTAU        uint8 = 10 // ICS Request sent for active-flag idle TAU resume
	AttachStepWaitingULAInterMMETAU    uint8 = 11 // ULR sent after inter-MME context import, waiting ULA
	AttachStepWaitingS13ECA            uint8 = 12 // ECR sent, waiting ME-Identity-Check-Answer
	AttachStepWaitingEquipmentIdentity uint8 = 13 // protected Identity Request sent for IMEI/IMEISV
)

// NAS timer names (3GPP TS 24.301).
const (
	TimerT3410 = "T3410" // Attach timer (15s default)
	TimerT3412 = "T3412" // Periodic TAU timer (stored so StopAllTimers can clean it up)
	TimerT3413 = "T3413" // Paging timer (6s default)
	TimerT3450 = "T3450" // Attach Accept / GUTI reallocation timer (6s)
	TimerT3460 = "T3460" // Authentication Request timer (6s)
	TimerT3470 = "T3470" // Identity Request timer (6s)

	TimerCreateBearerPrefix    = "CreateBearer:"
	TimerUpdateBearerPrefix    = "UpdateBearer:"
	TimerMobileReachable       = "MME-MobileReachable"
	TimerImplicitDetach        = "MME-ImplicitDetach"
	TimerImplicitDetachCleanup = "MME-ImplicitDetachCleanup"
)
