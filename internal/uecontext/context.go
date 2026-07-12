// Package uecontext manages the per-UE EMM state machine and security context.
package uecontext

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/security"
)

type S1BindingState uint8

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

	// Identity
	IMSI string
	IMEI string

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

	// NAS COUNTs
	ULNASCount security.NASCount
	DLNASCount security.NASCount

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
	EBIReservations           map[uint8]EBIReservation

	// Handover security state (TS 33.401 §7.2.8)
	NH  []byte // 32-byte Next Hop key; nil until first ICS sent
	NCC uint8  // Next hop Chaining Counter 0..7

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
	PagingAttempts uint8 // 0 = not paging; >0 = paging cycle active

	// Active timers
	timers map[string]*time.Timer

	// Created / last updated
	CreatedAt time.Time
	UpdatedAt time.Time
}

type SubscriberAPNConfig struct {
	ContextIdentifier   uint32
	ServiceSelection    string
	MIPHomeAgentAddress net.IP
	MIPHomeAgentHost    string
	PDNGWAllocationType *int32
}

type PDNContext struct {
	APN                    string
	ProcedureTransactionID uint8
	PDNType                uint8
	DefaultEBI             uint8
	LocalS11TEID           uint32
	SGWAddress             string
	SGWC_TEID              uint32
	SGWC_IP                net.IP
	SGWU_TEID              uint32
	SGWU_IP                net.IP
	ENBU_TEID              uint32
	ENBU_IP                net.IP
	UEIPv4                 net.IP
	UEPCO                  []byte
	PGWPCO                 []byte
	NASAccepted            bool
	ERABEstablished        bool
	ModifyBearerAccepted   bool
	State                  string
}

type CreateBearerState string

const (
	CreateBearerReceived       CreateBearerState = "received"
	CreateBearerWaitingForUE   CreateBearerState = "waiting_for_ue"
	CreateBearerPaging         CreateBearerState = "paging"
	CreateBearerActivatingNAS  CreateBearerState = "activating_nas"
	CreateBearerSettingUpERAB  CreateBearerState = "setting_up_erab"
	CreateBearerWaitingResults CreateBearerState = "waiting_results"
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

// NewContext creates a new UE context with an MME UE S1AP ID.
func NewContext(mmeID uint32) *Context {
	return &Context{
		MMEUES1APID:               mmeID,
		EMMState:                  emm.StateDeregistered,
		ECMState:                  emm.ECMIdle,
		PDNs:                      make(map[string]*PDNContext),
		DedicatedBearers:          make(map[uint8]*DedicatedBearerContext),
		PendingBearerTransactions: make(map[string]*DedicatedBearerTransaction),
		EBIReservations:           make(map[uint8]EBIReservation),
		timers:                    make(map[string]*time.Timer),
		CreatedAt:                 time.Now(),
		UpdatedAt:                 time.Now(),
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

// HOState represents the S1 handover preparation/execution state.
type HOState uint8

const (
	HOStateNone      HOState = 0
	HOStatePreparing HOState = 1 // HO Required received, HO Request sent to target
	HOStateExecuting HOState = 2 // HO Command sent, awaiting HO Notify
)

// AttachStep sub-states within EMM-REGISTERED-INITIATED.
const (
	AttachStepNone                  uint8 = 0
	AttachStepWaitingAIA            uint8 = 1  // AIR sent, waiting Authentication-Information-Answer
	AttachStepWaitingAuthResp       uint8 = 2  // Auth Request sent, waiting Auth Response
	AttachStepWaitingSMCCplt        uint8 = 3  // Security Mode Command sent, waiting SMC Complete
	AttachStepWaitingULA            uint8 = 4  // ULR sent, waiting Update-Location-Answer
	AttachStepWaitingCSRsp          uint8 = 5  // CSR sent to S-GW, waiting Create Session Response
	AttachStepWaitingICSResp        uint8 = 6  // ICS Request sent, waiting ICS Response
	AttachStepWaitingAttachCplt     uint8 = 7  // Attach Accept delivered, waiting Attach Complete
	AttachStepWaitingTAUComplete    uint8 = 8  // TAU Accept sent, waiting TAU Complete
	AttachStepWaitingICSRespSR      uint8 = 9  // ICS Request sent for Service Request re-establishment
	AttachStepWaitingULAInterMMETAU uint8 = 10 // ULR sent after inter-MME context import, waiting ULA
)

// NAS timer names (3GPP TS 24.301).
const (
	TimerT3410 = "T3410" // Attach timer (15s default)
	TimerT3412 = "T3412" // Periodic TAU timer (stored so StopAllTimers can clean it up)
	TimerT3413 = "T3413" // Paging timer (6s default)
	TimerT3450 = "T3450" // Attach Accept / GUTI reallocation timer (6s)
	TimerT3460 = "T3460" // Authentication Request timer (6s)
	TimerT3470 = "T3470" // Identity Request timer (6s)

	TimerCreateBearerPrefix = "CreateBearer:"
)
