// Package uecontext manages the per-UE EMM state machine and security context.
package uecontext

import (
	"net"
	"sync"
	"time"

	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/security"
)

// Context holds all runtime state for a single attached UE.
// It is protected by mu; all fields must be accessed under mu.
type Context struct {
	mu sync.Mutex

	// S1AP identifiers
	MMEUES1APID uint32
	ENBS1APID   uint32
	ENBGlobalID string // serialised GlobalENBID

	// S1 release in progress for the previous access context. Kept separate
	// from the current ENBS1APID so a fast Service Request can rebind the UE
	// before the old UE Context Release Complete arrives.
	S1ReleasePending bool
	S1ReleaseENBID   uint32
	S1ReleaseENBAddr string

	// Identity
	IMSI string
	IMEI string

	// GUTI
	GUTI *emm.GUTI

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

	// UE radio capability (raw S1AP UERadioCapability OCTET STRING).
	UERadioCapability []byte

	// Original unprotected Attach Request NAS PDU, as received in S1AP NAS-PDU.
	InitialAttachRequestNAS []byte

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
	MSISDN string
	APN    string

	// Attach flow sub-step (0=none; see AttachStep* constants)
	AttachStep    uint8
	PDNRequestPTI uint8 // PTI from ESM PDN Connectivity Request
	ESMContainer  []byte
	PDNRequest    []byte
	PCO           []byte

	// S11 GTPv2-C bearer state (populated after CSRsp)
	LocalS11TEID uint32
	SGWAddress   string
	SGWC_TEID    uint32
	SGWC_IP      net.IP
	SGWU_TEID    uint32
	SGWU_IP      net.IP
	ENBU_TEID    uint32 // from ICS Response
	ENBU_IP      net.IP
	DefaultEBI   uint8
	UEIPv4       net.IP

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

// NewContext creates a new UE context with an MME UE S1AP ID.
func NewContext(mmeID uint32) *Context {
	return &Context{
		MMEUES1APID: mmeID,
		EMMState:    emm.StateDeregistered,
		ECMState:    emm.ECMIdle,
		timers:      make(map[string]*time.Timer),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
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
)
