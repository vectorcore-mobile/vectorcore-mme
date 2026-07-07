package main

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
)

// nextS1UTEID is a package-level counter that allocates unique per-UE GTP-U TEIDs.
var nextS1UTEID uint32

const nasTimeout = 15 * time.Second

// UE simulates one LTE UE performing an EPS Attach procedure.
// It advertises only EIA0/EEA0 so the MME selects null security,
// removing the need to compute NAS MACs in the stressor.
type UE struct {
	cfg     *Config
	enb     *ENB
	imsi    string
	k       []byte // 16-byte auth key (per-UE, overrides cfg.K when set)
	opc     []byte // 16-byte OPc (per-UE, overrides cfg.OPC when set)
	enbUEID uint32
	mmeUEID uint32
	recvCh  chan []byte
	ulSeq   uint8  // NAS UL sequence number (new security context)
	s1uTEID uint32 // unique eNB GTP-U TEID for this UE's S1-U bearer
}

// NewUE creates a UE with the IMSI derived from the base by adding idx.
// If cfg.Credentials has an entry for this index, its K/OPC are used;
// otherwise the global cfg.K/OPC are used.
func NewUE(cfg *Config, enb *ENB, idx int) *UE {
	imsi := imsiAdd(cfg.IMSIBase, idx)
	k, opc := cfg.K, cfg.OPC
	if cred, ok := cfg.Credentials[imsi]; ok {
		k, opc = cred[0], cred[1]
	}
	return &UE{
		cfg:     cfg,
		enb:     enb,
		imsi:    imsi,
		k:       k,
		opc:     opc,
		recvCh:  make(chan []byte, 16),
		s1uTEID: atomic.AddUint32(&nextS1UTEID, 1),
	}
}

// Attach runs the full EPS Attach state machine. Returns nil on Attach Complete.
func (ue *UE) Attach() error {
	ue.enbUEID = ue.enb.AllocateUEID()
	ue.enb.RegisterUE(ue.enbUEID, ue.recvCh)
	defer ue.enb.UnregisterUE(ue.enbUEID)

	// Step 1: send Initial UE Message (Attach Request inside)
	if err := ue.sendInitialUEMessage(); err != nil {
		return fmt.Errorf("step1 initial UE message: %w", err)
	}

	// Step 2: receive Auth Request, compute RES, send Auth Response
	rand, autn, err := ue.recvAuthRequest()
	if err != nil {
		return fmt.Errorf("step2 auth request: %w", err)
	}

	res, _, _, ak, err := milenageAuth(ue.k, ue.opc, rand)
	if err != nil {
		return fmt.Errorf("step2 milenage: %w", err)
	}
	_ = autn // AUTN: stressor trusts MME; AK used only if needed for KASME
	_ = ak

	if err := ue.sendUplinkNAS(buildAuthResponse(res)); err != nil {
		return fmt.Errorf("step2 auth response: %w", err)
	}

	// Step 3: receive Security Mode Command, send Security Mode Complete
	if err := ue.recvSecurityModeCommand(); err != nil {
		return fmt.Errorf("step3 SMC: %w", err)
	}

	if err := ue.sendUplinkNAS(ue.buildSecurityModeComplete()); err != nil {
		return fmt.Errorf("step3 SM complete: %w", err)
	}
	// After SMC, UL NAS context is established; next UL message uses seq=1
	ue.ulSeq++

	// Step 4: receive Initial Context Setup Request (contains Attach Accept)
	if err := ue.recvInitialContextSetup(); err != nil {
		return fmt.Errorf("step4 ICS request: %w", err)
	}

	// Step 5: send ICS Response, then Attach Complete
	if err := ue.sendInitialContextSetupResponse(); err != nil {
		return fmt.Errorf("step5 ICS response: %w", err)
	}

	if err := ue.sendUplinkNAS(ue.buildAttachComplete()); err != nil {
		return fmt.Errorf("step5 attach complete: %w", err)
	}

	return nil
}

// ── Send helpers ─────────────────────────────────────────────────────────────

func (ue *UE) sendInitialUEMessage() error {
	nasPDU := buildAttachRequest(ue.imsi)

	taiBytes, err := ies.EncodeTAI(ies.TAI{MCC: ue.cfg.MCC, MNC: ue.cfg.MNC, TAC: ue.cfg.TAC})
	if err != nil {
		return err
	}
	ecgiBytes, err := ies.EncodeECGI(ies.ECGI{MCC: ue.cfg.MCC, MNC: ue.cfg.MNC, ECGI: ue.cfg.ENBID})
	if err != nil {
		return err
	}

	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(ue.enbUEID)},
		{ID: pdu.IENAS_PDU, Criticality: aper.CriticalityReject, Value: ies.EncodeNASPDU(nasPDU)},
		{ID: pdu.IETAI, Criticality: aper.CriticalityIgnore, Value: taiBytes},
		{ID: pdu.IECGI, Criticality: aper.CriticalityIgnore, Value: ecgiBytes},
		{ID: pdu.IERRCEstablishmentCause, Criticality: aper.CriticalityIgnore, Value: ies.EncodeRRCEstablishmentCause(3)}, // mo-Signalling
	}
	msg := pdu.BuildInitiatingMessage(pdu.ProcInitialUEMessage, aper.CriticalityIgnore, ieList)
	return ue.enb.Send(msg)
}

func (ue *UE) sendUplinkNAS(nasPDU []byte) error {
	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeMMEUEApID(ue.mmeUEID)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(ue.enbUEID)},
		{ID: pdu.IENAS_PDU, Criticality: aper.CriticalityReject, Value: ies.EncodeNASPDU(nasPDU)},
	}
	msg := pdu.BuildInitiatingMessage(pdu.ProcUplinkNASTransport, aper.CriticalityIgnore, ieList)
	return ue.enb.Send(msg)
}

func (ue *UE) sendInitialContextSetupResponse() error {
	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeMMEUEApID(ue.mmeUEID)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeENBUEApID(ue.enbUEID)},
		{ID: pdu.IEERABSetupListCtxtSURes, Criticality: aper.CriticalityIgnore, Value: encodeStressorERABSetupList(ue.cfg.ENBIP, ue.s1uTEID)},
	}
	msg := pdu.BuildSuccessfulOutcome(pdu.ProcInitialContextSetup, aper.CriticalityReject, ieList)
	return ue.enb.Send(msg)
}

// ── Receive helpers ──────────────────────────────────────────────────────────

// recvMsg waits for the next PDU dispatched to this UE (by ENB-UE-S1AP-ID).
func (ue *UE) recvMsg() ([]byte, error) {
	select {
	case data, ok := <-ue.recvCh:
		if !ok {
			return nil, fmt.Errorf("connection closed")
		}
		return data, nil
	case <-time.After(nasTimeout):
		return nil, fmt.Errorf("timeout after %s", nasTimeout)
	}
}

func (ue *UE) recvAuthRequest() (rand, autn []byte, err error) {
	for {
		data, err := ue.recvMsg()
		if err != nil {
			return nil, nil, err
		}
		p, err := pdu.Decode(data)
		if err != nil || p.ProcedureCode != pdu.ProcDownlinkNASTransport {
			continue
		}
		ieList, _ := pdu.DecodeIEContainer(p.Value)
		nas := extractNASFromIEs(ieList)
		if nas == nil {
			continue
		}
		ue.mmeUEID = extractMMEUEIDFromIEs(ieList)

		// Expect plain NAS Auth Request: 0x07 0x52 ...
		if len(nas) < 36 || nas[1] != emm.MsgAuthenticationRequest {
			continue
		}
		// nas[2]=NAS KSI; nas[3:19]=RAND(16); nas[19]=AUTN len(0x10); nas[20:36]=AUTN(16)
		rand = nas[3:19]
		autn = nas[20:36]
		return rand, autn, nil
	}
}

func (ue *UE) recvSecurityModeCommand() error {
	for {
		data, err := ue.recvMsg()
		if err != nil {
			return err
		}
		p, err := pdu.Decode(data)
		if err != nil || p.ProcedureCode != pdu.ProcDownlinkNASTransport {
			continue
		}
		ieList, _ := pdu.DecodeIEContainer(p.Value)
		nas := extractNASFromIEs(ieList)
		if nas == nil {
			continue
		}
		// SMC is integrity-protected (security header type in upper nibble of nas[0]).
		// Protected format: [secHdr|PD] [MAC 4B] [SQN] [inner PD] [inner msgType]
		// Inner message type is at nas[7]; plain NAS would have it at nas[1].
		secHdr := (nas[0] >> 4) & 0x0F
		if secHdr != 0 {
			if len(nas) >= 8 && nas[7] == emm.MsgSecurityModeCommand {
				return nil
			}
		} else if len(nas) >= 2 && nas[1] == emm.MsgSecurityModeCommand {
			return nil
		}
	}
}

func (ue *UE) recvInitialContextSetup() error {
	for {
		data, err := ue.recvMsg()
		if err != nil {
			return err
		}
		p, err := pdu.Decode(data)
		if err != nil {
			continue
		}
		if p.ProcedureCode == pdu.ProcInitialContextSetup && p.Type == pdu.PDUTypeInitiatingMessage {
			// Extract MME-UE-S1AP-ID if not already set
			ieList, _ := pdu.DecodeIEContainer(p.Value)
			if ue.mmeUEID == 0 {
				ue.mmeUEID = extractMMEUEIDFromIEs(ieList)
			}
			return nil
		}
	}
}

// ── NAS message builders ─────────────────────────────────────────────────────

// buildAttachRequest encodes a plain NAS Attach Request.
// Advertises EIA0+EEA0 only to force null security selection on the MME.
func buildAttachRequest(imsi string) []byte {
	b := []byte{
		emm.PDEPSMobilityMgmt | (emm.SecurityHeaderPlain << 4), // 0x07
		emm.MsgAttachRequest,                                    // 0x41
		0x71,                                                    // NAS KSI=7 (no key), attach type=1 (EPS only)
	}

	// EPS Mobile Identity (IMSI)
	mobileID := emm.EPSMobileIdentityIMSI(imsi)
	b = append(b, byte(len(mobileID)))
	b = append(b, mobileID...)

	// UE Network Capability: EEA0 only (0x80), EIA0 only (0x80)
	b = append(b, 0x02, 0x80, 0x80)

	// ESM container: PDN Connectivity Request
	esm := []byte{0x02, 0x01, 0xD0, 0x11} // PD=ESM, PTI=1, PDN Conn Req, type=initial/IPv4
	b = append(b, 0x00, byte(len(esm)))
	b = append(b, esm...)

	return b
}

func buildAuthResponse(res []byte) []byte {
	b := []byte{
		emm.PDEPSMobilityMgmt | (emm.SecurityHeaderPlain << 4), // 0x07
		emm.MsgAuthenticationResponse,                           // 0x53
		byte(len(res)),
	}
	b = append(b, res...)
	return b
}

// buildSecurityModeComplete builds a Security Mode Complete with null integrity (EIA0).
// Header type 0x03 = integrity-protected with new EPS security context.
func (ue *UE) buildSecurityModeComplete() []byte {
	inner := []byte{
		emm.PDEPSMobilityMgmt | (emm.SecurityHeaderPlain << 4), // 0x07
		emm.MsgSecurityModeComplete,                             // 0x5E
	}
	return buildSecureHeader(emm.SecurityHeaderNewEPSSecurityCtx, ue.ulSeq, inner)
}

// buildAttachComplete builds an Attach Complete with null integrity (EIA0).
// Header type 0x02 = integrity-protected + ciphered (EEA0 = null cipher).
func (ue *UE) buildAttachComplete() []byte {
	inner := []byte{
		emm.PDEPSMobilityMgmt | (emm.SecurityHeaderPlain << 4), // 0x07
		emm.MsgAttachComplete,                                   // 0x43
		// ESM container: empty (no PDN bearer in Phase 1)
		0x02, 0x01, 0x00, // ESM header: PD=2, PTI=0, (bearer ID=0)
	}
	// Wrap in security header type 0x02 (integrity + cipher). With EIA0+EEA0, MAC=0 and no ciphering.
	return buildSecureHeader(emm.SecurityHeaderIntegrityAndCipher, ue.ulSeq, inner)
}

// buildSecureHeader wraps a plain NAS message in a NAS security header.
// With EIA0, MAC is always 0x00000000 (null integrity).
func buildSecureHeader(hdrType uint8, seq uint8, inner []byte) []byte {
	b := make([]byte, 0, 7+len(inner))
	b = append(b, (hdrType<<4)|emm.PDEPSMobilityMgmt) // sec header type + EMM PD
	b = append(b, 0x00, 0x00, 0x00, 0x00)              // MAC = zero (EIA0)
	b = append(b, seq)                                  // NAS sequence number
	b = append(b, inner...)
	return b
}

// ── IE extraction helpers ────────────────────────────────────────────────────

func extractNASFromIEs(ieList []pdu.ProtocolIE) []byte {
	for _, ie := range ieList {
		if ie.ID == pdu.IENAS_PDU {
			nas, _ := ies.DecodeNASPDU(ie.Value)
			return nas
		}
	}
	return nil
}

func extractMMEUEIDFromIEs(ieList []pdu.ProtocolIE) uint32 {
	for _, ie := range ieList {
		if ie.ID == pdu.IEMMEUES1APID {
			id, _ := ies.DecodeMMEUEApID(ie.Value)
			return id
		}
	}
	return 0
}

// encodeStressorERABSetupList encodes an E-RABSetupListCtxtSURes with one item
// using the given eNB S1-U GTP-U IPv4 address and per-UE TEID.
func encodeStressorERABSetupList(enbIP []byte, teid uint32) []byte {
	// Item body: E-RABSetupItemCtxtSURes SEQUENCE (APER)
	w := aper.NewBitWriter()
	// extension marker = 0
	w.WriteBit(0)
	// optional iE-Extensions absent
	w.WriteBit(0)
	// E-RAB-ID (0..15) = 5
	_ = aper.EncodeConstrainedWholeNumber(w, 5, 0, 15)
	// transportLayerAddress BIT STRING (1..160,...): ext=0, length=32, then 4 IP bytes
	w.WriteBit(0) // no extension
	_ = aper.EncodeConstrainedWholeNumber(w, 32, 1, 160)
	w.AlignToByte()
	ip := enbIP
	if len(ip) != 4 {
		ip = []byte{127, 0, 0, 1}
	}
	w.WriteOctets(ip)
	// GTP-TEID OCTET STRING (SIZE 4): fixed-length, no length prefix
	w.AlignToByte()
	w.WriteOctets([]byte{byte(teid >> 24), byte(teid >> 16), byte(teid >> 8), byte(teid)})

	itemBody := w.Bytes()

	// Wrap in inner IE container (IE 50 = IEERABSetupItemCtxtSURes)
	innerContainer := pdu.EncodeIEContainer([]pdu.ProtocolIE{
		{ID: pdu.IEERABSetupItemCtxtSURes, Criticality: aper.CriticalityIgnore, Value: itemBody},
	})
	// Strip the 2-byte count prefix that EncodeIEContainer prepends.
	if len(innerContainer) >= 2 {
		innerContainer = innerContainer[2:]
	}

	// Outer: SEQUENCE OF (count=1, constrained 1..256)
	ow := aper.NewBitWriter()
	_ = aper.EncodeConstrainedWholeNumber(ow, 1, 1, 256)
	ow.AlignToByte()
	ow.WriteOctets(innerContainer)
	return ow.Bytes()
}

// ── IMSI arithmetic ──────────────────────────────────────────────────────────

func imsiAdd(base string, offset int) string {
	// Parse base as a number, add offset, format with leading zeros
	var n uint64
	for _, c := range base {
		n = n*10 + uint64(c-'0')
	}
	n += uint64(offset)

	// Encode back as decimal with same number of digits as base
	out := make([]byte, len(base))
	for i := len(out) - 1; i >= 0; i-- {
		out[i] = byte('0' + n%10)
		n /= 10
	}
	return string(out)
}

