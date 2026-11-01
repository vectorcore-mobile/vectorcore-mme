// Package sgd contains the SGd Diameter wire codec. It deliberately has no
// CP/RP or UE state: those belong to the transport-neutral SMS service.
package sgd

import (
	"fmt"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/fiorix/go-diameter/v4/diam/avp"
	"github.com/fiorix/go-diameter/v4/diam/datatype"
	"github.com/fiorix/go-diameter/v4/diam/dict"

	"github.com/vectorcore/mme/internal/config"
)

const (
	ApplicationID uint32 = 16777313
	VendorID      uint32 = 10415

	CommandMOForwardShortMessage uint32 = 8388645 // OFR/OFA
	CommandMTForwardShortMessage uint32 = 8388646 // TFR/TFA
	CommandAlertServiceCentre    uint32 = 8388648 // ALR/ALA

	avpUserIdentifier     uint32 = 3102
	avpMSISDN             uint32 = 701
	avpSCAddress          uint32 = 3300
	avpSMRPUI             uint32 = 3301
	avpSMSMICorrelationID uint32 = 3324
	avpMMENumberForMTSMS  uint32 = 1645

	avpSMDeliveryFailureCause           uint32 = 3303
	avpSMEnumeratedDeliveryFailureCause uint32 = 3304
	avpSMDiagnosticInfo                 uint32 = 3305
	avpAbsentUserDiagnosticSM           uint32 = 3322
)

const maxSMRPUI = 200

type MORequest struct {
	SessionID         string
	OriginHost        string
	OriginRealm       string
	DestinationHost   string
	DestinationRealm  string
	IMSI              string
	MSISDN            string // retained for service correlation; not an AVP label
	SCAddress         string
	SCAddressEncoding string
	SMRPUI            []byte
}

type MTRequest struct {
	SessionID     string
	IMSI          string
	SCAddress     []byte // standard TBCD form, not a display string
	SMRPUI        []byte
	CorrelationID []byte
	MMENumber     []byte
}

type MOAnswer struct {
	ResultCode uint32
	SMRPUI     []byte
}

type AlertRequest struct {
	SessionID         string
	OriginHost        string
	OriginRealm       string
	DestinationHost   string
	DestinationRealm  string
	IMSI              string
	MSISDN            string
	SCAddress         string
	SCAddressEncoding string
}

func DecodeOFA(m *diam.Message) (*MOAnswer, error) {
	if m == nil || m.Header.ApplicationID != ApplicationID || m.Header.CommandCode != CommandMOForwardShortMessage || m.Header.CommandFlags&diam.RequestFlag != 0 {
		return nil, fmt.Errorf("sgd: invalid OFA header")
	}
	a := findAVP(m, avp.ResultCode, 0)
	if a == nil {
		return nil, fmt.Errorf("sgd: OFA missing Result-Code")
	}
	code, ok := a.Data.(datatype.Unsigned32)
	if !ok {
		return nil, fmt.Errorf("sgd: invalid OFA Result-Code")
	}
	out := &MOAnswer{ResultCode: uint32(code)}
	if rp := findAVP(m, avpSMRPUI, VendorID); rp != nil {
		if v, ok := rp.Data.(datatype.OctetString); ok {
			out.SMRPUI = append([]byte(nil), v...)
		}
	}
	return out, nil
}

// BuildOFR builds the standards-defined MO-Forward-Short-Message-Request.
// Destination-Host is omitted for relay/DRA selection.
func BuildOFR(req MORequest) (*diam.Message, error) {
	if req.SessionID == "" || req.OriginHost == "" || req.OriginRealm == "" || req.DestinationRealm == "" || req.IMSI == "" {
		return nil, fmt.Errorf("sgd: missing mandatory OFR routing or subscriber field")
	}
	if len(req.SMRPUI) == 0 || len(req.SMRPUI) > maxSMRPUI {
		return nil, fmt.Errorf("sgd: SM-RP-UI length must be 1..%d octets", maxSMRPUI)
	}
	sc, err := config.EncodeSGdSCAddress(req.SCAddress, req.SCAddressEncoding)
	if err != nil {
		return nil, fmt.Errorf("sgd: SC-Address: %w", err)
	}
	m := diam.NewRequest(CommandMOForwardShortMessage, ApplicationID, dict.Default)
	m.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String(req.SessionID))
	m.NewAVP(avp.AuthSessionState, avp.Mbit, 0, datatype.Enumerated(1))
	m.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity(req.OriginHost))
	m.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity(req.OriginRealm))
	if req.DestinationHost != "" {
		m.NewAVP(avp.DestinationHost, avp.Mbit, 0, datatype.DiameterIdentity(req.DestinationHost))
	}
	m.NewAVP(avp.DestinationRealm, avp.Mbit, 0, datatype.DiameterIdentity(req.DestinationRealm))
	m.NewAVP(avpSCAddress, avp.Vbit|avp.Mbit, VendorID, datatype.OctetString(sc))
	m.NewAVP(avpUserIdentifier, avp.Vbit|avp.Mbit, VendorID, &diam.GroupedAVP{AVP: []*diam.AVP{
		diam.NewAVP(avp.UserName, avp.Mbit, 0, datatype.UTF8String(req.IMSI)),
	}})
	if req.MSISDN != "" {
		msisdn, err := encodeMSISDN(req.MSISDN)
		if err != nil {
			return nil, fmt.Errorf("sgd: MSISDN: %w", err)
		}
		m.NewAVP(avpMSISDN, avp.Vbit|avp.Mbit, VendorID, datatype.OctetString(msisdn))
	}
	m.NewAVP(avpSMRPUI, avp.Vbit|avp.Mbit, VendorID, datatype.OctetString(req.SMRPUI))
	return m, nil
}

// BuildALR creates the deployed SGd Alert-Service-Centre request. The
// standard release places this procedure on S6c; the paired SMSC accepts it
// on SGd, so the adapter keeps the compatibility isolated here.
func BuildALR(req AlertRequest) (*diam.Message, error) {
	if req.SessionID == "" || req.OriginHost == "" || req.OriginRealm == "" || req.DestinationRealm == "" || req.IMSI == "" {
		return nil, fmt.Errorf("sgd: missing mandatory ALR fields")
	}
	sc, err := config.EncodeSGdSCAddress(req.SCAddress, req.SCAddressEncoding)
	if err != nil {
		return nil, fmt.Errorf("sgd: ALR SC-Address: %w", err)
	}
	m := diam.NewRequest(CommandAlertServiceCentre, ApplicationID, dict.Default)
	m.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String(req.SessionID))
	m.NewAVP(avp.AuthSessionState, avp.Mbit, 0, datatype.Enumerated(1))
	m.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity(req.OriginHost))
	m.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity(req.OriginRealm))
	if req.DestinationHost != "" {
		m.NewAVP(avp.DestinationHost, avp.Mbit, 0, datatype.DiameterIdentity(req.DestinationHost))
	}
	m.NewAVP(avp.DestinationRealm, avp.Mbit, 0, datatype.DiameterIdentity(req.DestinationRealm))
	m.NewAVP(avp.UserName, avp.Mbit, 0, datatype.UTF8String(req.IMSI))
	if req.MSISDN != "" {
		msisdn, err := encodeMSISDN(req.MSISDN)
		if err != nil {
			return nil, fmt.Errorf("sgd: ALR MSISDN: %w", err)
		}
		m.NewAVP(avpMSISDN, avp.Vbit|avp.Mbit, VendorID, datatype.OctetString(msisdn))
	}
	m.NewAVP(avpSCAddress, avp.Vbit|avp.Mbit, VendorID, datatype.OctetString(sc))
	return m, nil
}

// encodeMSISDN encodes an E.164 number for the SGd MSISDN AVP (code 701).
// TS 29.338 takes MSISDN from TS 29.329 §6.3.2: plain TBCD digits (first
// digit in the low nibble, F filler for an odd count) with no length octet
// and no TON/NPI octet. A paired SMSC must decode it the same way
// (vectorcore-smsc: smsc.sgd_msisdn_encoding: tbcd, its default).
func encodeMSISDN(value string) ([]byte, error) {
	return config.EncodeTBCD(value)
}

func DecodeALA(m *diam.Message) (uint32, error) {
	if m == nil || m.Header.ApplicationID != ApplicationID || m.Header.CommandCode != CommandAlertServiceCentre || m.Header.CommandFlags&diam.RequestFlag != 0 {
		return 0, fmt.Errorf("sgd: invalid ALA header")
	}
	a := findAVP(m, avp.ResultCode, 0)
	if a == nil {
		return 0, fmt.Errorf("sgd: ALA missing Result-Code")
	}
	result, ok := a.Data.(datatype.Unsigned32)
	if !ok {
		return 0, fmt.Errorf("sgd: invalid ALA Result-Code")
	}
	return uint32(result), nil
}

// DecodeTFR validates only the SGd envelope and preserves the SM-RP-UI
// byte-for-byte for the NAS SMS layer.
func DecodeTFR(m *diam.Message) (*MTRequest, error) {
	if m == nil || m.Header.ApplicationID != ApplicationID || m.Header.CommandCode != CommandMTForwardShortMessage || m.Header.CommandFlags&diam.RequestFlag == 0 {
		return nil, fmt.Errorf("sgd: invalid TFR header")
	}
	get := func(code, vendor uint32) (*diam.AVP, error) {
		a := findAVP(m, code, vendor)
		if a == nil {
			return nil, fmt.Errorf("sgd: TFR missing AVP %d", code)
		}
		return a, nil
	}
	sid, err := get(avp.SessionID, 0)
	if err != nil {
		return nil, err
	}
	user, err := get(avp.UserName, 0)
	if err != nil {
		return nil, err
	}
	sc, err := get(avpSCAddress, VendorID)
	if err != nil {
		return nil, err
	}
	rp, err := get(avpSMRPUI, VendorID)
	if err != nil {
		return nil, err
	}
	value, ok := rp.Data.(datatype.OctetString)
	if !ok || len(value) == 0 || len(value) > maxSMRPUI {
		return nil, fmt.Errorf("sgd: invalid SM-RP-UI")
	}
	sessionID, ok := sid.Data.(datatype.UTF8String)
	if !ok || sessionID == "" {
		return nil, fmt.Errorf("sgd: invalid Session-Id")
	}
	imsi, ok := user.Data.(datatype.UTF8String)
	if !ok || imsi == "" {
		return nil, fmt.Errorf("sgd: invalid User-Name")
	}
	scAddress, ok := sc.Data.(datatype.OctetString)
	if !ok || len(scAddress) == 0 {
		return nil, fmt.Errorf("sgd: invalid SC-Address")
	}
	result := &MTRequest{SessionID: string(sessionID), IMSI: string(imsi), SCAddress: append([]byte(nil), []byte(scAddress)...), SMRPUI: append([]byte(nil), []byte(value)...)}
	if a := findAVP(m, avpSMSMICorrelationID, VendorID); a != nil {
		if v, ok := a.Data.(datatype.OctetString); ok {
			result.CorrelationID = append([]byte(nil), v...)
		}
	}
	if a := findAVP(m, avpMMENumberForMTSMS, VendorID); a != nil {
		if v, ok := a.Data.(datatype.OctetString); ok {
			result.MMENumber = append([]byte(nil), v...)
		}
	}
	return result, nil
}

func findAVP(m *diam.Message, code, vendor uint32) *diam.AVP {
	for _, a := range m.AVP {
		if a.Code == code && a.VendorID == vendor {
			return a
		}
	}
	return nil
}

// BuildTFA encodes the MT-Forward-Short-Message-Answer after the shared SMS
// service has finished delivery. It cannot claim delivery before then.
// Failures use Experimental-Result (TS 29.338 §6.3.2.4) with their
// diagnostic AVPs; base Result-Code is kept for success and MME-side faults.
func BuildTFA(req *diam.Message, originHost, originRealm string, outcome MTOutcome) (*diam.Message, error) {
	if req == nil || originHost == "" || originRealm == "" {
		return nil, fmt.Errorf("sgd: missing TFA arguments")
	}
	if (outcome.ResultCode == 0) == (outcome.ExperimentalResultCode == 0) {
		return nil, fmt.Errorf("sgd: TFA needs exactly one of Result-Code or Experimental-Result-Code")
	}
	if len(outcome.SMRPUI) > maxSMRPUI {
		return nil, fmt.Errorf("sgd: SM-RP-UI too long")
	}
	ans := req.Answer(outcome.ResultCode) // 0 adds no Result-Code AVP
	ans.NewAVP(avp.AuthSessionState, avp.Mbit, 0, datatype.Enumerated(1))
	ans.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity(originHost))
	ans.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity(originRealm))
	if outcome.ExperimentalResultCode != 0 {
		ans.NewAVP(avp.ExperimentalResult, avp.Mbit, 0, &diam.GroupedAVP{AVP: []*diam.AVP{
			diam.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(VendorID)),
			diam.NewAVP(avp.ExperimentalResultCode, avp.Mbit, 0, datatype.Unsigned32(outcome.ExperimentalResultCode)),
		}})
	}
	if outcome.AbsentUserDiagnostic != nil {
		ans.NewAVP(avpAbsentUserDiagnosticSM, avp.Vbit|avp.Mbit, VendorID, datatype.Unsigned32(*outcome.AbsentUserDiagnostic))
	}
	if outcome.DeliveryFailureCause != nil {
		children := []*diam.AVP{diam.NewAVP(avpSMEnumeratedDeliveryFailureCause, avp.Vbit|avp.Mbit, VendorID, datatype.Enumerated(int32(*outcome.DeliveryFailureCause)))}
		if len(outcome.DiagnosticInfo) > 0 {
			children = append(children, diam.NewAVP(avpSMDiagnosticInfo, avp.Vbit|avp.Mbit, VendorID, datatype.OctetString(outcome.DiagnosticInfo)))
		}
		ans.NewAVP(avpSMDeliveryFailureCause, avp.Vbit|avp.Mbit, VendorID, &diam.GroupedAVP{AVP: children})
	}
	if len(outcome.SMRPUI) > 0 {
		ans.NewAVP(avpSMRPUI, avp.Vbit, VendorID, datatype.OctetString(outcome.SMRPUI))
	}
	return ans, nil
}
