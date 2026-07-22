// Package s13 implements the wire format and policy primitives for the 3GPP
// S13 Equipment Identity Register interface (TS 29.272 clauses 7.2.19/20).
package s13

import (
	"fmt"
	"strings"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/fiorix/go-diameter/v4/diam/avp"
	"github.com/fiorix/go-diameter/v4/diam/datatype"

	"github.com/vectorcore/mme/internal/config"
)

const (
	ApplicationID uint32 = 16777252
	CommandCode   uint32 = 324
	VendorID      uint32 = 10415
)

// Status is the Equipment-Status AVP enumeration from TS 29.272 §7.3.51.
type Status uint32

const (
	Whitelisted Status = 0
	Blacklisted Status = 1
	Greylisted  Status = 2
)

func (s Status) String() string {
	switch s {
	case Whitelisted:
		return "whitelisted"
	case Blacklisted:
		return "blacklisted"
	case Greylisted:
		return "greylisted"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}

// CalculateIMEICheckDigit returns the IMEI-specific Luhn digit for a 14-digit
// base. Identities are deliberately strings: numeric conversion would lose a
// leading zero.
func CalculateIMEICheckDigit(base14 string) (byte, error) {
	if len(base14) != 14 {
		return 0, fmt.Errorf("IMEI base must contain 14 digits")
	}
	sum := 0
	for i := 0; i < len(base14); i++ {
		if base14[i] < '0' || base14[i] > '9' {
			return 0, fmt.Errorf("IMEI contains a non-decimal digit")
		}
		d := int(base14[i] - '0')
		if i%2 == 1 {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return byte('0' + (10-sum%10)%10), nil
}

func ValidateIMEI(imei string) error {
	if len(imei) != 15 {
		return fmt.Errorf("IMEI must contain 15 digits")
	}
	check, err := CalculateIMEICheckDigit(imei[:14])
	if err != nil {
		return err
	}
	if imei[14] != check {
		return fmt.Errorf("IMEI has an invalid check digit")
	}
	return nil
}

// IMEISVToIMEI derives the 15-digit EIR lookup identity from a 16-digit
// IMEISV. The final two IMEISV digits are software version, never an IMEI
// check digit.
func IMEISVToIMEI(imeisv string) (string, error) {
	if len(imeisv) != 16 {
		return "", fmt.Errorf("IMEISV must contain 16 digits")
	}
	for i := range imeisv {
		if imeisv[i] < '0' || imeisv[i] > '9' {
			return "", fmt.Errorf("IMEISV contains a non-decimal digit")
		}
	}
	check, err := CalculateIMEICheckDigit(imeisv[:14])
	if err != nil {
		return "", err
	}
	return imeisv[:14] + string(check), nil
}

// NormalizeIdentity returns the valid 15-digit IMEI used by S13 and an
// optional two-digit software version. A directly supplied IMEI is preserved;
// an IMEISV is converted using its 14-digit body and calculated Luhn digit.
func NormalizeIdentity(identity string) (imei, softwareVersion string, err error) {
	if len(identity) == 16 {
		imei, err := IMEISVToIMEI(identity)
		return imei, identity[14:], err
	}
	if len(identity) == 15 {
		return identity, "", ValidateIMEI(identity)
	}
	return "", "", fmt.Errorf("equipment identity must contain a 15-digit IMEI or 16-digit IMEISV")
}

// BuildECR constructs an ME-Identity-Check-Request. Destination-Host is only
// added for an explicitly selected EIR; otherwise common Diameter routing is
// allowed to select an S13-capable peer.
func BuildECR(sessionID, originHost, originRealm, destinationRealm, destinationHost, imsi, identity string) (*diam.Message, error) {
	if sessionID == "" || originHost == "" || originRealm == "" || destinationRealm == "" {
		return nil, fmt.Errorf("s13: session ID and origin/destination realms are required")
	}
	imei, sv, err := NormalizeIdentity(identity)
	if err != nil {
		return nil, fmt.Errorf("s13: invalid equipment identity: %w", err)
	}
	m := diam.NewRequest(CommandCode, ApplicationID, nil)
	m.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String(sessionID))
	m.NewAVP(avp.AuthSessionState, avp.Mbit, 0, datatype.Enumerated(1)) // NO_STATE_MAINTAINED
	m.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity(originHost))
	m.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity(originRealm))
	if destinationHost != "" {
		m.NewAVP(avp.DestinationHost, avp.Mbit, 0, datatype.DiameterIdentity(destinationHost))
	}
	m.NewAVP(avp.DestinationRealm, avp.Mbit, 0, datatype.DiameterIdentity(destinationRealm))
	if imsi != "" {
		m.NewAVP(avp.UserName, avp.Mbit, 0, datatype.UTF8String(imsi))
	}
	terminal := diam.NewAVP(avp.TerminalInformation, avp.Mbit|avp.Vbit, VendorID, &diam.GroupedAVP{AVP: []*diam.AVP{
		diam.NewAVP(avp.IMEI, avp.Vbit, VendorID, datatype.UTF8String(imei)),
	}})
	if sv != "" {
		terminal.Data.(*diam.GroupedAVP).AVP = append(terminal.Data.(*diam.GroupedAVP).AVP,
			diam.NewAVP(avp.SoftwareVersion, avp.Vbit, VendorID, datatype.UTF8String(sv)))
	}
	m.AddAVP(terminal)
	return m, nil
}

// Result is a validated ECA outcome. Verified is false for any Diameter or
// protocol failure, so callers cannot confuse an unavailable EIR with a white
// list decision.
type Result struct {
	Status         Status
	Verified       bool
	DiameterResult uint32
	Err            error
	Allowed        bool
	IMEI           string
	IMEISV         string
}

// DecodeECA validates and decodes an ME-Identity-Check-Answer.
func DecodeECA(m *diam.Message) Result {
	if m == nil {
		return Result{Err: fmt.Errorf("s13: nil ECA")}
	}
	if m.Header.CommandCode != CommandCode || m.Header.ApplicationID != ApplicationID || m.Header.CommandFlags&diam.RequestFlag != 0 {
		return Result{Err: fmt.Errorf("s13: invalid ECA header")}
	}
	resultAVP, err := m.FindAVP(avp.ResultCode, 0)
	if err != nil || resultAVP == nil {
		return Result{Err: fmt.Errorf("s13: ECA missing Result-Code")}
	}
	resultCode, ok := resultAVP.Data.(datatype.Unsigned32)
	if !ok {
		return Result{Err: fmt.Errorf("s13: ECA invalid Result-Code")}
	}
	r := Result{DiameterResult: uint32(resultCode)}
	if r.DiameterResult < 2000 || r.DiameterResult >= 3000 {
		r.Err = fmt.Errorf("s13: ECA result code %d", r.DiameterResult)
		return r
	}
	statusAVP, err := m.FindAVP(avp.EquipmentStatus, VendorID)
	if err != nil || statusAVP == nil {
		r.Err = fmt.Errorf("s13: ECA missing Equipment-Status")
		return r
	}
	status, ok := statusAVP.Data.(datatype.Enumerated)
	if !ok {
		r.Err = fmt.Errorf("s13: ECA invalid Equipment-Status")
		return r
	}
	r.Status = Status(status)
	if r.Status != Whitelisted && r.Status != Blacklisted && r.Status != Greylisted {
		r.Err = fmt.Errorf("s13: unsupported Equipment-Status %d", status)
		return r
	}
	r.Verified = true
	return r
}

// Allow applies the configured status and EIR-availability policies.
func Allow(cfg config.S13Config, result Result) bool {
	if !result.Verified {
		return cfg.FailurePolicy == "allow"
	}
	var policy string
	switch result.Status {
	case Whitelisted:
		policy = cfg.WhitelistPolicy
	case Blacklisted:
		policy = cfg.BlacklistPolicy
	case Greylisted:
		policy = cfg.GreylistPolicy
	default:
		policy = "reject"
	}
	return strings.EqualFold(policy, "allow")
}

// MaskIMEI returns the only equipment identifier permitted at INFO/WARN.
func MaskIMEI(imei string) string {
	if ValidateIMEI(imei) != nil {
		return "<invalid-imei>"
	}
	return imei[:6] + strings.Repeat("*", 6) + imei[len(imei)-3:]
}
