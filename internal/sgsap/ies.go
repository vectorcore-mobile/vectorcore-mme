package sgsap

import (
	"fmt"
	"strings"

	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/s1ap/ies"
)

// TAI and LAI reuse the existing TS 24.301/24.008 PLMN+TAC / PLMN+LAC 5-octet
// encodings already implemented for NAS (emm.TAI, emm.LAI): the SGsAP value
// parts for both IEs (§9.4.21a, §9.4.11) are defined as exactly that layout.
type TAI = emm.TAI
type LAI = emm.LAI

// EncodePLMN and DecodePLMN reuse the existing TS 24.008 MCC/MNC BCD codec.
func EncodePLMN(mcc, mnc string) ([3]byte, error) {
	b, err := ies.EncodePLMN(mcc, mnc)
	if err != nil {
		return [3]byte{}, err
	}
	var out [3]byte
	copy(out[:], b)
	return out, nil
}

func DecodePLMN(plmn [3]byte) (mcc, mnc string, err error) {
	return ies.DecodePLMN(plmn[:])
}

// --- IMSI (§9.4.6, defined by reference to TS 29.018 §18.4.10) ---

// encodeBCDIdentity packs a digit string using the TS 24.008 mobile identity
// BCD convention shared by the IMSI IE, the Mobile identity IE, and IMEISV:
// digit 1 always sits in the high nibble of octet 1 alongside the type/
// parity bits; every following pair of digits is low-nibble-first, and if
// the total digit count is even, the high nibble of the *last* octet (not
// the first) is filled with 1111.
func encodeBCDIdentity(typeAndParity byte, digits string) []byte {
	n := len(digits)
	odd := n%2 == 1
	out := make([]byte, 0, (n+1)/2+1)
	first := typeAndParity | (digits[0]-'0')<<4
	if odd {
		first |= 0x08
	}
	out = append(out, first)
	for i := 1; i < n; i += 2 {
		lo := digits[i] - '0'
		hi := byte(0x0F)
		if i+1 < n {
			hi = digits[i+1] - '0'
		}
		out = append(out, lo|hi<<4)
	}
	return out
}

// decodeBCDIdentity is the inverse of encodeBCDIdentity: it recovers the
// digit string from octet 1 onward, ignoring the type/parity bits in the low
// nibble of octet 1 (bits 1-4), which the caller has already inspected.
func decodeBCDIdentity(data []byte) (string, error) {
	if len(data) < 1 {
		return "", fmt.Errorf("sgsap: identity IE too short")
	}
	odd := (data[0]>>3)&1 == 1
	digits := make([]byte, 0, 16)
	digits = append(digits, '0'+(data[0]>>4))
	for i := 1; i < len(data); i++ {
		lo := data[i] & 0x0F
		hi := data[i] >> 4
		if odd && i == len(data)-1 && hi == 0x0F {
			break
		}
		if lo != 0x0F {
			digits = append(digits, '0'+lo)
		}
		if hi != 0x0F {
			digits = append(digits, '0'+hi)
		}
	}
	return string(digits), nil
}

// EncodeIMSI encodes the standalone IMSI IE value (type bits fixed to '001').
func EncodeIMSI(imsi string) []byte { return encodeBCDIdentity(0x01, imsi) }

// DecodeIMSI decodes the standalone IMSI IE value.
func DecodeIMSI(v []byte) (string, error) { return decodeBCDIdentity(v) }

// --- IMEISV (§9.4.5, TS 29.018 §18.4.9): 16 BCD digits, no type/parity bits ---

func EncodeIMEISV(imeisv string) ([]byte, error) {
	if len(imeisv) != 16 {
		return nil, fmt.Errorf("sgsap: IMEISV must be 16 digits, got %d", len(imeisv))
	}
	out := make([]byte, 8)
	for i := 0; i < 16; i += 2 {
		out[i/2] = (imeisv[i] - '0') | (imeisv[i+1]-'0')<<4
	}
	return out, nil
}

func DecodeIMEISV(v []byte) (string, error) {
	if len(v) != 8 {
		return "", fmt.Errorf("sgsap: IMEISV IE must be 8 octets, got %d", len(v))
	}
	var b strings.Builder
	for _, o := range v {
		b.WriteByte('0' + o&0x0F)
		b.WriteByte('0' + o>>4)
	}
	return b.String(), nil
}

// --- Mobile identity (§9.4.14, TS 29.018 §18.4.17): IMSI/IMEI/IMEISV/TMSI ---

type MobileIdentityKind uint8

const (
	MobileIdentityNone   MobileIdentityKind = 0x00
	MobileIdentityIMSI   MobileIdentityKind = 0x01
	MobileIdentityIMEI   MobileIdentityKind = 0x02
	MobileIdentityIMEISV MobileIdentityKind = 0x03
	MobileIdentityTMSI   MobileIdentityKind = 0x04
)

// MobileIdentity holds a decoded/to-be-encoded Mobile identity IE value.
// Digits carries the IMSI/IMEI/IMEISV digit string; TMSI carries the 32-bit
// value when Kind is MobileIdentityTMSI.
type MobileIdentity struct {
	Kind   MobileIdentityKind
	Digits string
	TMSI   uint32
}

func EncodeMobileIdentity(m MobileIdentity) []byte {
	if m.Kind == MobileIdentityTMSI {
		out := make([]byte, 5)
		out[0] = 0xF4 // fill(1111) + spare-odd/even(1) + type=100
		out[1] = byte(m.TMSI >> 24)
		out[2] = byte(m.TMSI >> 16)
		out[3] = byte(m.TMSI >> 8)
		out[4] = byte(m.TMSI)
		return out
	}
	return encodeBCDIdentity(byte(m.Kind), m.Digits)
}

func DecodeMobileIdentity(v []byte) (MobileIdentity, error) {
	if len(v) < 1 {
		return MobileIdentity{}, fmt.Errorf("sgsap: mobile identity IE too short")
	}
	kind := MobileIdentityKind(v[0] & 0x07)
	if kind == MobileIdentityTMSI {
		if len(v) != 5 {
			return MobileIdentity{}, fmt.Errorf("sgsap: TMSI mobile identity must be 5 octets, got %d", len(v))
		}
		tmsi := uint32(v[1])<<24 | uint32(v[2])<<16 | uint32(v[3])<<8 | uint32(v[4])
		return MobileIdentity{Kind: kind, TMSI: tmsi}, nil
	}
	digits, err := decodeBCDIdentity(v)
	if err != nil {
		return MobileIdentity{}, err
	}
	return MobileIdentity{Kind: kind, Digits: digits}, nil
}

// --- TMSI (§9.4.20, TS 29.018 §18.4.23): plain 4-octet value ---

func EncodeTMSI(tmsi uint32) []byte {
	return []byte{byte(tmsi >> 24), byte(tmsi >> 16), byte(tmsi >> 8), byte(tmsi)}
}

func DecodeTMSI(v []byte) (uint32, error) {
	if len(v) != 4 {
		return 0, fmt.Errorf("sgsap: TMSI IE must be 4 octets, got %d", len(v))
	}
	return uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3]), nil
}

// --- TMSI status (§9.4.21, TS 29.018 §18.4.24) ---

func EncodeTMSIStatus(valid bool) []byte {
	if valid {
		return []byte{0x01}
	}
	return []byte{0x00}
}

func DecodeTMSIStatus(v []byte) (bool, error) {
	if len(v) != 1 {
		return false, fmt.Errorf("sgsap: TMSI status IE must be 1 octet, got %d", len(v))
	}
	return v[0]&0x01 != 0, nil
}

// --- FQDN-style names (MME name §9.4.13, VLR name §9.4.22) ---
//
// Both are 3GPP "FQDN" label encodings: each label is prefixed by its
// length octet, concatenated with no trailing root (zero-length) label -
// the same convention already used for APN in internal/gtpv2. TS 29.118
// says the MME name value part "shall have" a fixed 55-octet length, but
// real VLR peers (and open5gs's own encoder) send the actual encoded
// length rather than padding, so this codec does the same for
// interoperability.

func encodeFQDNLabels(name string) []byte {
	if name == "" {
		return []byte{0}
	}
	var out []byte
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			label := name[start:i]
			out = append(out, byte(len(label)))
			out = append(out, label...)
			start = i + 1
		}
	}
	return out
}

func decodeFQDNLabels(v []byte) (string, error) {
	var parts []string
	for i := 0; i < len(v); {
		n := int(v[i])
		i++
		if n == 0 {
			break
		}
		if i+n > len(v) {
			return "", fmt.Errorf("sgsap: truncated FQDN label")
		}
		parts = append(parts, string(v[i:i+n]))
		i += n
	}
	return strings.Join(parts, "."), nil
}

func EncodeMMEName(name string) []byte       { return encodeFQDNLabels(name) }
func DecodeMMEName(v []byte) (string, error) { return decodeFQDNLabels(v) }
func EncodeVLRName(name string) []byte       { return encodeFQDNLabels(name) }
func DecodeVLRName(v []byte) (string, error) { return decodeFQDNLabels(v) }

// --- EPS location update type (§9.4.2) ---

type EPSLocationUpdateType uint8

const (
	EPSLocationUpdateTypeIMSIAttach EPSLocationUpdateType = 0x01
	EPSLocationUpdateTypeNormal     EPSLocationUpdateType = 0x02
)

func EncodeEPSLocationUpdateType(t EPSLocationUpdateType) []byte { return []byte{byte(t)} }

func DecodeEPSLocationUpdateType(v []byte) (EPSLocationUpdateType, error) {
	if len(v) != 1 {
		return 0, fmt.Errorf("sgsap: EPS location update type IE must be 1 octet, got %d", len(v))
	}
	return EPSLocationUpdateType(v[0]), nil
}

// --- SGs cause (§9.4.18) ---

type Cause uint8

const (
	CauseNormalUnspecified                     Cause = 0
	CauseIMSIDetachedForEPS                    Cause = 1
	CauseIMSIDetachedForEPSAndNonEPS           Cause = 2
	CauseIMSIUnknown                           Cause = 3
	CauseIMSIDetachedForNonEPS                 Cause = 4
	CauseIMSIImplicitlyDetachedForNonEPS       Cause = 5
	CauseUEUnreachable                         Cause = 6
	CauseMessageNotCompatibleWithProtocolState Cause = 7
	CauseMissingMandatoryIE                    Cause = 8
	CauseInvalidMandatoryInformation           Cause = 9
	CauseConditionalIEError                    Cause = 10
	CauseSemanticallyIncorrectMessage          Cause = 11
	CauseMessageUnknown                        Cause = 12
	CauseMTCSFBCallRejectedByUser              Cause = 13
	CauseUETemporarilyUnreachable              Cause = 14
)

func EncodeSGsCause(c Cause) []byte { return []byte{byte(c)} }

func DecodeSGsCause(v []byte) (Cause, error) {
	if len(v) != 1 {
		return 0, fmt.Errorf("sgsap: SGs cause IE must be 1 octet, got %d", len(v))
	}
	return Cause(v[0]), nil
}

// --- Reject cause (§9.4.16, value part is the TS 24.008 EMM/GMM reject
// cause octet, e.g. #9 UE identity cannot be derived, #13 roaming not
// allowed in this LA, #17 network failure) ---

func EncodeRejectCause(cause uint8) []byte { return []byte{cause} }

func DecodeRejectCause(v []byte) (uint8, error) {
	if len(v) != 1 {
		return 0, fmt.Errorf("sgsap: reject cause IE must be 1 octet, got %d", len(v))
	}
	return v[0], nil
}

// --- IMSI detach from EPS/non-EPS service type (§9.4.7, §9.4.8) ---

type EPSDetachType uint8

const (
	EPSDetachNetworkInitiated EPSDetachType = 1
	EPSDetachUEInitiated      EPSDetachType = 2
	EPSDetachEPSNotAllowed    EPSDetachType = 3
)

type NonEPSDetachType uint8

const (
	NonEPSDetachExplicitUEInitiated      NonEPSDetachType = 1
	NonEPSDetachCombinedUEInitiated      NonEPSDetachType = 2
	NonEPSDetachImplicitNetworkInitiated NonEPSDetachType = 3
)

func EncodeEPSDetachType(t EPSDetachType) []byte       { return []byte{byte(t)} }
func EncodeNonEPSDetachType(t NonEPSDetachType) []byte { return []byte{byte(t)} }

// --- NAS message container (§9.4.15): opaque CP-DATA/CP-ACK/CP-ERROR bytes ---

func EncodeNASMessageContainer(nas []byte) []byte { return append([]byte(nil), nas...) }
func DecodeNASMessageContainer(v []byte) []byte   { return append([]byte(nil), v...) }

// --- Service indicator (§9.4.17) ---

type ServiceIndicator uint8

const (
	ServiceIndicatorCSCall ServiceIndicator = 0x01
	ServiceIndicatorSMS    ServiceIndicator = 0x02
)

func EncodeServiceIndicator(s ServiceIndicator) []byte { return []byte{byte(s)} }

func DecodeServiceIndicator(v []byte) (ServiceIndicator, error) {
	if len(v) != 1 {
		return 0, fmt.Errorf("sgsap: service indicator IE must be 1 octet, got %d", len(v))
	}
	return ServiceIndicator(v[0]), nil
}

// --- UE EMM mode (§9.4.21c) ---

type UEEMMMode uint8

const (
	UEEMMModeIdle      UEEMMMode = 0x00
	UEEMMModeConnected UEEMMMode = 0x01
)

func EncodeUEEMMMode(m UEEMMMode) []byte { return []byte{byte(m)} }

func DecodeUEEMMMode(v []byte) (UEEMMMode, error) {
	if len(v) != 1 {
		return 0, fmt.Errorf("sgsap: UE EMM mode IE must be 1 octet, got %d", len(v))
	}
	return UEEMMMode(v[0]), nil
}

// --- E-UTRAN Cell Global Identity (§9.4.3a, layout per TS 29.274 §8.21.5:
// PLMN(3) + 4 spare bits + 28-bit E-UTRAN Cell Identity) ---

type ECGI struct {
	PLMN [3]byte
	ECI  uint32 // 28-bit E-UTRAN Cell Identity
}

func EncodeECGI(e ECGI) []byte {
	out := make([]byte, 7)
	copy(out[:3], e.PLMN[:])
	out[3] = byte(e.ECI >> 24 & 0x0F)
	out[4] = byte(e.ECI >> 16)
	out[5] = byte(e.ECI >> 8)
	out[6] = byte(e.ECI)
	return out
}

func DecodeECGI(v []byte) (ECGI, error) {
	if len(v) != 7 {
		return ECGI{}, fmt.Errorf("sgsap: E-CGI IE must be 7 octets, got %d", len(v))
	}
	var e ECGI
	copy(e.PLMN[:], v[:3])
	e.ECI = uint32(v[3]&0x0F)<<24 | uint32(v[4])<<16 | uint32(v[5])<<8 | uint32(v[6])
	return e, nil
}

// --- UE Time Zone (§9.4.21b, TS 24.008 §10.5.3.8: single octet, same
// half-quarter-hour-with-sign encoding used elsewhere for NITZ) ---

func EncodeUETimeZone(raw byte) []byte { return []byte{raw} }

func DecodeUETimeZone(v []byte) (byte, error) {
	if len(v) != 1 {
		return 0, fmt.Errorf("sgsap: UE Time Zone IE must be 1 octet, got %d", len(v))
	}
	return v[0], nil
}
