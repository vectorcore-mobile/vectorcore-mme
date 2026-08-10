package emm

import (
	"encoding/binary"
	"fmt"
	"time"
	"unicode/utf16"
)

// GUTI represents the Globally Unique Temporary Identifier.
// Encoded as 10 bytes: PLMN(3) + MMEGI(2) + MMEC(1) + M-TMSI(4)
type GUTI struct {
	PLMN  [3]byte
	MMEGI uint16
	MMEC  uint8
	MTMSI uint32
}

// Encode returns the 12-byte GUTI LV field (length byte + 11-byte value).
// The caller is responsible for prepending the IEI (0x50) separately.
func (g *GUTI) Encode() []byte {
	b := make([]byte, 12) // length(1) + value(11)
	b[0] = 0x0B           // length = 11
	b[1] = 0xF6           // identity type: GUTI (0x6), even parity (bit3=0), filler=0xF
	copy(b[2:5], g.PLMN[:])
	binary.BigEndian.PutUint16(b[5:], g.MMEGI)
	b[7] = g.MMEC
	binary.BigEndian.PutUint32(b[8:], g.MTMSI)
	return b
}

// String returns a human-readable GUTI representation.
func (g *GUTI) String() string {
	return fmt.Sprintf("GUTI{PLMN=%02X%02X%02X,MMEGI=%d,MMEC=%d,MTMSI=%08X}",
		g.PLMN[0], g.PLMN[1], g.PLMN[2], g.MMEGI, g.MMEC, g.MTMSI)
}

// TAI represents a Tracking Area Identity.
type TAI struct {
	PLMN [3]byte
	TAC  uint16
}

// LAI is the non-broadcast Location Area Identity assigned by the MME for a
// successful combined TAU with SMS in MME.  It is encoded as the TS 24.008
// five-octet PLMN/LAC value carried by the TS 24.301 TAU Accept IE.
type LAI struct {
	PLMN [3]byte
	LAC  uint16
}

// Encode returns the five-octet Location Area Identity value.
func (l *LAI) Encode() []byte {
	b := make([]byte, 5)
	copy(b[:3], l.PLMN[:])
	binary.BigEndian.PutUint16(b[3:], l.LAC)
	return b
}

// DecodeLAI decodes a five-octet Location Area Identity value.
func DecodeLAI(data []byte) (LAI, error) {
	if len(data) != 5 {
		return LAI{}, fmt.Errorf("emm: LAI length %d, want 5", len(data))
	}
	var l LAI
	copy(l.PLMN[:], data[:3])
	l.LAC = binary.BigEndian.Uint16(data[3:5])
	return l, nil
}

// EncodeMSIdentityTMSI encodes the value part of the "MS identity" IE
// (TS 24.301 §9.9.2.3, referencing TS 24.008 §10.5.1.4) as a TMSI-type
// mobile identity: fill nibble (1111), a zero spare/odd-even bit, identity
// type 100 (TMSI), then the 4-octet TMSI value big-endian. This is the same
// byte layout SGsAP's own Mobile Identity IE (TS 29.118 §9.4.14) uses for
// the identical purpose - confirmed against both internal/sgsap's own
// EncodeMobileIdentity and open5gs's emm-build.c, which independently agree
// on 0xF4 as octet 1.
func EncodeMSIdentityTMSI(tmsi uint32) []byte {
	b := make([]byte, 5)
	b[0] = 0xf4
	binary.BigEndian.PutUint32(b[1:], tmsi)
	return b
}

// DecodeMSIdentityTMSI is the inverse of EncodeMSIdentityTMSI. The MME only
// ever sends this IE (relaying a VLR-assigned TMSI); this decoder exists to
// round-trip test the encoder.
func DecodeMSIdentityTMSI(v []byte) (uint32, error) {
	if len(v) != 5 || v[0]&0x07 != 0x04 {
		return 0, fmt.Errorf("emm: MS identity is not a 5-octet TMSI-type mobile identity")
	}
	return binary.BigEndian.Uint32(v[1:]), nil
}

// EPSNetworkFeatureSupport represents TS 24.301 §9.9.3.12A.
type EPSNetworkFeatureSupport struct {
	IMSVoiceOverPSSessionInS1Mode bool
}

// EncodeEPSNetworkFeatureSupport encodes IEI 0x64. The first feature octet uses
// bit 1 for IMS voice over PS session in S1 mode; spare bits remain zero.
func EncodeEPSNetworkFeatureSupport(s EPSNetworkFeatureSupport) []byte {
	value := byte(0)
	if s.IMSVoiceOverPSSessionInS1Mode {
		value |= 0x01
	}
	return []byte{0x64, 0x01, value}
}

// Encode returns the 5-byte TAI encoding.
func (t *TAI) Encode() []byte {
	b := make([]byte, 5)
	copy(b[:3], t.PLMN[:])
	binary.BigEndian.PutUint16(b[3:], t.TAC)
	return b
}

// DecodeTAI decodes a TAI from 5 bytes.
func DecodeTAI(data []byte) (TAI, error) {
	if len(data) < 5 {
		return TAI{}, fmt.Errorf("emm: TAI too short: %d bytes", len(data))
	}
	var t TAI
	copy(t.PLMN[:], data[:3])
	t.TAC = binary.BigEndian.Uint16(data[3:5])
	return t, nil
}

// EPSMobileIdentityIMSI encodes an IMSI as an EPS Mobile Identity IE.
func EPSMobileIdentityIMSI(imsi string) []byte {
	// Type = IMSI (0x01); encoding: digit pairs BCD
	n := len(imsi)
	odd := n%2 == 1
	b := make([]byte, 0, (n+1)/2+1)

	first := byte(0x01) // identity type = IMSI
	if odd {
		first |= 0x08 // odd flag
		first |= byte(imsi[0]-'0') << 4
	} else {
		first |= byte(0xF0) // even: fill digit = 0xF
	}
	b = append(b, first)

	start := 1
	if !odd {
		start = 0
	}
	for i := start; i < n-1; i += 2 {
		b = append(b, (imsi[i+1]-'0')<<4|(imsi[i]-'0'))
	}
	return b
}

// UENetworkCapability represents UE security capabilities.
type UENetworkCapability struct {
	EIA [8]bool // EPS integrity algorithms 0-7
	EEA [8]bool // EPS encryption algorithms 0-7
	LPP bool    // LTE Positioning Protocol support (TS 24.301 §9.9.3.34, octet 7 bit 4)
}

// DecodeUENetworkCapability decodes UE network capability IE. Octets beyond
// EEA/EIA (octet 5 onward) are optional per TS 24.301 §9.9.3.34: a UE may
// omit trailing octets whose bits are all 0, so any capability bit not
// present in data defaults to false rather than being an error.
func DecodeUENetworkCapability(data []byte) (UENetworkCapability, error) {
	if len(data) < 2 {
		return UENetworkCapability{}, fmt.Errorf("emm: UE network capability too short: %d", len(data))
	}
	var cap UENetworkCapability
	for i := 0; i < 8; i++ {
		cap.EEA[i] = (data[0]>>(7-i))&1 == 1
		cap.EIA[i] = (data[1]>>(7-i))&1 == 1
	}
	if len(data) >= 5 {
		cap.LPP = data[4]&0x08 != 0 // octet 7 bit 4
	}
	return cap, nil
}

// SupportedAlgorithmNames returns the names of supported algorithms in priority order.
func (c *UENetworkCapability) SupportedIntegrityAlgs() []string {
	var algs []string
	names := []string{"EIA0", "EIA1", "EIA2", "EIA3", "EIA4", "EIA5", "EIA6", "EIA7"}
	for i, name := range names {
		if c.EIA[i] {
			algs = append(algs, name)
		}
	}
	return algs
}

func (c *UENetworkCapability) SupportedCipheringAlgs() []string {
	var algs []string
	names := []string{"EEA0", "EEA1", "EEA2", "EEA3", "EEA4", "EEA5", "EEA6", "EEA7"}
	for i, name := range names {
		if c.EEA[i] {
			algs = append(algs, name)
		}
	}
	return algs
}

// EncodeFullNetworkName encodes a Full Network Name IE (IEI 0x43, TS 24.008 §10.5.3.5a).
// Returns nil if name is empty.
func EncodeFullNetworkName(name string) []byte {
	return EncodeFullNetworkNameWithEncoding(name, "gsm7", false)
}

// EncodeFullNetworkNameWithEncoding encodes a Full Network Name IE using "gsm7" or "ucs2".
func EncodeFullNetworkNameWithEncoding(name, encoding string, addCountryInitials bool) []byte {
	if name == "" {
		return nil
	}
	return encodeNetworkNameIE(0x43, name, encoding, addCountryInitials)
}

// EncodeShortNetworkName encodes a Short Network Name IE (IEI 0x45, TS 24.008 §10.5.3.5a).
// Returns nil if name is empty.
func EncodeShortNetworkName(name string) []byte {
	return EncodeShortNetworkNameWithEncoding(name, "gsm7", false)
}

// EncodeShortNetworkNameWithEncoding encodes a Short Network Name IE using "gsm7" or "ucs2".
func EncodeShortNetworkNameWithEncoding(name, encoding string, addCountryInitials bool) []byte {
	if name == "" {
		return nil
	}
	return encodeNetworkNameIE(0x45, name, encoding, addCountryInitials)
}

func encodeNetworkNameIE(iei byte, name, encoding string, addCountryInitials bool) []byte {
	coding := byte(0x80) // ext=1, GSM 7-bit default alphabet, CI=0.
	payload := packGSM7(name)
	spareBits := gsm7SpareBits(len([]rune(name)))
	if encoding == "ucs2" {
		coding = 0x90 // ext=1, UCS2, CI=0.
		payload = encodeUCS2(name)
		spareBits = 0
	}
	if addCountryInitials {
		coding |= 0x08
	}
	coding |= byte(spareBits & 0x07)
	b := make([]byte, 3+len(payload))
	b[0] = iei
	b[1] = byte(1 + len(payload)) // coding byte + encoded name bytes
	b[2] = coding
	copy(b[3:], payload)
	return b
}

func gsm7SpareBits(septets int) int {
	if septets == 0 {
		return 0
	}
	return (8 - ((septets * 7) % 8)) % 8
}

func packGSM7(s string) []byte {
	if s == "" {
		return nil
	}
	septets := make([]byte, 0, len(s))
	for _, r := range s {
		septets = append(septets, gsm7Codepoint(r))
	}
	out := make([]byte, (len(septets)*7+7)/8)
	bit := 0
	for _, septet := range septets {
		v := septet & 0x7f
		for i := 0; i < 7; i++ {
			if v&(1<<i) != 0 {
				out[bit/8] |= 1 << uint(bit%8)
			}
			bit++
		}
	}
	return out
}

func gsm7Codepoint(r rune) byte {
	switch r {
	case '\n':
		return 0x0a
	case '\r':
		return 0x0d
	case '@':
		return 0x00
	case '£':
		return 0x01
	case '$':
		return 0x02
	case '¥':
		return 0x03
	case 'è':
		return 0x04
	case 'é':
		return 0x05
	case 'ù':
		return 0x06
	case 'ì':
		return 0x07
	case 'ò':
		return 0x08
	case 'Ç':
		return 0x09
	case 'Ø':
		return 0x0b
	case 'ø':
		return 0x0c
	case 'Å':
		return 0x0e
	case 'å':
		return 0x0f
	case 'Δ':
		return 0x10
	case '_':
		return 0x11
	case 'Φ':
		return 0x12
	case 'Γ':
		return 0x13
	case 'Λ':
		return 0x14
	case 'Ω':
		return 0x15
	case 'Π':
		return 0x16
	case 'Ψ':
		return 0x17
	case 'Σ':
		return 0x18
	case 'Θ':
		return 0x19
	case 'Ξ':
		return 0x1a
	case 'Æ':
		return 0x1c
	case 'æ':
		return 0x1d
	case 'ß':
		return 0x1e
	case 'É':
		return 0x1f
	case 'Ä':
		return 0x5b
	case 'Ö':
		return 0x5c
	case 'Ñ':
		return 0x5d
	case 'Ü':
		return 0x5e
	case '§':
		return 0x5f
	case '¿':
		return 0x60
	case 'ä':
		return 0x7b
	case 'ö':
		return 0x7c
	case 'ñ':
		return 0x7d
	case 'ü':
		return 0x7e
	case 'à':
		return 0x7f
	}
	if r >= 0x20 && r <= 0x7a && (r < 0x5b || r > 0x60) {
		return byte(r)
	}
	return '?'
}

func encodeUCS2(s string) []byte {
	encoded := utf16.Encode([]rune(s))
	out := make([]byte, len(encoded)*2)
	for i, v := range encoded {
		binary.BigEndian.PutUint16(out[i*2:], v)
	}
	return out
}

// encodeTZByte encodes a timezone offset in units of 15 minutes to the TS 23.040 §9.2.3.11
// single-byte BCD-swapped-nibbles format. The sign is encoded in bit 3 of the first nibble.
func encodeTZByte(offsetMinutes int) byte {
	units := offsetMinutes / 15
	if units < 0 {
		units = -units
	}
	hi := units / 10
	lo := units % 10
	v := byte((lo << 4) | (hi & 0x07))
	if offsetMinutes < 0 {
		v |= 0x08 // sign bit in high nibble bit 3
	}
	return v
}

// EncodeLocalTimeZone encodes a Local Time Zone IE (IEI 0x46, TS 24.301 §9.9.3.29).
func EncodeLocalTimeZone(offsetMinutes int) []byte {
	return []byte{0x46, encodeTZByte(offsetMinutes)}
}

// EncodeUniversalTimeAndLocalTimeZone encodes the Universal Time and Local Time Zone IE
// (IEI 0x47, TS 24.301 §9.9.3.32 / TS 23.040 §9.2.3.11). t should be in UTC.
func EncodeUniversalTimeAndLocalTimeZone(t time.Time, offsetMinutes int) []byte {
	bcd2 := func(v int) byte {
		hi := (v / 10) & 0x0F
		lo := v % 10
		return byte((lo << 4) | hi)
	}
	yr := t.Year() % 100
	b := make([]byte, 8)
	b[0] = 0x47
	b[1] = bcd2(yr)
	b[2] = bcd2(int(t.Month()))
	b[3] = bcd2(t.Day())
	b[4] = bcd2(t.Hour())
	b[5] = bcd2(t.Minute())
	b[6] = bcd2(t.Second())
	b[7] = encodeTZByte(offsetMinutes)
	return b
}

// EncodeDaylightSavingTime encodes a Daylight Saving Time IE (IEI 0x49, TS 24.301 §9.9.3.6a).
// dst: 0=no adjustment, 1=+1h, 2=+2h.
func EncodeDaylightSavingTime(dst uint8) []byte {
	return []byte{0x49, 0x01, dst & 0x03}
}
