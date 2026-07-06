package emm

import (
	"encoding/binary"
	"fmt"
	"time"
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
}

// DecodeUENetworkCapability decodes UE network capability IE.
func DecodeUENetworkCapability(data []byte) (UENetworkCapability, error) {
	if len(data) < 2 {
		return UENetworkCapability{}, fmt.Errorf("emm: UE network capability too short: %d", len(data))
	}
	var cap UENetworkCapability
	for i := 0; i < 8; i++ {
		cap.EEA[i] = (data[0]>>(7-i))&1 == 1
		cap.EIA[i] = (data[1]>>(7-i))&1 == 1
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
	if name == "" {
		return nil
	}
	b := make([]byte, 3+len(name))
	b[0] = 0x43
	b[1] = byte(1 + len(name)) // length: coding byte + name bytes
	b[2] = 0x80                 // coding = GSM 7-bit default alphabet, CI=0, spare=0
	copy(b[3:], name)
	return b
}

// EncodeShortNetworkName encodes a Short Network Name IE (IEI 0x45, TS 24.008 §10.5.3.5a).
// Returns nil if name is empty.
func EncodeShortNetworkName(name string) []byte {
	if name == "" {
		return nil
	}
	b := make([]byte, 3+len(name))
	b[0] = 0x45
	b[1] = byte(1 + len(name))
	b[2] = 0x80
	copy(b[3:], name)
	return b
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
