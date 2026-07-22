// Package sms implements the UE-facing CP and RP wire formats from TS 24.011.
// It has no SGd dependencies so SGs-AP can reuse it later.
package sms

import "fmt"

const (
	PDSMS    = 0x09
	CPData   = 0x01
	CPAck    = 0x04
	CPError  = 0x10
	RPDataMO = 0x00
	RPDataMT = 0x01
	// RP message type direction is encoded in the low three bits (TS 24.011).
	// The existing MO names describe messages received from the MS; replies to
	// an MO SMS travel in the opposite, network-to-MS direction.
	RPAckMO        = 0x02 // MS -> network
	RPAckNetwork   = 0x03 // network -> MS
	RPErrorMO      = 0x04 // MS -> network
	RPErrorNetwork = 0x05 // network -> MS
	RPUserDataIEI  = 0x41
	MaxRPDU        = 248
	MaxSMRPUI      = 200
)

type CPMessage struct {
	TI                uint8
	TransactionIDFlag bool
	Type              uint8
	RPDU              []byte
	Cause             *uint8
}
type RPData struct {
	Reference   uint8
	Originator  []byte
	Destination []byte
	TPDU        []byte
}

// EncodeRPDataMT wraps the TPDU received over SGd in the MT RP-DATA used on
// the UE-facing CP/RP interface. SGd SC-Address is raw TBCD (or the deployed
// ASCII-digits compatibility form), whereas RP addresses include a TOA.
func EncodeRPDataMT(reference uint8, scAddress, tpdu []byte) ([]byte, error) {
	if len(tpdu) == 0 || len(tpdu) > 233 {
		return nil, fmt.Errorf("sms: invalid MT TPDU")
	}
	digits, err := decodeSCAddressDigits(scAddress)
	if err != nil || len(digits) == 0 || len(digits) > 20 {
		return nil, fmt.Errorf("sms: invalid MT SC address")
	}
	bcd := make([]byte, 0, (len(digits)+1)/2)
	for i := 0; i < len(digits); i += 2 {
		lo := digits[i] - '0'
		hi := byte(0x0f)
		if i+1 < len(digits) {
			hi = digits[i+1] - '0'
		}
		bcd = append(bcd, lo|(hi<<4))
	}
	address := append([]byte{0x91}, bcd...)
	if len(address) > 11 {
		return nil, fmt.Errorf("sms: MT SC address too long")
	}
	b := []byte{RPDataMT, reference, byte(len(address))}
	b = append(b, address...)
	b = append(b, 0) // RP destination address is empty for MT
	b = append(b, byte(len(tpdu)))
	b = append(b, tpdu...)
	if len(b) > MaxRPDU {
		return nil, fmt.Errorf("sms: MT RP-DATA too long")
	}
	return b, nil
}

func decodeSCAddressDigits(b []byte) (string, error) {
	if len(b) == 0 {
		return "", fmt.Errorf("empty SC address")
	}
	ascii := true
	for _, c := range b {
		if c < '0' || c > '9' {
			ascii = false
			break
		}
	}
	if ascii {
		return string(b), nil
	}
	digits := make([]byte, 0, len(b)*2)
	for i, octet := range b {
		lo, hi := octet&0x0f, octet>>4
		if lo > 9 || (hi > 9 && !(hi == 0x0f && i == len(b)-1)) {
			return "", fmt.Errorf("invalid TBCD SC address")
		}
		digits = append(digits, '0'+lo)
		if hi <= 9 {
			digits = append(digits, '0'+hi)
		}
	}
	return string(digits), nil
}

func DecodeRPAckMO(b []byte) (uint8, []byte, error) {
	if len(b) < 2 || b[0]&7 != RPAckMO {
		return 0, nil, fmt.Errorf("sms: not MO RP-ACK")
	}
	if len(b) == 2 {
		return b[1], nil, nil
	}
	if len(b) < 4 || b[2] != RPUserDataIEI || int(b[3]) != len(b)-4 {
		return 0, nil, fmt.Errorf("sms: malformed RP-ACK")
	}
	return b[1], append([]byte(nil), b[4:]...), nil
}
func DecodeRPErrorMO(b []byte) (uint8, uint8, error) {
	if len(b) < 4 || b[0]&7 != RPErrorMO || b[2] != 1 {
		return 0, 0, fmt.Errorf("sms: malformed RP-ERROR")
	}
	return b[1], b[3], nil
}

func DecodeCP(b []byte) (*CPMessage, error) {
	if len(b) < 2 || b[0]&0x0f != PDSMS {
		return nil, fmt.Errorf("sms: invalid CP header")
	}
	m := &CPMessage{TI: (b[0] >> 4) & 0x07, TransactionIDFlag: b[0]&0x80 != 0, Type: b[1]}
	switch m.Type {
	case CPAck:
		if len(b) != 2 {
			return nil, fmt.Errorf("sms: malformed CP-ACK")
		}
		return m, nil
	case CPError:
		// TS 24.011 7.2.3: CP-Cause is a mandatory V field, not an
		// IEI/value pair. A valid CP-ERROR is three octets, e.g. 89 10 51.
		if len(b) != 3 {
			return nil, fmt.Errorf("sms: malformed CP-ERROR")
		}
		c := b[2]
		m.Cause = &c
		return m, nil
	case CPData:
		// TS 24.011 7.1/8.1.4.1: CP-User data is LV, not TLV. The
		// octet after CP-DATA is the RPDU length (e.g. 0x1e in the
		// captured MO SMS), not an IEI.
		if len(b) < 3 || int(b[2]) != len(b)-3 || len(b)-3 > MaxRPDU {
			return nil, fmt.Errorf("sms: malformed CP-DATA")
		}
		m.RPDU = append([]byte(nil), b[3:]...)
		return m, nil
	default:
		return nil, fmt.Errorf("sms: unsupported CP message type %#x", m.Type)
	}
}
func EncodeCPData(ti uint8, rpdu []byte) ([]byte, error) {
	return EncodeCPDataWithDirection(ti, false, rpdu)
}
func EncodeCPDataWithDirection(ti uint8, networkOriginated bool, rpdu []byte) ([]byte, error) {
	if ti > 7 || len(rpdu) == 0 || len(rpdu) > MaxRPDU {
		return nil, fmt.Errorf("sms: invalid CP-DATA")
	}
	header := ti<<4 | PDSMS
	if networkOriginated {
		header |= 0x80
	}
	return append([]byte{header, CPData, byte(len(rpdu))}, rpdu...), nil
}
func EncodeCPAck(ti uint8) ([]byte, error) {
	return EncodeCPAckWithDirection(ti, false)
}
func EncodeCPAckWithDirection(ti uint8, networkOriginated bool) ([]byte, error) {
	if ti > 7 {
		return nil, fmt.Errorf("sms: invalid TI")
	}
	header := ti<<4 | PDSMS
	if networkOriginated {
		header |= 0x80
	}
	return []byte{header, CPAck}, nil
}
func EncodeCPError(ti, cause uint8) ([]byte, error) {
	return EncodeCPErrorWithDirection(ti, false, cause)
}
func EncodeCPErrorWithDirection(ti uint8, networkOriginated bool, cause uint8) ([]byte, error) {
	if ti > 7 {
		return nil, fmt.Errorf("sms: invalid TI")
	}
	header := ti<<4 | PDSMS
	if networkOriginated {
		header |= 0x80
	}
	return []byte{header, CPError, cause}, nil
}

func DecodeRPDataMO(b []byte) (*RPData, error) {
	if len(b) < 5 || b[0]&7 != RPDataMO {
		return nil, fmt.Errorf("sms: not MO RP-DATA")
	}
	r := &RPData{Reference: b[1]}
	off := 2
	l := int(b[off])
	off++
	if l != 0 {
		return nil, fmt.Errorf("sms: MO RP-originator must be empty")
	}
	if off >= len(b) {
		return nil, fmt.Errorf("sms: truncated RP destination")
	}
	l = int(b[off])
	off++
	if l < 2 || l > 11 || off+l > len(b) {
		return nil, fmt.Errorf("sms: invalid RP destination")
	}
	r.Destination = append([]byte(nil), b[off:off+l]...)
	off += l
	if off >= len(b) {
		return nil, fmt.Errorf("sms: missing TPDU")
	}
	l = int(b[off])
	off++
	if l == 0 || l > 233 || off+l != len(b) {
		return nil, fmt.Errorf("sms: invalid TPDU")
	}
	r.TPDU = append([]byte(nil), b[off:]...)
	return r, nil
}

// EncodeRPAckToMS encodes the network-to-MS RP-ACK used to complete an MO
// SMS. It is type 0x03, not the MS-to-network RP-ACK type 0x02.
func EncodeRPAckToMS(ref uint8, tpdu []byte) ([]byte, error) {
	if len(tpdu) > 232 {
		return nil, fmt.Errorf("sms: RP-ACK TPDU too long")
	}
	b := []byte{RPAckNetwork, ref}
	if len(tpdu) > 0 {
		b = append(b, RPUserDataIEI, byte(len(tpdu)))
		b = append(b, tpdu...)
	}
	return b, nil
}
