package security

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"

	"github.com/vectorcore/mme/internal/nas/security/snow3g"
)

// NASIntegrityAlgorithm computes or verifies a 4-byte NAS MAC.
// direction: 0 = uplink, 1 = downlink.

// ComputeNASMAC computes a 4-byte MAC over the NAS message.
// algID selects EIA0, EIA1, or EIA2. count is the 32-bit NAS COUNT.
func ComputeNASMAC(algID uint8, key []byte, count uint32, bearer, direction uint8, msg []byte) ([]byte, error) {
	switch algID {
	case AlgIDEIA0:
		return eia0MAC()
	case AlgIDEIA1:
		return eia1MAC(key, count, bearer, direction, msg)
	case AlgIDEIA2:
		return eia2MAC(key, count, bearer, direction, msg)
	default:
		return nil, errors.New("security: unsupported EIA algorithm")
	}
}

// VerifyNASMAC verifies a 4-byte MAC. Returns nil if valid.
func VerifyNASMAC(algID uint8, key []byte, count uint32, bearer, direction uint8, msg, mac []byte) error {
	if algID == AlgIDEIA0 {
		return nil // null integrity: always valid
	}
	computed, err := ComputeNASMAC(algID, key, count, bearer, direction, msg)
	if err != nil {
		return err
	}
	if len(mac) < 4 || len(computed) < 4 {
		return errors.New("security: MAC too short")
	}
	for i := 0; i < 4; i++ {
		if computed[i] != mac[i] {
			return errors.New("security: NAS MAC mismatch")
		}
	}
	return nil
}

// eia0MAC returns a null (zero) MAC (EIA0 = no integrity).
func eia0MAC() ([]byte, error) {
	return []byte{0, 0, 0, 0}, nil
}

// eia1MAC implements EIA1 (SNOW 3G based) per TS 33.401 Annex B.2.2.
func eia1MAC(key []byte, count uint32, bearer, direction uint8, msg []byte) ([]byte, error) {
	if len(key) < 16 {
		return nil, errors.New("security: EIA1 key must be at least 16 bytes")
	}
	return snow3g.EIA1(key[:16], count, bearer, direction, msg), nil
}

// eia2MAC implements EIA2 (AES-CMAC based) per TS 33.401 §B.3.
func eia2MAC(key []byte, count uint32, bearer, direction uint8, msg []byte) ([]byte, error) {
	if len(key) < 16 {
		return nil, errors.New("security: EIA2 key must be at least 16 bytes")
	}

	m := EIA2CMACInput(count, bearer, direction, msg)
	mac, err := aesCMAC(key[:16], m)
	if err != nil {
		return nil, err
	}
	return mac[:4], nil
}

// EIA2CMACDetails contains diagnostic material for an EIA2 MAC calculation.
type EIA2CMACDetails struct {
	Input          []byte
	Full           []byte
	First4         []byte
	Last4          []byte
	ReversedFirst4 []byte
	ReversedLast4  []byte
}

// ComputeEIA2CMACDetails computes EIA2 and returns the full AES-CMAC result
// plus truncation variants. Production NAS integrity uses First4.
func ComputeEIA2CMACDetails(key []byte, count uint32, bearer, direction uint8, msg []byte) (*EIA2CMACDetails, error) {
	if len(key) < 16 {
		return nil, errors.New("security: EIA2 key must be at least 16 bytes")
	}
	input := EIA2CMACInput(count, bearer, direction, msg)
	full, err := aesCMAC(key[:16], input)
	if err != nil {
		return nil, err
	}
	d := &EIA2CMACDetails{
		Input:          input,
		Full:           full,
		First4:         append([]byte(nil), full[:4]...),
		Last4:          append([]byte(nil), full[len(full)-4:]...),
		ReversedFirst4: reverse4(full[:4]),
		ReversedLast4:  reverse4(full[len(full)-4:]),
	}
	return d, nil
}

// EIA2CMACInput builds the exact AES-CMAC input bit string M from
// TS 33.401 Annex B.2.3 for byte-aligned NAS/RRC messages:
// COUNT || BEARER || DIRECTION || 26 zero bits || MESSAGE.
func EIA2CMACInput(count uint32, bearer, direction uint8, msg []byte) []byte {
	m := make([]byte, 8, 8+len(msg))
	binary.BigEndian.PutUint32(m[0:], count)
	m[4] = (bearer&0x1F)<<3 | (direction&1)<<2
	return append(m, msg...)
}

// aesCMAC computes AES-CMAC per RFC 4493.
func aesCMAC(key, msg []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	k1, k2 := cmacSubkeys(c)

	n := (len(msg) + 15) / 16
	if n == 0 {
		n = 1
	}
	flag := len(msg)%16 == 0 && len(msg) != 0

	var lastBlock [16]byte
	if flag {
		copy(lastBlock[:], msg[(n-1)*16:])
		xor16(lastBlock[:], k1)
	} else {
		rem := len(msg) - (n-1)*16
		copy(lastBlock[:rem], msg[(n-1)*16:])
		lastBlock[rem] = 0x80
		xor16(lastBlock[:], k2)
	}

	x := make([]byte, 16)
	for i := 0; i < n-1; i++ {
		block := msg[i*16 : (i+1)*16]
		xor16(x, block)
		c.Encrypt(x, x)
	}
	xor16(x, lastBlock[:])
	c.Encrypt(x, x)
	return x, nil
}

func cmacSubkeys(c cipher.Block) (k1, k2 []byte) {
	l := make([]byte, 16)
	c.Encrypt(l, l)
	k1 = cmacShift(l)
	k2 = cmacShift(k1)
	return
}

func cmacShift(b []byte) []byte {
	out := make([]byte, 16)
	carry := byte(0)
	for i := 15; i >= 0; i-- {
		out[i] = b[i]<<1 | carry
		carry = b[i] >> 7
	}
	if b[0]>>7 == 1 {
		out[15] ^= 0x87
	}
	return out
}

func xor16(dst, src []byte) {
	for i := 0; i < 16; i++ {
		dst[i] ^= src[i]
	}
}

func reverse4(in []byte) []byte {
	if len(in) < 4 {
		return nil
	}
	return []byte{in[3], in[2], in[1], in[0]}
}
