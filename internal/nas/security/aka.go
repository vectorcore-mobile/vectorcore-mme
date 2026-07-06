// Package security implements 3GPP NAS security functions per TS 33.401.
//
// Key derivation chain:
//
//	K (in SIM/HSS) → CK, IK (from AKA) → KASME (KDF with SQN, PLMN) → KNASint, KNASenc
package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// AKAVectors holds one authentication vector received from the HSS via S6a AIR/AIA.
type AKAVector struct {
	RAND []byte // 16 bytes
	XRES []byte // 8 bytes
	AUTN []byte // 16 bytes: SQN_AK[6] | AMF[2] | MAC[8]
	KASME []byte // 32 bytes
}

// VerifyRES checks the UE's RES against XRES from the HSS.
func VerifyRES(xres, res []byte) bool {
	return hmac.Equal(xres, res)
}

// VerifyAUTN verifies the AUTN received from the MME (which relays it from HSS) using Milenage.
// This is done inside the SIM; the MME just relays RAND/AUTN from HSS and checks the UE's RES.
// For completeness, the MME can verify AUTN MAC using Milenage f1 if it has K — but normally it trusts HSS.
// Returns (sqn_xor_ak, amf, mac) parsed from AUTN.
func ParseAUTN(autn []byte) (sqnXorAK, amf, mac []byte, err error) {
	if len(autn) != 16 {
		return nil, nil, nil, fmt.Errorf("security: AUTN must be 16 bytes, got %d", len(autn))
	}
	sqnXorAK = autn[0:6]
	amf = autn[6:8]
	mac = autn[8:16]
	return
}

// DeriveKASME computes KASME from CK, IK, SQN XOR AK, and the PLMN identity per TS 33.401 §A.2.
// The HSS provides KASME directly in the authentication vector (via AIR/AIA), so the MME
// normally uses the HSS-provided KASME. This function is provided for verification/testing.
func DeriveKASME(ck, ik, plmn, sqnXorAK []byte) ([]byte, error) {
	if len(ck) != 16 || len(ik) != 16 {
		return nil, errors.New("security: CK and IK must each be 16 bytes")
	}
	if len(plmn) != 3 {
		return nil, errors.New("security: PLMN must be 3 bytes")
	}
	if len(sqnXorAK) != 6 {
		return nil, errors.New("security: SQN XOR AK must be 6 bytes")
	}

	// Key: CK || IK (256 bits)
	key := make([]byte, 32)
	copy(key[:16], ck)
	copy(key[16:], ik)

	// S = FC || P0 || L0 || P1 || L1
	// FC = 0x10
	// P0 = PLMN identity (3 bytes)
	// L0 = 0x00 0x03
	// P1 = SQN XOR AK (6 bytes)
	// L1 = 0x00 0x06
	s := []byte{0x10}
	s = append(s, plmn...)
	s = append(s, 0x00, 0x03)
	s = append(s, sqnXorAK...)
	s = append(s, 0x00, 0x06)

	h := hmac.New(sha256.New, key)
	h.Write(s)
	return h.Sum(nil), nil
}

// EncodePLMN encodes MCC/MNC into the 3-byte BCD format used in KASME derivation.
// MCC digits: d1 d2 d3; MNC digits: d4 d5 [d6 optional for 3-digit MNC].
func EncodePLMN(mcc, mnc string) ([]byte, error) {
	if len(mcc) != 3 {
		return nil, fmt.Errorf("security: MCC must be 3 digits, got %q", mcc)
	}
	if len(mnc) != 2 && len(mnc) != 3 {
		return nil, fmt.Errorf("security: MNC must be 2 or 3 digits, got %q", mnc)
	}
	d := func(s string, i int) byte {
		return s[i] - '0'
	}
	plmn := make([]byte, 3)
	plmn[0] = d(mcc, 1)<<4 | d(mcc, 0)
	if len(mnc) == 2 {
		plmn[1] = 0xF0 | d(mcc, 2)
		plmn[2] = d(mnc, 1)<<4 | d(mnc, 0)
	} else {
		plmn[1] = d(mnc, 2)<<4 | d(mcc, 2)
		plmn[2] = d(mnc, 1)<<4 | d(mnc, 0)
	}
	return plmn, nil
}

// NASCount is a 24-bit counter (bits 23:8 = overflow counter, bits 7:0 = sequence number).
type NASCount uint32

// Increment increments the NAS COUNT, wrapping at 2^24.
func (c *NASCount) Increment() {
	*c = (*c + 1) & 0xFFFFFF
}

// Bytes returns the 4-byte big-endian representation (per TS 33.401 §B.3).
func (c NASCount) Bytes() []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(c))
	return b
}

// SequenceNumber returns the low 8 bits (NAS sequence number in the NAS header).
func (c NASCount) SequenceNumber() uint8 {
	return uint8(c & 0xFF)
}
