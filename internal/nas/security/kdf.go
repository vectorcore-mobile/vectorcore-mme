package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

// AlgorithmID constants for NAS key derivation (TS 33.401 §A.7).
const (
	AlgTypeNASEnc uint8 = 0x01 // NAS ciphering algorithm
	AlgTypeNASInt uint8 = 0x02 // NAS integrity algorithm

	AlgIDEIA0 uint8 = 0x00 // null integrity
	AlgIDEIA1 uint8 = 0x01 // SNOW3G
	AlgIDEIA2 uint8 = 0x02 // AES-CMAC

	AlgIDEEA0 uint8 = 0x00 // null ciphering
	AlgIDEEA1 uint8 = 0x01 // SNOW3G
	AlgIDEEA2 uint8 = 0x02 // AES-CTR
)

// kdf is the 3GPP Key Derivation Function (HMAC-SHA-256 based), TS 33.401 §A.7.
func kdf(key, s []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(s)
	return h.Sum(nil)
}

// NASKeyMaterial contains the full TS 33.401 Annex A.7 KDF inputs and outputs.
type NASKeyMaterial struct {
	IntS   []byte
	EncS   []byte
	IntOut []byte
	EncOut []byte
}

// DeriveNASKeyMaterial returns the full NAS key derivation material for
// diagnostics and tests. Production code should use DeriveNASKeys.
func DeriveNASKeyMaterial(kasme []byte, intAlgID, encAlgID uint8) (*NASKeyMaterial, error) {
	if len(kasme) != 32 {
		return nil, errors.New("security: KASME must be 32 bytes")
	}

	// S = FC || P0 || L0 || P1 || L1
	// FC = 0x15 for NAS keys
	// P0 = algorithm type distinguisher (0x01 = NAS-enc-alg, 0x02 = NAS-int-alg)
	// L0 = 0x00 0x01
	// P1 = algorithm identity (0x00..0x0F)
	// L1 = 0x00 0x01
	buildS := func(algType, algID uint8) []byte {
		return []byte{0x15, algType, 0x00, 0x01, algID, 0x00, 0x01}
	}

	mat := &NASKeyMaterial{
		IntS: buildS(AlgTypeNASInt, intAlgID),
		EncS: buildS(AlgTypeNASEnc, encAlgID),
	}
	mat.IntOut = kdf(kasme, mat.IntS)
	mat.EncOut = kdf(kasme, mat.EncS)
	return mat, nil
}

// DeriveNASKeys derives KNASint and KNASenc from KASME using TS 33.401 §A.7.
//
//	KNASint: key used for NAS integrity protection (16 bytes, lower half of KDF output)
//	KNASenc: key used for NAS ciphering (16 bytes, lower half of KDF output)
func DeriveNASKeys(kasme []byte, intAlgID, encAlgID uint8) (knasInt, knasEnc []byte, err error) {
	mat, err := DeriveNASKeyMaterial(kasme, intAlgID, encAlgID)
	if err != nil {
		return nil, nil, err
	}

	// Use the 128 least significant bits (lower 16 bytes of 32-byte output)
	knasInt = mat.IntOut[16:]
	knasEnc = mat.EncOut[16:]
	return
}

// HashMME computes HASHMME/HASHUE per TS 33.401 Annex I.2:
// KDF with a 256-bit all-zero key over the entire unprotected plain Attach
// Request or TAU Request NAS message, taking the 64 least significant bits.
func HashMME(unprotectedRequest []byte) []byte {
	out := kdf(make([]byte, 32), unprotectedRequest)
	return out[24:]
}

// DeriveKeNB derives KeNB from KASME and the NAS uplink COUNT per TS 33.401 §A.3.
func DeriveKeNB(kasme []byte, ulNASCount uint32) ([]byte, error) {
	if len(kasme) != 32 {
		return nil, errors.New("security: KASME must be 32 bytes")
	}
	// S = FC || P0 || L0
	// FC = 0x11, P0 = UL_NAS_COUNT (4 bytes BE), L0 = 0x0004
	s := make([]byte, 7) // 1 + 4 + 2
	s[0] = 0x11
	s[1] = uint8(ulNASCount >> 24)
	s[2] = uint8(ulNASCount >> 16)
	s[3] = uint8(ulNASCount >> 8)
	s[4] = uint8(ulNASCount)
	s[5] = 0x00
	s[6] = 0x04
	return kdf(kasme, s), nil
}

// DeriveNH derives the Next Hop key from KASME and a 32-byte sync-input per TS 33.401 §A.4.
// syncInput is KeNB for the first NH (NCC=1) and the previous NH for subsequent derivations.
func DeriveNH(kasme, syncInput []byte) ([]byte, error) {
	if len(kasme) != 32 || len(syncInput) != 32 {
		return nil, errors.New("security: DeriveNH: inputs must be 32 bytes")
	}
	// S = FC=0x13 || P0(syncInput, 32 bytes) || L0(0x00 0x20)
	s := make([]byte, 1+32+2)
	s[0] = 0x13
	copy(s[1:33], syncInput)
	s[33] = 0x00
	s[34] = 0x20
	return kdf(kasme, s), nil
}

// PreferredAlgorithm selects the highest-priority algorithm from the UE's
// supported list vs. the network's preference list.
// Returns (algID, found). Priority list is highest-preferred first.
func PreferredAlgorithm(netPreference []string, ueSupported []string) (uint8, bool) {
	algMap := map[string]uint8{
		"EIA0": AlgIDEIA0, "EEA0": AlgIDEEA0,
		"EIA1": AlgIDEIA1, "EEA1": AlgIDEEA1,
		"EIA2": AlgIDEIA2, "EEA2": AlgIDEEA2,
	}
	for _, net := range netPreference {
		for _, ue := range ueSupported {
			if net == ue {
				id, ok := algMap[net]
				return id, ok
			}
		}
	}
	return 0, false
}
