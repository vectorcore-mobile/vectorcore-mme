package security

import (
	"crypto/aes"
	"encoding/binary"
	"errors"

	"github.com/vectorcore/mme/internal/nas/security/snow3g"
)

// CipherNAS encrypts or decrypts a NAS message payload.
// Encryption and decryption are the same operation for all supported algorithms.
// direction: 0 = uplink, 1 = downlink.
func CipherNAS(algID uint8, key []byte, count uint32, bearer, direction uint8, plaintext []byte) ([]byte, error) {
	switch algID {
	case AlgIDEEA0:
		return eea0Cipher(plaintext)
	case AlgIDEEA1:
		return eea1Cipher(key, count, bearer, direction, plaintext)
	case AlgIDEEA2:
		return eea2Cipher(key, count, bearer, direction, plaintext)
	default:
		return nil, errors.New("security: unsupported EEA algorithm")
	}
}

// eea0Cipher is the null cipher — plaintext is returned unchanged.
func eea0Cipher(in []byte) ([]byte, error) {
	out := make([]byte, len(in))
	copy(out, in)
	return out, nil
}

// eea1Cipher implements EEA1 (SNOW 3G) per TS 33.401 §B.4.
func eea1Cipher(key []byte, count uint32, bearer, direction uint8, in []byte) ([]byte, error) {
	if len(key) < 16 {
		return nil, errors.New("security: EEA1 key must be at least 16 bytes")
	}
	// Build IV: COUNT[31:0] || BEARER[4:0] DIRECTION[0] 0^26 || 0^32 || 0^32
	var iv [16]byte
	binary.BigEndian.PutUint32(iv[0:], count)
	iv[4] = (bearer&0x1F)<<3 | (direction&1)<<2

	ks := snow3g.Keystream(key[:16], iv[:], len(in))
	out := make([]byte, len(in))
	for i := range in {
		out[i] = in[i] ^ ks[i]
	}
	return out, nil
}

// eea2Cipher implements EEA2 (AES-CTR) per TS 33.401 §B.5.
func eea2Cipher(key []byte, count uint32, bearer, direction uint8, in []byte) ([]byte, error) {
	if len(key) < 16 {
		return nil, errors.New("security: EEA2 key must be at least 16 bytes")
	}

	// Counter block: COUNT[31:0] || BEARER[4:0] DIRECTION[0] 0^26 || 0^64
	var ctr [16]byte
	binary.BigEndian.PutUint32(ctr[0:], count)
	ctr[4] = (bearer&0x1F)<<3 | (direction&1)<<2

	c, err := aes.NewCipher(key[:16])
	if err != nil {
		return nil, err
	}

	out := make([]byte, len(in))
	// AES-CTR: XOR input with AES(counter)
	blockSize := 16
	block := make([]byte, blockSize)
	for offset := 0; offset < len(in); offset += blockSize {
		c.Encrypt(block, ctr[:])
		end := offset + blockSize
		if end > len(in) {
			end = len(in)
		}
		for i := offset; i < end; i++ {
			out[i] = in[i] ^ block[i-offset]
		}
		// Increment counter (big-endian, 128-bit)
		for i := 15; i >= 0; i-- {
			ctr[i]++
			if ctr[i] != 0 {
				break
			}
		}
	}
	return out, nil
}
