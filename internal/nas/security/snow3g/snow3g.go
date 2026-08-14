// Package snow3g implements the SNOW 3G stream cipher and its f8/f9 modes
// as specified in the ETSI/SAGE document "Specification of the 3GPP
// Confidentiality and Integrity Algorithms UEA2 & UIA2" (the core cipher
// underlying LTE's 128-EEA1 and 128-EIA1, TS 33.401 Annex B.1.2/B.2.2).
//
// The LFSR/FSM core, S-boxes, and GF(2^8)/GF(2^32) arithmetic below are a
// direct transcription of the ETSI/SAGE reference implementation (also
// shipped, byte-for-byte identical in structure, by open source 4G/5G
// cores such as open5gs). F8/F9/EEA1/EIA1 are validated against the
// official UEA2/UIA2 conformance test vectors in snow3g_test.go.
package snow3g

import "encoding/binary"

// MULx multiplies v by x in GF(2^8) with reduction polynomial c.
func MULx(v, c byte) byte {
	if v&0x80 != 0 {
		return (v << 1) ^ c
	}
	return v << 1
}

// MULxPOW computes x^i * v in GF(2^8) with reduction polynomial c.
func MULxPOW(v byte, i int, c byte) byte {
	for ; i > 0; i-- {
		v = MULx(v, c)
	}
	return v
}

// mulAlpha and divAlpha implement multiplication/division by the LFSR's
// primitive element alpha in GF(2^32), built from GF(2^8) (reduction
// polynomial 0xA9) per §3.4.2/§3.4.3 of the SNOW 3G specification.
func mulAlpha(c byte) uint32 {
	return uint32(MULxPOW(c, 23, 0xa9))<<24 |
		uint32(MULxPOW(c, 245, 0xa9))<<16 |
		uint32(MULxPOW(c, 48, 0xa9))<<8 |
		uint32(MULxPOW(c, 239, 0xa9))
}

func divAlpha(c byte) uint32 {
	return uint32(MULxPOW(c, 16, 0xa9))<<24 |
		uint32(MULxPOW(c, 39, 0xa9))<<16 |
		uint32(MULxPOW(c, 6, 0xa9))<<8 |
		uint32(MULxPOW(c, 64, 0xa9))
}

// SR is the Rijndael (AES) S-box, used by S1.
var SR = [256]byte{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
}

// SQ is SNOW 3G's own S-box, used by S2.
var SQ = [256]byte{
	0x25, 0x24, 0x73, 0x67, 0xd7, 0xae, 0x5c, 0x30, 0xa4, 0xee, 0x6e, 0xcb, 0x7d, 0xb5, 0x82, 0xdb,
	0xe4, 0x8e, 0x48, 0x49, 0x4f, 0x5d, 0x6a, 0x78, 0x70, 0x88, 0xe8, 0x5f, 0x5e, 0x84, 0x65, 0xe2,
	0xd8, 0xe9, 0xcc, 0xed, 0x40, 0x2f, 0x11, 0x28, 0x57, 0xd2, 0xac, 0xe3, 0x4a, 0x15, 0x1b, 0xb9,
	0xb2, 0x80, 0x85, 0xa6, 0x2e, 0x02, 0x47, 0x29, 0x07, 0x4b, 0x0e, 0xc1, 0x51, 0xaa, 0x89, 0xd4,
	0xca, 0x01, 0x46, 0xb3, 0xef, 0xdd, 0x44, 0x7b, 0xc2, 0x7f, 0xbe, 0xc3, 0x9f, 0x20, 0x4c, 0x64,
	0x83, 0xa2, 0x68, 0x42, 0x13, 0xb4, 0x41, 0xcd, 0xba, 0xc6, 0xbb, 0x6d, 0x4d, 0x71, 0x21, 0xf4,
	0x8d, 0xb0, 0xe5, 0x93, 0xfe, 0x8f, 0xe6, 0xcf, 0x43, 0x45, 0x31, 0x22, 0x37, 0x36, 0x96, 0xfa,
	0xbc, 0x0f, 0x08, 0x52, 0x1d, 0x55, 0x1a, 0xc5, 0x4e, 0x23, 0x69, 0x7a, 0x92, 0xff, 0x5b, 0x5a,
	0xeb, 0x9a, 0x1c, 0xa9, 0xd1, 0x7e, 0x0d, 0xfc, 0x50, 0x8a, 0xb6, 0x62, 0xf5, 0x0a, 0xf8, 0xdc,
	0x03, 0x3c, 0x0c, 0x39, 0xf1, 0xb8, 0xf3, 0x3d, 0xf2, 0xd5, 0x97, 0x66, 0x81, 0x32, 0xa0, 0x00,
	0x06, 0xce, 0xf6, 0xea, 0xb7, 0x17, 0xf7, 0x8c, 0x79, 0xd6, 0xa7, 0xbf, 0x8b, 0x3f, 0x1f, 0x53,
	0x63, 0x75, 0x35, 0x2c, 0x60, 0xfd, 0x27, 0xd3, 0x94, 0xa5, 0x7c, 0xa1, 0x05, 0x58, 0x2d, 0xbd,
	0xd9, 0xc7, 0xaf, 0x6b, 0x54, 0x0b, 0xe0, 0x38, 0x04, 0xc8, 0x9d, 0xe7, 0x14, 0xb1, 0x87, 0x9c,
	0xdf, 0x6f, 0xf9, 0xda, 0x2a, 0xc4, 0x59, 0x16, 0x74, 0x91, 0xab, 0x26, 0x61, 0x76, 0x34, 0x2b,
	0xad, 0x99, 0xfb, 0x72, 0xec, 0x33, 0x12, 0xde, 0x98, 0x3b, 0xc0, 0x9b, 0x3e, 0x18, 0x10, 0x3a,
	0x56, 0xe1, 0x77, 0xc9, 0x1e, 0x9e, 0x95, 0xa3, 0x90, 0x19, 0xa8, 0x6c, 0x09, 0xd0, 0xf0, 0x86,
}

// s1 is the 32x32-bit S-box S1: SR substitution followed by the same
// MDS (MixColumns-style) diffusion AES uses, per §3.3.1.
func s1(w uint32) uint32 {
	b0 := SR[byte(w>>24)]
	b1 := SR[byte(w>>16)]
	b2 := SR[byte(w>>8)]
	b3 := SR[byte(w)]
	r0 := MULx(b0, 0x1b) ^ b1 ^ b2 ^ (MULx(b3, 0x1b) ^ b3)
	r1 := (MULx(b0, 0x1b) ^ b0) ^ MULx(b1, 0x1b) ^ b2 ^ b3
	r2 := b0 ^ (MULx(b1, 0x1b) ^ b1) ^ MULx(b2, 0x1b) ^ b3
	r3 := b0 ^ b1 ^ (MULx(b2, 0x1b) ^ b2) ^ MULx(b3, 0x1b)
	return uint32(r0)<<24 | uint32(r1)<<16 | uint32(r2)<<8 | uint32(r3)
}

// s2 is the 32x32-bit S-box S2: SQ substitution with SNOW 3G's own MDS
// diffusion (reduction polynomial 0x69), per §3.3.2.
func s2(w uint32) uint32 {
	b0 := SQ[byte(w>>24)]
	b1 := SQ[byte(w>>16)]
	b2 := SQ[byte(w>>8)]
	b3 := SQ[byte(w)]
	r0 := MULx(b0, 0x69) ^ b1 ^ b2 ^ (MULx(b3, 0x69) ^ b3)
	r1 := (MULx(b0, 0x69) ^ b0) ^ MULx(b1, 0x69) ^ b2 ^ b3
	r2 := b0 ^ (MULx(b1, 0x69) ^ b1) ^ MULx(b2, 0x69) ^ b3
	r3 := b0 ^ b1 ^ (MULx(b2, 0x69) ^ b2) ^ MULx(b3, 0x69)
	return uint32(r0)<<24 | uint32(r1)<<16 | uint32(r2)<<8 | uint32(r3)
}

// state holds the 16-stage LFSR and 3-register FSM.
type state struct {
	lfsr       [16]uint32
	r1, r2, r3 uint32
}

// clockFSM produces one 32-bit word of FSM output and advances R1..R3.
// See §3.4.6.
func (s *state) clockFSM() uint32 {
	f := (s.lfsr[15] + s.r1) ^ s.r2
	r := s.r2 + (s.r3 ^ s.lfsr[5])
	s.r3 = s2(s.r2)
	s.r2 = s1(s.r1)
	s.r1 = r
	return f
}

// clockLFSR advances the LFSR by one clock. f is the FSM output XORed into
// the feedback during the 32-round initialization (§3.4.4); pass 0 for
// ordinary keystream-mode clocking (§3.4.5), which omits it.
func (s *state) clockLFSR(f uint32) {
	v := ((s.lfsr[0] << 8) & 0xffffff00) ^
		mulAlpha(byte(s.lfsr[0]>>24)) ^
		s.lfsr[2] ^
		((s.lfsr[11] >> 8) & 0x00ffffff) ^
		divAlpha(byte(s.lfsr[11])) ^
		f
	copy(s.lfsr[0:15], s.lfsr[1:16])
	s.lfsr[15] = v
}

// newState initializes the cipher for a 128-bit key and 128-bit IV per
// §4.1, with key and IV each in natural (first-word-first) word order —
// this is the raw primitive; F8/F9 below apply their own key word
// reversal before calling it, exactly as the reference implementation's
// f8/f9 wrappers do.
func newState(key, iv []byte) *state {
	var k [4]uint32
	for i := 0; i < 4; i++ {
		k[i] = binary.BigEndian.Uint32(key[4*i : 4*i+4])
	}
	var ivw [4]uint32
	for i := 0; i < 4; i++ {
		ivw[i] = binary.BigEndian.Uint32(iv[4*i : 4*i+4])
	}

	s := &state{}
	s.lfsr[15] = k[3] ^ ivw[0]
	s.lfsr[14] = k[2]
	s.lfsr[13] = k[1]
	s.lfsr[12] = k[0] ^ ivw[1]
	s.lfsr[11] = k[3] ^ 0xffffffff
	s.lfsr[10] = k[2] ^ 0xffffffff ^ ivw[2]
	s.lfsr[9] = k[1] ^ 0xffffffff ^ ivw[3]
	s.lfsr[8] = k[0] ^ 0xffffffff
	s.lfsr[7] = k[3]
	s.lfsr[6] = k[2]
	s.lfsr[5] = k[1]
	s.lfsr[4] = k[0]
	s.lfsr[3] = k[3] ^ 0xffffffff
	s.lfsr[2] = k[2] ^ 0xffffffff
	s.lfsr[1] = k[1] ^ 0xffffffff
	s.lfsr[0] = k[0] ^ 0xffffffff

	for i := 0; i < 32; i++ {
		f := s.clockFSM()
		s.clockLFSR(f)
	}
	return s
}

// generateKeystreamWords returns n 32-bit keystream words per §4.2. The
// first combined FSM/LFSR clock after initialization is discarded, as the
// spec requires, before any word is output.
func (s *state) generateKeystreamWords(n int) []uint32 {
	s.clockFSM()
	s.clockLFSR(0)
	ks := make([]uint32, n)
	for i := 0; i < n; i++ {
		f := s.clockFSM()
		ks[i] = f ^ s.lfsr[0]
		s.clockLFSR(0)
	}
	return ks
}

// Keystream returns n bytes of SNOW 3G keystream for a 128-bit key and IV.
func Keystream(key, iv []byte, n int) []byte {
	words := (n + 3) / 4
	s := newState(key, iv)
	ks := s.generateKeystreamWords(words)
	out := make([]byte, 0, words*4)
	for _, w := range ks {
		out = append(out, byte(w>>24), byte(w>>16), byte(w>>8), byte(w))
	}
	return out[:n]
}

// reverseKeyWords returns key with its four 32-bit words reordered
// (word0..word3 -> word3..word0). f8/f9 in the reference implementation
// build their internal K[4] this way (K[3-i] = word i of the raw key)
// before calling the raw initialization primitive, which itself takes
// natural (unreversed) word order; Keystream/newState above implement
// that raw primitive directly, so callers reproducing f8/f9 must reverse
// here first.
func reverseKeyWords(key []byte) [16]byte {
	var out [16]byte
	copy(out[0:4], key[12:16])
	copy(out[4:8], key[8:12])
	copy(out[8:12], key[4:8])
	copy(out[12:16], key[0:4])
	return out
}

// F8 is the SNOW 3G confidentiality primitive (UEA2 f8, TS 35.216 §3),
// also used directly as LTE's 128-EEA1 (TS 33.401 Annex B.1.2). data is
// byte-aligned; direction is 0 (uplink) or 1 (downlink).
func F8(key []byte, count uint32, bearer, direction uint8, data []byte) []byte {
	ivWord := uint32(bearer&0x1f)<<27 | uint32(direction&1)<<26
	var iv [16]byte
	binary.BigEndian.PutUint32(iv[0:4], ivWord)
	binary.BigEndian.PutUint32(iv[4:8], count)
	copy(iv[8:12], iv[0:4])
	copy(iv[12:16], iv[4:8])

	rk := reverseKeyWords(key)
	ks := Keystream(rk[:], iv[:], len(data))
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ ks[i]
	}
	return out
}

// EEA1 is LTE's 128-EEA1 confidentiality algorithm: an alias for F8.
func EEA1(key []byte, count uint32, bearer, direction uint8, data []byte) []byte {
	return F8(key, count, bearer, direction, data)
}

// F9 is the SNOW 3G integrity primitive (UIA2 f9, TS 35.216 §4): a GF(2^64)
// polynomial-evaluation MAC over byte-aligned data, returning a 4-byte MAC.
func F9(key []byte, count, fresh uint32, direction uint8, data []byte) []byte {
	dir := uint32(direction & 1)
	var iv [16]byte
	binary.BigEndian.PutUint32(iv[0:4], fresh^(dir<<15))
	binary.BigEndian.PutUint32(iv[4:8], count^(dir<<31))
	binary.BigEndian.PutUint32(iv[8:12], fresh)
	binary.BigEndian.PutUint32(iv[12:16], count)

	rk := reverseKeyWords(key)
	z := Keystream(rk[:], iv[:], 20) // z1..z5, one 32-bit word each
	p := binary.BigEndian.Uint64(z[0:8])
	q := binary.BigEndian.Uint64(z[8:16])
	z5 := binary.BigEndian.Uint32(z[16:20])

	nBytes := len(data)
	numBlocks := (nBytes + 7) / 8
	if numBlocks == 0 {
		numBlocks = 1
	}
	const c = 0x1b
	var eval uint64
	for i := 0; i < numBlocks; i++ {
		var block [8]byte
		start := i * 8
		end := start + 8
		if end > nBytes {
			end = nBytes
		}
		copy(block[:], data[start:end])
		eval = mul64(eval^binary.BigEndian.Uint64(block[:]), p, c)
	}
	eval ^= uint64(nBytes) * 8 // message bit length
	eval = mul64(eval, q, c)

	mac := make([]byte, 4)
	for i := 0; i < 4; i++ {
		mac[i] = byte(eval>>(56-8*i)) ^ byte(z5>>(24-8*i))
	}
	return mac
}

// EIA1 is LTE's 128-EIA1 integrity algorithm (TS 33.401 Annex B.2.2): F9
// with FRESH set to BEARER<<27.
func EIA1(key []byte, count uint32, bearer, direction uint8, data []byte) []byte {
	return F9(key, count, uint32(bearer&0x1f)<<27, direction, data)
}

func mul64x(v, c uint64) uint64 {
	if v&0x8000000000000000 != 0 {
		return (v << 1) ^ c
	}
	return v << 1
}

func mul64xPow(v uint64, i int, c uint64) uint64 {
	for ; i > 0; i-- {
		v = mul64x(v, c)
	}
	return v
}

func mul64(v, p, c uint64) uint64 {
	var result uint64
	for i := 0; i < 64; i++ {
		if (p>>uint(i))&1 != 0 {
			result ^= mul64xPow(v, i, c)
		}
	}
	return result
}
