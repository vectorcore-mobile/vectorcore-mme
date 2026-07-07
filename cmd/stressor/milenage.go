package main

import (
	"crypto/aes"
	"fmt"
)

// milenageAuth computes RES, CK, IK, AK from K (16 bytes), OPC (16 bytes), RAND (16 bytes).
// Implements 3GPP TS 35.206 functions f2, f3, f4, f5.
func milenageAuth(K, OPC, RAND []byte) (res, ck, ik, ak []byte, err error) {
	if len(K) != 16 || len(OPC) != 16 || len(RAND) != 16 {
		return nil, nil, nil, nil, fmt.Errorf("milenage: K, OPC, RAND must each be 16 bytes")
	}

	// TEMP = E_K(RAND XOR OPC)
	TEMP, err := aesECB(K, xor16(RAND, OPC))
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Constants per TS 35.206 §2.3
	c2 := make16(1)  // c2[15] = 1
	c3 := make16(2)  // c3[15] = 2
	c4 := make16(4)  // c4[15] = 4
	c5 := make16(8)  // c5[15] = 8

	// f2: XRES = E_K(rot(TEMP XOR OPC, 0) XOR c2) XOR OPC, bytes [8..15]
	t2 := xor16(xor16(TEMP, OPC), c2) // r2=0, no rotation
	out2, err := aesECB(K, t2)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	res = xor16(out2, OPC)[8:16]

	// f3: CK = E_K(rot(TEMP XOR OPC, 4) XOR c3) XOR OPC
	t3 := xor16(rot16(xor16(TEMP, OPC), 4), c3)
	out3, err := aesECB(K, t3)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	ck = xor16(out3, OPC)

	// f4: IK = E_K(rot(TEMP XOR OPC, 8) XOR c4) XOR OPC
	t4 := xor16(rot16(xor16(TEMP, OPC), 8), c4)
	out4, err := aesECB(K, t4)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	ik = xor16(out4, OPC)

	// f5: AK = E_K(rot(TEMP XOR OPC, 12) XOR c5) XOR OPC, bytes [0..5]
	t5 := xor16(rot16(xor16(TEMP, OPC), 12), c5)
	out5, err := aesECB(K, t5)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	ak = xor16(out5, OPC)[:6]

	return res, ck, ik, ak, nil
}

// milenageOPC derives OPC from K and OP: OPC = E_K(OP) XOR OP.
func milenageOPC(K, OP []byte) ([]byte, error) {
	ek, err := aesECB(K, OP)
	if err != nil {
		return nil, err
	}
	return xor16(ek, OP), nil
}

func aesECB(key, block []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 16)
	c.Encrypt(out, block)
	return out, nil
}

func xor16(a, b []byte) []byte {
	out := make([]byte, 16)
	for i := 0; i < 16; i++ {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// rot16 rotates a 16-byte slice left by n bytes.
func rot16(b []byte, n int) []byte {
	n = n % 16
	out := make([]byte, 16)
	for i := 0; i < 16; i++ {
		out[i] = b[(i+n)%16]
	}
	return out
}

// make16 returns a 16-byte slice with the last byte set to v.
func make16(v byte) []byte {
	b := make([]byte, 16)
	b[15] = v
	return b
}
