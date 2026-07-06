package security_test

import (
	"testing"

	"github.com/vectorcore/mme/internal/nas/security"
)

// ---- PLMN encoding ----

func TestEncodePLMN(t *testing.T) {
	// MCC=001, MNC=01 → BCD: 0x00 0xF1 0x10
	plmn, err := security.EncodePLMN("001", "01")
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x00, 0xF1, 0x10}
	for i, b := range want {
		if plmn[i] != b {
			t.Errorf("plmn[%d]: got %02x want %02x", i, plmn[i], b)
		}
	}
}

// ---- NAS key derivation ----

func TestDeriveNASKeys(t *testing.T) {
	kasme := make([]byte, 32)
	for i := range kasme {
		kasme[i] = byte(i)
	}
	knasInt, knasEnc, err := security.DeriveNASKeys(kasme, security.AlgIDEIA2, security.AlgIDEEA2)
	if err != nil {
		t.Fatal(err)
	}
	if len(knasInt) != 16 || len(knasEnc) != 16 {
		t.Errorf("key lengths: int=%d enc=%d, want 16 each", len(knasInt), len(knasEnc))
	}
	// Keys should not be zero
	allZeroInt := true
	for _, b := range knasInt {
		if b != 0 {
			allZeroInt = false
			break
		}
	}
	if allZeroInt {
		t.Error("KNASint is all zeros — derivation likely failed")
	}
}

// ---- EIA2 (AES-CMAC) MAC computation ----

func TestEIA2MAC(t *testing.T) {
	key := make([]byte, 16)
	msg := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	mac1, err := security.ComputeNASMAC(security.AlgIDEIA2, key, 0, 0, 0, msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(mac1) != 4 {
		t.Errorf("MAC length %d, want 4", len(mac1))
	}

	// Verify: computing same MAC again and checking
	if err := security.VerifyNASMAC(security.AlgIDEIA2, key, 0, 0, 0, msg, mac1); err != nil {
		t.Errorf("MAC verification failed: %v", err)
	}

	// Wrong count → different MAC
	mac2, _ := security.ComputeNASMAC(security.AlgIDEIA2, key, 1, 0, 0, msg)
	equal := mac1[0] == mac2[0] && mac1[1] == mac2[1] && mac1[2] == mac2[2] && mac1[3] == mac2[3]
	if equal {
		t.Error("MAC with count=0 and count=1 should differ")
	}
}

// ---- EIA0 (null) always validates ----

func TestEIA0(t *testing.T) {
	if err := security.VerifyNASMAC(security.AlgIDEIA0, nil, 0, 0, 0, []byte{1, 2, 3}, []byte{0, 0, 0, 0}); err != nil {
		t.Errorf("EIA0 should always pass: %v", err)
	}
}

// ---- EEA0 (null cipher) is identity ----

func TestEEA0(t *testing.T) {
	plain := []byte{0xAB, 0xCD, 0xEF}
	cipher, err := security.CipherNAS(security.AlgIDEEA0, nil, 0, 0, 0, plain)
	if err != nil {
		t.Fatal(err)
	}
	for i, b := range plain {
		if cipher[i] != b {
			t.Errorf("EEA0: byte[%d] %02x != %02x", i, cipher[i], b)
		}
	}
}

// ---- EEA2 (AES-CTR) encrypt/decrypt round-trip ----

func TestEEA2RoundTrip(t *testing.T) {
	key := make([]byte, 16)
	plain := []byte("hello, LTE world!")
	enc, err := security.CipherNAS(security.AlgIDEEA2, key, 0, 0, 0, plain)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := security.CipherNAS(security.AlgIDEEA2, key, 0, 0, 0, enc)
	if err != nil {
		t.Fatal(err)
	}
	for i, b := range plain {
		if dec[i] != b {
			t.Errorf("EEA2 round-trip byte[%d]: got %02x want %02x", i, dec[i], b)
		}
	}
}

// ---- NAS COUNT increment and sequence number ----

func TestNASCount(t *testing.T) {
	var c security.NASCount
	for i := 0; i < 256; i++ {
		c.Increment()
	}
	if c.SequenceNumber() != 0 {
		t.Errorf("after 256 increments, seq should wrap to 0, got %d", c.SequenceNumber())
	}
}
