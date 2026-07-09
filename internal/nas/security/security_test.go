package security_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/vectorcore/mme/internal/nas/security"
)

// ---- PLMN encoding ----

func TestEncodePLMN(t *testing.T) {
	tests := []struct {
		name string
		mcc  string
		mnc  string
		want []byte
	}{
		{name: "two digit 001/01", mcc: "001", mnc: "01", want: []byte{0x00, 0xF1, 0x10}},
		{name: "three digit 311/435", mcc: "311", mnc: "435", want: []byte{0x13, 0x51, 0x34}},
		{name: "three digit 310/260", mcc: "310", mnc: "260", want: []byte{0x13, 0x00, 0x62}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plmn, err := security.EncodePLMN(tt.mcc, tt.mnc)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(plmn, tt.want) {
				t.Fatalf("PLMN: got %x, want %x", plmn, tt.want)
			}
		})
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

func TestDeriveNASKeysCurrentSrsUEVector(t *testing.T) {
	kasme := mustHex(t, "0f71b0123698d22039cf8fe7c2f2b1ade502c8c37f5556a06a30b45dd764fff5")

	knasInt, knasEnc, err := security.DeriveNASKeys(kasme, security.AlgIDEIA2, security.AlgIDEEA2)
	if err != nil {
		t.Fatal(err)
	}

	// TS 33.401 Annex A.7: NAS-enc-alg type = 0x01, NAS-int-alg type = 0x02.
	// These values were cross-checked with Python cryptography/HMAC-SHA256.
	wantInt := mustHex(t, "71c14e50a8ba58495c4289bef3b998da")
	wantEnc := mustHex(t, "5177cef9a110df0a15d5839eabfb9e38")
	if !bytes.Equal(knasInt, wantInt) {
		t.Fatalf("KNASint: got %x, want %x", knasInt, wantInt)
	}
	if !bytes.Equal(knasEnc, wantEnc) {
		t.Fatalf("KNASenc: got %x, want %x", knasEnc, wantEnc)
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

func TestEIA2MACTS33401AnnexC2Set2(t *testing.T) {
	key := mustHex(t, "d3c5d592327fb11c4035c6680af8c6d1")
	msg := mustHex(t, "484583d5afe082ae")

	mac, err := security.ComputeNASMAC(security.AlgIDEIA2, key, 0x398a59b4, 0x1a, 1, msg)
	if err != nil {
		t.Fatal(err)
	}
	want := mustHex(t, "b93787e6")
	if !bytes.Equal(mac, want) {
		t.Fatalf("MAC: got %x, want %x", mac, want)
	}
}

func TestEIA2MACCurrentSecurityModeCommandVector(t *testing.T) {
	kasme := mustHex(t, "0f71b0123698d22039cf8fe7c2f2b1ade502c8c37f5556a06a30b45dd764fff5")
	plainSMC := mustHex(t, "075d220002f070")

	knasInt, knasEnc, err := security.DeriveNASKeys(kasme, security.AlgIDEIA2, security.AlgIDEEA2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(knasEnc, mustHex(t, "5177cef9a110df0a15d5839eabfb9e38")) {
		t.Fatalf("KNASenc regression: got %x", knasEnc)
	}

	nasMACInput := append([]byte{0x00}, plainSMC...)
	mac, err := security.ComputeNASMAC(security.AlgIDEIA2, knasInt, 0, 0, 1, nasMACInput)
	if err != nil {
		t.Fatal(err)
	}
	// Cross-checked with Python cryptography AES-CMAC over:
	// COUNT(0) || BEARER/DIRECTION(04 00 00 00) || NAS SQN || plain SMC.
	want := mustHex(t, "f01417b7")
	if !bytes.Equal(mac, want) {
		t.Fatalf("MAC: got %x, want %x", mac, want)
	}
	if bytes.Equal(mac, mustHex(t, "72caf91a")) {
		t.Fatal("MAC still matches the pre-fix value computed with NAS-enc as KNASint")
	}
}

func TestEIA2MACLatestSecurityModeCommandVector(t *testing.T) {
	kasme := mustHex(t, "662a46f4758004a5c636a16d3cb36ad79073ed6084217a94d75365a8b4b1a240")
	plainSMC := mustHex(t, "075d220002f070")

	knasInt, knasEnc, err := security.DeriveNASKeys(kasme, security.AlgIDEIA2, security.AlgIDEEA2)
	if err != nil {
		t.Fatal(err)
	}
	wantInt := mustHex(t, "7dd7daa2e47f2c9e1f8d8871a5acde52")
	wantEnc := mustHex(t, "23ae584014b6acc71ab53f98c28a97f2")
	if !bytes.Equal(knasInt, wantInt) {
		t.Fatalf("KNASint: got %x, want %x", knasInt, wantInt)
	}
	if !bytes.Equal(knasEnc, wantEnc) {
		t.Fatalf("KNASenc: got %x, want %x", knasEnc, wantEnc)
	}

	nasMACInput := append([]byte{0x00}, plainSMC...)
	downlinkInput := security.EIA2CMACInput(0, 0, 1, nasMACInput)
	uplinkInput := security.EIA2CMACInput(0, 0, 0, nasMACInput)
	if !bytes.Equal(downlinkInput, mustHex(t, "000000000400000000075d220002f070")) {
		t.Fatalf("downlink full CMAC input: got %x", downlinkInput)
	}
	if !bytes.Equal(uplinkInput, mustHex(t, "000000000000000000075d220002f070")) {
		t.Fatalf("uplink full CMAC input: got %x", uplinkInput)
	}

	downlinkMAC, err := security.ComputeNASMAC(security.AlgIDEIA2, knasInt, 0, 0, 1, nasMACInput)
	if err != nil {
		t.Fatal(err)
	}
	uplinkMAC, err := security.ComputeNASMAC(security.AlgIDEIA2, knasInt, 0, 0, 0, nasMACInput)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("EIA2 downlink input=%x mac=%x", downlinkInput, downlinkMAC)
	t.Logf("EIA2 uplink input=%x mac=%x", uplinkInput, uplinkMAC)

	// Cross-checked with Python cryptography AES-CMAC.
	if !bytes.Equal(downlinkMAC, mustHex(t, "0cba061d")) {
		t.Fatalf("downlink MAC: got %x, want 0cba061d", downlinkMAC)
	}
	if !bytes.Equal(uplinkMAC, mustHex(t, "84ed132f")) {
		t.Fatalf("uplink MAC: got %x, want 84ed132f", uplinkMAC)
	}
	protectedSMC := append([]byte{0x37}, downlinkMAC...)
	protectedSMC = append(protectedSMC, nasMACInput...)
	if !bytes.Equal(protectedSMC, mustHex(t, "370cba061d00075d220002f070")) {
		t.Fatalf("protected SMC: got %x", protectedSMC)
	}
}

func TestEIA2MACKDFHalfSelectionCurrentVector(t *testing.T) {
	kasme := mustHex(t, "ed5ad878b984563b23b013fc9ba344f827a2ac0b27398ff8ee4030f297a1f4b6")
	nasMACInput := mustHex(t, "00075d220002f070")

	mat, err := security.DeriveNASKeyMaterial(kasme, security.AlgIDEIA2, security.AlgIDEEA2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mat.IntS, mustHex(t, "15020001020001")) {
		t.Fatalf("NAS-int S: got %x", mat.IntS)
	}
	if !bytes.Equal(mat.EncS, mustHex(t, "15010001020001")) {
		t.Fatalf("NAS-enc S: got %x", mat.EncS)
	}
	wantIntOut := mustHex(t, "7d2920fa2b9a746d9d7d75b0c29f1035ad456f2c7bf9d0721f27829803374162")
	wantEncOut := mustHex(t, "a195e306eec4aded7afa7968a3435943fc44e60fea8d5efe769da32490b6fbc6")
	if !bytes.Equal(mat.IntOut, wantIntOut) {
		t.Fatalf("NAS-int KDF out: got %x, want %x", mat.IntOut, wantIntOut)
	}
	if !bytes.Equal(mat.EncOut, wantEncOut) {
		t.Fatalf("NAS-enc KDF out: got %x, want %x", mat.EncOut, wantEncOut)
	}

	intFirst16 := mat.IntOut[:16]
	intLast16 := mat.IntOut[16:]
	encLast16 := mat.EncOut[16:]
	if !bytes.Equal(intLast16, mustHex(t, "ad456f2c7bf9d0721f27829803374162")) {
		t.Fatalf("KNASint last16: got %x", intLast16)
	}
	if !bytes.Equal(encLast16, mustHex(t, "fc44e60fea8d5efe769da32490b6fbc6")) {
		t.Fatalf("KNASenc last16: got %x", encLast16)
	}

	first16MAC, err := security.ComputeNASMAC(security.AlgIDEIA2, intFirst16, 0, 0, 1, nasMACInput)
	if err != nil {
		t.Fatal(err)
	}
	last16MAC, err := security.ComputeNASMAC(security.AlgIDEIA2, intLast16, 0, 0, 1, nasMACInput)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("NAS-int KDF out=%x first16=%x last16=%x", mat.IntOut, intFirst16, intLast16)
	t.Logf("EIA2 first16 MAC=%x last16 MAC=%x", first16MAC, last16MAC)
	if !bytes.Equal(first16MAC, mustHex(t, "85eec536")) {
		t.Fatalf("first16 MAC: got %x, want 85eec536", first16MAC)
	}
	if !bytes.Equal(last16MAC, mustHex(t, "527adda1")) {
		t.Fatalf("last16 MAC: got %x, want 527adda1", last16MAC)
	}
}

func TestSecurityModeCommandMACWithLoggedAIAKASME(t *testing.T) {
	kasme := mustHex(t, "b719fae292889557d664ca6cacf5007089575dd89d9fdc413c2b6cc4d01be8ee")
	plainSMC := mustHex(t, "075d220002f0704f085592843df71d8e7b")

	mat, err := security.DeriveNASKeyMaterial(kasme, security.AlgIDEIA2, security.AlgIDEEA2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mat.IntS, mustHex(t, "15020001020001")) {
		t.Fatalf("NAS-int KDF S: got %x", mat.IntS)
	}
	if !bytes.Equal(mat.IntOut, mustHex(t, "c1bbb4269b1252a91a44abf2572fe9f1f1de00ef865f125f624988e17e0e6b13")) {
		t.Fatalf("NAS-int KDF output: got %x", mat.IntOut)
	}

	knasInt := mat.IntOut[16:]
	nasMACInput := append([]byte{0x00}, plainSMC...)
	details, err := security.ComputeEIA2CMACDetails(knasInt, 0, 0, 1, nasMACInput)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(details.Input, mustHex(t, "000000000400000000075d220002f0704f085592843df71d8e7b")) {
		t.Fatalf("EIA2 input: got %x", details.Input)
	}
	t.Logf("KNASint=%x", knasInt)
	t.Logf("EIA2 input=%x", details.Input)
	t.Logf("AES-CMAC full=%x first4=%x last4=%x reversed_first4=%x reversed_last4=%x",
		details.Full, details.First4, details.Last4, details.ReversedFirst4, details.ReversedLast4)

	// With the KASME logged in the AIA, TS 33.401 EIA2 produces d8711078.
	// srsUE reported ae30f743 for the same NAS COUNT and SMC bytes, which
	// proves the UE was using different KASME material. The runtime fix is to
	// send S6a Visited-PLMN-Id in the serving-network/KASME byte order so the
	// HSS returns the same KASME the UE derives locally.
	want := mustHex(t, "d8711078")
	if !bytes.Equal(details.First4, want) {
		t.Fatalf("Security Mode Command MAC: got %x, want %x", details.First4, want)
	}
	if bytes.Equal(details.First4, mustHex(t, "ae30f743")) {
		t.Fatal("old AIA KASME unexpectedly matches the srsUE MAC; re-check the vector")
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

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}
