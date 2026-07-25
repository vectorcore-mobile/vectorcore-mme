package emm_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/security"
)

// ── Identity ─────────────────────────────────────────────────────────────────

func TestEncodeIdentityRequestIMSI(t *testing.T) {
	b := emm.EncodeIdentityRequest(emm.IdentityTypeIMSI)
	want := []byte{0x07, 0x55, 0x01}
	if !bytes.Equal(b, want) {
		t.Fatalf("Identity Request: got %x, want %x", b, want)
	}
}

func TestEncodeAttachAcceptIncludesEPSNetworkFeatureSupport(t *testing.T) {
	tai := emm.TAI{PLMN: [3]byte{0x13, 0x51, 0x34}, TAC: 1}
	esm := []byte{0x52, 0x01, 0xd1, 0x21}
	features := &emm.EPSNetworkFeatureSupport{IMSVoiceOverPSSessionInS1Mode: true}
	got := emm.EncodeAttachAcceptWithParams(emm.AttachAcceptParams{
		AttachResult:             emm.AttachTypeCombinedEPSAndIMSI,
		T3412:                    0x49,
		TAIList:                  []emm.TAI{tai},
		ESMContainer:             esm,
		EPSNetworkFeatureSupport: features,
	})
	wantSuffix := []byte{0x64, 0x01, 0x01}
	if !bytes.HasSuffix(got, wantSuffix) {
		t.Fatalf("Attach Accept got %x, want EPS Network Feature Support suffix %x", got, wantSuffix)
	}
}

func TestEncodeAttachAcceptCiscoSGdCombinedPolicy(t *testing.T) {
	tai := emm.TAI{PLMN: [3]byte{0x13, 0x51, 0x34}, TAC: 1}
	noAdditionalInfo := uint8(0)
	got := emm.EncodeAttachAcceptWithParams(emm.AttachAcceptParams{
		AttachResult:             emm.AttachTypeCombinedEPSAndIMSI,
		T3412:                    0x49,
		TAIList:                  []emm.TAI{tai},
		ESMContainer:             []byte{0x52, 0x01, 0xd1, 0x21},
		EPSNetworkFeatureSupport: &emm.EPSNetworkFeatureSupport{IMSVoiceOverPSSessionInS1Mode: true},
		AdditionalUpdateResult:   &noAdditionalInfo,
	})
	// External Cisco field model: result 2, EPS network feature support, F0;
	// no LAI (13/05) and no SMS-only F2.
	if got[2]&0x07 != emm.AttachTypeCombinedEPSAndIMSI || !bytes.HasSuffix(got, []byte{0x64, 0x01, 0x01, 0xf0}) {
		t.Fatalf("Cisco-compatible combined Attach fields got %x", got)
	}
	if bytes.Contains(got, []byte{0x13, 0x05}) || bytes.Contains(got, []byte{0xf2}) {
		t.Fatalf("combined Attach unexpectedly included LAI or F2: %x", got)
	}
}

func TestEncodeEPSNetworkFeatureSupportIMSVoiceOverPS(t *testing.T) {
	got := emm.EncodeEPSNetworkFeatureSupport(emm.EPSNetworkFeatureSupport{
		IMSVoiceOverPSSessionInS1Mode: true,
	})
	want := []byte{0x64, 0x01, 0x01}
	if !bytes.Equal(got, want) {
		t.Fatalf("EPS Network Feature Support got %x, want %x", got, want)
	}
}

func TestDecodeIdentityResponseIMSI(t *testing.T) {
	const imsi = "001010123456789"
	mobileID := emm.EPSMobileIdentityIMSI(imsi)
	body := append([]byte{byte(len(mobileID))}, mobileID...)

	resp, err := emm.DecodeIdentityResponse(body)
	if err != nil {
		t.Fatalf("DecodeIdentityResponse: %v", err)
	}
	if resp.IdentityType != emm.IdentityTypeIMSI {
		t.Fatalf("IdentityType: got %d, want %d", resp.IdentityType, emm.IdentityTypeIMSI)
	}
	if resp.IMSI != imsi {
		t.Fatalf("IMSI: got %q, want %q", resp.IMSI, imsi)
	}
}

// ── Authentication ────────────────────────────────────────────────────────────

func TestEncodeAuthenticationRequest(t *testing.T) {
	rand := make([]byte, 16)
	autn := make([]byte, 16)
	for i := range rand {
		rand[i] = byte(0xAA + i)
		autn[i] = byte(0x11 + i)
	}

	b, err := emm.EncodeAuthenticationRequest(0x01, rand, autn)
	if err != nil {
		t.Fatalf("encode error: %v", err)
	}
	// 2 header + 1 KSI + 16 RAND + 1 AUTN-length + 16 AUTN = 36
	if len(b) != 36 {
		t.Fatalf("length: got %d, want 36", len(b))
	}

	// Byte 0: PD=0x07 (EMM), security header=0x00 (plain) → 0x07
	if b[0] != emm.PDEPSMobilityMgmt {
		t.Errorf("byte[0] PD: got %#x, want %#x", b[0], emm.PDEPSMobilityMgmt)
	}
	// Byte 1: message type
	if b[1] != emm.MsgAuthenticationRequest {
		t.Errorf("byte[1] msg type: got %#x, want %#x", b[1], emm.MsgAuthenticationRequest)
	}
	// Byte 2: NAS KSI
	if b[2] != 0x01 {
		t.Errorf("byte[2] KSI: got %#x, want 0x01", b[2])
	}
	// Bytes 3..18: RAND
	if !bytes.Equal(b[3:19], rand) {
		t.Errorf("RAND mismatch")
	}
	// Byte 19: AUTN length = 0x10 (16)
	if b[19] != 0x10 {
		t.Errorf("AUTN length byte: got %#x, want 0x10", b[19])
	}
	// Bytes 20..35: AUTN
	if !bytes.Equal(b[20:36], autn) {
		t.Errorf("AUTN mismatch")
	}
}

func TestEncodeAuthenticationRequest_InvalidLengths(t *testing.T) {
	_, err := emm.EncodeAuthenticationRequest(0, make([]byte, 8), make([]byte, 16))
	if err == nil {
		t.Error("expected error for 8-byte RAND, got nil")
	}
	_, err = emm.EncodeAuthenticationRequest(0, make([]byte, 16), make([]byte, 4))
	if err == nil {
		t.Error("expected error for 4-byte AUTN, got nil")
	}
}

func TestDecodeAuthenticationResponse(t *testing.T) {
	res := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x42}
	// LV: length(1) + value
	data := append([]byte{byte(len(res))}, res...)

	resp, err := emm.DecodeAuthenticationResponse(data)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if !bytes.Equal(resp.RES, res) {
		t.Errorf("RES: got %x, want %x", resp.RES, res)
	}
}

func TestEncodeAuthenticationReject(t *testing.T) {
	b := emm.EncodeAuthenticationReject()
	if len(b) != 2 {
		t.Fatalf("length: got %d, want 2", len(b))
	}
	if b[0] != emm.PDEPSMobilityMgmt {
		t.Errorf("byte[0] PD: got %#x, want %#x", b[0], emm.PDEPSMobilityMgmt)
	}
	if b[1] != emm.MsgAuthenticationReject {
		t.Errorf("byte[1] msg type: got %#x, want %#x", b[1], emm.MsgAuthenticationReject)
	}
}

func TestSecurityModeCommandWithHashMME(t *testing.T) {
	attachRequest := mustHex(t, "21170876eb9d010741010bf613513400140ac000000502f07000050201d011d191e0")
	hashMME := security.HashMME(attachRequest)
	wantHash := mustHex(t, "4caba3d8e98b6958")
	if !bytes.Equal(hashMME, wantHash) {
		t.Fatalf("HashMME: got %x, want %x", hashMME, wantHash)
	}

	smc := emm.EncodeSecurityModeCommandWithHashMME(2, 2, []byte{0xf0, 0x70}, hashMME)
	want := mustHex(t, "075d220002f0704f084caba3d8e98b6958")
	if !bytes.Equal(smc, want) {
		t.Fatalf("SMC with HashMME: got %x, want %x", smc, want)
	}
}

func TestSecurityModeCommandWithExplicitKSI(t *testing.T) {
	smc := emm.EncodeSecurityModeCommandWithKSIAndHashMME(2, 2, 5, []byte{0xf0, 0x70}, nil)
	want := mustHex(t, "075d220502f070")
	if !bytes.Equal(smc, want) {
		t.Fatalf("SMC with explicit KSI: got %x, want %x", smc, want)
	}
}

func TestSecurityModeCommandIMEISVRequest(t *testing.T) {
	got := emm.EncodeSecurityModeCommandWithKSIHashAndIMEISVRequest(2, 2, 0, []byte{0xf0, 0x70}, nil, true)
	if got[len(got)-1] != 0xc1 {
		t.Fatalf("IMEISV request IE got %x, want c1", got[len(got)-1])
	}
}

func TestDecodeSecurityModeCompleteCapturedIMEISV(t *testing.T) {
	// Captured SMC optional IE: 23 09 03 51 90 03 50 41 19 16 f8.
	smc, err := emm.DecodeSecurityModeComplete([]byte{0x23, 0x09, 0x03, 0x51, 0x90, 0x03, 0x50, 0x41, 0x19, 0x16, 0xf8})
	if err != nil {
		t.Fatal(err)
	}
	got, err := emm.DecodeEquipmentIdentity(smc.IMEISV)
	if err != nil || got != "0150930051491618" {
		t.Fatalf("got %q, err=%v", got, err)
	}
}

func TestAttachRejectIMEINotAccepted(t *testing.T) {
	got := emm.EncodeAttachReject(emm.CauseIMEINotAccepted)
	want := []byte{0x07, emm.MsgAttachReject, emm.CauseIMEINotAccepted}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestReplayedUESecurityCapabilityFromUENetworkCapability(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "eps only srsue",
			in:   "f070",
			want: "f070",
		},
		{
			name: "real ue extra eps capability octet is not gea",
			in:   "f0f0e0e01d",
			want: "f0f0e060",
		},
		{
			name: "real ue uea uia",
			in:   "f070c04019",
			want: "f070c040",
		},
		{
			name: "real ue fifth eps capability octet is not gea",
			in:   "f0f0c04009",
			want: "f0f0c040",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := emm.ReplayedUESecurityCapabilityFromUENetworkCapability(mustHex(t, tt.in))
			want := mustHex(t, tt.want)
			if !bytes.Equal(got, want) {
				t.Fatalf("replayed UE security cap: got %x, want %x", got, want)
			}
		})
	}
}

func TestSecurityModeCommandUsesReplayedUESecurityCapability(t *testing.T) {
	hashMME := mustHex(t, "8f5b0baf1fa722e9")
	ueNetCap := mustHex(t, "f0f0e0e01d")
	replayed := emm.ReplayedUESecurityCapabilityFromUENetworkCapability(ueNetCap)

	smc := emm.EncodeSecurityModeCommandWithHashMME(2, 2, replayed, hashMME)
	want := mustHex(t, "075d220004f0f0e0604f088f5b0baf1fa722e9")
	if !bytes.Equal(smc, want) {
		t.Fatalf("SMC with replayed UE security cap: got %x, want %x", smc, want)
	}
}

func TestReplayedUESecurityCapabilityUsesMSNetworkCapabilityGEA(t *testing.T) {
	ueNetCap := mustHex(t, "f0f0c04009")
	msNetCap := mustHex(t, "65a07e")
	got := emm.ReplayedUESecurityCapability(ueNetCap, msNetCap)
	want := mustHex(t, "f0f0c04010")
	if !bytes.Equal(got, want) {
		t.Fatalf("replayed UE security cap with MS network cap: got %x, want %x", got, want)
	}
}

func TestSecurityModeCommandUsesMSNetworkCapabilityGEA(t *testing.T) {
	hashMME := mustHex(t, "0bb2947672b4062e")
	ueNetCap := mustHex(t, "f0f0c04009")
	msNetCap := mustHex(t, "65a07e")
	replayed := emm.ReplayedUESecurityCapability(ueNetCap, msNetCap)

	smc := emm.EncodeSecurityModeCommandWithHashMME(2, 2, replayed, hashMME)
	want := mustHex(t, "075d220005f0f0c040104f080bb2947672b4062e")
	if !bytes.Equal(smc, want) {
		t.Fatalf("SMC with five-byte replayed UE security cap: got %x, want %x", smc, want)
	}
}

func TestDecodeAttachRequestCapturesMSNetworkCapability(t *testing.T) {
	plainAttach := mustHex(t, "0741620bf61351347fa601c100980605f0f0c0400900200236d011271a8080211001010010810600000000830600000000000d000010005213513400015c0803310365a07e901103571882200a60140462918100127e00400800021f00040240045d0103e0c1")
	req, err := emm.DecodeAttachRequest(plainAttach[2:])
	if err != nil {
		t.Fatalf("DecodeAttachRequest: %v", err)
	}
	wantUE := mustHex(t, "f0f0c04009")
	if !bytes.Equal(req.UENetworkCapability, wantUE) {
		t.Fatalf("UE network capability: got %x, want %x", req.UENetworkCapability, wantUE)
	}
	wantMS := mustHex(t, "65a07e")
	if !bytes.Equal(req.MSNetworkCapability, wantMS) {
		t.Fatalf("MS network capability: got %x, want %x", req.MSNetworkCapability, wantMS)
	}
}

// ── Attach ────────────────────────────────────────────────────────────────────

func TestDecodeAttachRequest_WithIMSI(t *testing.T) {
	// Build a minimal attach request body (after the 2-byte header):
	// byte 0: AttachType(EPS=0x01) | NASKeySetIdentifier(no key=0x07)<<4 → 0x71
	// byte 1: mobile identity length (9 for a 15-digit IMSI)
	// bytes 2-10: IMSI encoding:
	//   byte 2: identity type(1=IMSI) | (IMSI digit 1)<<4 | 0x09 (odd length, type IMSI)
	//   Example IMSI 204950000000001:
	//     digit string: 2,0,4,9,5,0,0,0,0,0,0,0,0,0,1
	//     BCD: 0x02, 0x94, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01
	//     byte 2 (first byte of identity): 0x91 (type=001, odd, first digit 2)... wait
	//     Actually per 3GPP TS 24.008 §10.5.1.4:
	//       byte 0 of identity: bits 7:4 = digit 1, bit 3 = odd/even, bits 2:0 = identity type
	//       For IMSI 204950000000001 (15 digits, odd):
	//         first byte: 0x29 (digit1=2, odd=1, type=001)
	//         then BCD pairs: 04 95 00 00 00 00 01 (7 bytes for digits 2-15 with trailing F for even)
	//     Wait, 15 digits: odd parity. Length = ceil(15/2) + 1 = 9 bytes total.
	//     byte[0] = (digit_1 << 4) | (1 << 3) | 0x01 = 0x29
	//     then digits 2-15 in BCD: 04 95 00 00 00 00 01 → 7 bytes, no trailing F for odd length
	imsiIDLen := 9
	imsiIDBytes := []byte{
		0x29,                   // digit1=2, odd, type=IMSI(1)
		0x40, 0x59, 0x00, 0x00, // digits 3-4=04, 5-6=95, 7-8=00, 9-10=00
		0x00, 0x00, 0x00, 0x10, // digits 11-12=00, 13-14=00, 15=1 (with trailing F packed)
	}
	// Actually let me build this more carefully with a known IMSI.
	// IMSI 001010000000001 (15 digits):
	// digit string: 0,0,1,0,1,0,0,0,0,0,0,0,0,0,1
	// byte 0 of identity value: digit1=0, odd=1, type=1 → 0x09
	// then BCD: 10 (d2=1, d3=0), 01 (d4=0, d5=1), 00,00,00,00,10 → wait
	// Actually: digits in pairs after d1: (d2,d3)=10, (d4,d5)=01, (d6,d7)=00, (d8,d9)=00, (d10,d11)=00, (d12,d13)=00, (d14,d15)=01
	imsiIDBytes = []byte{
		0x09,       // digit1=0, odd, type=IMSI
		0x10, 0x01, // d2=1,d3=0 → 0x10; d4=0,d5=1 → 0x01
		0x00, 0x00, // d6-d9
		0x00, 0x00, // d10-d13
		0x00, 0x10, // d14=0, d15=1 → BCD pair (low=0,high=1) → 0x10
	}
	imsiIDLen = len(imsiIDBytes) // 9

	// NAS net capability: 2-byte LV (length 1, value 0xE0)
	netCapLen := 1
	netCapBytes := []byte{byte(netCapLen), 0xE0}

	// ESM container: 2-byte big-endian length + minimal PDN Connectivity Request
	// PDN Connectivity Request = 3 bytes minimum: PD+EBI, msg type, request type
	esmData := []byte{0x01, 0x08, 0xAB} // minimal ESM container
	esmContainer := append([]byte{0x00, byte(len(esmData))}, esmData...)

	body := make([]byte, 0, 32)
	body = append(body, 0x71) // AttachType=EPS|no-KSI
	body = append(body, byte(imsiIDLen))
	body = append(body, imsiIDBytes...)
	body = append(body, netCapBytes...)
	body = append(body, esmContainer...)

	ar, err := emm.DecodeAttachRequest(body)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if ar.AttachType != emm.AttachTypeEPSOnly {
		t.Errorf("AttachType: got %d, want %d (EPSOnly)", ar.AttachType, emm.AttachTypeEPSOnly)
	}
	if ar.IdentityType != emm.IdentityTypeIMSI {
		t.Errorf("IdentityType: got %d, want %d (IMSI)", ar.IdentityType, emm.IdentityTypeIMSI)
	}
	if ar.IMSI == "" {
		t.Errorf("IMSI should not be empty")
	}
}

func TestEncodeAttachAccept(t *testing.T) {
	tai := emm.TAI{PLMN: [3]byte{0x00, 0xF1, 0x10}, TAC: 0x0001}
	esm := []byte{0xAA, 0xBB, 0xCC}

	b := emm.EncodeAttachAccept(emm.AttachTypeEPSOnly, []emm.TAI{tai}, nil, esm)

	if len(b) < 10 {
		t.Fatalf("output too short: %d bytes", len(b))
	}
	// Byte 0: PD=EMM, security header=plain
	if b[0] != emm.PDEPSMobilityMgmt {
		t.Errorf("byte[0] PD: got %#x, want %#x", b[0], emm.PDEPSMobilityMgmt)
	}
	// Byte 1: message type = Attach Accept
	if b[1] != emm.MsgAttachAccept {
		t.Errorf("byte[1] msg type: got %#x, want %#x", b[1], emm.MsgAttachAccept)
	}
	// Byte 2: attach result
	if b[2] != emm.AttachTypeEPSOnly {
		t.Errorf("byte[2] attach result: got %#x, want %#x", b[2], emm.AttachTypeEPSOnly)
	}
}

func TestEncodeAttachAccept_WithGUTI(t *testing.T) {
	tai := emm.TAI{PLMN: [3]byte{0x00, 0xF1, 0x10}, TAC: 0x0007}
	esm := []byte{0x01, 0x02, 0x03}
	guti := &emm.GUTI{PLMN: [3]byte{0x00, 0xF1, 0x10}, MMEGI: 1, MMEC: 1, MTMSI: 0x11223344}

	b := emm.EncodeAttachAccept(emm.AttachTypeEPSOnly, []emm.TAI{tai}, guti, esm)
	if len(b) < 20 {
		t.Fatalf("output too short with GUTI: %d bytes", len(b))
	}

	// Check GUTI IEI 0x50 appears somewhere after the fixed fields
	found := false
	for i := 3; i < len(b); i++ {
		if b[i] == 0x50 {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("GUTI IEI 0x50 not found in Attach Accept")
	}
}

func TestEncodeAttachReject(t *testing.T) {
	const cause = uint8(0x0E) // #14 = EPS services not allowed
	b := emm.EncodeAttachReject(cause)

	if len(b) != 3 {
		t.Fatalf("length: got %d, want 3", len(b))
	}
	if b[0] != emm.PDEPSMobilityMgmt {
		t.Errorf("byte[0] PD: got %#x, want %#x", b[0], emm.PDEPSMobilityMgmt)
	}
	if b[1] != emm.MsgAttachReject {
		t.Errorf("byte[1] msg type: got %#x, want %#x", b[1], emm.MsgAttachReject)
	}
	if b[2] != cause {
		t.Errorf("byte[2] cause: got %#x, want %#x", b[2], cause)
	}
}

// ── Detach ────────────────────────────────────────────────────────────────────

func TestDecodeDetachRequest_Normal(t *testing.T) {
	// MO detach: byte 0 = DetachType(EPS=1) | SwitchOff=0 | NAS-KSI(7)<<4 = 0x71
	body := []byte{0x71}

	dr, err := emm.DecodeDetachRequest(body)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if dr == nil {
		t.Fatal("got nil DetachRequest")
	}
	if dr.DetachType != emm.DetachTypeNormal {
		t.Errorf("DetachType: got %d, want %d (normal)", dr.DetachType, emm.DetachTypeNormal)
	}
	if dr.SwitchOff {
		t.Errorf("SwitchOff should be false for type 0x01")
	}
}

func TestDecodeDetachRequest_SwitchOff(t *testing.T) {
	// Switch-off bit is bit 3: type=1(EPS), switch_off=1 → byte = 0x09
	body := []byte{0x09}

	dr, err := emm.DecodeDetachRequest(body)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if !dr.SwitchOff {
		t.Errorf("SwitchOff should be true for byte 0x09")
	}
}

func TestEncodeDetachAccept(t *testing.T) {
	b := emm.EncodeDetachAccept()
	if len(b) != 2 {
		t.Fatalf("length: got %d, want 2", len(b))
	}
	if b[0] != emm.PDEPSMobilityMgmt {
		t.Errorf("byte[0] PD: got %#x, want %#x", b[0], emm.PDEPSMobilityMgmt)
	}
	if b[1] != emm.MsgDetachAccept {
		t.Errorf("byte[1] msg type: got %#x, want %#x", b[1], emm.MsgDetachAccept)
	}
}

// ── Round-trip ────────────────────────────────────────────────────────────────

func TestAuthRequest_DecodeSecurityHeader(t *testing.T) {
	rand := make([]byte, 16)
	autn := make([]byte, 16)
	b, err := emm.EncodeAuthenticationRequest(0x05, rand, autn)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	// ParsePlainNASMessage should extract the message type
	msgType, payload, err := emm.ParsePlainNASMessage(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if msgType != emm.MsgAuthenticationRequest {
		t.Errorf("msgType: got %#x, want %#x", msgType, emm.MsgAuthenticationRequest)
	}
	// payload[0] = KSI, payload[1..16] = RAND, payload[17] = AUTN len, payload[18..33] = AUTN
	if len(payload) < 33 {
		t.Fatalf("payload too short: %d", len(payload))
	}
	if payload[0] != 0x05 {
		t.Errorf("KSI in payload: got %#x, want 0x05", payload[0])
	}
}

func TestDecodeAttachCompleteESMContainer(t *testing.T) {
	body := []byte{
		0x00, 0x03,
		0x52, 0x01, 0xc2,
	}
	got, err := emm.DecodeAttachComplete(body)
	if err != nil {
		t.Fatalf("DecodeAttachComplete: %v", err)
	}
	want := []byte{0x52, 0x01, 0xc2}
	if !bytes.Equal(got.ESMContainer, want) {
		t.Fatalf("ESM container got %x, want %x", got.ESMContainer, want)
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
