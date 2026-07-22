package nas

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/esm"
	"github.com/vectorcore/mme/internal/nas/security"
)

func TestEncodeIntegrityProtectedUsesStandardSecurityHeader(t *testing.T) {
	plain := []byte{0x07, emm.MsgAttachAccept, 0x01}

	protected, err := EncodeIntegrityProtected(plain, security.AlgIDEIA0, nil, 1)
	if err != nil {
		t.Fatalf("EncodeIntegrityProtected: %v", err)
	}
	if got, want := protected[0]>>4, emm.SecurityHeaderIntegrityProtected; got != want {
		t.Fatalf("security header: got %d, want %d", got, want)
	}
	if got, want := protected[0]&0x0f, emm.PDEPSMobilityMgmt; got != want {
		t.Fatalf("protocol discriminator: got %d, want %d", got, want)
	}
	if !bytes.Equal(protected[6:], plain) {
		t.Fatalf("inner plain NAS: got %x, want %x", protected[6:], plain)
	}
}

func TestEncodeIntegrityProtectedNewEPSSecurityContextUsesHeader3(t *testing.T) {
	plain := emm.EncodeSecurityModeCommand(security.AlgIDEIA0, security.AlgIDEEA0, []byte{0xe0, 0xe0})

	protected, err := EncodeIntegrityProtectedNewEPSSecurityContext(plain, security.AlgIDEIA0, nil, 1)
	if err != nil {
		t.Fatalf("EncodeIntegrityProtectedNewEPSSecurityContext: %v", err)
	}
	if got, want := protected[0]>>4, emm.SecurityHeaderNewEPSSecurityCtx; got != want {
		t.Fatalf("security header: got %d, want %d", got, want)
	}
	if got, want := protected[0]&0x0f, emm.PDEPSMobilityMgmt; got != want {
		t.Fatalf("protocol discriminator: got %d, want %d", got, want)
	}
	if !bytes.Equal(protected[6:], plain) {
		t.Fatalf("inner plain NAS: got %x, want %x", protected[6:], plain)
	}
}

func TestEncodeIntegrityAndCipheredEEA0UsesCipheredHeaderAndValidMAC(t *testing.T) {
	plain := []byte{0x07, emm.MsgAttachAccept, 0x01, 0x69}
	knasInt := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00}

	protected, err := EncodeIntegrityAndCiphered(plain, security.AlgIDEIA2, security.AlgIDEEA0, knasInt, nil, 7)
	if err != nil {
		t.Fatalf("EncodeIntegrityAndCiphered: %v", err)
	}
	if got, want := protected[0]>>4, emm.SecurityHeaderIntegrityAndCipher; got != want {
		t.Fatalf("security header: got %d, want %d", got, want)
	}
	if !bytes.Equal(protected[6:], plain) {
		t.Fatalf("EEA0 changed payload: got %x, want %x", protected[6:], plain)
	}
	if err := security.VerifyNASMAC(security.AlgIDEIA2, knasInt, 7, 0, 1, protected[5:], protected[1:5]); err != nil {
		t.Fatalf("VerifyNASMAC: %v", err)
	}
}

func TestEncodeIntegrityAndCipheredEEA2EncryptsAndValidatesMAC(t *testing.T) {
	plain := []byte{0x07, emm.MsgAttachAccept, 0x01, 0x69, 0xaa, 0xbb, 0xcc}
	knasInt := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00}
	knasEnc := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	protected, err := EncodeIntegrityAndCiphered(plain, security.AlgIDEIA2, security.AlgIDEEA2, knasInt, knasEnc, 7)
	if err != nil {
		t.Fatalf("EncodeIntegrityAndCiphered: %v", err)
	}
	if got, want := protected[0]>>4, emm.SecurityHeaderIntegrityAndCipher; got != want {
		t.Fatalf("security header: got %d, want %d", got, want)
	}
	if bytes.Equal(protected[6:], plain) {
		t.Fatal("EEA2 left payload unchanged")
	}
	if err := security.VerifyNASMAC(security.AlgIDEIA2, knasInt, 7, 0, 1, protected[5:], protected[1:5]); err != nil {
		t.Fatalf("VerifyNASMAC: %v", err)
	}
	decoded, err := security.CipherNAS(security.AlgIDEEA2, knasEnc, 7, 0, 1, protected[6:])
	if err != nil {
		t.Fatalf("CipherNAS (decrypt): %v", err)
	}
	if !bytes.Equal(decoded, plain) {
		t.Fatalf("decoded payload: got %x, want %x", decoded, plain)
	}
}

func TestDecodeSecurityModeCompleteWithCipheredNewEPSSecurityContextHeader(t *testing.T) {
	inner := []byte{0x07, emm.MsgSecurityModeComplete}
	raw := append([]byte{
		emm.PDEPSMobilityMgmt | (emm.SecurityHeaderCipherNewEPSSecCtx << 4),
		0x00, 0x00, 0x00, 0x00,
		0x01,
	}, inner...)

	result, err := Decode(raw, security.AlgIDEIA0, security.AlgIDEEA0, nil, nil, 1)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if result.SecHeaderType != emm.SecurityHeaderCipherNewEPSSecCtx {
		t.Fatalf("security header: got %d, want %d", result.SecHeaderType, emm.SecurityHeaderCipherNewEPSSecCtx)
	}
	if result.PD != emm.PDEPSMobilityMgmt {
		t.Fatalf("pd: got %d, want %d", result.PD, emm.PDEPSMobilityMgmt)
	}
	if result.MsgType != emm.MsgSecurityModeComplete {
		t.Fatalf("msg type: got %#x, want %#x", result.MsgType, emm.MsgSecurityModeComplete)
	}
}

func TestDecodePlainDispatchesEMMAndESMByInnerProtocolDiscriminator(t *testing.T) {
	tests := []struct {
		name    string
		hexPDU  string
		wantPD  uint8
		wantMsg uint8
	}{
		{
			name:    "EMM Attach Complete",
			hexPDU:  "074300035200c2",
			wantPD:  emm.PDEPSMobilityMgmt,
			wantMsg: emm.MsgAttachComplete,
		},
		{
			name:    "EMM TAU Request",
			hexPDU:  "074801",
			wantPD:  emm.PDEPSMobilityMgmt,
			wantMsg: emm.MsgTrackingAreaUpdateRequest,
		},
		{
			name:    "ESM IMS PDN Connectivity Request",
			hexPDU:  "0201d031280403696d7327238080211001010010810600000000830600000000000100000300000c00000d00001000",
			wantPD:  esm.PDEPSSessionMgmt,
			wantMsg: esm.MsgPDNConnectivityRequest,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := hex.DecodeString(tt.hexPDU)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Decode(raw, 0, 0, nil, nil, 0)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if got.PD != tt.wantPD {
				t.Fatalf("PD got %#x, want %#x", got.PD, tt.wantPD)
			}
			if got.MsgType != tt.wantMsg {
				t.Fatalf("MsgType got %#x, want %#x", got.MsgType, tt.wantMsg)
			}
		})
	}
}
