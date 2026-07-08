package nas_test

import (
	"bytes"
	"testing"

	nas "github.com/vectorcore/mme/internal/nas"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/security"
)

func TestEncodeIntegrityProtectedUsesStandardSecurityHeader(t *testing.T) {
	plain := []byte{0x07, emm.MsgAttachAccept, 0x01}

	protected, err := nas.EncodeIntegrityProtected(plain, security.AlgIDEIA0, nil, 1)
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

	protected, err := nas.EncodeIntegrityProtectedNewEPSSecurityContext(plain, security.AlgIDEIA0, nil, 1)
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

func TestDecodeSecurityModeCompleteWithCipheredNewEPSSecurityContextHeader(t *testing.T) {
	inner := []byte{0x07, emm.MsgSecurityModeComplete}
	raw := append([]byte{
		emm.PDEPSMobilityMgmt | (emm.SecurityHeaderCipherNewEPSSecCtx << 4),
		0x00, 0x00, 0x00, 0x00,
		0x01,
	}, inner...)

	result, err := nas.Decode(raw, security.AlgIDEIA0, security.AlgIDEEA0, nil, nil, 1)
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
