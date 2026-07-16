package emm_test

import (
	"testing"

	"github.com/vectorcore/mme/internal/nas/emm"
)

func TestDecodeExtendedServiceRequestTMSI(t *testing.T) {
	body := []byte{0x00, 0x05, 0xF4, 0x3F, 0xC8, 0x44, 0xD0, 0x57, 0x02, 0x20, 0x00}

	req, err := emm.DecodeExtendedServiceRequest(body)
	if err != nil {
		t.Fatalf("DecodeExtendedServiceRequest: %v", err)
	}
	if req.IdentityType != emm.IdentityTypeTMSI {
		t.Fatalf("IdentityType got %d, want %d", req.IdentityType, emm.IdentityTypeTMSI)
	}
	if req.MTMSI != 0x3FC844D0 {
		t.Fatalf("MTMSI got %#x, want 0x3fc844d0", req.MTMSI)
	}
	if req.ServiceType != 0 {
		t.Fatalf("ServiceType got %d, want 0", req.ServiceType)
	}
}
