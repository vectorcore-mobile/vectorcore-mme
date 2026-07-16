package s1ap

import (
	nas "github.com/vectorcore/mme/internal/nas"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/uecontext"
	"go.uber.org/zap"
	"testing"
)

func TestProcessEMM_ExtendedServiceRequestDoesNotPromoteSinglePendingDefaultBearer(t *testing.T) {
	srv := newTAUTestServer()
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070573"
	ue.PDNs = map[string]*uecontext.PDNContext{
		"ims": {
			APN:                  "ims",
			DefaultEBI:           6,
			NASAccepted:          false,
			ERABEstablished:      true,
			ModifyBearerSent:     false,
			ModifyBearerAccepted: false,
			State:                "erab-setup-pending",
		},
	}
	ue.Unlock()

	result := &nas.DecodeResult{
		MsgType: emm.MsgExtendedServiceRequest,
		Inner:   []byte{0x00, 0x05, 0xf4, 0x2c, 0xfc, 0x75, 0xfd, 0x57, 0x02, 0x20, 0x00},
	}
	if err := srv.processEMM(ue, result, 0); err != nil {
		t.Fatalf("processEMM: %v", err)
	}

	ue.Lock()
	defer ue.Unlock()
	pdn := ue.PDNs["ims"]
	if pdn == nil {
		t.Fatal("IMS PDN missing")
	}
	if pdn.NASAccepted {
		t.Fatal("NASAccepted=true, want false")
	}
	if pdn.State != "erab-setup-pending" {
		t.Fatalf("state got %q, want erab-setup-pending", pdn.State)
	}
}

func TestProcessEMM_ExtendedServiceRequestDoesNotPromotePendingIMSPDNEarly(t *testing.T) {
	srv := newTAUTestServer()
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070573"
	ue.PendingPDN = &uecontext.PDNContext{
		APN:                    "ims",
		ProcedureTransactionID: 2,
		DefaultEBI:             6,
		NASAccepted:            false,
		State:                  "csr-sent",
	}
	ue.Unlock()

	result := &nas.DecodeResult{
		MsgType: emm.MsgExtendedServiceRequest,
		Inner:   []byte{0x00, 0x05, 0xf4, 0x30, 0x91, 0xf1, 0x29, 0x57, 0x02, 0x20, 0x00},
	}
	if err := srv.processEMM(ue, result, 0); err != nil {
		t.Fatalf("processEMM: %v", err)
	}

	ue.Lock()
	defer ue.Unlock()
	if ue.PendingPDN == nil {
		t.Fatal("PendingPDN missing")
	}
	if ue.PendingPDN.NASAccepted {
		t.Fatal("PendingPDN.NASAccepted=true, want false")
	}
	if ue.PendingPDN.State != "csr-sent" {
		t.Fatalf("PendingPDN state got %q, want csr-sent", ue.PendingPDN.State)
	}
}

func TestProcessExtendedServiceRequestDoesNotPromoteAmbiguousDefaultBearers(t *testing.T) {
	srv := newTAUTestServer()
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070573"
	ue.PDNs = map[string]*uecontext.PDNContext{
		"ims": {
			APN:                  "ims",
			DefaultEBI:           6,
			NASAccepted:          false,
			ERABEstablished:      true,
			ModifyBearerAccepted: false,
		},
		"hos": {
			APN:                  "hos",
			DefaultEBI:           7,
			NASAccepted:          false,
			ERABEstablished:      true,
			ModifyBearerAccepted: false,
		},
	}
	ue.Unlock()

	if err := srv.processExtendedServiceRequest(ue, []byte{0x00}, zap.NewNop()); err != nil {
		t.Fatalf("processExtendedServiceRequest: %v", err)
	}

	ue.Lock()
	defer ue.Unlock()
	if ue.PDNs["ims"].NASAccepted {
		t.Fatal("IMS NASAccepted=true, want false")
	}
	if ue.PDNs["hos"].NASAccepted {
		t.Fatal("HOS NASAccepted=true, want false")
	}
}
