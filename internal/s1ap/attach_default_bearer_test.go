package s1ap

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/vectorcore/mme/internal/gtpv2"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/esm"
	"github.com/vectorcore/mme/internal/uecontext"
)

func TestProcessAttachCompletePromotesDefaultPDNState(t *testing.T) {
	mock := &capturingMBRS11{}
	srv := newTestServer(mock)

	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070572"
	ue.MSISDN = "16752012834"
	ue.APN = "internet"
	ue.DefaultEBI = 5
	ue.SGWAddress = "10.90.250.59:2123"
	ue.SGWC_TEID = 0xe25fbda7
	ue.ENBU_TEID = 0x1e91ff54
	ue.ENBU_IP = net.ParseIP("192.168.105.247").To4()
	ue.DLNASCount = 1
	ue.TAI = &emm.TAI{PLMN: [3]byte{0x13, 0x51, 0x34}, TAC: 1}
	ue.GUTI = &emm.GUTI{PLMN: [3]byte{0x13, 0x51, 0x34}, MMEGI: 1, MMEC: 1, MTMSI: 0xcedf65ea}
	ue.KNASint = make([]byte, 16)
	ue.KNASenc = make([]byte, 16)
	ue.IntAlg = 0
	ue.EncAlg = 0
	ue.PDNs = map[string]*uecontext.PDNContext{
		"internet": {
			APN:                    "internet",
			ProcedureTransactionID: 1,
			DefaultEBI:             5,
			LocalS11TEID:           1,
			SGWAddress:             "10.90.250.59:2123",
			SGWC_TEID:              0xe25fbda7,
			SGWU_TEID:              0x18e9c7ad,
			UEIPv4:                 net.ParseIP("100.64.0.234").To4(),
			ERABEstablished:        true,
			State:                  "activating",
		},
	}
	ue.Unlock()

	esmContainer := []byte{(5 << 4) | esm.PDEPSSessionMgmt, 0x00, esm.MsgActivateDefaultEPSBearerContextAccept}
	body := make([]byte, 2+len(esmContainer))
	binary.BigEndian.PutUint16(body[:2], uint16(len(esmContainer)))
	copy(body[2:], esmContainer)
	if err := srv.processAttachComplete(ue, body, srv.log); err != nil {
		t.Fatalf("processAttachComplete: %v", err)
	}

	ue.Lock()
	pdn := ue.PDNs["internet"]
	ue.Unlock()
	if pdn == nil {
		t.Fatal("internet PDN missing")
	}
	if !pdn.NASAccepted {
		t.Fatal("internet PDN NASAccepted=false, want true")
	}
	if !pdn.ModifyBearerSent {
		t.Fatal("internet PDN ModifyBearerSent=false, want true")
	}
	if pdn.ModifyBearerAccepted {
		t.Fatal("internet PDN ModifyBearerAccepted=true, want false before MBRsp")
	}
	if pdn.State != "modify-bearer-pending" {
		t.Fatalf("internet PDN state got %q, want modify-bearer-pending", pdn.State)
	}
	deadline := time.Now().Add(200 * time.Millisecond)
	for len(mock.calls) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if len(mock.calls) != 1 {
		t.Fatalf("MBR calls got %d, want 1", len(mock.calls))
	}
	if got := mock.calls[0].EBI; got != 5 {
		t.Fatalf("MBR EBI got %d, want 5", got)
	}
}

func TestInitialContextSetupResponsePromotesDefaultPDNAccessState(t *testing.T) {
	srv := newTAUTestServer()

	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.DefaultEBI = 5
	ue.PDNs = map[string]*uecontext.PDNContext{
		"internet": {
			APN:             "internet",
			DefaultEBI:      5,
			SGWU_TEID:       0x18e9c7ad,
			ERABEstablished: false,
			State:           "activating",
		},
	}
	ue.Unlock()

	srv.completeIMSDefaultERABSetupForBearer(ue, ERABSetupResult{
		EBI:        5,
		Success:    true,
		ENBS1UTEID: 0x1e91ff54,
		ENBS1UIPv4: net.ParseIP("192.168.105.247").To4(),
	}, srv.log)

	ue.Lock()
	pdn := ue.PDNs["internet"]
	ue.Unlock()
	if pdn == nil {
		t.Fatal("internet PDN missing")
	}
	if !pdn.ERABEstablished {
		t.Fatal("internet PDN ERABEstablished=false, want true")
	}
	if pdn.ENBU_TEID != 0x1e91ff54 {
		t.Fatalf("internet PDN ENBU_TEID got %#x, want %#x", pdn.ENBU_TEID, 0x1e91ff54)
	}
	if got := pdn.ENBU_IP.String(); got != "192.168.105.247" {
		t.Fatalf("internet PDN ENBU_IP got %s, want 192.168.105.247", got)
	}
}

func TestHandleMBRResultPromotesAttachDefaultPDNToActive(t *testing.T) {
	srv := newTestServer(&mockS11{})

	ue := srv.ueManager.Allocate()
	ue.Lock()
	mmeUEID := ue.MMEUES1APID
	ue.PDNs = map[string]*uecontext.PDNContext{
		"internet": {
			APN:                  "internet",
			DefaultEBI:           5,
			NASAccepted:          true,
			ERABEstablished:      true,
			ModifyBearerSent:     true,
			ModifyBearerAccepted: false,
			ModifyBearerFailed:   false,
			State:                "modify-bearer-pending",
		},
	}
	ue.Unlock()

	srv.HandleMBRResult(mmeUEID, "", &gtpv2.ModifyBearerResponse{Cause: gtpv2.CauseRequestAccepted}, nil)

	ue.Lock()
	pdn := ue.PDNs["internet"]
	ue.Unlock()
	if pdn == nil {
		t.Fatal("internet PDN missing")
	}
	if !pdn.ModifyBearerAccepted {
		t.Fatal("internet PDN ModifyBearerAccepted=false, want true")
	}
	if pdn.State != "active" {
		t.Fatalf("internet PDN state got %q, want active", pdn.State)
	}
}
