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
	mock := &initialAccessMBRS11{calls: make(chan gtpv2.ModifyBearerRequest, 1)}
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
	ue.ENBS1APID = 1
	ue.ENBGlobalID = "test-enb"
	ue.S1BindingGeneration = 1
	ue.S1BindingState = uecontext.S1BindingActive
	ue.SetECMState(emm.ECMConnected)
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
			SGWU_IP:                net.ParseIP("10.90.250.59").To4(),
			ENBU_TEID:              0x1e91ff54,
			ENBU_IP:                net.ParseIP("192.168.105.247").To4(),
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
	if got := requireInitialAccessMBR(t, mock.calls).EBI; got != 5 {
		t.Fatalf("MBR EBI got %d, want 5", got)
	}
}

type initialAccessMBRS11 struct {
	calls chan gtpv2.ModifyBearerRequest
}

func (m *initialAccessMBRS11) SendCSR(_ uint32, _ *gtpv2.CreateSessionRequest) error { return nil }
func (m *initialAccessMBRS11) SendDSR(_ uint32, _ *gtpv2.DeleteSessionRequest) error { return nil }
func (m *initialAccessMBRS11) SendMBR(_ uint32, req *gtpv2.ModifyBearerRequest) error {
	m.calls <- *req
	return nil
}

func initialAccessTestUE(srv *Server, nasAccepted, erabEstablished bool) *uecontext.Context {
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.DefaultEBI = 5
	ue.ENBS1APID = 1
	ue.ENBGlobalID = "test-enb"
	ue.S1BindingGeneration = 1
	ue.S1BindingState = uecontext.S1BindingActive
	ue.SetECMState(emm.ECMConnected)
	ue.PDNs = map[string]*uecontext.PDNContext{
		"internet": {
			APN:             "internet",
			DefaultEBI:      5,
			SGWAddress:      "10.90.250.59:2123",
			SGWC_TEID:       0xe25fbda7,
			SGWU_TEID:       0x18e9c7ad,
			SGWU_IP:         net.ParseIP("10.90.250.59").To4(),
			NASAccepted:     nasAccepted,
			ERABEstablished: erabEstablished,
			ENBU_TEID:       1,
			ENBU_IP:         net.ParseIP("192.168.105.6").To4(),
		},
	}
	ue.Unlock()
	return ue
}

func requireInitialAccessMBR(t *testing.T, calls <-chan gtpv2.ModifyBearerRequest) gtpv2.ModifyBearerRequest {
	t.Helper()
	select {
	case req := <-calls:
		return req
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timed out waiting for initial access Modify Bearer Request")
		return gtpv2.ModifyBearerRequest{}
	}
}

func requireNoInitialAccessMBR(t *testing.T, calls <-chan gtpv2.ModifyBearerRequest) {
	t.Helper()
	select {
	case req := <-calls:
		t.Fatalf("unexpected initial access Modify Bearer Request: %+v", req)
	case <-time.After(20 * time.Millisecond):
	}
}

func TestInitialAccessModifyBearerWaitsForBothAttachCompleteAndICS(t *testing.T) {
	t.Run("attach complete first", func(t *testing.T) {
		mock := &initialAccessMBRS11{calls: make(chan gtpv2.ModifyBearerRequest, 2)}
		srv := newTestServer(mock)
		ue := initialAccessTestUE(srv, true, false)

		srv.tryStartInitialAccessModifyBearer(ue, "attach-complete")
		requireNoInitialAccessMBR(t, mock.calls)

		ue.Lock()
		pdn := ue.PDNs["internet"]
		pdn.ERABEstablished = true
		ue.Unlock()
		srv.tryStartInitialAccessModifyBearer(ue, "initial-context-setup-response")
		req := requireInitialAccessMBR(t, mock.calls)
		if req.EBI != 5 || req.ENBU_TEID != 1 || req.ENBU_IP.String() != "192.168.105.6" || req.SGWC_TEID != 0xe25fbda7 {
			t.Fatalf("unexpected MBR: %+v", req)
		}
	})

	t.Run("ICS first", func(t *testing.T) {
		mock := &initialAccessMBRS11{calls: make(chan gtpv2.ModifyBearerRequest, 2)}
		srv := newTestServer(mock)
		ue := initialAccessTestUE(srv, false, true)

		srv.tryStartInitialAccessModifyBearer(ue, "initial-context-setup-response")
		requireNoInitialAccessMBR(t, mock.calls)
		ue.Lock()
		ue.PDNs["internet"].NASAccepted = true
		ue.Unlock()
		srv.tryStartInitialAccessModifyBearer(ue, "attach-complete")
		requireInitialAccessMBR(t, mock.calls)
	})
}

func TestInitialAccessModifyBearerIsIdempotentAndRejectsStaleBinding(t *testing.T) {
	mock := &initialAccessMBRS11{calls: make(chan gtpv2.ModifyBearerRequest, 4)}
	srv := newTestServer(mock)
	ue := initialAccessTestUE(srv, true, true)

	done := make(chan struct{}, 2)
	go func() { srv.tryStartInitialAccessModifyBearer(ue, "attach-complete"); done <- struct{}{} }()
	go func() {
		srv.tryStartInitialAccessModifyBearer(ue, "initial-context-setup-response")
		done <- struct{}{}
	}()
	<-done
	<-done
	requireInitialAccessMBR(t, mock.calls)
	requireNoInitialAccessMBR(t, mock.calls)

	ue.Lock()
	ue.PDNs["internet"].ModifyBearerSent = false
	ue.PDNs["internet"].State = "access-established"
	ue.S1BindingGeneration++
	ue.S1BindingState = uecontext.S1BindingReleased
	ue.Unlock()
	srv.tryStartInitialAccessModifyBearer(ue, "stale-ics-response")
	requireNoInitialAccessMBR(t, mock.calls)
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
