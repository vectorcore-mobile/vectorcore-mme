package s1ap

import (
	"testing"
	"time"

	"github.com/vectorcore/mme/internal/gateway"
	"github.com/vectorcore/mme/internal/gtpv2"
	"github.com/vectorcore/mme/internal/nas"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/esm"
	"github.com/vectorcore/mme/internal/uecontext"
)

func TestHandleULAResultWithSubscriberProfileRejectsAttachWhenPolicyIncomplete(t *testing.T) {
	mock := &capturingCSRS11{}
	srv := newTestServer(mock)
	const remoteAddr = "10.0.0.30:36412"
	ch := registerTestENBWithChan(srv, remoteAddr)

	ue := allocateTestUE(srv, remoteAddr, 0, false)
	ue.Lock()
	ue.AttachStep = uecontext.AttachStepWaitingULA
	mmeUEID := ue.MMEUES1APID
	ue.Unlock()

	profile := &gateway.SubscriberProfile{
		DefaultContextID: 1,
		APNs: map[string]gateway.APNConfiguration{
			"internet": {
				ContextIdentifier:    1,
				ServiceSelection:     "internet",
				PDNType:              gtpv2.PDNTypeIPv4,
				QCI:                  9,
				ARPPriority:          8,
				APNAMBRDown:          512,
				APNAMBRUp:            384,
				PreemptionCapability: false,
			},
		},
		UEAMBRDown: 0,
		UEAMBRUp:   1024,
	}

	srv.HandleULAResultWithSubscriberProfile(mmeUEID, "15551234567", profile, nil)

	if len(mock.csrCalls) != 0 {
		t.Fatalf("CSR calls got %d, want 0", len(mock.csrCalls))
	}

	var raw []byte
	select {
	case raw = <-ch:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no Attach Reject sent")
	}
	gotNAS := decodeDownlinkNASFromRawPDU(t, raw)
	if got, want := gotNAS[0], uint8(emm.PDEPSMobilityMgmt); got != want {
		t.Fatalf("NAS PD got %#x, want %#x", got, want)
	}
	if got, want := gotNAS[1], uint8(emm.MsgAttachReject); got != want {
		t.Fatalf("NAS msg type got %#x, want %#x", got, want)
	}
	if got, want := gotNAS[2], uint8(emm.CauseNetworkFailure); got != want {
		t.Fatalf("EMM cause got %#x, want %#x", got, want)
	}
	if _, ok := srv.ueManager.GetByMMEID(mmeUEID); ok {
		t.Fatal("UE still present after attach reject")
	}
}

func TestHandleULAResultWithSubscriberProfileRejectsAttachWhenWBEUTRANRestricted(t *testing.T) {
	mock := &capturingCSRS11{}
	srv := newTestServer(mock)
	const remoteAddr = "10.0.0.30:36412"
	ch := registerTestENBWithChan(srv, remoteAddr)

	ue := allocateTestUE(srv, remoteAddr, 0, false)
	ue.Lock()
	ue.AttachStep = uecontext.AttachStepWaitingULA
	mmeUEID := ue.MMEUES1APID
	ue.Unlock()

	profile := &gateway.SubscriberProfile{
		DefaultContextID: 1,
		APNs: map[string]gateway.APNConfiguration{
			"internet": {
				ContextIdentifier:    1,
				ServiceSelection:     "internet",
				PDNType:              gtpv2.PDNTypeIPv4,
				QCI:                  9,
				ARPPriority:          8,
				APNAMBRDown:          512,
				APNAMBRUp:            384,
				PreemptionCapability: false,
			},
		},
		UEAMBRDown:            256,
		UEAMBRUp:              1024,
		AccessRestrictionData: gateway.AccessRestrictWBEUTRAN,
	}

	srv.HandleULAResultWithSubscriberProfile(mmeUEID, "15551234567", profile, nil)

	if len(mock.csrCalls) != 0 {
		t.Fatalf("CSR calls got %d, want 0", len(mock.csrCalls))
	}

	var raw []byte
	select {
	case raw = <-ch:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no Attach Reject sent")
	}
	gotNAS := decodeDownlinkNASFromRawPDU(t, raw)
	if got, want := gotNAS[0], uint8(emm.PDEPSMobilityMgmt); got != want {
		t.Fatalf("NAS PD got %#x, want %#x", got, want)
	}
	if got, want := gotNAS[1], uint8(emm.MsgAttachReject); got != want {
		t.Fatalf("NAS msg type got %#x, want %#x", got, want)
	}
	if got, want := gotNAS[2], uint8(emm.CauseEPSServicesNotAllowed); got != want {
		t.Fatalf("EMM cause got %#x, want %#x", got, want)
	}
	if _, ok := srv.ueManager.GetByMMEID(mmeUEID); ok {
		t.Fatal("UE still present after attach reject")
	}
}

func TestProcessESM_PDNConnectivityRequestRejectsIncompletePolicy(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "10.0.0.31:36412"
	ch := setupSendCapture(srv, remoteAddr)

	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070574"
	ue.APN = "internet"
	ue.ENBGlobalID = remoteAddr
	ue.ENBS1APID = 231
	ue.KNASint = make([]byte, 16)
	ue.KNASenc = make([]byte, 16)
	ue.IntAlg = 0
	ue.EncAlg = 0
	ue.ECMState = emm.ECMConnected
	ue.SubscriberAPNs = []string{"ims"}
	ue.SubscriberAPNConfigs = map[string]uecontext.SubscriberAPNConfig{
		"ims": {
			ServiceSelection: "ims",
			PDNType:          gtpv2.PDNTypeIPv4,
			QCI:              5,
			ARPPriority:      6,
			APNAMBRUp:        256,
		},
	}
	ue.Unlock()

	result := &nas.DecodeResult{
		Plain: []byte{
			0x02, 0x01, esm.MsgPDNConnectivityRequest, 0x31,
			0x28, 0x04, 0x03, 'i', 'm', 's',
		},
	}
	if err := srv.processESM(ue, result, srv.log); err != nil {
		t.Fatalf("processESM: %v", err)
	}

	var raw []byte
	select {
	case raw = <-ch:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no PDN Connectivity Reject sent")
	}
	gotNAS := decodeDownlinkNASFromRawPDU(t, raw)
	if len(gotNAS) < 10 {
		t.Fatalf("protected NAS too short: %x", gotNAS)
	}
	plain := gotNAS[6:]
	if got, want := plain[2], uint8(esm.MsgPDNConnectivityReject); got != want {
		t.Fatalf("reject msg type got %#x, want %#x", got, want)
	}
	if got, want := plain[3], uint8(esm.ESMCauseRequestRejectedUnspecified); got != want {
		t.Fatalf("reject cause got %#x, want %#x", got, want)
	}

	ue.Lock()
	defer ue.Unlock()
	if ue.PendingPDN != nil {
		t.Fatalf("PendingPDN got %+v, want nil", ue.PendingPDN)
	}
}
