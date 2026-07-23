package s1ap

import (
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/nas/esm"
	"github.com/vectorcore/mme/internal/uecontext"
)

func TestT3485ProductionDuration(t *testing.T) {
	if t3485Duration != 8*time.Second {
		t.Fatalf("T3485 duration got %s, want 8s", t3485Duration)
	}
	if t3485MaxRetransmits != 4 {
		t.Fatalf("T3485 retransmissions got %d, want 4", t3485MaxRetransmits)
	}
}

func TestDefaultBearerAcceptStopsT3485(t *testing.T) {
	srv := newTestServer(&mockS11{})
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.PDNs["ims"] = &uecontext.PDNContext{APN: "ims", DefaultEBI: 6, ActivationTimerActive: true, ActivationTimerGeneration: 7}
	ue.Unlock()

	if err := srv.handleStandaloneBearerAccept(ue, &esm.ActivateDefaultEPSBearerContextAccept{EPSBearerID: 6}, zap.NewNop()); err != nil {
		t.Fatalf("handleStandaloneBearerAccept: %v", err)
	}
	ue.Lock()
	pdn := ue.PDNs["ims"]
	if pdn.ActivationTimerActive || pdn.ActivationTimerGeneration != 8 {
		ue.Unlock()
		t.Fatalf("T3485 was not invalidated: active=%v generation=%d", pdn.ActivationTimerActive, pdn.ActivationTimerGeneration)
	}
	ue.Unlock()
}

func TestDefaultBearerRejectStopsT3485AndCleansIMSPDN(t *testing.T) {
	mock := &mockS11{}
	srv := newTestServer(mock)
	ue := srv.ueManager.Allocate()
	mmeID := ue.MMEUES1APID
	ue.Lock()
	ue.PDNs["internet"] = &uecontext.PDNContext{APN: "internet", DefaultEBI: 5, NASAccepted: true, State: "active"}
	ue.PDNs["ims"] = &uecontext.PDNContext{
		APN: "ims", DefaultEBI: 6, SGWAddress: "10.90.250.59:2123", SGWC_TEID: 0x01020304,
		ActivationTimerActive: true, ActivationTimerGeneration: 4, State: "access-established",
	}
	ue.Unlock()

	if err := srv.handleStandaloneBearerReject(ue, &esm.BearerProcedureResponse{EPSBearerID: 6, Cause: 0x1f}, zap.NewNop()); err != nil {
		t.Fatalf("handleStandaloneBearerReject: %v", err)
	}
	if len(mock.dsrCalls) != 1 || mock.dsrCalls[0].EBI != 6 {
		t.Fatalf("Delete Session calls got %+v, want one IMS EBI 6 request", mock.dsrCalls)
	}
	ue.Lock()
	pdn := ue.PDNs["ims"]
	if pdn == nil || pdn.ActivationTimerActive || pdn.ActivationTimerGeneration != 5 || pdn.State != "pdn-disconnect-delete-session-pending" {
		ue.Unlock()
		t.Fatalf("IMS reject state got %+v", pdn)
	}
	ue.Unlock()

	srv.HandleDSRResult(mmeID, 6, nil)
	ue.Lock()
	_, imsPresent := ue.PDNs["ims"]
	internet := ue.PDNs["internet"]
	ue.Unlock()
	if imsPresent || internet == nil || !internet.NASAccepted {
		t.Fatalf("IMS cleanup affected PDNs: ims_present=%v internet=%+v", imsPresent, internet)
	}
}

func TestContextRemoveInvalidatesActivationTimers(t *testing.T) {
	srv := newTestServer(&mockS11{})
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.PDNs["ims"] = &uecontext.PDNContext{APN: "ims", DefaultEBI: 6, ActivationTimerActive: true, ActivationTimerGeneration: 2}
	ue.DedicatedBearers[7] = &uecontext.DedicatedBearerContext{AssignedEBI: 7, ActivationTimerActive: true, ActivationTimerGeneration: 3}
	ue.Unlock()
	srv.ueManager.Remove(ue)
	ue.Lock()
	pdn := ue.PDNs["ims"]
	proc := ue.DedicatedBearers[7]
	if pdn.ActivationTimerActive || pdn.ActivationTimerGeneration != 3 || proc.ActivationTimerActive || proc.ActivationTimerGeneration != 4 {
		ue.Unlock()
		t.Fatalf("terminal removal did not invalidate activation timers: pdn=%+v proc=%+v", pdn, proc)
	}
	ue.Unlock()
}
