package s1ap

import (
	"bytes"
	"testing"
	"time"

	"go.uber.org/zap"

	nas "github.com/vectorcore/mme/internal/nas"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"github.com/vectorcore/mme/internal/sgsap"
	"github.com/vectorcore/mme/internal/uecontext"
)

func TestProcessEMM_MOCSFBESRSendsProtectedRejectAndPreservesIMS(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "10.0.0.90:36412"
	ch := setupSendCapture(srv, remoteAddr)
	ue, _ := makeRegisteredUEWithNullKeys(srv, remoteAddr)
	ue.Lock()
	ue.PDNs["ims"] = &uecontext.PDNContext{APN: "ims", DefaultEBI: 6, State: "erab-setup-pending", NASAccepted: false, ERABEstablished: true}
	ue.PendingPDN = ue.PDNs["ims"]
	ue.DedicatedBearers[7] = &uecontext.DedicatedBearerContext{AssignedEBI: 7, LinkedEBI: 6, State: "activation-pending"}
	ue.DedicatedBearers[8] = &uecontext.DedicatedBearerContext{AssignedEBI: 8, LinkedEBI: 6, State: "activation-pending"}
	before := uint32(ue.DLNASCount)
	ue.Unlock()

	// service type 0 = mobile-originating CS fallback; a valid GUTI identity
	// follows. The connected handler must use the existing protected context.
	result := &nas.DecodeResult{MsgType: emm.MsgExtendedServiceRequest, Inner: []byte{0x00, 0x05, 0xf4, 0xaa, 0xbb, 0xcc, 0xdd}}
	if err := srv.processEMM(ue, result, 0); err != nil {
		t.Fatalf("processEMM: %v", err)
	}
	select {
	case sent := <-ch:
		nasPDU := decodeDownlinkNASFromRawPDU(t, sent)
		if len(nasPDU) < 9 || nasPDU[0]>>4 != 2 || nasPDU[6] != emm.PDEPSMobilityMgmt || nasPDU[7] != 0x4e || nasPDU[8] != emm.CauseCSDomainNotAvailable {
			t.Fatalf("protected Service Reject got %x", nasPDU)
		}
		if nasPDU[5] != byte(before) {
			t.Fatalf("Service Reject sequence got %d, want %d", nasPDU[5], before)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no Service Reject sent")
	}
	ue.Lock()
	defer ue.Unlock()
	if uint32(ue.DLNASCount) != before+1 || ue.PendingPDN == nil || ue.PDNs["ims"] == nil || ue.DedicatedBearers[7] == nil || ue.DedicatedBearers[8] == nil {
		t.Fatalf("CSFB reject changed IMS activation state or NAS count: pending=%v ims=%v ebi7=%v ebi8=%v count=%d", ue.PendingPDN, ue.PDNs["ims"], ue.DedicatedBearers[7], ue.DedicatedBearers[8], ue.DLNASCount)
	}
}

func TestInitialUEMOCSFBESRRejectPreservesAuthoritativeUE(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "10.0.0.91:36412"
	ch := setupSendCapture(srv, remoteAddr)
	realUE, guti := makeRegisteredUEWithNullKeys(srv, remoteAddr)
	realUE.Lock()
	realUE.SetECMState(emm.ECMIdle)
	realUE.PDNs["ims"] = &uecontext.PDNContext{APN: "ims", DefaultEBI: 6, State: "active", NASAccepted: true}
	realUE.Unlock()
	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBGlobalID = remoteAddr
	tempUE.ENBS1APID = 77
	tempUE.Unlock()
	body := append([]byte{0x00}, guti.Encode()...)
	srv.handleInitialUEExtendedServiceRequest(tempUE, nil, body, append([]byte{emm.PDEPSMobilityMgmt, emm.MsgExtendedServiceRequest}, body...))
	select {
	case sent := <-ch:
		nasPDU := decodeDownlinkNASFromRawPDU(t, sent)
		if len(nasPDU) < 9 || nasPDU[7] != emm.MsgServiceReject || nasPDU[8] != emm.CauseCSDomainNotAvailable {
			t.Fatalf("idle protected Service Reject got %x", nasPDU)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no idle Service Reject sent")
	}
	realUE.Lock()
	defer realUE.Unlock()
	if realUE.PDNs["ims"] == nil || realUE.EMMState != emm.StateRegistered || realUE.ECMState != emm.ECMIdle {
		t.Fatalf("idle CSFB reject mutated authoritative UE: ims=%v emm=%s ecm=%s", realUE.PDNs["ims"], realUE.EMMState, realUE.ECMState)
	}
}

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

func TestProcessEMM_MTCSFBExtendedServiceRequestCompletesSGsPaging(t *testing.T) {
	srv, fake := sgsTestServer()
	const remoteAddr = "10.0.0.91:36412"
	setupSendCapture(srv, remoteAddr)
	ue, _ := makeRegisteredUEWithNullKeys(srv, remoteAddr)
	ue.Lock()
	ue.IMSI = "001010123456789"
	ue.SGsPendingPaging = &uecontext.SGsPagingContext{VLRName: "vlr-1", ServiceIndicator: 1}
	ue.Unlock()
	srv.ueManager.Register(ue)

	// byte0 = (ksi<<4)|serviceType; serviceType=1 is mobile terminating CS
	// fallback (TS 24.301 §9.9.3.27 table 9.9.3.27.1).
	result := &nas.DecodeResult{MsgType: emm.MsgExtendedServiceRequest, Inner: []byte{0x01, 0x05, 0xf4, 0xaa, 0xbb, 0xcc, 0xdd}}
	if err := srv.processEMM(ue, result, 0); err != nil {
		t.Fatalf("processEMM: %v", err)
	}

	fake.mu.Lock()
	got := fake.lastServiceRequest
	fake.mu.Unlock()
	if got == nil || got.IMSI != ue.IMSI || got.UEEMMMode != sgsap.UEEMMModeConnected {
		t.Fatalf("expected SERVICE-REQUEST sent to VLR after MT CSFB ESR, got %+v", got)
	}
	ue.Lock()
	pending := ue.SGsPendingPaging
	ue.Unlock()
	if pending != nil {
		t.Fatalf("expected SGs pending paging cleared, got %+v", pending)
	}
}

func TestProcessEMM_MOCSFBExtendedServiceRequestWithSGsAssociationSignalsRealCSFB(t *testing.T) {
	srv, fake := sgsTestServer()
	const remoteAddr = "10.0.0.92:36412"
	ch := setupSendCapture(srv, remoteAddr)
	ue, _ := makeRegisteredUEWithNullKeys(srv, remoteAddr)
	ue.Lock()
	ue.IMSI = "001010123456789"
	ue.ENBS1APID = 0x010209
	ue.SGsState = uecontext.SGsUEAssociated
	ue.SGsVLRName = "vlr-1"
	ue.Unlock()

	// service type 0 = mobile-originating CS fallback.
	result := &nas.DecodeResult{MsgType: emm.MsgExtendedServiceRequest, Inner: []byte{0x00, 0x05, 0xf4, 0xaa, 0xbb, 0xcc, 0xdd}}
	if err := srv.processEMM(ue, result, 0); err != nil {
		t.Fatalf("processEMM: %v", err)
	}

	fake.mu.Lock()
	gotSR := fake.lastServiceRequest
	gotInd := fake.lastMOCSFBIndication
	fake.mu.Unlock()
	if gotSR == nil || gotSR.IMSI != ue.IMSI || gotSR.ServiceIndicator != sgsap.ServiceIndicatorCSCall {
		t.Fatalf("expected CS-call SERVICE-REQUEST sent to VLR for MO CSFB, got %+v", gotSR)
	}
	if gotInd == nil || gotInd.IMSI != ue.IMSI {
		t.Fatalf("expected MO-CSFB-INDICATION sent to VLR, got %+v", gotInd)
	}

	msg := readCapturedPDU(t, ch)
	ieList, err := pdu.DecodeIEContainer(msg.Value)
	if err != nil {
		t.Fatalf("DecodeIEContainer: %v", err)
	}
	found := false
	for _, ie := range ieList {
		if ie.ID == pdu.IECSFallbackIndicator {
			found = true
			if !bytes.Equal(ie.Value, ies.EncodeCSFallbackIndicator()) {
				t.Fatalf("CS Fallback Indicator value = %x", ie.Value)
			}
		}
	}
	if !found {
		t.Fatal("expected CS Fallback Indicator IE in UE Context Modification Request for MO CSFB")
	}
}

func TestProcessEMM_MOCSFBExtendedServiceRequestWithoutSGsAssociationFallsBackToReject(t *testing.T) {
	srv, _ := sgsTestServer()
	const remoteAddr = "10.0.0.93:36412"
	ch := setupSendCapture(srv, remoteAddr)
	ue, _ := makeRegisteredUEWithNullKeys(srv, remoteAddr)
	ue.Lock()
	ue.IMSI = "001010123456789"
	// SGs is enabled at the server level, but this UE has never associated.
	ue.SGsState = uecontext.SGsUENull
	ue.Unlock()

	result := &nas.DecodeResult{MsgType: emm.MsgExtendedServiceRequest, Inner: []byte{0x00, 0x05, 0xf4, 0xaa, 0xbb, 0xcc, 0xdd}}
	if err := srv.processEMM(ue, result, 0); err != nil {
		t.Fatalf("processEMM: %v", err)
	}
	select {
	case sent := <-ch:
		nasPDU := decodeDownlinkNASFromRawPDU(t, sent)
		if len(nasPDU) < 9 || nasPDU[7] != emm.MsgServiceReject || nasPDU[8] != emm.CauseCSDomainNotAvailable {
			t.Fatalf("expected protected Service Reject for unassociated MO CSFB, got %x", nasPDU)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no Service Reject sent")
	}
}
