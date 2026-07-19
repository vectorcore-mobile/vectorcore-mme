package s1ap

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"reflect"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/gtpv2"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/security"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"github.com/vectorcore/mme/internal/uecontext"
)

// makeRegisteredIdleUE creates a UE in EMM-REGISTERED + ECM-IDLE with EIA0 security
// and a default bearer, registered in the manager under a known GUTI.
// Returns the UE and the MMEC/MTMSI values that form its S-TMSI.
func makeRegisteredIdleUE(srv *Server, remoteAddr string) (*uecontext.Context, uint8, uint32) {
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.ENBGlobalID = remoteAddr
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMIdle
	ue.IMSI = "001010099900001"
	ue.APN = "internet"
	ue.DefaultEBI = 5
	ue.SGWU_TEID = 0xAABB1122
	ue.SGWU_IP = net.ParseIP("10.99.0.1").To4()
	ue.SGWC_TEID = 0xCCDD3344
	ue.UEAMBRDown = 100000000
	ue.UEAMBRUp = 100000000
	ue.SubscriberAPNConfigs = map[string]uecontext.SubscriberAPNConfig{
		"internet": {
			ServiceSelection:        "internet",
			PDNType:                 gtpv2.PDNTypeIPv4,
			QCI:                     9,
			ARPPriority:             8,
			PreemptionCapability:    false,
			PreemptionVulnerability: true,
			APNAMBRDown:             100000,
			APNAMBRUp:               100000,
		},
		"ims": {
			ServiceSelection:        "ims",
			PDNType:                 gtpv2.PDNTypeIPv4,
			QCI:                     5,
			ARPPriority:             8,
			PreemptionCapability:    false,
			PreemptionVulnerability: true,
			APNAMBRDown:             100000,
			APNAMBRUp:               100000,
		},
	}
	ue.KNASint = make([]byte, 16) // EIA0 null key
	ue.KNASenc = make([]byte, 16)
	ue.IntAlg = 0
	ue.EncAlg = 0
	ue.KASME = make([]byte, 32) // required for DeriveKeNB in SendInitialContextSetup
	ue.Unlock()

	// MMEC=1, MTMSI=0xDEAD0001 — must match the server's own MMEC/MMEGI/PLMN
	const testMMEC uint8 = 1
	const testMTMSI uint32 = 0xDEAD0001
	guti := &emm.GUTI{
		PLMN:  [3]byte{0x00, 0xF1, 0x10}, // MCC=001, MNC=01
		MMEGI: 1,
		MMEC:  testMMEC,
		MTMSI: testMTMSI,
	}
	srv.ueManager.UpdateGUTI(ue, guti)
	return ue, testMMEC, testMTMSI
}

// buildSRPDU builds a 4-byte NAS Service Request PDU with EIA0 null MAC.
// SN must be > ULNASCount lower 5 bits to avoid the +0x20 wrap; SN=1 is safe for freshly
// allocated UEs (ULNASCount=0: count=1 > 0, MAC from EIA0 is {0,0,0,0}).
func buildSRPDU(sn uint8) []byte {
	return []byte{
		0xC7, // security header 0x0C | PD 0x07
		sn,   // KSI=0 | SN
		0x00, // ShortMAC high (EIA0 → 0)
		0x00, // ShortMAC low  (EIA0 → 0)
	}
}

// ── Tests ─────────────────────────────────────────────────────────────────────

func TestHandleServiceRequest_NoSTMSI(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.0.0.10:36412"
	ch := setupSendCapture(srv, addr)

	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 100
	tempUE.ENBGlobalID = addr
	tempUE.Unlock()

	before := srv.ueManager.Count()
	srv.handleServiceRequest(tempUE, 0, 0, nil, false /*stmsiPresent=false*/, nil, buildSRPDU(1))

	// Service Reject sent
	select {
	case <-ch:
	case <-time.After(100 * time.Millisecond):
		t.Error("no PDU sent for Service Reject")
	}
	// tempUE removed
	if srv.ueManager.Count() != before-1 {
		t.Errorf("manager count: got %d, want %d", srv.ueManager.Count(), before-1)
	}
}

func TestHandleServiceRequest_UnknownSTMSI(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.0.0.11:36412"
	ch := setupSendCapture(srv, addr)

	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 101
	tempUE.ENBGlobalID = addr
	tempUE.Unlock()

	before := srv.ueManager.Count()
	// MMEC/MTMSI not registered in the manager
	srv.handleServiceRequest(tempUE, 0xFE, 0xDEADFFFF, nil, true, nil, buildSRPDU(1))

	select {
	case <-ch:
	case <-time.After(100 * time.Millisecond):
		t.Error("no Service Reject sent for unknown S-TMSI")
	}
	if srv.ueManager.Count() != before-1 {
		t.Errorf("manager count: got %d, want %d", srv.ueManager.Count(), before-1)
	}
}

func TestHandleServiceRequest_AlreadyConnected(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.0.0.12:36412"
	ch := setupSendCapture(srv, addr)

	realUE, mmec, mtmsi := makeRegisteredIdleUE(srv, addr)
	// Override: UE already ECM-CONNECTED
	realUE.Lock()
	realUE.ECMState = emm.ECMConnected
	realUE.Unlock()

	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 102
	tempUE.ENBGlobalID = addr
	tempUE.Unlock()

	srv.handleServiceRequest(tempUE, mmec, mtmsi, nil, true, nil, buildSRPDU(1))

	select {
	case <-ch:
	case <-time.After(100 * time.Millisecond):
		t.Error("no Service Reject for already-connected UE")
	}
	// realUE should still be in the manager
	if _, ok := srv.ueManager.GetByMMEID(realUE.MMEUES1APID); !ok {
		t.Error("realUE was incorrectly removed from manager")
	}
}

func TestHandleServiceRequest_DuplicatePendingResumeRebindsAndRetransmitsICS(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.0.0.12b:36412"
	ch := setupSendCapture(srv, addr)

	realUE, mmec, mtmsi := makeRegisteredIdleUE(srv, addr)

	tempUE1 := srv.ueManager.Allocate()
	tempUE1.Lock()
	tempUE1.ENBS1APID = 202
	tempUE1.ENBGlobalID = addr
	tempUE1.Unlock()

	srv.handleServiceRequest(tempUE1, mmec, mtmsi, nil, true, nil, buildSRPDU(1))

	select {
	case first := <-ch:
		msg, err := pdu.Decode(first)
		if err != nil {
			t.Fatalf("decode first ICS PDU: %v", err)
		}
		if msg.Type != pdu.PDUTypeInitiatingMessage || msg.ProcedureCode != pdu.ProcInitialContextSetup {
			t.Fatalf("first PDU got type=%s proc=%d, want InitialContextSetup", msg.Type, msg.ProcedureCode)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no first Initial Context Setup sent for Service Request")
	}

	realUE.Lock()
	firstBindingGeneration := realUE.S1BindingGeneration
	firstSnapshotGeneration := realUE.KeNBSnapshotGeneration
	firstSnapshotULCount := realUE.KeNBULCount
	firstSnapshotKey := append([]byte(nil), realUE.KeNB...)
	realUE.Unlock()

	tempUE2 := srv.ueManager.Allocate()
	tempUE2.Lock()
	tempUE2.ENBS1APID = 203
	tempUE2.ENBGlobalID = addr
	tempUE2.Unlock()

	srv.handleServiceRequest(tempUE2, mmec, mtmsi, nil, true, nil, buildSRPDU(2))

	select {
	case second := <-ch:
		msg, err := pdu.Decode(second)
		if err != nil {
			t.Fatalf("decode retransmitted ICS PDU: %v", err)
		}
		if msg.Type != pdu.PDUTypeInitiatingMessage || msg.ProcedureCode != pdu.ProcInitialContextSetup {
			t.Fatalf("retransmit PDU got type=%s proc=%d, want InitialContextSetup", msg.Type, msg.ProcedureCode)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no retransmitted Initial Context Setup sent for duplicate Service Request")
	}

	realUE.Lock()
	defer realUE.Unlock()
	if realUE.ENBS1APID != 203 {
		t.Fatalf("ENBS1APID got %d, want 203", realUE.ENBS1APID)
	}
	if realUE.AttachStep != uecontext.AttachStepWaitingICSRespSR {
		t.Fatalf("AttachStep got %d, want WaitingICSRespSR", realUE.AttachStep)
	}
	if realUE.EMMState != emm.StateServiceRequestInitiated {
		t.Fatalf("EMMState got %v, want ServiceRequestInitiated", realUE.EMMState)
	}
	if realUE.S1BindingGeneration != firstBindingGeneration+1 {
		t.Fatalf("S1BindingGeneration got %d, want %d", realUE.S1BindingGeneration, firstBindingGeneration+1)
	}
	if realUE.KeNBSnapshotGeneration != realUE.S1BindingGeneration {
		t.Fatalf("KeNBSnapshotGeneration got %d, want %d", realUE.KeNBSnapshotGeneration, realUE.S1BindingGeneration)
	}
	if realUE.KeNBULCount != uint32(realUE.ULNASCount) {
		t.Fatalf("KeNBULCount got %d, want current ULNASCount %d", realUE.KeNBULCount, uint32(realUE.ULNASCount))
	}
	if realUE.KeNBSnapshotGeneration == firstSnapshotGeneration && realUE.KeNBULCount == firstSnapshotULCount {
		t.Fatal("duplicate Service Request reused stale AS security snapshot")
	}
	if bytes.Equal(realUE.KeNB, firstSnapshotKey) {
		t.Fatal("duplicate Service Request kept previous KeNB snapshot")
	}
}

func TestHandleServiceRequest_MissingBearer(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.0.0.13:36412"
	ch := setupSendCapture(srv, addr)

	realUE, mmec, mtmsi := makeRegisteredIdleUE(srv, addr)
	// Override: no bearer
	realUE.Lock()
	realUE.DefaultEBI = 0
	realUE.SGWU_TEID = 0
	realUE.Unlock()

	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 103
	tempUE.ENBGlobalID = addr
	tempUE.Unlock()

	srv.handleServiceRequest(tempUE, mmec, mtmsi, nil, true, nil, buildSRPDU(1))

	select {
	case <-ch:
	case <-time.After(100 * time.Millisecond):
		t.Error("no Service Reject for missing bearer")
	}
}

func TestHandleServiceRequest_InvalidMAC(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.0.0.14:36412"
	ch := setupSendCapture(srv, addr)

	_, mmec, mtmsi := makeRegisteredIdleUE(srv, addr)

	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 104
	tempUE.ENBGlobalID = addr
	tempUE.Unlock()

	// Wrong MAC bytes — EIA0 produces {0,0} but we send {0x01,0x02}
	badMAC := []byte{0xC7, 0x01, 0x01, 0x02}
	srv.handleServiceRequest(tempUE, mmec, mtmsi, nil, true, nil, badMAC)

	select {
	case <-ch:
	case <-time.After(100 * time.Millisecond):
		t.Error("no Service Reject for invalid MAC")
	}
}

func TestHandleServiceRequest_ValidKnownUE(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.0.0.15:36412"
	ch := setupSendCapture(srv, addr)

	realUE, mmec, mtmsi := makeRegisteredIdleUE(srv, addr)

	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 105
	tempUE.ENBGlobalID = addr
	tempUE.Unlock()

	countBefore := srv.ueManager.Count()
	srv.handleServiceRequest(tempUE, mmec, mtmsi, nil, true, nil, buildSRPDU(1))

	// ICS Request should be sent (tempUE removed, realUE still present)
	select {
	case <-ch:
	case <-time.After(200 * time.Millisecond):
		t.Error("no ICS Request PDU sent on valid Service Request")
	}

	// tempUE removed
	if srv.ueManager.Count() != countBefore-1 {
		t.Errorf("manager count: got %d, want %d (tempUE removed)", srv.ueManager.Count(), countBefore-1)
	}

	// realUE step set to WaitingICSRespSR
	realUE.Lock()
	step := realUE.AttachStep
	enbUEID := realUE.ENBS1APID
	realUE.Unlock()

	if step != uecontext.AttachStepWaitingICSRespSR {
		t.Errorf("AttachStep: got %d, want WaitingICSRespSR(%d)", step, uecontext.AttachStepWaitingICSRespSR)
	}
	if enbUEID != 105 {
		t.Errorf("ENBS1APID: got %d, want 105 (transferred from tempUE)", enbUEID)
	}
}

func TestHandleServiceRequest_ResumeICSCarriesRetainedBearers(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.0.0.18:36412"
	ch := setupSendCapture(srv, addr)

	realUE, mmec, mtmsi := makeRegisteredIdleUE(srv, addr)
	realUE.Lock()
	realUE.PDNs["ims"] = &uecontext.PDNContext{
		APN:                  "ims",
		DefaultEBI:           5,
		SGWU_TEID:            0xAABB1122,
		SGWU_IP:              net.ParseIP("10.99.0.1").To4(),
		ERABEstablished:      true,
		ModifyBearerAccepted: true,
		State:                "active",
	}
	realUE.DedicatedBearers[9] = &uecontext.DedicatedBearerContext{
		AssignedEBI:     9,
		LinkedEBI:       5,
		QCI:             1,
		ARP:             0x08,
		SGWS1UTEID:      0x11111111,
		SGWS1UIP:        net.ParseIP("10.99.0.2").To4(),
		ERABEstablished: true,
		State:           "active",
	}
	realUE.DedicatedBearers[10] = &uecontext.DedicatedBearerContext{
		AssignedEBI:     10,
		LinkedEBI:       5,
		QCI:             2,
		ARP:             0x10,
		SGWS1UTEID:      0x22222222,
		SGWS1UIP:        net.ParseIP("10.99.0.3").To4(),
		ERABEstablished: true,
		State:           "active",
	}
	realUE.Unlock()

	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 108
	tempUE.ENBGlobalID = addr
	tempUE.Unlock()

	srv.handleServiceRequest(tempUE, mmec, mtmsi, nil, true, nil, buildSRPDU(1))

	msg := readCapturedPDU(t, ch)
	if msg.Type != pdu.PDUTypeInitiatingMessage || msg.ProcedureCode != pdu.ProcInitialContextSetup {
		t.Fatalf("PDU got type=%s proc=%d, want InitialContextSetup", msg.Type, msg.ProcedureCode)
	}
	ieList, err := pdu.DecodeIEContainer(msg.Value)
	if err != nil {
		t.Fatalf("decode ICS IE list: %v", err)
	}
	var erabList []byte
	for _, ie := range ieList {
		if ie.ID == pdu.IENAS_PDU {
			t.Fatal("resume ICS unexpectedly included top-level NAS-PDU")
		}
		if ie.ID == pdu.IEERABToBeSetupListCtxtSUReq {
			erabList = ie.Value
		}
	}
	if len(erabList) == 0 {
		t.Fatal("resume ICS missing E-RABToBeSetupListCtxtSUReq")
	}
	items := decodeResumeICSErabList(t, erabList)
	if got, want := len(items), 1; got != want {
		t.Fatalf("resume ICS item count got %d, want %d", got, want)
	}
	gotEBIs := []uint8{items[0].EBI}
	wantEBIs := []uint8{5}
	for i := range wantEBIs {
		if gotEBIs[i] != wantEBIs[i] {
			t.Fatalf("resume ICS EBI[%d] got %d, want %d", i, gotEBIs[i], wantEBIs[i])
		}
		if items[i].NASPDUPresent {
			t.Fatalf("resume ICS item %d unexpectedly carried NAS-PDU", i)
		}
		if items[i].TransportAddressBits != 32 {
			t.Fatalf("resume ICS item %d transport bits got %d, want 32", i, items[i].TransportAddressBits)
		}
		if items[i].DecodedWithoutTrailingOctets != true {
			t.Fatalf("resume ICS item %d left trailing bytes undecoded", i)
		}
	}
	if items[0].QCI != 5 {
		t.Fatalf("resume ICS QCI got %d, want 5", items[0].QCI)
	}
	if items[0].ARPPriority != 8 {
		t.Fatalf("resume ICS ARP priority got %d, want 8", items[0].ARPPriority)
	}
	if items[0].PreemptionCapability || !items[0].PreemptionVulnerability {
		t.Fatalf("resume ICS item 0 preemption flags got capability=%t vulnerability=%t, want false/true", items[0].PreemptionCapability, items[0].PreemptionVulnerability)
	}
	if items[0].SGWS1UIPv4 != "10.99.0.1" || items[0].SGWS1UTEID != 0xAABB1122 {
		t.Fatalf("resume ICS item 0 transport got ip=%s teid=%#x", items[0].SGWS1UIPv4, items[0].SGWS1UTEID)
	}
}

func TestHandleServiceRequest_ResumeICSOrdersDefaultBearersWithLegacyLast(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.0.0.28:36412"
	ch := setupSendCapture(srv, addr)

	realUE, mmec, mtmsi := makeRegisteredIdleUE(srv, addr)
	realUE.Lock()
	realUE.DefaultEBI = 5
	realUE.APN = "internet"
	realUE.SubscriberAPNConfigs["ims"] = uecontext.SubscriberAPNConfig{
		ServiceSelection:        "ims",
		PDNType:                 1,
		QCI:                     5,
		ARPPriority:             1,
		PreemptionCapability:    false,
		PreemptionVulnerability: false,
		APNAMBRDown:             1530000,
		APNAMBRUp:               3850000,
	}
	realUE.SubscriberAPNConfigs["mms"] = uecontext.SubscriberAPNConfig{
		ServiceSelection:        "mms",
		PDNType:                 1,
		QCI:                     8,
		ARPPriority:             8,
		PreemptionCapability:    false,
		PreemptionVulnerability: false,
		APNAMBRDown:             128000,
		APNAMBRUp:               128000,
	}
	realUE.PDNs = map[string]*uecontext.PDNContext{
		"ims": {
			APN:                  "ims",
			DefaultEBI:           6,
			SGWU_TEID:            0x60000006,
			SGWU_IP:              net.ParseIP("10.1.0.6").To4(),
			ERABEstablished:      true,
			ModifyBearerAccepted: true,
			State:                "active",
		},
		"mms": {
			APN:                  "mms",
			DefaultEBI:           9,
			SGWU_TEID:            0x90000009,
			SGWU_IP:              net.ParseIP("10.1.0.9").To4(),
			ERABEstablished:      true,
			ModifyBearerAccepted: true,
			State:                "active",
		},
	}
	realUE.DedicatedBearers[7] = &uecontext.DedicatedBearerContext{
		AssignedEBI:     7,
		LinkedEBI:       6,
		QCI:             2,
		ARP:             0x10,
		BearerQoS:       encodeBearerQoSForTest(2, 0x10, 128000, 128000, 128000, 128000),
		SGWS1UTEID:      0x70000007,
		SGWS1UIP:        net.ParseIP("10.2.0.7").To4(),
		ERABEstablished: true,
		NASAccepted:     true,
		State:           "active",
	}
	realUE.DedicatedBearers[8] = &uecontext.DedicatedBearerContext{
		AssignedEBI:     8,
		LinkedEBI:       6,
		QCI:             1,
		ARP:             0x08,
		BearerQoS:       encodeBearerQoSForTest(1, 0x08, 128000, 128000, 128000, 128000),
		SGWS1UTEID:      0x80000008,
		SGWS1UIP:        net.ParseIP("10.2.0.8").To4(),
		ERABEstablished: true,
		NASAccepted:     true,
		State:           "active",
	}
	realUE.Unlock()

	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 208
	tempUE.ENBGlobalID = addr
	tempUE.Unlock()

	srv.handleServiceRequest(tempUE, mmec, mtmsi, nil, true, nil, buildSRPDU(1))

	msg := readCapturedPDU(t, ch)
	if msg.Type != pdu.PDUTypeInitiatingMessage || msg.ProcedureCode != pdu.ProcInitialContextSetup {
		t.Fatalf("PDU got type=%s proc=%d, want InitialContextSetup", msg.Type, msg.ProcedureCode)
	}
	ieList, err := pdu.DecodeIEContainer(msg.Value)
	if err != nil {
		t.Fatalf("decode ICS IE list: %v", err)
	}
	var erabList []byte
	for _, ie := range ieList {
		if ie.ID == pdu.IEERABToBeSetupListCtxtSUReq {
			erabList = ie.Value
			break
		}
	}
	if len(erabList) == 0 {
		t.Fatal("resume ICS missing E-RABToBeSetupListCtxtSUReq")
	}
	items := decodeResumeICSErabList(t, erabList)
	gotEBIs := make([]uint8, 0, len(items))
	for _, item := range items {
		gotEBIs = append(gotEBIs, item.EBI)
	}
	wantEBIs := []uint8{6, 9, 5}
	if !reflect.DeepEqual(gotEBIs, wantEBIs) {
		t.Fatalf("resume ICS EBIs got %v, want %v", gotEBIs, wantEBIs)
	}
	for _, item := range items {
		if item.NASPDUPresent {
			t.Fatalf("resume ICS item %d unexpectedly carried NAS-PDU", item.EBI)
		}
	}
}

func TestHandleServiceRequest_ResumeICSExcludesDedicatedBearers(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.0.0.281:36412"
	ch := setupSendCapture(srv, addr)

	realUE, mmec, mtmsi := makeRegisteredIdleUE(srv, addr)
	realUE.Lock()
	realUE.DefaultEBI = 5
	realUE.APN = "internet"
	realUE.SubscriberAPNConfigs["mms"] = uecontext.SubscriberAPNConfig{
		ServiceSelection:        "mms",
		PDNType:                 1,
		QCI:                     8,
		ARPPriority:             8,
		PreemptionCapability:    false,
		PreemptionVulnerability: false,
		APNAMBRDown:             128000,
		APNAMBRUp:               128000,
	}
	realUE.PDNs = map[string]*uecontext.PDNContext{
		"ims": {
			APN:                  "ims",
			DefaultEBI:           6,
			SGWU_TEID:            0x60000006,
			SGWU_IP:              net.ParseIP("10.1.0.6").To4(),
			ERABEstablished:      false,
			ModifyBearerAccepted: true,
			NASAccepted:          true,
			State:                "idle",
		},
		"mms": {
			APN:                  "mms",
			DefaultEBI:           10,
			SGWU_TEID:            0xa000000a,
			SGWU_IP:              net.ParseIP("10.1.0.10").To4(),
			ERABEstablished:      false,
			ModifyBearerAccepted: true,
			NASAccepted:          true,
			State:                "idle",
		},
	}
	realUE.DedicatedBearers[7] = &uecontext.DedicatedBearerContext{
		AssignedEBI: 7, LinkedEBI: 6, QCI: 2,
		SGWS1UTEID: 0x70000007, SGWS1UIP: net.ParseIP("10.2.0.7").To4(),
		NASAccepted: true, State: "idle",
	}
	realUE.DedicatedBearers[8] = &uecontext.DedicatedBearerContext{
		AssignedEBI: 8, LinkedEBI: 6, QCI: 1,
		SGWS1UTEID: 0x80000008, SGWS1UIP: net.ParseIP("10.2.0.8").To4(),
		NASAccepted: true, State: "idle",
	}
	realUE.Unlock()

	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 281
	tempUE.ENBGlobalID = addr
	tempUE.Unlock()

	srv.handleServiceRequest(tempUE, mmec, mtmsi, nil, true, nil, buildSRPDU(1))

	msg := readCapturedPDU(t, ch)
	if msg.Type != pdu.PDUTypeInitiatingMessage || msg.ProcedureCode != pdu.ProcInitialContextSetup {
		t.Fatalf("PDU got type=%s proc=%d, want InitialContextSetup", msg.Type, msg.ProcedureCode)
	}
	ieList, err := pdu.DecodeIEContainer(msg.Value)
	if err != nil {
		t.Fatalf("decode ICS IE list: %v", err)
	}
	var erabList []byte
	for _, ie := range ieList {
		if ie.ID == pdu.IEERABToBeSetupListCtxtSUReq {
			erabList = ie.Value
			break
		}
	}
	if len(erabList) == 0 {
		t.Fatal("resume ICS missing E-RABToBeSetupListCtxtSUReq")
	}
	items := decodeResumeICSErabList(t, erabList)
	gotEBIs := make([]uint8, 0, len(items))
	for _, item := range items {
		gotEBIs = append(gotEBIs, item.EBI)
		if item.NASPDUPresent {
			t.Fatalf("resume ICS item %d unexpectedly carried NAS-PDU", item.EBI)
		}
	}
	wantEBIs := []uint8{6, 10, 5}
	if !reflect.DeepEqual(gotEBIs, wantEBIs) {
		t.Fatalf("resume ICS EBIs got %v, want %v", gotEBIs, wantEBIs)
	}
}

func TestHandleServiceRequest_IncompleteRetainedPolicySendsServiceReject(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.0.0.18:36412"
	ch := setupSendCapture(srv, addr)

	realUE, mmec, mtmsi := makeRegisteredIdleUE(srv, addr)
	realUE.Lock()
	realUE.SubscriberAPNConfigs = map[string]uecontext.SubscriberAPNConfig{
		"internet": {
			ServiceSelection: "internet",
			PDNType:          gtpv2.PDNTypeIPv4,
			QCI:              9,
			ARPPriority:      8,
			APNAMBRDown:      100000,
			// APNAMBRUp intentionally missing to force retained-policy rejection.
		},
	}
	realUE.Unlock()

	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 118
	tempUE.ENBGlobalID = addr
	tempUE.Unlock()

	srv.handleServiceRequest(tempUE, mmec, mtmsi, nil, true, nil, buildSRPDU(1))

	msg := readCapturedPDU(t, ch)
	nasPDU := decodeNASPDUFromPDU(t, msg)
	if got, want := nasPDU[0], uint8(emm.PDEPSMobilityMgmt); got != want {
		t.Fatalf("NAS PD got %#x, want %#x", got, want)
	}
	if got, want := nasPDU[1], uint8(emm.MsgServiceReject); got != want {
		t.Fatalf("NAS msg type got %#x, want %#x", got, want)
	}
	if got, want := nasPDU[2], uint8(emm.CauseNetworkFailure); got != want {
		t.Fatalf("EMM cause got %#x, want %#x", got, want)
	}

	realUE.Lock()
	defer realUE.Unlock()
	if realUE.AttachStep != uecontext.AttachStepNone {
		t.Fatalf("AttachStep got %d, want %d", realUE.AttachStep, uecontext.AttachStepNone)
	}
	if realUE.ECMState != emm.ECMIdle {
		t.Fatalf("ECMState got %s, want %s", realUE.ECMState, emm.ECMIdle)
	}
}

func TestHandleServiceRequest_ResumeICSSkipsDisconnectingIMSBearer(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.0.0.19:36412"
	ch := setupSendCapture(srv, addr)

	realUE, mmec, mtmsi := makeRegisteredIdleUE(srv, addr)
	realUE.Lock()
	realUE.PDNs["ims"] = &uecontext.PDNContext{
		APN:                   "ims",
		DefaultEBI:            6,
		SGWU_TEID:             0xBBCC2233,
		SGWU_IP:               net.ParseIP("10.99.0.2").To4(),
		ERABEstablished:       true,
		ModifyBearerAccepted:  true,
		DisconnectRequested:   true,
		DisconnectNASAccepted: true,
		State:                 "pdn-disconnect-delete-session-pending",
	}
	realUE.Unlock()

	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 109
	tempUE.ENBGlobalID = addr
	tempUE.Unlock()

	srv.handleServiceRequest(tempUE, mmec, mtmsi, nil, true, nil, buildSRPDU(1))

	var raw []byte
	select {
	case raw = <-ch:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("no ICS Request PDU sent on valid Service Request")
	}
	msg, err := pdu.Decode(raw)
	if err != nil {
		t.Fatalf("decode ICS PDU: %v", err)
	}
	if msg.Type != pdu.PDUTypeInitiatingMessage || msg.ProcedureCode != pdu.ProcInitialContextSetup {
		t.Fatalf("PDU got type=%s proc=%d, want InitialContextSetup", msg.Type, msg.ProcedureCode)
	}
	ieList, err := pdu.DecodeIEContainer(msg.Value)
	if err != nil {
		t.Fatalf("decode ICS IE list: %v", err)
	}
	var erabList []byte
	for _, ie := range ieList {
		if ie.ID == pdu.IEERABToBeSetupListCtxtSUReq {
			erabList = ie.Value
			break
		}
	}
	if len(erabList) == 0 {
		t.Fatal("resume ICS missing E-RABToBeSetupListCtxtSUReq")
	}
	bearers := decodeResumeICSErabList(t, erabList)
	if len(bearers) != 1 {
		t.Fatalf("E-RAB item count got %d, want 1", len(bearers))
	}
	if bearers[0].EBI != 5 {
		t.Fatalf("resumed EBI got %d, want only default bearer 5", bearers[0].EBI)
	}
}

func TestHandleServiceRequest_ResumeICSSkipsDedicatedBearerPendingDelete(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.0.0.19b:36412"
	ch := setupSendCapture(srv, addr)

	realUE, mmec, mtmsi := makeRegisteredIdleUE(srv, addr)
	realUE.Lock()
	realUE.PDNs["ims"] = &uecontext.PDNContext{
		APN:                  "ims",
		DefaultEBI:           6,
		SGWU_TEID:            0xBBCC2233,
		SGWU_IP:              net.ParseIP("10.99.0.2").To4(),
		ERABEstablished:      true,
		ModifyBearerAccepted: true,
		State:                "active",
	}
	realUE.DedicatedBearers[9] = &uecontext.DedicatedBearerContext{
		AssignedEBI:     9,
		LinkedEBI:       6,
		QCI:             1,
		ARP:             0x08,
		BearerQoS:       encodeBearerQoSForTest(1, 0x08, 128000, 128000, 128000, 128000),
		SGWS1UTEID:      0x11111111,
		SGWS1UIP:        net.ParseIP("10.99.0.3").To4(),
		ERABEstablished: true,
		NASAccepted:     true,
		State:           "active",
	}
	realUE.DedicatedBearers[10] = &uecontext.DedicatedBearerContext{
		AssignedEBI:     10,
		LinkedEBI:       6,
		QCI:             5,
		ARP:             0x08,
		BearerQoS:       encodeBearerQoSForTest(5, 0x08, 128000, 128000, 128000, 128000),
		SGWS1UTEID:      0x10101010,
		SGWS1UIP:        net.ParseIP("10.99.0.4").To4(),
		ERABEstablished: true,
		NASAccepted:     true,
		State:           "active",
	}
	realUE.PendingBearerTransactions = map[string]*uecontext.DedicatedBearerTransaction{
		"delete-ebi-10": {
			ID:          "dbr-1-0000000f-000001",
			Kind:        bearerTxDelete,
			PeerAddress: "10.90.250.59:2123",
			LocalTEID:   0x0f,
			SequenceNum: 1,
			EBIs:        []uint8{10},
			Bearers: map[uint8]*uecontext.DedicatedBearerContext{
				10: {
					AssignedEBI:     10,
					LinkedEBI:       6,
					QCI:             5,
					ARP:             0x08,
					SGWS1UTEID:      0x10101010,
					SGWS1UIP:        net.ParseIP("10.99.0.4").To4(),
					ERABEstablished: true,
					NASAccepted:     true,
					State:           "active",
				},
			},
			State: "deleting",
		},
	}
	realUE.Unlock()

	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 110
	tempUE.ENBGlobalID = addr
	tempUE.Unlock()

	srv.handleServiceRequest(tempUE, mmec, mtmsi, nil, true, nil, buildSRPDU(1))

	msg := readCapturedPDU(t, ch)
	if msg.Type != pdu.PDUTypeInitiatingMessage || msg.ProcedureCode != pdu.ProcInitialContextSetup {
		t.Fatalf("PDU got type=%s proc=%d, want InitialContextSetup", msg.Type, msg.ProcedureCode)
	}
	ieList, err := pdu.DecodeIEContainer(msg.Value)
	if err != nil {
		t.Fatalf("decode ICS IE list: %v", err)
	}
	var erabList []byte
	for _, ie := range ieList {
		if ie.ID == pdu.IEERABToBeSetupListCtxtSUReq {
			erabList = ie.Value
			break
		}
	}
	if len(erabList) == 0 {
		t.Fatal("resume ICS missing E-RABToBeSetupListCtxtSUReq")
	}
	bearers := decodeResumeICSErabList(t, erabList)
	if got, want := len(bearers), 2; got != want {
		t.Fatalf("E-RAB item count got %d, want %d", got, want)
	}
	gotEBIs := []uint8{bearers[0].EBI, bearers[1].EBI}
	wantEBIs := []uint8{6, 5}
	if !reflect.DeepEqual(gotEBIs, wantEBIs) {
		t.Fatalf("resumed EBIs got %v, want %v", gotEBIs, wantEBIs)
	}
}

func decodeResumeICSErabList(t *testing.T, data []byte) []normalizedERABSetupItem {
	t.Helper()
	r := aper.NewBitReader(data)
	count, err := aper.DecodeConstrainedWholeNumber(r, 1, 256)
	if err != nil {
		t.Fatalf("decode resume ICS E-RAB count: %v", err)
	}
	r.AlignToByte()
	items := make([]normalizedERABSetupItem, 0, int(count))
	for i := 0; i < int(count); i++ {
		ieID, err := aper.DecodeConstrainedWholeNumber(r, 0, 65535)
		if err != nil {
			t.Fatalf("decode resume ICS item %d IE ID: %v", i, err)
		}
		crit, err := aper.DecodeCriticality(r)
		if err != nil {
			t.Fatalf("decode resume ICS item %d criticality: %v", i, err)
		}
		itemBytes, err := aper.ReadOpenType(r)
		if err != nil {
			t.Fatalf("read resume ICS item %d open type: %v", i, err)
		}
		item := decodeResumeICSErabItem(t, itemBytes)
		item.SingleContainerIEID = uint16(ieID)
		item.SingleContainerCriticality = crit
		items = append(items, item)
	}
	return items
}

func decodeResumeICSErabItem(t *testing.T, data []byte) normalizedERABSetupItem {
	t.Helper()
	r := aper.NewBitReader(data)
	if _, err := r.ReadBit(); err != nil {
		t.Fatalf("decode resume ICS extension bit: %v", err)
	}
	nasPresent, err := r.ReadBit()
	if err != nil {
		t.Fatalf("decode resume ICS NAS presence: %v", err)
	}
	item := normalizedERABSetupItem{NASPDUPresent: nasPresent == 1}
	if _, err := r.ReadBit(); err != nil {
		t.Fatalf("decode resume ICS IE extension presence: %v", err)
	}
	if ext, err := r.ReadBit(); err != nil || ext != 0 {
		t.Fatalf("decode resume ICS E-RAB ID extension got %d err=%v, want 0 nil", ext, err)
	}
	ebi, err := aper.DecodeConstrainedWholeNumber(r, 0, 15)
	if err != nil {
		t.Fatalf("decode resume ICS E-RAB ID: %v", err)
	}
	item.EBI = uint8(ebi)
	if ext, err := r.ReadBit(); err != nil || ext != 0 {
		t.Fatalf("decode resume ICS QoS extension got %d err=%v, want 0 nil", ext, err)
	}
	gbrPresent, err := r.ReadBit()
	if err != nil {
		t.Fatalf("decode resume ICS GBR presence: %v", err)
	}
	item.GBRQosInformationPresent = gbrPresent == 1
	if ieExt, err := r.ReadBit(); err != nil || ieExt != 0 {
		t.Fatalf("decode resume ICS QoS IE extensions got %d err=%v, want 0 nil", ieExt, err)
	}
	qci, err := aper.DecodeConstrainedWholeNumber(r, 0, 255)
	if err != nil {
		t.Fatalf("decode resume ICS QCI: %v", err)
	}
	item.QCI = uint8(qci)
	if item.GBRQosInformationPresent {
		for i := 0; i < 4; i++ {
			if _, err := aper.DecodeConstrainedWholeNumber(r, 0, 10000000000); err != nil {
				t.Fatalf("decode resume ICS GBR bitrate %d: %v", i, err)
			}
		}
	}
	if ext, err := r.ReadBit(); err != nil || ext != 0 {
		t.Fatalf("decode resume ICS ARP extension got %d err=%v, want 0 nil", ext, err)
	}
	if ieExt, err := r.ReadBit(); err != nil || ieExt != 0 {
		t.Fatalf("decode resume ICS ARP IE extensions got %d err=%v, want 0 nil", ieExt, err)
	}
	arp, err := aper.DecodeConstrainedWholeNumber(r, 0, 15)
	if err != nil {
		t.Fatalf("decode resume ICS ARP priority: %v", err)
	}
	item.ARPPriority = uint8(arp)
	pc, err := aper.DecodeConstrainedWholeNumber(r, 0, 1)
	if err != nil {
		t.Fatalf("decode resume ICS preemption capability: %v", err)
	}
	pv, err := aper.DecodeConstrainedWholeNumber(r, 0, 1)
	if err != nil {
		t.Fatalf("decode resume ICS preemption vulnerability: %v", err)
	}
	item.PreemptionCapability = pc == 1
	item.PreemptionVulnerability = pv == 1
	addrExt, err := r.ReadBit()
	if err != nil {
		t.Fatalf("decode resume ICS transportLayerAddress extension: %v", err)
	}
	var addrBits int64
	if addrExt == 0 {
		addrBits, err = aper.DecodeConstrainedWholeNumber(r, 1, 160)
	} else {
		addrBits, err = aper.DecodeConstrainedWholeNumber(r, 0, 65535)
	}
	if err != nil {
		t.Fatalf("decode resume ICS transportLayerAddress bit length: %v", err)
	}
	item.TransportAddressBits = int(addrBits)
	r.AlignToByte()
	addrBytes, err := r.ReadOctets(int((addrBits + 7) / 8))
	if err != nil {
		t.Fatalf("decode resume ICS transportLayerAddress: %v", err)
	}
	if len(addrBytes) < 4 {
		t.Fatalf("decode resume ICS transportLayerAddress too short: %x", addrBytes)
	}
	item.SGWS1UIPv4 = net.IP(addrBytes[:4]).String()
	teidBytes, err := r.ReadOctets(4)
	if err != nil {
		t.Fatalf("decode resume ICS GTP TEID: %v", err)
	}
	item.SGWS1UTEID = binary.BigEndian.Uint32(teidBytes)
	if item.NASPDUPresent {
		nasLen, err := aper.DecodeUnconstrainedLength(r)
		if err != nil {
			t.Fatalf("decode resume ICS NAS-PDU length: %v", err)
		}
		nas, err := r.ReadOctets(nasLen)
		if err != nil {
			t.Fatalf("decode resume ICS NAS-PDU: %v", err)
		}
		item.NASPDU = nas
	}
	item.DecodedWithoutTrailingOctets = r.Remaining() == 0
	return item
}

func TestHandleServiceRequest_DelaysResumeICSPendingReleaseComplete(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.0.0.15:36412"
	ch := setupSendCapture(srv, addr)

	realUE, mmec, mtmsi := makeRegisteredIdleUE(srv, addr)
	realUE.Lock()
	realUE.S1ReleasePending = true
	realUE.S1ReleaseENBID = 1
	realUE.S1ReleaseENBAddr = addr
	realUE.Unlock()

	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 106
	tempUE.ENBGlobalID = addr
	tempUE.Unlock()

	srv.handleServiceRequest(tempUE, mmec, mtmsi, nil, true, nil, buildSRPDU(1))

	select {
	case msg := <-ch:
		t.Fatalf("resume ICS sent before pending release debounce elapsed: %x", msg)
	case <-time.After(75 * time.Millisecond):
	}

	realUE.Lock()
	realUE.S1ReleasePending = false
	realUE.S1ReleaseENBID = 0
	realUE.S1ReleaseENBAddr = ""
	realUE.Unlock()

	select {
	case <-ch:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("delayed resume ICS was not sent")
	}

	realUE.Lock()
	step := realUE.AttachStep
	enbUEID := realUE.ENBS1APID
	realUE.Unlock()

	if step != uecontext.AttachStepWaitingICSRespSR {
		t.Errorf("AttachStep: got %d, want WaitingICSRespSR(%d)", step, uecontext.AttachStepWaitingICSRespSR)
	}
	if enbUEID != 106 {
		t.Errorf("ENBS1APID: got %d, want 106", enbUEID)
	}
}

func TestResumeIdleUEFromInitialUE_DelaysResumeICSPendingReleaseComplete(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.0.0.18:36412"
	ch := setupSendCapture(srv, addr)

	realUE, _, _ := makeRegisteredIdleUE(srv, addr)
	realUE.Lock()
	realUE.S1ReleasePending = true
	realUE.S1ReleaseENBID = 1
	realUE.S1ReleaseENBAddr = addr
	realUE.Unlock()

	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 108
	tempUE.ENBGlobalID = addr
	tempUE.Unlock()

	srv.resumeIdleUEFromInitialUE(tempUE, realUE, nil, srv.log)

	select {
	case msg := <-ch:
		t.Fatalf("resume ICS sent before release cleared: %x", msg)
	case <-time.After(75 * time.Millisecond):
	}

	realUE.Lock()
	realUE.S1ReleasePending = false
	realUE.S1ReleaseENBID = 0
	realUE.S1ReleaseENBAddr = ""
	realUE.Unlock()

	select {
	case <-ch:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("resume ICS was not sent after release cleared")
	}
}

func TestHandleServiceRequest_ThreeDigitMNCGUTILookup(t *testing.T) {
	srv := newTAUTestServer()
	srv.nfCfg.MCC = "311"
	srv.nfCfg.MNC = "435"
	srv.nfCfg.MMEGI = 1
	srv.nfCfg.MMEC = 1
	gutiAlloc, err := uecontext.NewGUTIAllocator("311", "435", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	srv.gutiAlloc = gutiAlloc

	const addr = "10.0.0.17:36412"
	ch := setupSendCapture(srv, addr)

	realUE, _, _ := makeRegisteredIdleUE(srv, addr)
	plmn, err := security.EncodePLMN("311", "435")
	if err != nil {
		t.Fatal(err)
	}
	guti := &emm.GUTI{MMEGI: 1, MMEC: 1, MTMSI: 2}
	copy(guti.PLMN[:], plmn)
	if got, want := uecontext.SerialiseGUTI(guti), "13513400010100000002"; got != want {
		t.Fatalf("GUTI key got %s, want %s", got, want)
	}
	srv.ueManager.UpdateGUTI(realUE, guti)

	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 107
	tempUE.ENBGlobalID = addr
	tempUE.Unlock()

	before := srv.ueManager.Count()
	stmsiRaw, err := hex.DecodeString("004000000002")
	if err != nil {
		t.Fatal(err)
	}
	srv.handleServiceRequest(tempUE, 1, 2, stmsiRaw, true, nil, buildSRPDU(1))

	select {
	case <-ch:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("no ICS Request PDU sent on Service Request")
	}
	if srv.ueManager.Count() != before-1 {
		t.Fatalf("manager count got %d, want %d", srv.ueManager.Count(), before-1)
	}
	realUE.Lock()
	step := realUE.AttachStep
	enbUEID := realUE.ENBS1APID
	realUE.Unlock()
	if step != uecontext.AttachStepWaitingICSRespSR {
		t.Fatalf("AttachStep got %d, want WaitingICSRespSR", step)
	}
	if enbUEID != 107 {
		t.Fatalf("ENBS1APID got %d, want 107", enbUEID)
	}
}

func TestHandleServiceRequest_StoresNASPLMNEncodedTAIOnResume(t *testing.T) {
	srv := newTAUTestServer()
	srv.nfCfg.MCC = "311"
	srv.nfCfg.MNC = "435"
	srv.nfCfg.MMEGI = 1
	srv.nfCfg.MMEC = 1
	gutiAlloc, err := uecontext.NewGUTIAllocator("311", "435", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	srv.gutiAlloc = gutiAlloc

	const addr = "10.0.0.17b:36412"
	ch := setupSendCapture(srv, addr)

	realUE, _, _ := makeRegisteredIdleUE(srv, addr)
	plmn, err := security.EncodePLMN("311", "435")
	if err != nil {
		t.Fatal(err)
	}
	guti := &emm.GUTI{MMEGI: 1, MMEC: 1, MTMSI: 2}
	copy(guti.PLMN[:], plmn)
	srv.ueManager.UpdateGUTI(realUE, guti)

	tempUE := srv.ueManager.Allocate()
	tempUE.Lock()
	tempUE.ENBS1APID = 207
	tempUE.ENBGlobalID = addr
	tempUE.Unlock()

	currentTAI := &ies.TAI{MCC: "311", MNC: "435", TAC: 1}
	srv.handleServiceRequest(tempUE, 1, 2, nil, true, currentTAI, buildSRPDU(1))

	select {
	case <-ch:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("no ICS Request PDU sent on valid Service Request")
	}

	realUE.Lock()
	defer realUE.Unlock()
	if realUE.TAI == nil {
		t.Fatal("realUE TAI not updated")
	}
	if got, want := realUE.TAI.PLMN[:], plmn; !bytes.Equal(got, want) {
		t.Fatalf("realUE TAI PLMN got %x, want %x", got, want)
	}
}

func TestInitialUEMessageServiceRequestUsesSTMSIIE(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.0.0.16:36412"
	ch := setupSendCapture(srv, addr)
	realUE, _, _ := makeRegisteredIdleUE(srv, addr)
	guti := &emm.GUTI{PLMN: [3]byte{0x00, 0xF1, 0x10}, MMEGI: 1, MMEC: 1, MTMSI: 2}
	srv.ueManager.UpdateGUTI(realUE, guti)

	stmsi, err := hex.DecodeString("004000000002")
	if err != nil {
		t.Fatal(err)
	}
	taiValue, err := ies.EncodeTAI(ies.TAI{MCC: "001", MNC: "01", TAC: 1})
	if err != nil {
		t.Fatal(err)
	}
	ecgiValue, err := ies.EncodeECGI(ies.ECGI{MCC: "001", MNC: "01", ECGI: 0x12345})
	if err != nil {
		t.Fatal(err)
	}
	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(106)},
		{ID: pdu.IENAS_PDU, Criticality: aper.CriticalityReject, Value: ies.EncodeNASPDU(buildSRPDU(1))},
		{ID: pdu.IETAI, Criticality: aper.CriticalityReject, Value: taiValue},
		{ID: pdu.IECGI, Criticality: aper.CriticalityIgnore, Value: ecgiValue},
		{ID: pdu.IERRCEstablishmentCause, Criticality: aper.CriticalityIgnore, Value: ies.EncodeRRCEstablishmentCause(3)},
		{ID: pdu.IESTMSI, Criticality: aper.CriticalityReject, Value: stmsi},
	}

	before := srv.ueManager.Count()
	srv.handleMessage(addr, pdu.BuildInitiatingMessage(pdu.ProcInitialUEMessage, aper.CriticalityIgnore, ieList))
	select {
	case <-ch:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("no ICS Request PDU sent on Service Request")
	}
	if srv.ueManager.Count() != before {
		t.Fatalf("manager count got %d, want %d", srv.ueManager.Count(), before)
	}
	realUE.Lock()
	step := realUE.AttachStep
	enbUEID := realUE.ENBS1APID
	realUE.Unlock()
	if step != uecontext.AttachStepWaitingICSRespSR {
		t.Fatalf("AttachStep got %d, want WaitingICSRespSR", step)
	}
	if enbUEID != 106 {
		t.Fatalf("eNB UE ID got %d, want 106", enbUEID)
	}
}

func TestInitialUEMessageExtendedServiceRequestUsesNASMobileIdentity(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.0.0.17:36412"
	ch := setupSendCapture(srv, addr)
	realUE, _, _ := makeRegisteredIdleUE(srv, addr)
	guti := &emm.GUTI{PLMN: [3]byte{0x00, 0xF1, 0x10}, MMEGI: 1, MMEC: 1, MTMSI: 2}
	srv.ueManager.UpdateGUTI(realUE, guti)

	taiValue, err := ies.EncodeTAI(ies.TAI{MCC: "001", MNC: "01", TAC: 1})
	if err != nil {
		t.Fatal(err)
	}
	ecgiValue, err := ies.EncodeECGI(ies.ECGI{MCC: "001", MNC: "01", ECGI: 0x12345})
	if err != nil {
		t.Fatal(err)
	}
	nasPDU := []byte{emm.PDEPSMobilityMgmt, emm.MsgExtendedServiceRequest, 0x00, 0x05, 0xF4, 0x00, 0x00, 0x00, 0x02, 0x57, 0x02, 0x20, 0x00}
	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(108)},
		{ID: pdu.IENAS_PDU, Criticality: aper.CriticalityReject, Value: ies.EncodeNASPDU(nasPDU)},
		{ID: pdu.IETAI, Criticality: aper.CriticalityReject, Value: taiValue},
		{ID: pdu.IECGI, Criticality: aper.CriticalityIgnore, Value: ecgiValue},
		{ID: pdu.IERRCEstablishmentCause, Criticality: aper.CriticalityIgnore, Value: ies.EncodeRRCEstablishmentCause(3)},
	}

	before := srv.ueManager.Count()
	srv.handleMessage(addr, pdu.BuildInitiatingMessage(pdu.ProcInitialUEMessage, aper.CriticalityIgnore, ieList))
	select {
	case <-ch:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("no ICS Request PDU sent on Extended Service Request")
	}
	if srv.ueManager.Count() != before {
		t.Fatalf("manager count got %d, want %d", srv.ueManager.Count(), before)
	}
	realUE.Lock()
	step := realUE.AttachStep
	enbUEID := realUE.ENBS1APID
	realUE.Unlock()
	if step != uecontext.AttachStepWaitingICSRespSR {
		t.Fatalf("AttachStep got %d, want WaitingICSRespSR", step)
	}
	if enbUEID != 108 {
		t.Fatalf("eNB UE ID got %d, want 108", enbUEID)
	}
}

func TestInitialUEMessageExtendedServiceRequestRefreshesStaleASSnapshot(t *testing.T) {
	srv := newTAUTestServer()
	logger, logs := newObservedLogger()
	srv.log = logger
	const addr = "10.0.0.17a:36412"
	ch := setupSendCapture(srv, addr)

	realUE, _, _ := makeRegisteredIdleUE(srv, addr)
	guti := &emm.GUTI{PLMN: [3]byte{0x00, 0xF1, 0x10}, MMEGI: 1, MMEC: 1, MTMSI: 2}
	srv.ueManager.UpdateGUTI(realUE, guti)

	realUE.Lock()
	realUE.KASME = bytes.Repeat([]byte{0x5a}, 32)
	realUE.UENetworkCapability = []byte{0xf0, 0x70}
	realUE.ULNASCount = security.NASCount(1)
	if _, _, err := deriveAndStoreASContextLocked(realUE); err != nil {
		realUE.Unlock()
		t.Fatalf("deriveAndStoreASContextLocked: %v", err)
	}
	staleSnapshot := append([]byte(nil), realUE.KeNB...)
	realUE.ULNASCount = security.NASCount(6)
	expectedKeNB, err := security.DeriveKeNB(realUE.KASME, uint32(realUE.ULNASCount))
	if err != nil {
		realUE.Unlock()
		t.Fatalf("DeriveKeNB(current UL count): %v", err)
	}
	realUE.Unlock()

	taiValue, err := ies.EncodeTAI(ies.TAI{MCC: "001", MNC: "01", TAC: 1})
	if err != nil {
		t.Fatal(err)
	}
	ecgiValue, err := ies.EncodeECGI(ies.ECGI{MCC: "001", MNC: "01", ECGI: 0x12345})
	if err != nil {
		t.Fatal(err)
	}
	nasPDU := []byte{emm.PDEPSMobilityMgmt, emm.MsgExtendedServiceRequest, 0x00, 0x05, 0xF4, 0x00, 0x00, 0x00, 0x02, 0x57, 0x02, 0x20, 0x00}
	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(109)},
		{ID: pdu.IENAS_PDU, Criticality: aper.CriticalityReject, Value: ies.EncodeNASPDU(nasPDU)},
		{ID: pdu.IETAI, Criticality: aper.CriticalityReject, Value: taiValue},
		{ID: pdu.IECGI, Criticality: aper.CriticalityIgnore, Value: ecgiValue},
		{ID: pdu.IERRCEstablishmentCause, Criticality: aper.CriticalityIgnore, Value: ies.EncodeRRCEstablishmentCause(3)},
	}

	srv.handleMessage(addr, pdu.BuildInitiatingMessage(pdu.ProcInitialUEMessage, aper.CriticalityIgnore, ieList))

	var raw []byte
	select {
	case raw = <-ch:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("no ICS Request PDU sent on Extended Service Request")
	}
	if got := decodeICSSecurityKeyBytes(t, raw); !bytes.Equal(got, expectedKeNB) {
		t.Fatalf("ICS key got %x, want refreshed %x", got, expectedKeNB)
	}
	if bytes.Equal(expectedKeNB, staleSnapshot) {
		t.Fatal("test setup produced identical stale and refreshed KeNB")
	}

	created := findObservedEventWhere(t, logs, "as_security_snapshot_created", func(m map[string]interface{}) bool {
		return m["procedure"] == "service_request"
	})
	selected := findObservedEventWhere(t, logs, "ics_security_key_selected", func(m map[string]interface{}) bool {
		return m["procedure"] == "service_request"
	})
	_ = created
	if got, want := selected["security_key_source"], "snapshot"; got != want {
		t.Fatalf("security_key_source got %v, want %v", got, want)
	}
}

func TestInitialUEMessageExtendedServiceRequestDuplicatePendingResumeRetransmitsICS(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.0.0.17b:36412"
	ch := setupSendCapture(srv, addr)
	realUE, _, _ := makeRegisteredIdleUE(srv, addr)
	guti := &emm.GUTI{PLMN: [3]byte{0x00, 0xF1, 0x10}, MMEGI: 1, MMEC: 1, MTMSI: 2}
	srv.ueManager.UpdateGUTI(realUE, guti)

	taiValue, err := ies.EncodeTAI(ies.TAI{MCC: "001", MNC: "01", TAC: 1})
	if err != nil {
		t.Fatal(err)
	}
	ecgiValue, err := ies.EncodeECGI(ies.ECGI{MCC: "001", MNC: "01", ECGI: 0x12345})
	if err != nil {
		t.Fatal(err)
	}
	nasPDU := []byte{emm.PDEPSMobilityMgmt, emm.MsgExtendedServiceRequest, 0x00, 0x05, 0xF4, 0x00, 0x00, 0x00, 0x02, 0x57, 0x02, 0x20, 0x00}
	firstIEs := []pdu.ProtocolIE{
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(118)},
		{ID: pdu.IENAS_PDU, Criticality: aper.CriticalityReject, Value: ies.EncodeNASPDU(nasPDU)},
		{ID: pdu.IETAI, Criticality: aper.CriticalityReject, Value: taiValue},
		{ID: pdu.IECGI, Criticality: aper.CriticalityIgnore, Value: ecgiValue},
		{ID: pdu.IERRCEstablishmentCause, Criticality: aper.CriticalityIgnore, Value: ies.EncodeRRCEstablishmentCause(3)},
	}

	srv.handleMessage(addr, pdu.BuildInitiatingMessage(pdu.ProcInitialUEMessage, aper.CriticalityIgnore, firstIEs))
	select {
	case <-ch:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("no first ICS Request PDU sent on Extended Service Request")
	}

	secondIEs := []pdu.ProtocolIE{
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(119)},
		{ID: pdu.IENAS_PDU, Criticality: aper.CriticalityReject, Value: ies.EncodeNASPDU(nasPDU)},
		{ID: pdu.IETAI, Criticality: aper.CriticalityReject, Value: taiValue},
		{ID: pdu.IECGI, Criticality: aper.CriticalityIgnore, Value: ecgiValue},
		{ID: pdu.IERRCEstablishmentCause, Criticality: aper.CriticalityIgnore, Value: ies.EncodeRRCEstablishmentCause(3)},
	}

	srv.handleMessage(addr, pdu.BuildInitiatingMessage(pdu.ProcInitialUEMessage, aper.CriticalityIgnore, secondIEs))
	select {
	case second := <-ch:
		msg, err := pdu.Decode(second)
		if err != nil {
			t.Fatalf("decode retransmitted ICS PDU: %v", err)
		}
		if msg.Type != pdu.PDUTypeInitiatingMessage || msg.ProcedureCode != pdu.ProcInitialContextSetup {
			t.Fatalf("retransmit PDU got type=%s proc=%d, want InitialContextSetup", msg.Type, msg.ProcedureCode)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("no retransmitted ICS Request PDU sent on duplicate Extended Service Request")
	}

	realUE.Lock()
	step := realUE.AttachStep
	enbUEID := realUE.ENBS1APID
	emmState := realUE.EMMState
	realUE.Unlock()
	if step != uecontext.AttachStepWaitingICSRespSR {
		t.Fatalf("AttachStep got %d, want WaitingICSRespSR", step)
	}
	if enbUEID != 119 {
		t.Fatalf("eNB UE ID got %d, want 119", enbUEID)
	}
	if emmState != emm.StateServiceRequestInitiated {
		t.Fatalf("EMMState got %v, want ServiceRequestInitiated", emmState)
	}
}

func TestInitialUEExtendedServiceRequestIncompleteRetainedPolicySendsServiceReject(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.0.0.19:36412"
	ch := setupSendCapture(srv, addr)

	realUE, _, _ := makeRegisteredIdleUE(srv, addr)
	guti := &emm.GUTI{PLMN: [3]byte{0x00, 0xF1, 0x10}, MMEGI: 1, MMEC: 1, MTMSI: 2}
	srv.ueManager.UpdateGUTI(realUE, guti)
	realUE.Lock()
	realUE.SubscriberAPNConfigs = map[string]uecontext.SubscriberAPNConfig{
		"internet": {
			ServiceSelection: "internet",
			PDNType:          gtpv2.PDNTypeIPv4,
			QCI:              9,
			ARPPriority:      8,
			APNAMBRDown:      100000,
			// APNAMBRUp intentionally missing to force retained-policy rejection.
		},
	}
	realUE.Unlock()

	taiValue, err := ies.EncodeTAI(ies.TAI{MCC: "001", MNC: "01", TAC: 1})
	if err != nil {
		t.Fatal(err)
	}
	ecgiValue, err := ies.EncodeECGI(ies.ECGI{MCC: "001", MNC: "01", ECGI: 0x12345})
	if err != nil {
		t.Fatal(err)
	}
	nasPDU := []byte{emm.PDEPSMobilityMgmt, emm.MsgExtendedServiceRequest, 0x00, 0x05, 0xF4, 0x00, 0x00, 0x00, 0x02, 0x57, 0x02, 0x20, 0x00}
	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(119)},
		{ID: pdu.IENAS_PDU, Criticality: aper.CriticalityReject, Value: ies.EncodeNASPDU(nasPDU)},
		{ID: pdu.IETAI, Criticality: aper.CriticalityReject, Value: taiValue},
		{ID: pdu.IECGI, Criticality: aper.CriticalityIgnore, Value: ecgiValue},
		{ID: pdu.IERRCEstablishmentCause, Criticality: aper.CriticalityIgnore, Value: ies.EncodeRRCEstablishmentCause(3)},
	}

	srv.handleMessage(addr, pdu.BuildInitiatingMessage(pdu.ProcInitialUEMessage, aper.CriticalityIgnore, ieList))

	msg := readCapturedPDU(t, ch)
	downlinkNAS := decodeNASPDUFromPDU(t, msg)
	if got, want := downlinkNAS[0], uint8(emm.PDEPSMobilityMgmt); got != want {
		t.Fatalf("NAS PD got %#x, want %#x", got, want)
	}
	if got, want := downlinkNAS[1], uint8(emm.MsgServiceReject); got != want {
		t.Fatalf("NAS msg type got %#x, want %#x", got, want)
	}
	if got, want := downlinkNAS[2], uint8(emm.CauseNetworkFailure); got != want {
		t.Fatalf("EMM cause got %#x, want %#x", got, want)
	}

	realUE.Lock()
	defer realUE.Unlock()
	if realUE.AttachStep != uecontext.AttachStepNone {
		t.Fatalf("AttachStep got %d, want %d", realUE.AttachStep, uecontext.AttachStepNone)
	}
	if realUE.ECMState != emm.ECMIdle {
		t.Fatalf("ECMState got %s, want %s", realUE.ECMState, emm.ECMIdle)
	}
}

// ── handleServiceRequestReestablished tests ───────────────────────────────────

func TestHandleServiceRequestReestablished_UpdatesState(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.0.0.20:36412"

	ue, _, _ := makeRegisteredIdleUE(srv, addr)
	ue.Lock()
	ue.SetECMState(emm.ECMConnected) // ICS Response already set this
	ue.AttachStep = uecontext.AttachStepWaitingICSRespSR
	ue.Unlock()

	log := srv.log.With(zap.String("test", "sr_reestablished"))
	srv.handleServiceRequestReestablished(ue, log)

	ue.Lock()
	state := ue.EMMState
	step := ue.AttachStep
	ue.Unlock()

	if state != emm.StateRegistered {
		t.Errorf("EMMState: got %v, want StateRegistered", state)
	}
	if step != uecontext.AttachStepNone {
		t.Errorf("AttachStep: got %d, want None(%d)", step, uecontext.AttachStepNone)
	}
}

func TestHandleServiceRequestReestablished_MBRSent(t *testing.T) {
	mbrCh := make(chan struct{}, 1)
	trackingS11 := &mbrTrackingS11{ch: mbrCh}

	srv := newTestServer(trackingS11)
	srv.gutiAlloc, _ = uecontext.NewGUTIAllocator("001", "01", 1, 1)

	const addr = "10.0.0.21:36412"

	ue, _, _ := makeRegisteredIdleUE(srv, addr)
	ue.Lock()
	ue.SetECMState(emm.ECMConnected)
	ue.AttachStep = uecontext.AttachStepWaitingICSRespSR
	ue.ENBU_TEID = 0xBEEF0001
	ue.ENBU_IP = net.ParseIP("192.168.10.1").To4()
	ue.Unlock()

	log := srv.log.With(zap.String("test", "sr_mbr"))
	srv.handleServiceRequestReestablished(ue, log)

	select {
	case <-mbrCh:
		// MBR was sent
	case <-time.After(500 * time.Millisecond):
		t.Error("SendMBR was not called after Service Request re-establishment")
	}
}

func TestHandleServiceRequestReestablished_SendsMultiBearerMBR(t *testing.T) {
	trackingS11 := &capturingServiceRequestMBRS11{ch: make(chan *gtpv2.ModifyBearerRequest, 4)}

	srv := newTestServer(trackingS11)
	srv.gutiAlloc, _ = uecontext.NewGUTIAllocator("001", "01", 1, 1)

	const addr = "10.0.0.31:36412"

	ue, _, _ := makeRegisteredIdleUE(srv, addr)
	ue.Lock()
	ue.SetECMState(emm.ECMConnected)
	ue.AttachStep = uecontext.AttachStepWaitingICSRespSR
	ue.ENBU_TEID = 0x50000005
	ue.ENBU_IP = net.ParseIP("192.168.105.247").To4()
	ue.PDNs = map[string]*uecontext.PDNContext{
		"ims": {
			APN:                  "ims",
			DefaultEBI:           6,
			SGWAddress:           "10.0.0.1:2123",
			SGWC_TEID:            0x11110001,
			SGWU_TEID:            0x22220001,
			SGWU_IP:              net.ParseIP("10.1.0.6").To4(),
			ENBU_TEID:            0x60000006,
			ENBU_IP:              net.ParseIP("192.168.105.247").To4(),
			ERABEstablished:      true,
			NASAccepted:          true,
			ModifyBearerAccepted: true,
			State:                "active",
		},
		"mms": {
			APN:                  "mms",
			DefaultEBI:           9,
			SGWAddress:           "10.0.0.1:2123",
			SGWC_TEID:            0x11110002,
			SGWU_TEID:            0x22220002,
			SGWU_IP:              net.ParseIP("10.1.0.9").To4(),
			ENBU_TEID:            0x90000009,
			ENBU_IP:              net.ParseIP("192.168.105.247").To4(),
			ERABEstablished:      true,
			NASAccepted:          true,
			ModifyBearerAccepted: true,
			State:                "active",
		},
	}
	ue.DedicatedBearers[7] = &uecontext.DedicatedBearerContext{
		AssignedEBI:     7,
		LinkedEBI:       6,
		QCI:             2,
		SGWS1UTEID:      0x33330001,
		SGWS1UIP:        net.ParseIP("10.2.0.7").To4(),
		ENBS1UTEID:      0x70000007,
		ENBS1UIP:        net.ParseIP("192.168.105.247").To4(),
		ERABEstablished: true,
		NASAccepted:     true,
	}
	ue.DedicatedBearers[8] = &uecontext.DedicatedBearerContext{
		AssignedEBI:     8,
		LinkedEBI:       6,
		QCI:             1,
		SGWS1UTEID:      0x33330002,
		SGWS1UIP:        net.ParseIP("10.2.0.8").To4(),
		ENBS1UTEID:      0x80000008,
		ENBS1UIP:        net.ParseIP("192.168.105.247").To4(),
		ERABEstablished: true,
		NASAccepted:     true,
	}
	ue.Unlock()

	log := srv.log.With(zap.String("test", "sr_multi_bearer_mbr"))
	srv.handleServiceRequestReestablished(ue, log)

	got := collectServiceRequestMBRBearers(t, trackingS11.ch, 3)
	want := [][]uint8{
		{6, 7, 8},
		{9},
		{5},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("MBR bearer groups got %v want %v", got, want)
	}
}

func TestInitialContextSetupResponse_ServiceRequestPartialFailurePrunesFailedRetainedBearers(t *testing.T) {
	trackingS11 := &capturingServiceRequestMBRS11{ch: make(chan *gtpv2.ModifyBearerRequest, 4)}

	srv := newTestServer(trackingS11)
	srv.gutiAlloc, _ = uecontext.NewGUTIAllocator("001", "01", 1, 1)

	const addr = "10.0.0.32:36412"

	ue, _, _ := makeRegisteredIdleUE(srv, addr)
	ue.Lock()
	ue.SetEMMState(emm.StateServiceRequestInitiated)
	ue.SetECMState(emm.ECMIdle)
	ue.AttachStep = uecontext.AttachStepWaitingICSRespSR
	ue.ENBS1APID = 0x84
	ue.ENBGlobalID = addr
	ue.ENBU_TEID = 0
	ue.ENBU_IP = nil
	ue.PDNs = map[string]*uecontext.PDNContext{
		"ims": {
			APN:                  "ims",
			DefaultEBI:           6,
			SGWAddress:           "10.0.0.1:2123",
			SGWC_TEID:            0x11110001,
			SGWU_TEID:            0x22220001,
			SGWU_IP:              net.ParseIP("10.1.0.6").To4(),
			NASAccepted:          true,
			ModifyBearerAccepted: true,
			State:                "idle",
		},
		"mms": {
			APN:                  "mms",
			DefaultEBI:           10,
			SGWAddress:           "10.0.0.1:2123",
			SGWC_TEID:            0x11110002,
			SGWU_TEID:            0x22220002,
			SGWU_IP:              net.ParseIP("10.1.0.10").To4(),
			NASAccepted:          true,
			ModifyBearerAccepted: true,
			State:                "idle",
		},
	}
	ue.DedicatedBearers[7] = &uecontext.DedicatedBearerContext{
		AssignedEBI: 7,
		LinkedEBI:   6,
		QCI:         2,
		SGWS1UTEID:  0x33330001,
		SGWS1UIP:    net.ParseIP("10.2.0.7").To4(),
		NASAccepted: true,
		State:       "idle",
	}
	ue.DedicatedBearers[8] = &uecontext.DedicatedBearerContext{
		AssignedEBI: 8,
		LinkedEBI:   6,
		QCI:         1,
		SGWS1UTEID:  0x33330002,
		SGWS1UIP:    net.ParseIP("10.2.0.8").To4(),
		NASAccepted: true,
		State:       "idle",
	}
	mmeID := ue.MMEUES1APID
	enbID := ue.ENBS1APID
	ue.Unlock()

	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeMMEUEApID(mmeID)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeENBUEApID(enbID)},
		{ID: pdu.IEERABSetupListCtxtSURes, Criticality: aper.CriticalityIgnore, Value: encodeICSResponseSetupListForTest([]ERABSetupSuccess{
			{EBI: 5, ENBS1UAddr: net.ParseIP("192.168.105.247").To4(), ENBS1UTEID: 0x50000005},
			{EBI: 6, ENBS1UAddr: net.ParseIP("192.168.105.247").To4(), ENBS1UTEID: 0x60000006},
			{EBI: 10, ENBS1UAddr: net.ParseIP("192.168.105.247").To4(), ENBS1UTEID: 0xa000000a},
		})},
		{ID: pdu.IEERABFailedToSetupListCtxtSURes, Criticality: aper.CriticalityIgnore, Value: encodeERABFailedToSetupListForTest([]ERABSetupFailure{
			{EBI: 7, CauseGroup: uint8(ies.CauseGroupRadioNetwork), Cause: uint32(ies.CauseRadioNetworkUnspecified)},
			{EBI: 8, CauseGroup: uint8(ies.CauseGroupRadioNetwork), Cause: uint32(ies.CauseRadioNetworkUnspecified)},
		})},
	}

	srv.handleInitialContextSetupResponse(addr, &pdu.PDU{
		Type:          pdu.PDUTypeSuccessfulOutcome,
		ProcedureCode: pdu.ProcInitialContextSetup,
		Criticality:   aper.CriticalityIgnore,
	}, ieList)

	got := collectServiceRequestMBRBearers(t, trackingS11.ch, 3)
	want := [][]uint8{
		{6},
		{10},
		{5},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("MBR bearer groups got %v want %v", got, want)
	}

	ue.Lock()
	if proc := ue.DedicatedBearers[7]; proc == nil || !proc.ERABFailed || proc.State != "erab-setup-failed" {
		t.Fatalf("dedicated bearer 7 got %+v, want ERABFailed state", proc)
	}
	if proc := ue.DedicatedBearers[8]; proc == nil || !proc.ERABFailed || proc.State != "erab-setup-failed" {
		t.Fatalf("dedicated bearer 8 got %+v, want ERABFailed state", proc)
	}
	status, _, _ := tauMMEBearerContextStatusSnapshotLocked(ue)
	ue.Unlock()
	if got, want := tauBearerStatusHex(status), "0460"; got != want {
		t.Fatalf("retained EPS bearer status got %s, want %s", got, want)
	}
}

func encodeICSResponseSetupListForTest(items []ERABSetupSuccess) []byte {
	w := aper.NewBitWriter()
	_ = aper.EncodeConstrainedWholeNumber(w, int64(len(items)), 1, 256)
	w.AlignToByte()
	for _, item := range items {
		body := encodeERABSetupResponseItemForTest(item)
		w.WriteOctets(encodeSingleContainerIEForTest(pdu.IEERABSetupItemCtxtSURes, aper.CriticalityIgnore, body))
	}
	return w.Bytes()
}

func collectServiceRequestMBRBearers(t *testing.T, ch <-chan *gtpv2.ModifyBearerRequest, wantCount int) [][]uint8 {
	t.Helper()

	got := make([][]uint8, 0, wantCount)
	deadline := time.After(500 * time.Millisecond)
	for len(got) < wantCount {
		select {
		case req := <-ch:
			ebis := make([]uint8, 0, len(req.Bearers))
			for _, bearer := range req.Bearers {
				ebis = append(ebis, bearer.EBI)
			}
			got = append(got, ebis)
		case <-deadline:
			t.Fatalf("collected %d MBRs, want %d", len(got), wantCount)
		}
	}
	return got
}

func TestErrorIndicationDuringServiceRequestResumeRestoresIdle(t *testing.T) {
	srv := newTAUTestServer()
	const addr = "10.0.0.22:36412"

	ue, _, _ := makeRegisteredIdleUE(srv, addr)
	ue.Lock()
	ue.SetEMMState(emm.StateServiceRequestInitiated)
	ue.SetECMState(emm.ECMIdle)
	ue.AttachStep = uecontext.AttachStepWaitingICSRespSR
	ue.ENBS1APID = 2
	ue.ENBGlobalID = addr
	ue.ENBU_TEID = 0x11111111
	ue.ENBU_IP = net.ParseIP("192.168.105.34").To4()
	mmeID := ue.MMEUES1APID
	ue.Unlock()

	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeMMEUEApID(mmeID)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeENBUEApID(2)},
		{ID: pdu.IECause, Criticality: aper.CriticalityIgnore, Value: ies.EncodeCause(ies.CauseGroupRadioNetwork, ies.CauseRadioNetworkUserInactivity)},
	}
	srv.handleErrorIndication(addr, nil, ieList)

	found, ok := srv.ueManager.GetByMMEID(mmeID)
	if !ok {
		t.Fatal("UE removed from manager; expected idle retention")
	}
	found.Lock()
	emmState := found.EMMState
	ecmState := found.ECMState
	step := found.AttachStep
	enbUEID := found.ENBS1APID
	enbAddr := found.ENBGlobalID
	enbuTEID := found.ENBU_TEID
	found.Unlock()

	if emmState != emm.StateRegistered {
		t.Fatalf("EMMState got %v, want Registered", emmState)
	}
	if ecmState != emm.ECMIdle {
		t.Fatalf("ECMState got %v, want Idle", ecmState)
	}
	if step != uecontext.AttachStepNone {
		t.Fatalf("AttachStep got %d, want None", step)
	}
	if enbUEID != 0 || enbAddr != "" || enbuTEID != 0 {
		t.Fatalf("access context not cleared: enbUEID=%d enbAddr=%q enbuTEID=%#x", enbUEID, enbAddr, enbuTEID)
	}
}

// mbrTrackingS11 signals on ch whenever SendMBR is called.
type mbrTrackingS11 struct {
	ch chan struct{}
}

func (m *mbrTrackingS11) SendCSR(_ uint32, _ *gtpv2.CreateSessionRequest) error { return nil }
func (m *mbrTrackingS11) SendMBR(_ uint32, _ *gtpv2.ModifyBearerRequest) error {
	m.ch <- struct{}{}
	return nil
}
func (m *mbrTrackingS11) SendDSR(_ uint32, _ *gtpv2.DeleteSessionRequest) error { return nil }

type capturingServiceRequestMBRS11 struct {
	NoopS11Client
	ch chan *gtpv2.ModifyBearerRequest
}

func (m *capturingServiceRequestMBRS11) SendMBR(_ uint32, req *gtpv2.ModifyBearerRequest) error {
	copyReq := *req
	copyReq.Bearers = append([]gtpv2.ModifyBearer(nil), req.Bearers...)
	m.ch <- &copyReq
	return nil
}
