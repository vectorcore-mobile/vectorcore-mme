package s1ap

import (
	"testing"
	"time"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
)

func TestInitialUEMessageBeforeS1SetupIsDropped(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.9:36412"
	ch := make(chan []byte, 8)
	srv.sends.Store(remoteAddr, (chan<- []byte)(ch))

	nasPDU := buildAttachRequestWithGUTIForS1APTest()
	tai, err := ies.EncodeTAI(ies.TAI{MCC: "001", MNC: "01", TAC: 1})
	if err != nil {
		t.Fatalf("EncodeTAI: %v", err)
	}
	ecgi, err := ies.EncodeECGI(ies.ECGI{MCC: "001", MNC: "01", ECGI: 0x12345})
	if err != nil {
		t.Fatalf("EncodeECGI: %v", err)
	}
	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(7)},
		{ID: pdu.IENAS_PDU, Criticality: aper.CriticalityReject, Value: ies.EncodeNASPDU(nasPDU)},
		{ID: pdu.IETAI, Criticality: aper.CriticalityReject, Value: tai},
		{ID: pdu.IECGI, Criticality: aper.CriticalityIgnore, Value: ecgi},
		{ID: pdu.IERRCEstablishmentCause, Criticality: aper.CriticalityIgnore, Value: ies.EncodeRRCEstablishmentCause(0)},
	}

	srv.handleMessage(remoteAddr, pdu.BuildInitiatingMessage(pdu.ProcInitialUEMessage, aper.CriticalityIgnore, ieList))

	select {
	case raw := <-ch:
		t.Fatalf("unexpected response before S1Setup: %x", raw)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestInitialUEMessageMissingTAISendsErrorIndication(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.10:36412"
	ch := setupSendCapture(srv, remoteAddr)

	nasPDU := buildAttachRequestWithGUTIForS1APTest()
	ecgi, err := ies.EncodeECGI(ies.ECGI{MCC: "001", MNC: "01", ECGI: 0x12345})
	if err != nil {
		t.Fatalf("EncodeECGI: %v", err)
	}
	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(7)},
		{ID: pdu.IENAS_PDU, Criticality: aper.CriticalityReject, Value: ies.EncodeNASPDU(nasPDU)},
		{ID: pdu.IECGI, Criticality: aper.CriticalityIgnore, Value: ecgi},
		{ID: pdu.IERRCEstablishmentCause, Criticality: aper.CriticalityIgnore, Value: ies.EncodeRRCEstablishmentCause(0)},
	}

	srv.handleMessage(remoteAddr, pdu.BuildInitiatingMessage(pdu.ProcInitialUEMessage, aper.CriticalityIgnore, ieList))

	msg := readCapturedPDU(t, ch)
	if msg.ProcedureCode != pdu.ProcErrorIndication {
		t.Fatalf("procedureCode: got %d, want ErrorIndication", msg.ProcedureCode)
	}
	assertErrorIndicationCause(t, msg, ies.CauseGroupProtocol, ies.CauseProtocolSemanticError)
	assertErrorIndicationDiagnostics(t, msg, diagnosticExpectation{
		ProcedureCode:        pdu.ProcInitialUEMessage,
		TriggeringMessage:    pdu.PDUTypeInitiatingMessage,
		ProcedureCriticality: aper.CriticalityIgnore,
		Items: []diagnosticIEExpectation{
			{IEID: pdu.IETAI, Criticality: aper.CriticalityReject, TypeOfError: typeOfErrorMissing},
		},
	})
}

func TestUplinkNASTransportMissingTAIAndECGISendsErrorIndication(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.11:36412"
	ch := setupSendCapture(srv, remoteAddr)

	ue, _ := makeRegisteredUEWithNullKeys(srv, remoteAddr)
	ue.Lock()
	mmeUEID := ue.MMEUES1APID
	enbUEID := ue.ENBS1APID
	ue.Unlock()

	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeMMEUEApID(mmeUEID)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(enbUEID)},
		{ID: pdu.IENAS_PDU, Criticality: aper.CriticalityReject, Value: ies.EncodeNASPDU([]byte{emm.PDEPSMobilityMgmt, emm.MsgTrackingAreaUpdateRequest, 0x00})},
	}

	srv.handleMessage(remoteAddr, pdu.BuildInitiatingMessage(pdu.ProcUplinkNASTransport, aper.CriticalityIgnore, ieList))

	msg := readCapturedPDU(t, ch)
	if msg.ProcedureCode != pdu.ProcErrorIndication {
		t.Fatalf("procedureCode: got %d, want ErrorIndication", msg.ProcedureCode)
	}
	assertErrorIndicationCause(t, msg, ies.CauseGroupProtocol, ies.CauseProtocolSemanticError)
	assertErrorIndicationDiagnostics(t, msg, diagnosticExpectation{
		ProcedureCode:        pdu.ProcUplinkNASTransport,
		TriggeringMessage:    pdu.PDUTypeInitiatingMessage,
		ProcedureCriticality: aper.CriticalityIgnore,
		Items: []diagnosticIEExpectation{
			{IEID: pdu.IETAI, Criticality: aper.CriticalityIgnore, TypeOfError: typeOfErrorMissing},
			{IEID: pdu.IECGI, Criticality: aper.CriticalityIgnore, TypeOfError: typeOfErrorMissing},
		},
	})
}

func TestUplinkNASTransportUpdatesStoredTAIAndECGI(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.12:36412"
	setupSendCapture(srv, remoteAddr)

	ue, _ := makeRegisteredUEWithNullKeys(srv, remoteAddr)
	ue.Lock()
	mmeUEID := ue.MMEUES1APID
	ue.ENBS1APID = 7
	enbUEID := ue.ENBS1APID
	ue.TAI = &emm.TAI{PLMN: [3]byte{0x00, 0xF1, 0x10}, TAC: 9}
	ue.ECGIPLMN = [3]byte{0x00, 0xF1, 0x10}
	ue.ECGIECI = 0x11111
	ue.Unlock()

	taiValue, err := ies.EncodeTAI(ies.TAI{MCC: "001", MNC: "01", TAC: 7})
	if err != nil {
		t.Fatalf("EncodeTAI: %v", err)
	}
	ecgiValue, err := ies.EncodeECGI(ies.ECGI{MCC: "001", MNC: "01", ECGI: 0x22222})
	if err != nil {
		t.Fatalf("EncodeECGI: %v", err)
	}
	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeMMEUEApID(mmeUEID)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(enbUEID)},
		{ID: pdu.IENAS_PDU, Criticality: aper.CriticalityReject, Value: ies.EncodeNASPDU([]byte{emm.PDEPSMobilityMgmt, emm.MsgEMMStatus, 0x5f})},
		{ID: pdu.IECGI, Criticality: aper.CriticalityIgnore, Value: ecgiValue},
		{ID: pdu.IETAI, Criticality: aper.CriticalityIgnore, Value: taiValue},
	}

	srv.handleMessage(remoteAddr, pdu.BuildInitiatingMessage(pdu.ProcUplinkNASTransport, aper.CriticalityIgnore, ieList))

	ue.Lock()
	defer ue.Unlock()
	if ue.TAI == nil || ue.TAI.TAC != 7 {
		t.Fatalf("updated TAI got %+v, want TAC 7", ue.TAI)
	}
	if ue.ECGIECI != 0x22222 {
		t.Fatalf("updated ECGI got %#x, want %#x", ue.ECGIECI, 0x22222)
	}
}

func TestUplinkNASTransportUpdatesStoredTAIAndECGIWithAPERPrefixedLocationIEs(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.12:36412"
	setupSendCapture(srv, remoteAddr)

	ue, _ := makeRegisteredUEWithNullKeys(srv, remoteAddr)
	ue.Lock()
	mmeUEID := ue.MMEUES1APID
	ue.ENBS1APID = 7
	enbUEID := ue.ENBS1APID
	ue.TAI = &emm.TAI{PLMN: [3]byte{0x13, 0x51, 0x34}, TAC: 9}
	ue.ECGIPLMN = [3]byte{0x13, 0x51, 0x34}
	ue.ECGIECI = 0x11111
	ue.Unlock()

	taiValue, err := ies.EncodeTAI(ies.TAI{MCC: "311", MNC: "435", TAC: 1})
	if err != nil {
		t.Fatalf("EncodeTAI: %v", err)
	}
	ecgiValue, err := ies.EncodeECGI(ies.ECGI{MCC: "311", MNC: "435", ECGI: 0x000c8001})
	if err != nil {
		t.Fatalf("EncodeECGI: %v", err)
	}
	taiValue = append([]byte{0x00}, taiValue...)
	ecgiValue = append([]byte{0x00}, ecgiValue...)

	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeMMEUEApID(mmeUEID)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(enbUEID)},
		{ID: pdu.IENAS_PDU, Criticality: aper.CriticalityReject, Value: ies.EncodeNASPDU([]byte{emm.PDEPSMobilityMgmt, emm.MsgEMMStatus, 0x5f})},
		{ID: pdu.IECGI, Criticality: aper.CriticalityIgnore, Value: ecgiValue},
		{ID: pdu.IETAI, Criticality: aper.CriticalityIgnore, Value: taiValue},
	}

	srv.handleMessage(remoteAddr, pdu.BuildInitiatingMessage(pdu.ProcUplinkNASTransport, aper.CriticalityIgnore, ieList))

	ue.Lock()
	defer ue.Unlock()
	if ue.TAI == nil || ue.TAI.TAC != 1 {
		t.Fatalf("updated TAI got %+v, want TAC 1", ue.TAI)
	}
	if ue.ECGIECI != 0x000c8001 {
		t.Fatalf("updated ECGI got %#x, want %#x", ue.ECGIECI, 0x000c8001)
	}
}

func TestInitialUEMessageDuplicateENBUEIDSendsFalselyConstructedErrorIndication(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.14:36412"
	ch := setupSendCapture(srv, remoteAddr)

	nasPDU := buildAttachRequestWithGUTIForS1APTest()
	tai, err := ies.EncodeTAI(ies.TAI{MCC: "001", MNC: "01", TAC: 1})
	if err != nil {
		t.Fatalf("EncodeTAI: %v", err)
	}
	ecgi, err := ies.EncodeECGI(ies.ECGI{MCC: "001", MNC: "01", ECGI: 0x12345})
	if err != nil {
		t.Fatalf("EncodeECGI: %v", err)
	}
	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(7)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(8)},
		{ID: pdu.IENAS_PDU, Criticality: aper.CriticalityReject, Value: ies.EncodeNASPDU(nasPDU)},
		{ID: pdu.IETAI, Criticality: aper.CriticalityReject, Value: tai},
		{ID: pdu.IECGI, Criticality: aper.CriticalityIgnore, Value: ecgi},
		{ID: pdu.IERRCEstablishmentCause, Criticality: aper.CriticalityIgnore, Value: ies.EncodeRRCEstablishmentCause(0)},
	}

	srv.handleMessage(remoteAddr, pdu.BuildInitiatingMessage(pdu.ProcInitialUEMessage, aper.CriticalityIgnore, ieList))

	msg := readCapturedPDU(t, ch)
	if msg.ProcedureCode != pdu.ProcErrorIndication {
		t.Fatalf("procedureCode: got %d, want ErrorIndication", msg.ProcedureCode)
	}
	assertErrorIndicationCause(t, msg, ies.CauseGroupProtocol, ies.CauseProtocolFalselyConstructedMessage)
	assertErrorIndicationDiagnostics(t, msg, diagnosticExpectation{
		ProcedureCode:        pdu.ProcInitialUEMessage,
		TriggeringMessage:    pdu.PDUTypeInitiatingMessage,
		ProcedureCriticality: aper.CriticalityIgnore,
		Items: []diagnosticIEExpectation{
			{IEID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, TypeOfError: typeOfErrorNotUnderstood},
		},
	})
}

func TestInitialUEMessageOutOfOrderTAISendsFalselyConstructedErrorIndication(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.15:36412"
	ch := setupSendCapture(srv, remoteAddr)

	nasPDU := buildAttachRequestWithGUTIForS1APTest()
	tai, err := ies.EncodeTAI(ies.TAI{MCC: "001", MNC: "01", TAC: 1})
	if err != nil {
		t.Fatalf("EncodeTAI: %v", err)
	}
	ecgi, err := ies.EncodeECGI(ies.ECGI{MCC: "001", MNC: "01", ECGI: 0x12345})
	if err != nil {
		t.Fatalf("EncodeECGI: %v", err)
	}
	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(7)},
		{ID: pdu.IENAS_PDU, Criticality: aper.CriticalityReject, Value: ies.EncodeNASPDU(nasPDU)},
		{ID: pdu.IECGI, Criticality: aper.CriticalityIgnore, Value: ecgi},
		{ID: pdu.IETAI, Criticality: aper.CriticalityReject, Value: tai},
		{ID: pdu.IERRCEstablishmentCause, Criticality: aper.CriticalityIgnore, Value: ies.EncodeRRCEstablishmentCause(0)},
	}

	srv.handleMessage(remoteAddr, pdu.BuildInitiatingMessage(pdu.ProcInitialUEMessage, aper.CriticalityIgnore, ieList))

	msg := readCapturedPDU(t, ch)
	if msg.ProcedureCode != pdu.ProcErrorIndication {
		t.Fatalf("procedureCode: got %d, want ErrorIndication", msg.ProcedureCode)
	}
	assertErrorIndicationCause(t, msg, ies.CauseGroupProtocol, ies.CauseProtocolFalselyConstructedMessage)
	assertErrorIndicationDiagnostics(t, msg, diagnosticExpectation{
		ProcedureCode:        pdu.ProcInitialUEMessage,
		TriggeringMessage:    pdu.PDUTypeInitiatingMessage,
		ProcedureCriticality: aper.CriticalityIgnore,
		Items: []diagnosticIEExpectation{
			{IEID: pdu.IETAI, Criticality: aper.CriticalityReject, TypeOfError: typeOfErrorNotUnderstood},
		},
	})
}

func TestInitialUEMessageUnknownRejectIESendsSemanticErrorIndication(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.16:36412"
	ch := setupSendCapture(srv, remoteAddr)

	nasPDU := buildAttachRequestWithGUTIForS1APTest()
	tai, err := ies.EncodeTAI(ies.TAI{MCC: "001", MNC: "01", TAC: 1})
	if err != nil {
		t.Fatalf("EncodeTAI: %v", err)
	}
	ecgi, err := ies.EncodeECGI(ies.ECGI{MCC: "001", MNC: "01", ECGI: 0x12345})
	if err != nil {
		t.Fatalf("EncodeECGI: %v", err)
	}
	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(7)},
		{ID: pdu.IENAS_PDU, Criticality: aper.CriticalityReject, Value: ies.EncodeNASPDU(nasPDU)},
		{ID: pdu.IETAI, Criticality: aper.CriticalityReject, Value: tai},
		{ID: pdu.IECGI, Criticality: aper.CriticalityIgnore, Value: ecgi},
		{ID: pdu.IERRCEstablishmentCause, Criticality: aper.CriticalityIgnore, Value: ies.EncodeRRCEstablishmentCause(0)},
		{ID: 999, Criticality: aper.CriticalityReject, Value: []byte{0x00}},
	}

	srv.handleMessage(remoteAddr, pdu.BuildInitiatingMessage(pdu.ProcInitialUEMessage, aper.CriticalityIgnore, ieList))

	msg := readCapturedPDU(t, ch)
	if msg.ProcedureCode != pdu.ProcErrorIndication {
		t.Fatalf("procedureCode: got %d, want ErrorIndication", msg.ProcedureCode)
	}
	assertErrorIndicationCause(t, msg, ies.CauseGroupProtocol, ies.CauseProtocolSemanticError)
	assertErrorIndicationDiagnostics(t, msg, diagnosticExpectation{
		ProcedureCode:        pdu.ProcInitialUEMessage,
		TriggeringMessage:    pdu.PDUTypeInitiatingMessage,
		ProcedureCriticality: aper.CriticalityIgnore,
		Items: []diagnosticIEExpectation{
			{IEID: 999, Criticality: aper.CriticalityReject, TypeOfError: typeOfErrorNotUnderstood},
		},
	})
}

func TestSendInitialContextSetupRequiresBearer(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.12:36412"
	setupSendCapture(srv, remoteAddr)

	ue := allocateTestUE(srv, remoteAddr, 0, true)
	ue.Lock()
	mmeUEID := ue.MMEUES1APID
	ue.KASME = make([]byte, 32)
	ue.Unlock()

	if err := srv.SendInitialContextSetup(mmeUEID, []byte{0x27, 0x42}, nil); err == nil {
		t.Fatal("SendInitialContextSetup(nil bearer) succeeded, want error")
	}
	if err := srv.SendInitialContextSetupWithBearers(mmeUEID, []byte{0x27, 0x42}, nil); err == nil {
		t.Fatal("SendInitialContextSetupWithBearers(empty) succeeded, want error")
	}
}

func TestHandleENBConfigurationUpdateSendsAcknowledgeAndUpdatesContext(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.13:36412"
	ch := setupSendCapture(srv, remoteAddr)

	srv.enbs.Store(remoteAddr, &ENBContext{
		GlobalENBID: ies.GlobalENBID{
			MCC: "311",
			MNC: "435",
			ENB: ies.ENBID{Type: ies.ENBIDTypeMacro, Value: 0x197},
		},
		RemoteAddr:    remoteAddr,
		SetupComplete: true,
	})

	plmn, err := ies.EncodePLMN("311", "435")
	if err != nil {
		t.Fatalf("EncodePLMN: %v", err)
	}
	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEeNBname, Criticality: aper.CriticalityIgnore, Value: encodeVisibleStringForTest("lab-enb-updated")},
		{ID: pdu.IESupportedTAs, Criticality: aper.CriticalityReject, Value: encodeSupportedTAsForTest(plmn, 2, true)},
	}

	srv.handleMessage(remoteAddr, pdu.BuildInitiatingMessage(pdu.ProcENBConfigurationUpdate, aper.CriticalityReject, ieList))

	msg := readCapturedPDU(t, ch)
	if msg.Type != pdu.PDUTypeSuccessfulOutcome || msg.ProcedureCode != pdu.ProcENBConfigurationUpdate {
		t.Fatalf("ack got type=%s proc=%d, want successful ENBConfigurationUpdate", msg.Type, msg.ProcedureCode)
	}

	v, ok := srv.enbs.Load(remoteAddr)
	if !ok {
		t.Fatal("updated eNB context not stored")
	}
	enb := v.(*ENBContext)
	if enb.ENBName != "lab-enb-updated" {
		t.Fatalf("ENBName: got %q, want %q", enb.ENBName, "lab-enb-updated")
	}
	if len(enb.SupportedTAs) != 1 || enb.SupportedTAs[0].TAC != 2 {
		t.Fatalf("SupportedTAs: got %+v, want TAC 2", enb.SupportedTAs)
	}

	select {
	case <-time.After(10 * time.Millisecond):
	default:
	}
}

func TestHandleENBConfigurationUpdateMalformedENBNameSendsFailure(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.18:36412"
	ch := setupSendCapture(srv, remoteAddr)

	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEeNBname, Criticality: aper.CriticalityIgnore, Value: []byte{0x80}},
	}

	srv.handleMessage(remoteAddr, pdu.BuildInitiatingMessage(pdu.ProcENBConfigurationUpdate, aper.CriticalityReject, ieList))

	msg := readCapturedPDU(t, ch)
	if msg.Type != pdu.PDUTypeUnsuccessfulOutcome || msg.ProcedureCode != pdu.ProcENBConfigurationUpdate {
		t.Fatalf("got type=%s proc=%d, want unsuccessful ENBConfigurationUpdate", msg.Type, msg.ProcedureCode)
	}
	assertENBConfigurationUpdateFailureCause(t, msg, ies.CauseGroupProtocol, ies.CauseProtocolFalselyConstructedMessage)
	assertENBConfigurationUpdateFailureTimeToWait(t, msg, ies.TimeToWaitV10s)
	assertENBConfigurationUpdateFailureDiagnostics(t, msg, diagnosticExpectation{
		ProcedureCode:        pdu.ProcENBConfigurationUpdate,
		TriggeringMessage:    pdu.PDUTypeInitiatingMessage,
		ProcedureCriticality: aper.CriticalityReject,
		Items: []diagnosticIEExpectation{
			{IEID: pdu.IEeNBname, Criticality: aper.CriticalityIgnore, TypeOfError: typeOfErrorNotUnderstood},
		},
	})
}

func TestHandleENBConfigurationUpdateMalformedSupportedTAsSendsFailure(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.19:36412"
	ch := setupSendCapture(srv, remoteAddr)

	ieList := []pdu.ProtocolIE{
		{ID: pdu.IESupportedTAs, Criticality: aper.CriticalityReject, Value: []byte{0xff, 0x00, 0xaa}},
	}

	srv.handleMessage(remoteAddr, pdu.BuildInitiatingMessage(pdu.ProcENBConfigurationUpdate, aper.CriticalityReject, ieList))

	msg := readCapturedPDU(t, ch)
	if msg.Type != pdu.PDUTypeUnsuccessfulOutcome || msg.ProcedureCode != pdu.ProcENBConfigurationUpdate {
		t.Fatalf("got type=%s proc=%d, want unsuccessful ENBConfigurationUpdate", msg.Type, msg.ProcedureCode)
	}
	assertENBConfigurationUpdateFailureCause(t, msg, ies.CauseGroupProtocol, ies.CauseProtocolFalselyConstructedMessage)
	assertENBConfigurationUpdateFailureTimeToWait(t, msg, ies.TimeToWaitV10s)
	assertENBConfigurationUpdateFailureDiagnostics(t, msg, diagnosticExpectation{
		ProcedureCode:        pdu.ProcENBConfigurationUpdate,
		TriggeringMessage:    pdu.PDUTypeInitiatingMessage,
		ProcedureCriticality: aper.CriticalityReject,
		Items: []diagnosticIEExpectation{
			{IEID: pdu.IESupportedTAs, Criticality: aper.CriticalityReject, TypeOfError: typeOfErrorNotUnderstood},
		},
	})
}

func TestENBConfigurationUpdateUnknownNotifyIESendsErrorIndicationButStillAcknowledges(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.17:36412"
	ch := setupSendCapture(srv, remoteAddr)

	srv.enbs.Store(remoteAddr, &ENBContext{
		GlobalENBID: ies.GlobalENBID{
			MCC: "311",
			MNC: "435",
			ENB: ies.ENBID{Type: ies.ENBIDTypeMacro, Value: 0x197},
		},
		RemoteAddr:    remoteAddr,
		SetupComplete: true,
	})

	plmn, err := ies.EncodePLMN("311", "435")
	if err != nil {
		t.Fatalf("EncodePLMN: %v", err)
	}
	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEeNBname, Criticality: aper.CriticalityIgnore, Value: encodeVisibleStringForTest("lab-enb-notify")},
		{ID: pdu.IESupportedTAs, Criticality: aper.CriticalityReject, Value: encodeSupportedTAsForTest(plmn, 3, true)},
		{ID: 999, Criticality: aper.CriticalityNotify, Value: []byte{0x00}},
	}

	srv.handleMessage(remoteAddr, pdu.BuildInitiatingMessage(pdu.ProcENBConfigurationUpdate, aper.CriticalityReject, ieList))

	msg := readCapturedPDU(t, ch)
	if msg.ProcedureCode != pdu.ProcErrorIndication {
		t.Fatalf("first procedureCode: got %d, want ErrorIndication", msg.ProcedureCode)
	}
	assertErrorIndicationCause(t, msg, ies.CauseGroupProtocol, ies.CauseProtocolAbstractSyntaxErrorIgnoreAndNotify)
	assertErrorIndicationDiagnostics(t, msg, diagnosticExpectation{
		ProcedureCode:        pdu.ProcENBConfigurationUpdate,
		TriggeringMessage:    pdu.PDUTypeInitiatingMessage,
		ProcedureCriticality: aper.CriticalityReject,
		Items: []diagnosticIEExpectation{
			{IEID: 999, Criticality: aper.CriticalityNotify, TypeOfError: typeOfErrorNotUnderstood},
		},
	})

	ack := readCapturedPDU(t, ch)
	if ack.Type != pdu.PDUTypeSuccessfulOutcome || ack.ProcedureCode != pdu.ProcENBConfigurationUpdate {
		t.Fatalf("ack got type=%s proc=%d, want successful ENBConfigurationUpdate", ack.Type, ack.ProcedureCode)
	}

	v, ok := srv.enbs.Load(remoteAddr)
	if !ok {
		t.Fatal("updated eNB context not stored")
	}
	enb := v.(*ENBContext)
	if enb.ENBName != "lab-enb-notify" {
		t.Fatalf("ENBName: got %q, want %q", enb.ENBName, "lab-enb-notify")
	}
	if len(enb.SupportedTAs) != 1 || enb.SupportedTAs[0].TAC != 3 {
		t.Fatalf("SupportedTAs: got %+v, want TAC 3", enb.SupportedTAs)
	}
}

func assertErrorIndicationCause(t *testing.T, msg *pdu.PDU, wantGroup ies.CauseGroup, wantCause uint8) {
	t.Helper()
	ieList, err := pdu.DecodeProcedureIEContainer(msg.Value)
	if err != nil {
		t.Fatalf("DecodeProcedureIEContainer: %v", err)
	}
	for _, ie := range ieList {
		if ie.ID != pdu.IECause {
			continue
		}
		group, cause, err := ies.DecodeCause(ie.Value)
		if err != nil {
			t.Fatalf("DecodeCause: %v", err)
		}
		if group != wantGroup || cause != wantCause {
			t.Fatalf("cause got group=%d cause=%d, want group=%d cause=%d", group, cause, wantGroup, wantCause)
		}
		return
	}
	t.Fatal("ErrorIndication missing Cause IE")
}

func assertENBConfigurationUpdateFailureCause(t *testing.T, msg *pdu.PDU, wantGroup ies.CauseGroup, wantCause uint8) {
	t.Helper()
	ieList, err := pdu.DecodeProcedureIEContainer(msg.Value)
	if err != nil {
		t.Fatalf("DecodeProcedureIEContainer: %v", err)
	}
	for _, ie := range ieList {
		if ie.ID != pdu.IECause {
			continue
		}
		group, cause, err := ies.DecodeCause(ie.Value)
		if err != nil {
			t.Fatalf("DecodeCause: %v", err)
		}
		if group != wantGroup || cause != wantCause {
			t.Fatalf("cause got group=%d cause=%d, want group=%d cause=%d", group, cause, wantGroup, wantCause)
		}
		return
	}
	t.Fatal("ENBConfigurationUpdateFailure missing Cause IE")
}

type diagnosticIEExpectation struct {
	IEID        uint16
	Criticality aper.Criticality
	TypeOfError uint8
}

type diagnosticExpectation struct {
	ProcedureCode        uint8
	TriggeringMessage    pdu.PDUType
	ProcedureCriticality aper.Criticality
	Items                []diagnosticIEExpectation
}

func assertErrorIndicationDiagnostics(t *testing.T, msg *pdu.PDU, want diagnosticExpectation) {
	t.Helper()
	ieList, err := pdu.DecodeProcedureIEContainer(msg.Value)
	if err != nil {
		t.Fatalf("DecodeProcedureIEContainer: %v", err)
	}
	for _, ie := range ieList {
		if ie.ID != pdu.IECriticalityDiagnostics {
			continue
		}
		got := decodeCriticalityDiagnosticsForTest(t, ie.Value)
		if got.ProcedureCode != want.ProcedureCode {
			t.Fatalf("diagnostic procedure code: got %d, want %d", got.ProcedureCode, want.ProcedureCode)
		}
		if got.TriggeringMessage != want.TriggeringMessage {
			t.Fatalf("diagnostic triggering message: got %s, want %s", got.TriggeringMessage, want.TriggeringMessage)
		}
		if got.ProcedureCriticality != want.ProcedureCriticality {
			t.Fatalf("diagnostic procedure criticality: got %s, want %s", got.ProcedureCriticality, want.ProcedureCriticality)
		}
		if len(got.Items) != len(want.Items) {
			t.Fatalf("diagnostic item count: got %d, want %d", len(got.Items), len(want.Items))
		}
		wantByKey := make(map[diagnosticIEExpectation]int, len(want.Items))
		for _, item := range want.Items {
			wantByKey[item]++
		}
		for _, item := range got.Items {
			if wantByKey[item] == 0 {
				t.Fatalf("unexpected diagnostic item: got %+v want %+v", item, want.Items)
			}
			wantByKey[item]--
		}
		for item, count := range wantByKey {
			if count != 0 {
				t.Fatalf("missing diagnostic item: want %+v in %+v", item, got.Items)
			}
		}
		return
	}
	t.Fatal("ErrorIndication missing CriticalityDiagnostics IE")
}

func assertENBConfigurationUpdateFailureDiagnostics(t *testing.T, msg *pdu.PDU, want diagnosticExpectation) {
	t.Helper()
	ieList, err := pdu.DecodeProcedureIEContainer(msg.Value)
	if err != nil {
		t.Fatalf("DecodeProcedureIEContainer: %v", err)
	}
	for _, ie := range ieList {
		if ie.ID != pdu.IECriticalityDiagnostics {
			continue
		}
		got := decodeCriticalityDiagnosticsForTest(t, ie.Value)
		if got.ProcedureCode != want.ProcedureCode {
			t.Fatalf("diagnostic procedure code: got %d, want %d", got.ProcedureCode, want.ProcedureCode)
		}
		if got.TriggeringMessage != want.TriggeringMessage {
			t.Fatalf("diagnostic triggering message: got %s, want %s", got.TriggeringMessage, want.TriggeringMessage)
		}
		if got.ProcedureCriticality != want.ProcedureCriticality {
			t.Fatalf("diagnostic procedure criticality: got %s, want %s", got.ProcedureCriticality, want.ProcedureCriticality)
		}
		if len(got.Items) != len(want.Items) {
			t.Fatalf("diagnostic item count: got %d, want %d", len(got.Items), len(want.Items))
		}
		wantByKey := make(map[diagnosticIEExpectation]int, len(want.Items))
		for _, item := range want.Items {
			wantByKey[item]++
		}
		for _, item := range got.Items {
			if wantByKey[item] == 0 {
				t.Fatalf("unexpected diagnostic item: got %+v want %+v", item, want.Items)
			}
			wantByKey[item]--
		}
		for item, count := range wantByKey {
			if count != 0 {
				t.Fatalf("missing diagnostic item: want %+v in %+v", item, got.Items)
			}
		}
		return
	}
	t.Fatal("ENBConfigurationUpdateFailure missing CriticalityDiagnostics IE")
}

func assertENBConfigurationUpdateFailureTimeToWait(t *testing.T, msg *pdu.PDU, want uint8) {
	t.Helper()
	ieList, err := pdu.DecodeProcedureIEContainer(msg.Value)
	if err != nil {
		t.Fatalf("DecodeProcedureIEContainer: %v", err)
	}
	for _, ie := range ieList {
		if ie.ID != pdu.IETimeToWait {
			continue
		}
		r := aper.NewBitReader(ie.Value)
		got, err := aper.DecodeEnumerated(r, 6)
		if err != nil {
			t.Fatalf("DecodeEnumerated(TimeToWait): %v", err)
		}
		if uint8(got) != want {
			t.Fatalf("TimeToWait: got %d, want %d", got, want)
		}
		return
	}
	t.Fatal("ENBConfigurationUpdateFailure missing TimeToWait IE")
}

func decodeCriticalityDiagnosticsForTest(t *testing.T, data []byte) diagnosticExpectation {
	t.Helper()
	r := aper.NewBitReader(data)
	if ext, err := r.ReadBit(); err != nil || ext != 0 {
		t.Fatalf("diagnostic extension: got %d err=%v, want 0 nil", ext, err)
	}
	present := [5]uint8{}
	for i := range present {
		bit, err := r.ReadBit()
		if err != nil {
			t.Fatalf("diagnostic presence bit %d: %v", i, err)
		}
		present[i] = bit
	}
	if present[0] != 1 || present[1] != 1 || present[2] != 1 || present[3] != 1 {
		t.Fatalf("diagnostic presence bits: got %v", present)
	}
	r.AlignToByte()
	procCode, err := r.ReadOctet()
	if err != nil {
		t.Fatalf("diagnostic procedure code: %v", err)
	}
	triggeringMessageBits, err := r.ReadBits(2)
	if err != nil {
		t.Fatalf("diagnostic triggering message: %v", err)
	}
	crit, err := aper.DecodeCriticality(r)
	if err != nil {
		t.Fatalf("diagnostic procedure criticality: %v", err)
	}
	count, err := aper.DecodeConstrainedWholeNumber(r, 1, 256)
	if err != nil {
		t.Fatalf("diagnostic item count: %v", err)
	}
	items := make([]diagnosticIEExpectation, 0, count)
	for i := int64(0); i < count; i++ {
		ext, err := r.ReadBit()
		if err != nil {
			t.Fatalf("diagnostic item %d extension: %v", i, err)
		}
		if ext != 0 {
			t.Fatalf("diagnostic item %d extension: got %d, want 0", i, ext)
		}
		ieExtPresent, err := r.ReadBit()
		if err != nil {
			t.Fatalf("diagnostic item %d ieExtensions: %v", i, err)
		}
		if ieExtPresent != 0 {
			t.Fatalf("diagnostic item %d ieExtensions: got %d, want 0", i, ieExtPresent)
		}
		itemCrit, err := aper.DecodeCriticality(r)
		if err != nil {
			t.Fatalf("diagnostic item %d criticality: %v", i, err)
		}
		ieID, err := aper.DecodeConstrainedWholeNumber(r, 0, 65535)
		if err != nil {
			t.Fatalf("diagnostic item %d ieID: %v", i, err)
		}
		typeExt, err := r.ReadBit()
		if err != nil {
			t.Fatalf("diagnostic item %d type extension: %v", i, err)
		}
		if typeExt != 0 {
			t.Fatalf("diagnostic item %d type extension: got %d, want 0", i, typeExt)
		}
		typeOfError, err := aper.DecodeConstrainedWholeNumber(r, 0, 1)
		if err != nil {
			t.Fatalf("diagnostic item %d typeOfError: %v", i, err)
		}
		items = append(items, diagnosticIEExpectation{
			IEID:        uint16(ieID),
			Criticality: itemCrit,
			TypeOfError: uint8(typeOfError),
		})
	}
	return diagnosticExpectation{
		ProcedureCode:        procCode,
		TriggeringMessage:    pdu.PDUType(triggeringMessageBits),
		ProcedureCriticality: crit,
		Items:                items,
	}
}

func encodeVisibleStringForTest(value string) []byte {
	w := aper.NewBitWriter()
	w.WriteBit(0)
	_ = aper.EncodeUTF8String(w, value, 1, 150)
	return w.Bytes()
}
