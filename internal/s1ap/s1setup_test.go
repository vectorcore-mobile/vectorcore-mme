package s1ap

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
)

func capturedSrsENBS1SetupRequest() []byte {
	return []byte{
		0x00, 0x11, 0x00, 0x2d, 0x00, 0x00, 0x04,
		0x00, 0x3b, 0x00, 0x08, 0x00, 0x13, 0x41, 0x53, 0x00, 0x00, 0x19, 0x70,
		0x00, 0x3c, 0x40, 0x0a, 0x03, 0x80, 0x73, 0x72, 0x73, 0x65, 0x6e, 0x62, 0x30, 0x31,
		0x00, 0x40, 0x00, 0x07, 0x00, 0x00, 0x40, 0x13, 0x41, 0x53, 0x00,
		0x00, 0x89, 0x40, 0x01, 0x40,
	}
}

func TestHandleCapturedSrsENBS1SetupRequestSendsResponse(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.168.105.34:36412"
	ch := setupSendCapture(srv, remoteAddr)

	srv.handleMessage(remoteAddr, capturedSrsENBS1SetupRequest())

	var rawResp []byte
	select {
	case rawResp = <-ch:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("no S1Setup response sent")
	}

	resp, err := pdu.Decode(rawResp)
	if err != nil {
		t.Fatalf("response Decode: %v", err)
	}
	if resp.Type != pdu.PDUTypeSuccessfulOutcome {
		t.Fatalf("response Type: got %d, want successfulOutcome", resp.Type)
	}
	if resp.ProcedureCode != pdu.ProcS1Setup {
		t.Fatalf("response ProcedureCode: got %d, want %d", resp.ProcedureCode, pdu.ProcS1Setup)
	}

	ieList, err := pdu.DecodeProcedureIEContainer(resp.Value)
	if err != nil {
		t.Fatalf("response DecodeProcedureIEContainer: %v", err)
	}
	byID := map[uint16]pdu.ProtocolIE{}
	for _, ie := range ieList {
		byID[ie.ID] = ie
	}
	if _, ok := byID[pdu.IEGUMMEIList]; ok {
		t.Fatalf("response used GUMMEIList IE %d; S1SetupResponse requires ServedGUMMEIs IE %d", pdu.IEGUMMEIList, pdu.IEServedGUMMEIs)
	}
	for _, id := range []uint16{pdu.IEServedGUMMEIs, pdu.IERelativeMMECapacity} {
		if _, ok := byID[id]; !ok {
			t.Fatalf("response missing IE %d", id)
		}
	}
}

func TestHandleS1SetupRequestStoresPLMNAndSupportedTA(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.168.105.34:36412"
	setupSendCapture(srv, remoteAddr)

	srv.handleMessage(remoteAddr, buildS1SetupRequestForTest(t, "311", "435", 0x197, 1))

	val, ok := srv.enbs.Load(remoteAddr)
	if !ok {
		t.Fatal("eNB context was not stored")
	}
	enb := val.(*ENBContext)
	if got, want := enb.GlobalENBID.Serialise(), "311435-0-407"; got != want {
		t.Fatalf("GlobalENBID: got %q, want %q", got, want)
	}
	if len(enb.SupportedTAs) != 1 {
		t.Fatalf("SupportedTAs count: got %d, want 1", len(enb.SupportedTAs))
	}
	if got, want := enb.SupportedTAs[0].TAC, uint16(1); got != want {
		t.Fatalf("SupportedTA TAC: got %d, want %d", got, want)
	}
	if len(enb.SupportedTAs[0].BroadcastPLMNs) != 1 {
		t.Fatalf("BroadcastPLMNs count: got %d, want 1", len(enb.SupportedTAs[0].BroadcastPLMNs))
	}
	bp := enb.SupportedTAs[0].BroadcastPLMNs[0]
	if bp.MCC != "311" || bp.MNC != "435" {
		t.Fatalf("BroadcastPLMN: got %s/%s, want 311/435", bp.MCC, bp.MNC)
	}

	peer, ok := srv.enbTracker.Get(remoteAddr)
	if !ok {
		t.Fatal("eNB peer tracker entry was not stored")
	}
	if peer.SupportedTAs == "" || peer.SupportedTAs == "null" {
		t.Fatalf("peer SupportedTAs = %q, want decoded TA JSON", peer.SupportedTAs)
	}
	if !strings.Contains(peer.SupportedTAs, `"TAC":1`) || !strings.Contains(peer.SupportedTAs, `"MCC":"311"`) || !strings.Contains(peer.SupportedTAs, `"MNC":"435"`) {
		t.Fatalf("peer SupportedTAs = %s, want TAC 1 PLMN 311/435", peer.SupportedTAs)
	}
}

func TestHandleS1SetupRequestMalformedSupportedTAsStillConnects(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.168.105.36:36412"
	ch := setupSendCapture(srv, remoteAddr)

	globalENBID, err := ies.EncodeGlobalENBID(ies.GlobalENBID{
		MCC: "311",
		MNC: "435",
		ENB: ies.ENBID{Type: ies.ENBIDTypeMacro, Value: 0x197},
	})
	if err != nil {
		t.Fatal(err)
	}
	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEGlobal_ENB_ID, Criticality: aper.CriticalityReject, Value: globalENBID},
		{ID: pdu.IESupportedTAs, Criticality: aper.CriticalityReject, Value: []byte{0xff, 0x00, 0xaa}},
		{ID: pdu.IEDefaultPagingDRX, Criticality: aper.CriticalityIgnore, Value: ies.EncodePagingDRX(1)},
	}

	srv.handleMessage(remoteAddr, pdu.BuildInitiatingMessage(pdu.ProcS1Setup, aper.CriticalityReject, ieList))

	resp := readCapturedPDU(t, ch)
	if resp.Type != pdu.PDUTypeSuccessfulOutcome {
		t.Fatalf("response Type: got %s, want successfulOutcome", resp.Type)
	}
	if resp.ProcedureCode != pdu.ProcS1Setup {
		t.Fatalf("response ProcedureCode: got %d, want %d", resp.ProcedureCode, pdu.ProcS1Setup)
	}

	val, ok := srv.enbs.Load(remoteAddr)
	if !ok {
		t.Fatal("eNB context was not stored")
	}
	enb := val.(*ENBContext)
	if len(enb.SupportedTAs) != 0 {
		t.Fatalf("SupportedTAs: got %+v, want empty list on decode failure", enb.SupportedTAs)
	}
}

func TestHandleS1SetupRequestMissingDefaultPagingDRXSendsFailure(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.168.105.35:36412"
	ch := setupSendCapture(srv, remoteAddr)

	globalENBID, err := ies.EncodeGlobalENBID(ies.GlobalENBID{
		MCC: "311",
		MNC: "435",
		ENB: ies.ENBID{Type: ies.ENBIDTypeMacro, Value: 0x197},
	})
	if err != nil {
		t.Fatal(err)
	}
	plmn, err := ies.EncodePLMN("311", "435")
	if err != nil {
		t.Fatal(err)
	}
	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEGlobal_ENB_ID, Criticality: aper.CriticalityReject, Value: globalENBID},
		{ID: pdu.IESupportedTAs, Criticality: aper.CriticalityReject, Value: encodeSupportedTAsForTest(plmn, 1, true)},
	}

	srv.handleMessage(remoteAddr, pdu.BuildInitiatingMessage(pdu.ProcS1Setup, aper.CriticalityReject, ieList))

	resp := readCapturedPDU(t, ch)
	if resp.Type != pdu.PDUTypeInitiatingMessage {
		t.Fatalf("response Type: got %s, want initiatingMessage", resp.Type)
	}
	if resp.ProcedureCode != pdu.ProcErrorIndication {
		t.Fatalf("response ProcedureCode: got %d, want %d", resp.ProcedureCode, pdu.ProcErrorIndication)
	}
	assertErrorIndicationCause(t, resp, ies.CauseGroupProtocol, ies.CauseProtocolSemanticError)
	assertErrorIndicationDiagnostics(t, resp, diagnosticExpectation{
		ProcedureCode:        pdu.ProcS1Setup,
		TriggeringMessage:    pdu.PDUTypeInitiatingMessage,
		ProcedureCriticality: aper.CriticalityReject,
		Items: []diagnosticIEExpectation{
			{IEID: pdu.IEDefaultPagingDRX, Criticality: aper.CriticalityIgnore, TypeOfError: typeOfErrorMissing},
		},
	})
}

func TestDecodeSupportedTAsBareAndHeaderForms(t *testing.T) {
	for _, c := range []struct {
		name       string
		withHeader bool
	}{
		{name: "header", withHeader: true},
		{name: "bare", withHeader: false},
	} {
		t.Run(c.name, func(t *testing.T) {
			plmn, err := ies.EncodePLMN("311", "435")
			if err != nil {
				t.Fatal(err)
			}
			tas := decodeSupportedTAs(encodeSupportedTAsForTest(plmn, 1, c.withHeader))
			if len(tas) != 1 {
				t.Fatalf("count: got %d, want 1", len(tas))
			}
			if tas[0].TAC != 1 {
				t.Fatalf("TAC: got %d, want 1", tas[0].TAC)
			}
			if len(tas[0].BroadcastPLMNs) != 1 || tas[0].BroadcastPLMNs[0].MCC != "311" || tas[0].BroadcastPLMNs[0].MNC != "435" {
				t.Fatalf("BroadcastPLMNs: got %+v", tas[0].BroadcastPLMNs)
			}
		})
	}
}

func TestDecodeSupportedTAsRealENBEncoding(t *testing.T) {
	data, err := hex.DecodeString("00000040134153")
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	tas, err := decodeSupportedTAsStrict(data)
	if err != nil {
		t.Fatalf("decodeSupportedTAsStrict: %v", err)
	}
	if len(tas) != 1 {
		t.Fatalf("count: got %d, want 1", len(tas))
	}
	if tas[0].TAC != 1 {
		t.Fatalf("TAC: got %d, want 1", tas[0].TAC)
	}
	if len(tas[0].BroadcastPLMNs) != 1 {
		t.Fatalf("BroadcastPLMNs count: got %d, want 1", len(tas[0].BroadcastPLMNs))
	}
	if tas[0].BroadcastPLMNs[0].MCC != "311" || tas[0].BroadcastPLMNs[0].MNC != "435" {
		t.Fatalf("BroadcastPLMN: got %+v, want 311/435", tas[0].BroadcastPLMNs[0])
	}
}

func TestEncodeServedGUMMEIsAdvertisesConfiguredMMEIdentity(t *testing.T) {
	srv := newTAUTestServer()
	srv.nfCfg.MCC = "311"
	srv.nfCfg.MNC = "435"
	srv.nfCfg.MMEGI = 1
	srv.nfCfg.MMEC = 1

	r := aper.NewBitReader(srv.encodeServedGUMMEIs())
	gummeiCount, err := aper.DecodeConstrainedWholeNumber(r, 1, 8)
	if err != nil {
		t.Fatalf("GUMMEI count: %v", err)
	}
	if gummeiCount != 1 {
		t.Fatalf("GUMMEI count: got %d, want 1", gummeiCount)
	}
	ext, err := r.ReadBit()
	if err != nil {
		t.Fatalf("item extension: %v", err)
	}
	if ext != 0 {
		t.Fatalf("item extension: got %d, want 0", ext)
	}
	if _, err := r.ReadBit(); err != nil {
		t.Fatalf("item optional bitmap: %v", err)
	}

	plmnCount, err := aper.DecodeConstrainedWholeNumber(r, 1, 32)
	if err != nil {
		t.Fatalf("PLMN count: %v", err)
	}
	if plmnCount != 1 {
		t.Fatalf("PLMN count: got %d, want 1", plmnCount)
	}
	plmn, err := aper.DecodeOctetString(r, 3, 3)
	if err != nil {
		t.Fatalf("PLMN: %v", err)
	}
	mcc, mnc, err := ies.DecodePLMN(plmn)
	if err != nil {
		t.Fatalf("DecodePLMN: %v", err)
	}
	if mcc != "311" || mnc != "435" {
		t.Fatalf("PLMN: got %s/%s, want 311/435", mcc, mnc)
	}

	groupCount, err := aper.DecodeConstrainedWholeNumber(r, 1, 65535)
	if err != nil {
		t.Fatalf("group count: %v", err)
	}
	if groupCount != 1 {
		t.Fatalf("group count: got %d, want 1", groupCount)
	}
	mmegi, err := aper.DecodeOctetString(r, 2, 2)
	if err != nil {
		t.Fatalf("MMEGI: %v", err)
	}
	if len(mmegi) != 2 || mmegi[0] != 0 || mmegi[1] != 1 {
		t.Fatalf("MMEGI: got % X, want 00 01", mmegi)
	}

	mmecCount, err := aper.DecodeConstrainedWholeNumber(r, 1, 256)
	if err != nil {
		t.Fatalf("MMEC count: %v", err)
	}
	if mmecCount != 1 {
		t.Fatalf("MMEC count: got %d, want 1", mmecCount)
	}
	mmec, err := aper.DecodeOctetString(r, 1, 1)
	if err != nil {
		t.Fatalf("MMEC: %v", err)
	}
	if len(mmec) != 1 || mmec[0] != 1 {
		t.Fatalf("MMEC: got % X, want 01", mmec)
	}
}

func TestHandleResetMissingResetTypeSendsErrorIndication(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.40:36412"
	ch := setupSendCapture(srv, remoteAddr)

	ieList := []pdu.ProtocolIE{
		{ID: pdu.IECause, Criticality: aper.CriticalityIgnore, Value: ies.EncodeCause(ies.CauseGroupProtocol, ies.CauseProtocolSemanticError)},
	}

	srv.handleMessage(remoteAddr, pdu.BuildInitiatingMessage(pdu.ProcReset, aper.CriticalityReject, ieList))

	msg := readCapturedPDU(t, ch)
	if msg.ProcedureCode != pdu.ProcErrorIndication {
		t.Fatalf("procedureCode: got %d, want ErrorIndication", msg.ProcedureCode)
	}
	assertErrorIndicationCause(t, msg, ies.CauseGroupProtocol, ies.CauseProtocolSemanticError)
	assertErrorIndicationDiagnostics(t, msg, diagnosticExpectation{
		ProcedureCode:        pdu.ProcReset,
		TriggeringMessage:    pdu.PDUTypeInitiatingMessage,
		ProcedureCriticality: aper.CriticalityReject,
		Items: []diagnosticIEExpectation{
			{IEID: pdu.IEResetType, Criticality: aper.CriticalityReject, TypeOfError: typeOfErrorMissing},
		},
	})
}

func TestHandleResetMalformedResetTypeSendsErrorIndication(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.41:36412"
	ch := setupSendCapture(srv, remoteAddr)

	ieList := []pdu.ProtocolIE{
		{ID: pdu.IECause, Criticality: aper.CriticalityIgnore, Value: ies.EncodeCause(ies.CauseGroupProtocol, ies.CauseProtocolSemanticError)},
		{ID: pdu.IEResetType, Criticality: aper.CriticalityReject, Value: []byte{0x80}},
	}

	srv.handleMessage(remoteAddr, pdu.BuildInitiatingMessage(pdu.ProcReset, aper.CriticalityReject, ieList))

	msg := readCapturedPDU(t, ch)
	if msg.ProcedureCode != pdu.ProcErrorIndication {
		t.Fatalf("procedureCode: got %d, want ErrorIndication", msg.ProcedureCode)
	}
	assertErrorIndicationCause(t, msg, ies.CauseGroupProtocol, ies.CauseProtocolFalselyConstructedMessage)
}

func buildS1SetupRequestForTest(t *testing.T, mcc, mnc string, enbID uint32, tac uint16) []byte {
	t.Helper()
	globalENBID, err := ies.EncodeGlobalENBID(ies.GlobalENBID{
		MCC: mcc,
		MNC: mnc,
		ENB: ies.ENBID{Type: ies.ENBIDTypeMacro, Value: enbID},
	})
	if err != nil {
		t.Fatal(err)
	}
	plmn, err := ies.EncodePLMN(mcc, mnc)
	if err != nil {
		t.Fatal(err)
	}
	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEGlobal_ENB_ID, Criticality: aper.CriticalityReject, Value: globalENBID},
		{ID: pdu.IESupportedTAs, Criticality: aper.CriticalityReject, Value: encodeSupportedTAsForTest(plmn, tac, true)},
		{ID: pdu.IEDefaultPagingDRX, Criticality: aper.CriticalityIgnore, Value: ies.EncodePagingDRX(1)},
	}
	return pdu.Encode(&pdu.PDU{
		Type:          pdu.PDUTypeInitiatingMessage,
		ProcedureCode: pdu.ProcS1Setup,
		Criticality:   aper.CriticalityReject,
		Value:         pdu.EncodeProcedureIEContainer(ieList),
	})
}

func encodeSupportedTAsForTest(plmn []byte, tac uint16, withItemHeader bool) []byte {
	w := aper.NewBitWriter()
	_ = aper.EncodeConstrainedWholeNumber(w, 1, 1, 256)
	if withItemHeader {
		w.WriteBit(0)
		w.WriteBit(0)
	}
	_ = aper.EncodeOctetString(w, []byte{byte(tac >> 8), byte(tac)}, 2, 2)
	_ = aper.EncodeConstrainedWholeNumber(w, 1, 1, 6)
	w.AlignToByte()
	w.WriteOctets(plmn)
	return w.Bytes()
}
