package s1ap

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"github.com/vectorcore/mme/internal/uecontext"
)

func encodeVisibleStringForS1SetupTest(t *testing.T, value string) []byte {
	t.Helper()
	w := aper.NewBitWriter()
	if err := aper.EncodeVisibleStringExt(w, value, 1, 150); err != nil {
		t.Fatalf("EncodeVisibleStringExt(%q): %v", value, err)
	}
	return w.Bytes()
}

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

func TestHandleCapturedSrsENBS1SetupRequestSendsConfiguredMMEName(t *testing.T) {
	srv := newTAUTestServer()
	srv.nfCfg.MMEName = "vectorcore-mme"
	const remoteAddr = "192.168.105.34:36412"
	ch := setupSendCapture(srv, remoteAddr)

	srv.handleMessage(remoteAddr, capturedSrsENBS1SetupRequest())

	resp := readCapturedPDU(t, ch)
	if resp.Type != pdu.PDUTypeSuccessfulOutcome {
		t.Fatalf("response Type: got %d, want successfulOutcome", resp.Type)
	}

	ieList, err := pdu.DecodeProcedureIEContainer(resp.Value)
	if err != nil {
		t.Fatalf("response DecodeProcedureIEContainer: %v", err)
	}
	byID := map[uint16]pdu.ProtocolIE{}
	for _, ie := range ieList {
		byID[ie.ID] = ie
	}
	got, ok := byID[pdu.IEMMEname]
	if !ok {
		t.Fatal("response missing MMEname IE")
	}
	want := encodeVisibleStringForS1SetupTest(t, "vectorcore-mme")
	if !bytes.Equal(got.Value, want) {
		t.Fatalf("MMEname IE value = %x, want %x", got.Value, want)
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

func TestHandleS1SetupRequestMalformedSupportedTAsSendsFailure(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.168.105.36:36412"
	ch := make(chan []byte, 16)
	srv.sends.Store(remoteAddr, (chan<- []byte)(ch))

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
	if resp.Type != pdu.PDUTypeUnsuccessfulOutcome {
		t.Fatalf("response Type: got %s, want unsuccessfulOutcome", resp.Type)
	}
	if resp.ProcedureCode != pdu.ProcS1Setup {
		t.Fatalf("response ProcedureCode: got %d, want %d", resp.ProcedureCode, pdu.ProcS1Setup)
	}
	assertS1SetupFailureTimeToWait(t, resp, ies.TimeToWaitV10s)
	assertS1SetupFailureDiagnostics(t, resp, diagnosticExpectation{
		ProcedureCode:        pdu.ProcS1Setup,
		TriggeringMessage:    pdu.PDUTypeInitiatingMessage,
		ProcedureCriticality: aper.CriticalityReject,
		Items: []diagnosticIEExpectation{
			{IEID: pdu.IESupportedTAs, Criticality: aper.CriticalityReject, TypeOfError: typeOfErrorNotUnderstood},
		},
	})

	if _, ok := srv.enbs.Load(remoteAddr); ok {
		t.Fatal("eNB context was stored after malformed SupportedTAs")
	}
	if _, ok := srv.enbTracker.Get(remoteAddr); ok {
		t.Fatal("eNB peer tracker entry was stored after malformed SupportedTAs")
	}
}

func TestHandleS1SetupRequestMalformedDefaultPagingDRXSendsFailure(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.168.105.37:36412"
	ch := make(chan []byte, 16)
	srv.sends.Store(remoteAddr, (chan<- []byte)(ch))

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
		{ID: pdu.IEDefaultPagingDRX, Criticality: aper.CriticalityIgnore, Value: []byte{0x80}},
	}

	srv.handleMessage(remoteAddr, pdu.BuildInitiatingMessage(pdu.ProcS1Setup, aper.CriticalityReject, ieList))

	resp := readCapturedPDU(t, ch)
	if resp.Type != pdu.PDUTypeUnsuccessfulOutcome {
		t.Fatalf("response Type: got %s, want unsuccessfulOutcome", resp.Type)
	}
	if resp.ProcedureCode != pdu.ProcS1Setup {
		t.Fatalf("response ProcedureCode: got %d, want %d", resp.ProcedureCode, pdu.ProcS1Setup)
	}
	assertS1SetupFailureTimeToWait(t, resp, ies.TimeToWaitV10s)
	assertS1SetupFailureDiagnostics(t, resp, diagnosticExpectation{
		ProcedureCode:        pdu.ProcS1Setup,
		TriggeringMessage:    pdu.PDUTypeInitiatingMessage,
		ProcedureCriticality: aper.CriticalityReject,
		Items: []diagnosticIEExpectation{
			{IEID: pdu.IEDefaultPagingDRX, Criticality: aper.CriticalityIgnore, TypeOfError: typeOfErrorNotUnderstood},
		},
	})
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

func TestSendInitialContextSetupUsesSubscriberUEAMBR(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.168.105.34:36412"
	ch := setupSendCapture(srv, remoteAddr)
	ue := allocateTestUE(srv, remoteAddr, 0, true)
	ue.ENBS1APID = 1
	ue.KASME = make([]byte, 32)
	ue.UENetworkCapability = []byte{0xf0, 0x70}
	ue.UEAMBRDown = 1530000
	ue.UEAMBRUp = 3850000

	err := srv.SendInitialContextSetup(ue.MMEUES1APID, []byte{0x27, 0x42}, &BearerInfo{
		EBI:                     5,
		QCI:                     9,
		ARPPriority:             8,
		PreemptionVulnerability: true,
		SGWU_IP:                 []byte{10, 90, 250, 59},
		SGWU_TEID:               0x1c2c87d3,
	})
	if err != nil {
		t.Fatalf("SendInitialContextSetup: %v", err)
	}

	msg := readCapturedPDU(t, ch)
	container, err := pdu.DecodeProcedureIEContainer(msg.Value)
	if err != nil {
		t.Fatalf("DecodeProcedureIEContainer: %v", err)
	}
	want := ies.EncodeUEAggregateMaxBitrate(1530000, 3850000)
	for _, ie := range container {
		if ie.ID != pdu.IEUEAggregateMaxBitrate {
			continue
		}
		if !bytes.Equal(ie.Value, want) {
			t.Fatalf("UE AMBR IE: got %x, want %x", ie.Value, want)
		}
		return
	}
	t.Fatal("missing UE AMBR IE")
}

func TestEncodeERABItemBodyPreservesPreemptionVulnerability(t *testing.T) {
	body := encodeERABItemBody(BearerInfo{
		EBI:                     5,
		QCI:                     9,
		ARPPriority:             8,
		PreemptionCapability:    false,
		PreemptionVulnerability: false,
		SGWU_IP:                 []byte{10, 90, 250, 59},
		SGWU_TEID:               0x1c2c87d3,
	}, nil)

	r := aper.NewBitReader(body)
	if _, err := r.ReadBit(); err != nil {
		t.Fatalf("decode extension bit: %v", err)
	}
	if _, err := r.ReadBit(); err != nil {
		t.Fatalf("decode NAS presence: %v", err)
	}
	if _, err := r.ReadBit(); err != nil {
		t.Fatalf("decode IE extension presence: %v", err)
	}
	if ext, err := r.ReadBit(); err != nil || ext != 0 {
		t.Fatalf("decode E-RAB ID extension got %d err=%v, want 0 nil", ext, err)
	}
	if _, err := aper.DecodeConstrainedWholeNumber(r, 0, 15); err != nil {
		t.Fatalf("decode E-RAB ID: %v", err)
	}
	if ext, err := r.ReadBit(); err != nil || ext != 0 {
		t.Fatalf("decode QoS extension got %d err=%v, want 0 nil", ext, err)
	}
	if _, err := r.ReadBit(); err != nil {
		t.Fatalf("decode GBR presence: %v", err)
	}
	if ieExt, err := r.ReadBit(); err != nil || ieExt != 0 {
		t.Fatalf("decode QoS IE extensions got %d err=%v, want 0 nil", ieExt, err)
	}
	if _, err := aper.DecodeConstrainedWholeNumber(r, 0, 255); err != nil {
		t.Fatalf("decode QCI: %v", err)
	}
	if ext, err := r.ReadBit(); err != nil || ext != 0 {
		t.Fatalf("decode ARP extension got %d err=%v, want 0 nil", ext, err)
	}
	if ieExt, err := r.ReadBit(); err != nil || ieExt != 0 {
		t.Fatalf("decode ARP IE extensions got %d err=%v, want 0 nil", ieExt, err)
	}
	if _, err := aper.DecodeConstrainedWholeNumber(r, 0, 15); err != nil {
		t.Fatalf("decode ARP priority: %v", err)
	}
	pc, err := aper.DecodeConstrainedWholeNumber(r, 0, 1)
	if err != nil {
		t.Fatalf("decode preemption capability: %v", err)
	}
	pv, err := aper.DecodeConstrainedWholeNumber(r, 0, 1)
	if err != nil {
		t.Fatalf("decode preemption vulnerability: %v", err)
	}
	if pc != 0 {
		t.Fatalf("preemption capability got %d, want 0", pc)
	}
	if pv != 0 {
		t.Fatalf("preemption vulnerability got %d, want 0", pv)
	}
}

func TestEncodeERABItemBodyIncludesGBRQoSWhenBearerQoSPresent(t *testing.T) {
	body := encodeERABItemBody(BearerInfo{
		EBI:                     7,
		QCI:                     2,
		ARPPriority:             4,
		PreemptionCapability:    true,
		PreemptionVulnerability: true,
		BearerQoS:               encodeBearerQoSForTest(2, 16, 128000, 128000, 128000, 128000),
		SGWU_IP:                 []byte{10, 90, 250, 59},
		SGWU_TEID:               0xed2bffcb,
	}, []byte{0x27, 0x62, 0x00, 0xc6})

	item := decodeResumeICSErabItem(t, body)
	if !item.GBRQosInformationPresent {
		t.Fatalf("GBR QoS presence got false, want true")
	}
	if got, want := item.EBI, uint8(7); got != want {
		t.Fatalf("EBI got %d, want %d", got, want)
	}
	if got, want := item.QCI, uint8(2); got != want {
		t.Fatalf("QCI got %d, want %d", got, want)
	}
	if got, want := item.SGWS1UTEID, uint32(0xed2bffcb); got != want {
		t.Fatalf("SGW TEID got %#x, want %#x", got, want)
	}
	if got, want := item.SGWS1UIPv4, "10.90.250.59"; got != want {
		t.Fatalf("SGW IP got %s, want %s", got, want)
	}
	if got, want := item.NASPDU, []byte{0x27, 0x62, 0x00, 0xc6}; !bytes.Equal(got, want) {
		t.Fatalf("NAS PDU got %x, want %x", got, want)
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

func TestHandleResetPreservesRegisteredUEAsIdle(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.42:36412"
	ch := setupSendCapture(srv, remoteAddr)

	ue := allocateTestUE(srv, remoteAddr, 0x12345678, true)
	ue.Lock()
	ue.ENBS1APID = 0x44
	ue.S1BindingGeneration = 7
	ue.S1BindingState = uecontext.S1BindingActive
	ue.SetEMMState(emm.StateRegistered)
	ue.SetECMState(emm.ECMConnected)
	ue.Unlock()

	ieList := []pdu.ProtocolIE{
		{ID: pdu.IECause, Criticality: aper.CriticalityIgnore, Value: ies.EncodeCause(ies.CauseGroupProtocol, ies.CauseProtocolSemanticError)},
		{ID: pdu.IEResetType, Criticality: aper.CriticalityReject, Value: []byte{0x00}},
	}

	srv.handleMessage(remoteAddr, pdu.BuildInitiatingMessage(pdu.ProcReset, aper.CriticalityReject, ieList))

	msg := readCapturedPDU(t, ch)
	if msg.Type != pdu.PDUTypeSuccessfulOutcome {
		t.Fatalf("response Type: got %s, want successfulOutcome", msg.Type)
	}
	if msg.ProcedureCode != pdu.ProcReset {
		t.Fatalf("procedureCode: got %d, want Reset", msg.ProcedureCode)
	}

	found := srv.ueManager.MustGetByMMEID(ue.MMEUES1APID)
	found.Lock()
	ecmState := found.ECMState
	enbAddr := found.ENBGlobalID
	enbUEID := found.ENBS1APID
	bindingState := found.S1BindingState
	sgwcTEID := found.SGWC_TEID
	found.Unlock()

	if ecmState != emm.ECMIdle {
		t.Fatalf("ECM state: got %s, want %s", ecmState, emm.ECMIdle)
	}
	if enbAddr != "" {
		t.Fatalf("ENBGlobalID: got %q, want empty", enbAddr)
	}
	if enbUEID != 0 {
		t.Fatalf("ENBS1APID: got %d, want 0", enbUEID)
	}
	if bindingState != uecontext.S1BindingReleased {
		t.Fatalf("S1BindingState: got %s, want %s", bindingState, uecontext.S1BindingReleased)
	}
	if sgwcTEID == 0 {
		t.Fatal("SGWC_TEID cleared on reset-preserve path")
	}
}

func TestHandleResetClearsPendingServiceRequestResume(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.44:36412"
	ch := setupSendCapture(srv, remoteAddr)

	ue := allocateTestUE(srv, remoteAddr, 0x22334455, true)
	ue.Lock()
	ue.ENBS1APID = 0x66
	ue.S1BindingGeneration = 9
	ue.S1BindingState = uecontext.S1BindingActive
	ue.SetEMMState(emm.StateServiceRequestInitiated)
	ue.SetECMState(emm.ECMConnected)
	ue.AttachStep = uecontext.AttachStepWaitingICSRespSR
	ue.Unlock()

	ieList := []pdu.ProtocolIE{
		{ID: pdu.IECause, Criticality: aper.CriticalityIgnore, Value: ies.EncodeCause(ies.CauseGroupProtocol, ies.CauseProtocolSemanticError)},
		{ID: pdu.IEResetType, Criticality: aper.CriticalityReject, Value: []byte{0x00}},
	}

	srv.handleMessage(remoteAddr, pdu.BuildInitiatingMessage(pdu.ProcReset, aper.CriticalityReject, ieList))

	msg := readCapturedPDU(t, ch)
	if msg.Type != pdu.PDUTypeSuccessfulOutcome {
		t.Fatalf("response Type: got %s, want successfulOutcome", msg.Type)
	}

	found := srv.ueManager.MustGetByMMEID(ue.MMEUES1APID)
	found.Lock()
	emmState := found.EMMState
	ecmState := found.ECMState
	attachStep := found.AttachStep
	found.Unlock()

	if emmState != emm.StateRegistered {
		t.Fatalf("EMM state: got %s, want %s", emmState, emm.StateRegistered)
	}
	if ecmState != emm.ECMIdle {
		t.Fatalf("ECM state: got %s, want %s", ecmState, emm.ECMIdle)
	}
	if attachStep != uecontext.AttachStepNone {
		t.Fatalf("AttachStep: got %d, want %d", attachStep, uecontext.AttachStepNone)
	}
}

func TestHandleResetEvictsIncompleteUEContext(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.43:36412"
	ch := setupSendCapture(srv, remoteAddr)

	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.ENBGlobalID = remoteAddr
	ue.ENBS1APID = 0x55
	ue.S1BindingState = uecontext.S1BindingActive
	ue.Unlock()

	ieList := []pdu.ProtocolIE{
		{ID: pdu.IECause, Criticality: aper.CriticalityIgnore, Value: ies.EncodeCause(ies.CauseGroupProtocol, ies.CauseProtocolSemanticError)},
		{ID: pdu.IEResetType, Criticality: aper.CriticalityReject, Value: []byte{0x00}},
	}

	srv.handleMessage(remoteAddr, pdu.BuildInitiatingMessage(pdu.ProcReset, aper.CriticalityReject, ieList))

	msg := readCapturedPDU(t, ch)
	if msg.Type != pdu.PDUTypeSuccessfulOutcome {
		t.Fatalf("response Type: got %s, want successfulOutcome", msg.Type)
	}
	if _, ok := srv.ueManager.GetByMMEID(ue.MMEUES1APID); ok {
		t.Fatal("incomplete UE context still present after reset")
	}
}

func assertS1SetupFailureDiagnostics(t *testing.T, msg *pdu.PDU, want diagnosticExpectation) {
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
	t.Fatal("S1SetupFailure missing CriticalityDiagnostics IE")
}

func assertS1SetupFailureTimeToWait(t *testing.T, msg *pdu.PDU, want uint8) {
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
	t.Fatal("S1SetupFailure missing TimeToWait IE")
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
