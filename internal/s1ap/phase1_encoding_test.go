package s1ap

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/gtpv2"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
)

func TestSendDownlinkNASTransportEncodesRel16IEs(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.10:36412"
	ch := setupSendCapture(srv, remoteAddr)
	ue := allocateTestUE(srv, remoteAddr, 0, true)
	ue.ENBS1APID = 0x010203

	nasPDU := emm.EncodeIdentityRequest(emm.IdentityTypeIMSI)
	if err := srv.SendDownlinkNAS(ue.MMEUES1APID, nasPDU); err != nil {
		t.Fatalf("SendDownlinkNAS: %v", err)
	}
	msg := readCapturedPDU(t, ch)
	assertPDUIEs(t, msg, pdu.PDUTypeInitiatingMessage, pdu.ProcDownlinkNASTransport, []uint16{
		pdu.IEMMEUES1APID,
		pdu.IEENBS1APID,
		pdu.IENAS_PDU,
	})
	assertNASPDU(t, msg, nasPDU)
}

func TestInitialUEMessageENBUEIDPropagatesToDownlinkNASTransport(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.10:36412"
	ch := setupSendCapture(srv, remoteAddr)
	const enbUEID = uint32(1)

	nasPDU := buildAttachRequestWithGUTIForS1APTest()
	tai, err := ies.EncodeTAI(ies.TAI{MCC: "001", MNC: "01", TAC: 1})
	if err != nil {
		t.Fatal(err)
	}
	ecgi, err := ies.EncodeECGI(ies.ECGI{MCC: "001", MNC: "01", ECGI: 1})
	if err != nil {
		t.Fatal(err)
	}
	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(enbUEID)},
		{ID: pdu.IENAS_PDU, Criticality: aper.CriticalityReject, Value: ies.EncodeNASPDU(nasPDU)},
		{ID: pdu.IETAI, Criticality: aper.CriticalityReject, Value: tai},
		{ID: pdu.IECGI, Criticality: aper.CriticalityIgnore, Value: ecgi},
		{ID: pdu.IERRCEstablishmentCause, Criticality: aper.CriticalityIgnore, Value: ies.EncodeRRCEstablishmentCause(3)},
	}

	srv.handleMessage(remoteAddr, pdu.BuildInitiatingMessage(pdu.ProcInitialUEMessage, aper.CriticalityIgnore, ieList))
	msg := readCapturedPDU(t, ch)
	assertPDUIEs(t, msg, pdu.PDUTypeInitiatingMessage, pdu.ProcDownlinkNASTransport, []uint16{
		pdu.IEMMEUES1APID,
		pdu.IEENBS1APID,
		pdu.IENAS_PDU,
	})
	gotENBUEID := decodeENBUEIDFromPDU(t, msg)
	if gotENBUEID != enbUEID {
		t.Fatalf("DownlinkNASTransport eNB-UE-S1AP-ID: got %d, want %d", gotENBUEID, enbUEID)
	}
}

func TestCapturedInitialUEMessageDecodesENBUEID(t *testing.T) {
	msg := decodeCapturedInitialUEMessage(t)
	if msg.Type != pdu.PDUTypeInitiatingMessage {
		t.Fatalf("PDU type: got %d, want initiatingMessage", msg.Type)
	}
	if msg.ProcedureCode != pdu.ProcInitialUEMessage {
		t.Fatalf("procedure: got %d, want %d", msg.ProcedureCode, pdu.ProcInitialUEMessage)
	}
	container, err := pdu.DecodeProcedureIEContainer(msg.Value)
	if err != nil {
		t.Fatalf("DecodeProcedureIEContainer: %v", err)
	}
	byID := map[uint16]pdu.ProtocolIE{}
	for _, ie := range container {
		byID[ie.ID] = ie
	}
	for _, id := range []uint16{pdu.IEENBS1APID, pdu.IENAS_PDU, pdu.IETAI, pdu.IECGI, pdu.IERRCEstablishmentCause} {
		if _, ok := byID[id]; !ok {
			t.Fatalf("missing IE %d", id)
		}
	}
	if got := hex.EncodeToString(byID[pdu.IEENBS1APID].Value); got != "0001" {
		t.Fatalf("eNB-UE-S1AP-ID open type value: got %s, want 0001", got)
	}
	enbUEID, err := ies.DecodeENBUEApID(byID[pdu.IEENBS1APID].Value)
	if err != nil {
		t.Fatalf("DecodeENBUEApID: %v", err)
	}
	if enbUEID != 1 {
		t.Fatalf("eNB-UE-S1AP-ID: got %d, want 1", enbUEID)
	}
	nasPDU, err := ies.DecodeNASPDU(byID[pdu.IENAS_PDU].Value)
	if err != nil {
		t.Fatalf("DecodeNASPDU: %v", err)
	}
	if len(nasPDU) == 0 {
		t.Fatal("NAS-PDU is empty")
	}
}

func TestCapturedInitialUEMessageTriggersDownlinkNASWithSameENBUEID(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.10:36412"
	ch := setupSendCapture(srv, remoteAddr)

	srv.handleMessage(remoteAddr, capturedInitialUEMessagePDU(t))
	msg := readCapturedPDU(t, ch)
	if msg.ProcedureCode != pdu.ProcDownlinkNASTransport {
		t.Fatalf("procedure: got %d, want DownlinkNASTransport", msg.ProcedureCode)
	}
	if got := decodeENBUEIDFromPDU(t, msg); got != 1 {
		t.Fatalf("DownlinkNASTransport eNB-UE-S1AP-ID: got %d, want 1", got)
	}
	assertNASPDU(t, msg, emm.EncodeIdentityRequest(emm.IdentityTypeIMSI))
}

func TestSendUEContextReleaseCommandEncodesRel16IEs(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.10:36412"
	ch := setupSendCapture(srv, remoteAddr)

	srv.sendUEContextReleaseCommand(remoteAddr, 1, 2)
	msg := readCapturedPDU(t, ch)
	assertPDUIEs(t, msg, pdu.PDUTypeInitiatingMessage, pdu.ProcUEContextRelease, []uint16{
		pdu.IEUES1APIDs,
		pdu.IECause,
	})
}

func TestProcedureCodesMatchRel16(t *testing.T) {
	if pdu.ProcReset != 14 {
		t.Fatalf("ProcReset: got %d, want 14", pdu.ProcReset)
	}
	if pdu.ProcErrorIndication != 15 {
		t.Fatalf("ProcErrorIndication: got %d, want 15", pdu.ProcErrorIndication)
	}
	if pdu.ProcNASNonDeliveryIndication != 16 {
		t.Fatalf("ProcNASNonDeliveryIndication: got %d, want 16", pdu.ProcNASNonDeliveryIndication)
	}
}

func TestHandleErrorIndicationDoesNotRespond(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.10:36412"
	ch := setupSendCapture(srv, remoteAddr)

	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeMMEUEApID(1)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeENBUEApID(2)},
		{ID: pdu.IECause, Criticality: aper.CriticalityIgnore, Value: ies.EncodeCause(ies.CauseGroupProtocol, 0)},
	}
	raw := pdu.BuildInitiatingMessage(pdu.ProcErrorIndication, aper.CriticalityIgnore, ieList)
	srv.handleMessage(remoteAddr, raw)

	select {
	case msg := <-ch:
		t.Fatalf("unexpected ErrorIndication response: %x", msg)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestHandleUECapabilityInfoIndicationStoresCapabilityAndDoesNotRespond(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.10:36412"
	ch := setupSendCapture(srv, remoteAddr)
	ue := allocateTestUE(srv, remoteAddr, 0, true)
	ue.ENBS1APID = 2
	capability := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeMMEUEApID(ue.MMEUES1APID)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(ue.ENBS1APID)},
		{ID: pdu.IEUERadioCapability, Criticality: aper.CriticalityIgnore, Value: ies.EncodeUERadioCapability(capability)},
	}
	raw := pdu.BuildInitiatingMessage(pdu.ProcUECapabilityInfoIndication, aper.CriticalityIgnore, ieList)
	srv.handleMessage(remoteAddr, raw)

	ue.Lock()
	got := append([]byte(nil), ue.UERadioCapability...)
	ue.Unlock()
	if !bytes.Equal(got, capability) {
		t.Fatalf("UE radio capability got %x, want %x", got, capability)
	}
	select {
	case msg := <-ch:
		t.Fatalf("unexpected UECapabilityInfoIndication response: %x", msg)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestHandleUECapabilityInfoIndicationFindsUEByENBIDWhenMMEIDZero(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.10:36412"
	ch := setupSendCapture(srv, remoteAddr)
	ue := allocateTestUE(srv, remoteAddr, 0, true)
	ue.ENBS1APID = 7
	capability := []byte{0xaa, 0xbb, 0xcc}

	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeMMEUEApID(0)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(ue.ENBS1APID)},
		{ID: pdu.IEUERadioCapability, Criticality: aper.CriticalityIgnore, Value: ies.EncodeUERadioCapability(capability)},
	}
	raw := pdu.BuildInitiatingMessage(pdu.ProcUECapabilityInfoIndication, aper.CriticalityIgnore, ieList)
	srv.handleMessage(remoteAddr, raw)

	ue.Lock()
	got := append([]byte(nil), ue.UERadioCapability...)
	ue.Unlock()
	if !bytes.Equal(got, capability) {
		t.Fatalf("UE radio capability got %x, want %x", got, capability)
	}
	select {
	case msg := <-ch:
		t.Fatalf("unexpected UECapabilityInfoIndication response: %x", msg)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestHandleUEContextReleaseRequestResolvesMMEIDBeforeCommand(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.10:36412"
	ch := setupSendCapture(srv, remoteAddr)
	ue := allocateTestUE(srv, remoteAddr, 0, true)
	ue.ENBS1APID = 9
	wantENBID := ue.ENBS1APID

	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeMMEUEApID(0)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(wantENBID)},
	}
	raw := pdu.BuildInitiatingMessage(pdu.ProcUEContextReleaseRequest, aper.CriticalityIgnore, ieList)
	srv.handleMessage(remoteAddr, raw)

	msg := readCapturedPDU(t, ch)
	if msg.ProcedureCode != pdu.ProcUEContextRelease {
		t.Fatalf("procedure: got %d, want UEContextReleaseCommand", msg.ProcedureCode)
	}
	mmeID, enbID := decodeUES1APIDsFromReleaseCommand(t, msg)
	if mmeID != ue.MMEUES1APID {
		t.Fatalf("release command MME-UE-S1AP-ID got %d, want %d", mmeID, ue.MMEUES1APID)
	}
	if enbID != wantENBID {
		t.Fatalf("release command eNB-UE-S1AP-ID got %d, want %d", enbID, wantENBID)
	}
}

func TestHandleCSRResultAttachAcceptUsesCurrentDLCountThenIncrements(t *testing.T) {
	srv := newTAUTestServer()
	srv.nasCfg.EPSNetworkFeatureSupport.IMSVoiceOverPS = true
	const remoteAddr = "192.0.2.10:36412"
	ch := setupSendCapture(srv, remoteAddr)
	ue := allocateTestUE(srv, remoteAddr, 0, false)
	ue.ENBS1APID = 1
	plmn, _ := ies.EncodePLMN("001", "01")
	tai := &emm.TAI{TAC: 1}
	copy(tai.PLMN[:], plmn)
	ue.Lock()
	ue.TAI = tai
	ue.KASME = make([]byte, 32)
	ue.KNASint = make([]byte, 16)
	ue.KNASenc = make([]byte, 16)
	ue.IntAlg = 0
	ue.EncAlg = 0
	ue.DLNASCount = 1
	ue.PDNRequestPTI = 1
	ue.APN = "internet"
	ue.Unlock()

	pgwPCO := []byte{0x80, 0x00, 0x0d, 0x04, 0x01, 0x01, 0x01, 0x01}
	srv.HandleCSRResult(ue.MMEUES1APID, &gtpv2.CreateSessionResponse{
		Cause:     gtpv2.CauseRequestAccepted,
		SGWC_TEID: 0x100,
		SGWC_IP:   net.ParseIP("10.0.0.2"),
		SGWU_TEID: 0x200,
		SGWU_IP:   net.ParseIP("10.0.0.3"),
		UEIPv4:    net.ParseIP("10.45.0.10"),
		EBI:       5,
		PCO:       pgwPCO,
	}, nil)

	msg := readCapturedPDU(t, ch)
	if msg.ProcedureCode != pdu.ProcInitialContextSetup {
		t.Fatalf("procedure: got %d, want InitialContextSetup", msg.ProcedureCode)
	}
	nasPDU := decodeNASPDUFromInitialContextSetup(t, msg)
	if got, want := nasPDU[0]>>4, emm.SecurityHeaderIntegrityProtected; got != want {
		t.Fatalf("security header: got %d, want %d", got, want)
	}
	if got, want := nasPDU[5], byte(1); got != want {
		t.Fatalf("Attach Accept NAS sequence number: got %d, want %d", got, want)
	}
	if got, want := nasPDU[6], byte(emm.PDEPSMobilityMgmt); got != want {
		t.Fatalf("plain Attach Accept PD/header: got %#x, want %#x", got, want)
	}
	if got, want := nasPDU[7], emm.MsgAttachAccept; got != want {
		t.Fatalf("plain message type: got %#x, want Attach Accept %#x", got, want)
	}
	if got, want := nasPDU[8], emm.AttachTypeEPSOnly; got != want {
		t.Fatalf("EPS attach result: got %#x, want EPS-only %#x", got, want)
	}
	esmContainer := decodeAttachAcceptESMContainer(t, nasPDU[6:])
	if got, want := esmContainer[0]>>4, byte(5); got != want {
		t.Fatalf("Activate Default EPS Bearer EBI: got %d, want %d", got, want)
	}
	if got, want := esmContainer[0]&0x0f, byte(0x02); got != want {
		t.Fatalf("Activate Default EPS Bearer PD: got %d, want ESM %d", got, want)
	}
	if got, want := esmContainer[2], byte(0xc1); got != want {
		t.Fatalf("ESM message type: got %#x, want Activate Default EPS Bearer Context Request %#x", got, want)
	}
	if got, want := esmContainer[4], byte(9); got != want {
		t.Fatalf("EPS QoS QCI: got %d, want %d", got, want)
	}
	apnLen := int(esmContainer[5])
	apn := esmContainer[6 : 6+apnLen]
	if got, want := string(apn), "\binternet"; got != want {
		t.Fatalf("APN field got %q, want %q", got, want)
	}
	paa := esmContainer[6+apnLen:]
	if len(paa) < 6 {
		t.Fatalf("PAA too short: %x", paa)
	}
	if got, want := paa[0], byte(5); got != want {
		t.Fatalf("PAA length: got %d, want %d", got, want)
	}
	if got, want := paa[1], byte(1); got != want {
		t.Fatalf("PAA PDN type: got %d, want IPv4 %d", got, want)
	}
	if got, want := net.IP(paa[2:6]).String(), "10.45.0.10"; got != want {
		t.Fatalf("PAA IPv4: got %s, want %s", got, want)
	}
	pcoIE := paa[6:]
	if len(pcoIE) < 2 {
		t.Fatalf("PCO IE missing after PAA: esm=%x", esmContainer)
	}
	if got, want := pcoIE[0], byte(0x27); got != want {
		t.Fatalf("PCO IEI: got %#x, want %#x", got, want)
	}
	if got, want := int(pcoIE[1]), len(pgwPCO); got != want {
		t.Fatalf("PCO length: got %d, want %d", got, want)
	}
	if got := pcoIE[2:]; !bytes.Equal(got, pgwPCO) {
		t.Fatalf("PCO value got %x, want %x", got, pgwPCO)
	}
	if !bytes.Contains(nasPDU[6:], []byte{0x64, 0x01, 0x01}) {
		t.Fatalf("Attach Accept missing EPS Network Feature Support IMS VoPS IE: %x", nasPDU[6:])
	}
	ue.Lock()
	dlCount := uint32(ue.DLNASCount)
	ue.Unlock()
	if dlCount != 2 {
		t.Fatalf("stored DL NAS COUNT after Attach Accept: got %d, want 2", dlCount)
	}
}

func TestDecodeInitialContextSetupResponseERABSetupVector(t *testing.T) {
	raw, err := hex.DecodeString("000032400a0a1fc0a8692200000001")
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	setup, err := decodeICSResponseERABSetup(raw)
	if err != nil {
		t.Fatalf("decodeICSResponseERABSetup: %v", err)
	}
	if got, want := setup.ERABID, uint8(5); got != want {
		t.Fatalf("E-RAB ID: got %d, want %d", got, want)
	}
	if got, want := setup.ENBUIP.String(), "192.168.105.34"; got != want {
		t.Fatalf("eNB S1-U IPv4: got %s, want %s", got, want)
	}
	if got, want := setup.ENBUTEID, uint32(1); got != want {
		t.Fatalf("eNB S1-U TEID: got %#x, want %#x", got, want)
	}
}

func TestSendInitialContextSetupEncodesRel16IEs(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.10:36412"
	ch := setupSendCapture(srv, remoteAddr)
	ue := allocateTestUE(srv, remoteAddr, 0, true)
	ue.ENBS1APID = 0x010203
	ue.KASME = make([]byte, 32)

	bearer := &BearerInfo{EBI: 5, SGWU_TEID: 0x01020304, SGWU_IP: []byte{10, 0, 0, 1}}
	if err := srv.SendInitialContextSetup(ue.MMEUES1APID, []byte{0x27, 0x42}, bearer); err != nil {
		t.Fatalf("SendInitialContextSetup: %v", err)
	}
	msg := readCapturedPDU(t, ch)
	assertPDUIEs(t, msg, pdu.PDUTypeInitiatingMessage, pdu.ProcInitialContextSetup, []uint16{
		pdu.IEMMEUES1APID,
		pdu.IEENBS1APID,
		pdu.IEUEAggregateMaxBitrate,
		pdu.IEERABToBeSetupListCtxtSUReq,
		pdu.IEUESecurityCapabilities,
		pdu.IESecurityKey,
	})

	ieList, err := pdu.DecodeIEContainer(msg.Value)
	if err != nil {
		t.Fatalf("DecodeIEContainer: %v", err)
	}
	seenAMBR := false
	seenSecurityCapabilities := false
	for i, ie := range ieList {
		if ie.ID == pdu.IEUESecurityCapabilities {
			seenSecurityCapabilities = true
			want := []byte{0x00, 0x00, 0x00, 0x00, 0x00}
			if !bytes.Equal(ie.Value, want) {
				t.Fatalf("UESecurityCapabilities got %x, want %x", ie.Value, want)
			}
			continue
		}
		if ie.ID != pdu.IEUEAggregateMaxBitrate {
			continue
		}
		seenAMBR = true
		want := []byte{
			0x18, 0x05, 0xf5, 0xe1, 0x00,
			0x60, 0x05, 0xf5, 0xe1, 0x00,
		}
		if !bytes.Equal(ie.Value, want) {
			t.Fatalf("UEAggregateMaximumBitrate got %x, want %x", ie.Value, want)
		}
		if i+1 >= len(ieList) {
			t.Fatal("UEAggregateMaximumBitrate is last IE; expected following E-RAB list")
		}
		if got := ieList[i+1].ID; got != pdu.IEERABToBeSetupListCtxtSUReq {
			t.Fatalf("IE after UEAggregateMaximumBitrate got %d, want %d", got, pdu.IEERABToBeSetupListCtxtSUReq)
		}
		erabItem := firstERABItemValue(ieList[i+1].Value)
		if len(erabItem) == 0 {
			t.Fatal("E-RABToBeSetupItemCtxtSUReq item value is empty")
		}
		if erabItem[0] != 0x45 {
			t.Fatalf("E-RAB item first byte got 0x%02x, want 0x45", erabItem[0])
		}
		if got, err := decodeSrsRANERABToBeSetupItemID(erabItem); err != nil {
			t.Fatalf("decode E-RAB-ID using srsRAN-compatible layout: %v", err)
		} else if got != 5 {
			t.Fatalf("srsRAN-compatible E-RAB-ID decode got %d, want 5", got)
		}
		wantTLA := []byte{0x0f, 0x80, 0x0a, 0x00, 0x00, 0x01}
		if !bytes.Contains(erabItem, wantTLA) {
			t.Fatalf("E-RAB transportLayerAddress got %x, want encoded TLA subsequence %x", erabItem, wantTLA)
		}
	}
	if !seenAMBR {
		t.Fatal("UEAggregateMaximumBitrate IE missing")
	}
	if !seenSecurityCapabilities {
		t.Fatal("UESecurityCapabilities IE missing")
	}
}

func TestSendInitialContextSetupMapsRealUESecurityCapabilities(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.10:36412"
	ch := setupSendCapture(srv, remoteAddr)
	ue := allocateTestUE(srv, remoteAddr, 0, true)
	ue.ENBS1APID = 268208
	ue.KASME = make([]byte, 32)
	ue.UENetworkCapability = []byte{0xf0, 0xf0, 0xe0, 0xe0, 0x1d}

	bearer := &BearerInfo{EBI: 5, SGWU_TEID: 0xf09d607c, SGWU_IP: []byte{10, 90, 250, 59}}
	if err := srv.SendInitialContextSetup(ue.MMEUES1APID, []byte{0x27, 0x42}, bearer); err != nil {
		t.Fatalf("SendInitialContextSetup: %v", err)
	}
	msg := readCapturedPDU(t, ch)
	ieList, err := pdu.DecodeIEContainer(msg.Value)
	if err != nil {
		t.Fatalf("DecodeIEContainer: %v", err)
	}

	var got []byte
	for _, ie := range ieList {
		if ie.ID == pdu.IEUESecurityCapabilities {
			got = ie.Value
			break
		}
	}
	want := []byte{0x1c, 0x00, 0x0e, 0x00, 0x00}
	if !bytes.Equal(got, want) {
		t.Fatalf("UESecurityCapabilities got %x, want Open5GS-style S1AP encoding %x", got, want)
	}
}

func TestERABToBeSetupItemERABIDUsesExtensibleInteger(t *testing.T) {
	bearer := &BearerInfo{EBI: 5, SGWU_TEID: 0x802de005, SGWU_IP: []byte{10, 90, 250, 81}}
	erabItem := firstERABItemValue(encodeERABList(bearer, []byte{0x27, 0x42}))
	if len(erabItem) == 0 {
		t.Fatal("E-RAB item is empty")
	}
	if got, want := erabItem[0], byte(0x45); got != want {
		t.Fatalf("E-RAB item first byte got 0x%02x, want 0x%02x", got, want)
	}
	id, err := decodeSrsRANERABToBeSetupItemID(erabItem)
	if err != nil {
		t.Fatalf("decode E-RAB-ID: %v", err)
	}
	if id != 5 {
		t.Fatalf("E-RAB-ID got %d, want 5", id)
	}
}

func TestERABToBeSetupItemWithoutNASPDUDecodesERABIDFive(t *testing.T) {
	bearer := &BearerInfo{EBI: 5, SGWU_TEID: 0xc1f44821, SGWU_IP: []byte{10, 90, 250, 59}}
	erabItem := firstERABItemValue(encodeERABList(bearer, nil))
	if len(erabItem) == 0 {
		t.Fatal("E-RAB item is empty")
	}
	if got, want := erabItem[0], byte(0x05); got != want {
		t.Fatalf("E-RAB item without NAS first byte got 0x%02x, want 0x%02x", got, want)
	}
	id, err := decodeSrsRANERABToBeSetupItemID(erabItem)
	if err != nil {
		t.Fatalf("decode E-RAB-ID: %v", err)
	}
	if id != 5 {
		t.Fatalf("E-RAB-ID got %d, want 5", id)
	}
	want := "050009210f800a5afa3bc1f44821"
	if got := hex.EncodeToString(erabItem); got != want {
		t.Fatalf("E-RAB item without NAS got %s, want %s", got, want)
	}
}

func TestOldERABToBeSetupItemPrefixWouldDecodeAs10(t *testing.T) {
	id, err := decodeSrsRANERABToBeSetupItemID([]byte{0x4a, 0x00})
	if err != nil {
		t.Fatalf("decode old E-RAB-ID prefix: %v", err)
	}
	if id != 10 {
		t.Fatalf("old 0x4a prefix decoded E-RAB-ID got %d, want 10", id)
	}
}

func readCapturedPDU(t *testing.T, ch <-chan []byte) *pdu.PDU {
	t.Helper()
	select {
	case raw := <-ch:
		msg, err := pdu.Decode(raw)
		if err != nil {
			t.Fatalf("Decode: %v", err)
		}
		return msg
	case <-time.After(200 * time.Millisecond):
		t.Fatal("no PDU captured")
	}
	return nil
}

func assertPDUIEs(t *testing.T, msg *pdu.PDU, typ pdu.PDUType, proc uint8, required []uint16) {
	t.Helper()
	if msg.Type != typ {
		t.Fatalf("PDU type: got %d, want %d", msg.Type, typ)
	}
	if msg.ProcedureCode != proc {
		t.Fatalf("procedureCode: got %d, want %d", msg.ProcedureCode, proc)
	}
	ies, err := pdu.DecodeProcedureIEContainer(msg.Value)
	if err != nil {
		t.Fatalf("DecodeProcedureIEContainer: %v", err)
	}
	byID := map[uint16]pdu.ProtocolIE{}
	for _, ie := range ies {
		byID[ie.ID] = ie
		meta, ok := pdu.Phase1ProcedureIEs[pdu.ProcedureIEKey{ProcedureCode: proc, PDUType: typ, IEID: ie.ID}]
		if ok && ie.Criticality != meta.Criticality {
			t.Fatalf("IE %d criticality: got %s, want %s", ie.ID, ie.Criticality, meta.Criticality)
		}
	}
	for _, id := range required {
		if _, ok := byID[id]; !ok {
			t.Fatalf("missing IE %d", id)
		}
	}
}

func assertNASPDU(t *testing.T, msg *pdu.PDU, want []byte) {
	t.Helper()
	container, err := pdu.DecodeProcedureIEContainer(msg.Value)
	if err != nil {
		t.Fatalf("DecodeProcedureIEContainer: %v", err)
	}
	for _, ie := range container {
		if ie.ID != pdu.IENAS_PDU {
			continue
		}
		got, err := ies.DecodeNASPDU(ie.Value)
		if err != nil {
			t.Fatalf("DecodeNASPDU: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("NAS-PDU: got %x, want %x", got, want)
		}
		return
	}
	t.Fatal("missing NAS-PDU IE")
}

func decodeENBUEIDFromPDU(t *testing.T, msg *pdu.PDU) uint32 {
	t.Helper()
	container, err := pdu.DecodeProcedureIEContainer(msg.Value)
	if err != nil {
		t.Fatalf("DecodeProcedureIEContainer: %v", err)
	}
	for _, ie := range container {
		if ie.ID != pdu.IEENBS1APID {
			continue
		}
		id, err := ies.DecodeENBUEApID(ie.Value)
		if err != nil {
			t.Fatalf("DecodeENBUEApID: %v", err)
		}
		return id
	}
	t.Fatal("missing eNB-UE-S1AP-ID IE")
	return 0
}

func decodeUES1APIDsFromReleaseCommand(t *testing.T, msg *pdu.PDU) (uint32, uint32) {
	t.Helper()
	container, err := pdu.DecodeProcedureIEContainer(msg.Value)
	if err != nil {
		t.Fatalf("DecodeProcedureIEContainer: %v", err)
	}
	for _, ie := range container {
		if ie.ID != pdu.IEUES1APIDs {
			continue
		}
		mmeID, enbID, err := ies.DecodeUES1APIDPair(ie.Value)
		if err != nil {
			t.Fatalf("DecodeUES1APIDPair: %v", err)
		}
		return mmeID, enbID
	}
	t.Fatal("missing UE-S1AP-IDs IE")
	return 0, 0
}

func decodeNASPDUFromInitialContextSetup(t *testing.T, msg *pdu.PDU) []byte {
	t.Helper()
	container, err := pdu.DecodeProcedureIEContainer(msg.Value)
	if err != nil {
		t.Fatalf("DecodeProcedureIEContainer: %v", err)
	}
	for _, ie := range container {
		if ie.ID != pdu.IEERABToBeSetupListCtxtSUReq {
			continue
		}
		item := firstERABItemValue(ie.Value)
		prefix := []byte{emm.PDEPSMobilityMgmt | (emm.SecurityHeaderIntegrityProtected << 4), 0, 0, 0, 0, 1, emm.PDEPSMobilityMgmt, emm.MsgAttachAccept}
		idx := bytes.Index(item, prefix)
		if idx < 0 {
			t.Fatalf("Attach Accept NAS-PDU prefix not found in E-RAB item: %x", item)
		}
		return append([]byte(nil), item[idx:]...)
	}
	t.Fatal("missing E-RABToBeSetupListCtxtSUReq IE")
	return nil
}

func decodeAttachAcceptESMContainer(t *testing.T, plainAttachAccept []byte) []byte {
	t.Helper()
	if len(plainAttachAccept) < 7 {
		t.Fatalf("Attach Accept too short: %x", plainAttachAccept)
	}
	taiListLen := int(plainAttachAccept[4])
	esmLenOffset := 5 + taiListLen
	if len(plainAttachAccept) < esmLenOffset+2 {
		t.Fatalf("Attach Accept missing ESM length: %x", plainAttachAccept)
	}
	esmLen := int(plainAttachAccept[esmLenOffset])<<8 | int(plainAttachAccept[esmLenOffset+1])
	esmStart := esmLenOffset + 2
	if len(plainAttachAccept) < esmStart+esmLen {
		t.Fatalf("Attach Accept ESM length %d exceeds message: %x", esmLen, plainAttachAccept)
	}
	return plainAttachAccept[esmStart : esmStart+esmLen]
}

func decodeSrsRANERABToBeSetupItemID(item []byte) (uint8, error) {
	r := aper.NewBitReader(item)
	if _, err := r.ReadBit(); err != nil {
		return 0, err
	}
	if _, err := r.ReadBit(); err != nil {
		return 0, err
	}
	if _, err := r.ReadBit(); err != nil {
		return 0, err
	}
	ext, err := r.ReadBit()
	if err != nil {
		return 0, err
	}
	if ext != 0 {
		return 0, fmt.Errorf("unexpected E-RAB-ID extension value")
	}
	id, err := aper.DecodeConstrainedWholeNumber(r, 0, 15)
	if err != nil {
		return 0, err
	}
	return uint8(id), nil
}

func buildAttachRequestWithGUTIForS1APTest() []byte {
	guti := (&emm.GUTI{
		PLMN:  [3]byte{0x00, 0xf1, 0x10},
		MMEGI: 1,
		MMEC:  1,
		MTMSI: 0x01020304,
	}).Encode()
	mobileID := guti[1:]
	esm := []byte{0x02, 0x01, 0xd0}
	body := []byte{0x71, byte(len(mobileID))}
	body = append(body, mobileID...)
	body = append(body, 0x02, 0xe0, 0xe0)
	body = append(body, 0x00, byte(len(esm)))
	body = append(body, esm...)
	return append([]byte{emm.PDEPSMobilityMgmt, emm.MsgAttachRequest}, body...)
}

func decodeCapturedInitialUEMessage(t *testing.T) *pdu.PDU {
	t.Helper()
	msg, err := pdu.Decode(capturedInitialUEMessagePDU(t))
	if err != nil {
		t.Fatalf("Decode captured InitialUEMessage: %v", err)
	}
	return msg
}

func capturedInitialUEMessagePDU(t *testing.T) []byte {
	t.Helper()
	raw, err := hex.DecodeString("000c4054000006000800020001001a0022211705e751810b0741610bf613513400140ac000000502f07000050201d011d191e0004300060013415300010064400800134153001979300086400140006000060280c0000005")
	if err != nil {
		t.Fatalf("hex DecodeString: %v", err)
	}
	return raw
}
