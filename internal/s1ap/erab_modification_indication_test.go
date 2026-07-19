package s1ap

import (
	"net"
	"testing"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/gtpv2"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"github.com/vectorcore/mme/internal/uecontext"
)

func TestERABModificationIndicationUpdatesBearersAndSendsConfirm(t *testing.T) {
	mockS11 := newMBRMock(nil)
	srv := newTestServer(mockS11)
	const addr = "10.0.0.31:36412"
	ch := setupSendCapture(srv, addr)

	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070590"
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMConnected
	ue.ENBGlobalID = addr
	ue.ENBS1APID = 61
	ue.SGWAddress = "10.90.250.59:2123"
	ue.SGWC_TEID = 0xabcdef01
	ue.DefaultEBI = 5
	ue.ENBU_TEID = 0x11110001
	ue.ENBU_IP = net.ParseIP("192.0.2.10").To4()
	ue.PDNs["ims"] = &uecontext.PDNContext{
		APN:             "ims",
		DefaultEBI:      5,
		ERABEstablished: true,
		ENBU_TEID:       0x11110001,
		ENBU_IP:         net.ParseIP("192.0.2.10").To4(),
	}
	ue.DedicatedBearers[9] = &uecontext.DedicatedBearerContext{
		AssignedEBI:     9,
		LinkedEBI:       5,
		ERABEstablished: true,
		ENBS1UTEID:      0x22220001,
		ENBS1UIP:        net.ParseIP("192.0.2.20").To4(),
		SGWS1UTEID:      0x33330001,
		SGWS1UIP:        net.ParseIP("198.51.100.20").To4(),
	}
	mmeID := ue.MMEUES1APID
	enbID := ue.ENBS1APID
	ue.Unlock()

	srv.handleERABModificationIndication(addr, &pdu.PDU{
		Type:          pdu.PDUTypeInitiatingMessage,
		ProcedureCode: pdu.ProcERABModificationIndication,
		Criticality:   aper.CriticalityReject,
	}, buildERABModificationIndicationIEs(mmeID, enbID,
		[]erabModificationIndicationItem{{EBI: 9, TEID: 0x44440001, IP: net.ParseIP("192.0.2.44").To4()}},
		[]erabModificationIndicationItem{{EBI: 5, TEID: 0x55550001, IP: net.ParseIP("192.0.2.55").To4()}},
	))

	if len(mockS11.reqs) != 1 {
		t.Fatalf("Modify Bearer calls: got %d want 1", len(mockS11.reqs))
	}
	if got := mockS11.reqs[0].Bearers; len(got) != 2 {
		t.Fatalf("Modify Bearer bearer count: got %d want 2", len(got))
	}
	correlationID := mockS11.reqs[0].CorrelationID
	if correlationID == "" {
		t.Fatal("missing Modify Bearer correlation ID")
	}

	ue.Lock()
	if ue.ENBU_TEID != 0x11110001 || !ue.ENBU_IP.Equal(net.ParseIP("192.0.2.10").To4()) {
		t.Fatalf("default bearer root tunnel updated before MBR result: teid=%#x ip=%v", ue.ENBU_TEID, ue.ENBU_IP)
	}
	if pdn := ue.PDNs["ims"]; pdn == nil || pdn.ENBU_TEID != 0x11110001 || !pdn.ENBU_IP.Equal(net.ParseIP("192.0.2.10").To4()) {
		t.Fatalf("pdn tunnel updated before MBR result: %+v", pdn)
	}
	if bearer := ue.DedicatedBearers[9]; bearer == nil || bearer.ENBS1UTEID != 0x22220001 || !bearer.ENBS1UIP.Equal(net.ParseIP("192.0.2.20").To4()) {
		t.Fatalf("dedicated bearer tunnel updated before MBR result: %+v", bearer)
	}
	ue.Unlock()

	srv.HandleMBRResult(mmeID, correlationID, &gtpv2.ModifyBearerResponse{
		Cause: gtpv2.CauseRequestAccepted,
		ModifiedBearers: []gtpv2.ModifyBearerBearerResult{
			{EBI: 5, Cause: gtpv2.CauseRequestAccepted},
			{EBI: 9, Cause: gtpv2.CauseRequestAccepted},
		},
	}, nil)

	msg := readCapturedPDU(t, ch)
	if msg.ProcedureCode != pdu.ProcERABModificationIndication || msg.Type != pdu.PDUTypeSuccessfulOutcome {
		t.Fatalf("confirm got procedure=%d type=%s", msg.ProcedureCode, msg.Type)
	}
	iesOut, err := decodeProcedureIEsCompat(msg.Value)
	if err != nil {
		t.Fatalf("decode confirm IEs: %v", err)
	}
	var sawSuccess bool
	for _, ie := range iesOut {
		if ie.ID == pdu.IEERABModifyListBearerModConf {
			sawSuccess = true
		}
	}
	if !sawSuccess {
		t.Fatal("confirm missing success list")
	}
	ue.Lock()
	if ue.ENBU_TEID != 0x55550001 || !ue.ENBU_IP.Equal(net.ParseIP("192.0.2.55").To4()) {
		ue.Unlock()
		t.Fatalf("default bearer root tunnel not updated after MBR result: teid=%#x ip=%v", ue.ENBU_TEID, ue.ENBU_IP)
	}
	if pdn := ue.PDNs["ims"]; pdn == nil || pdn.ENBU_TEID != 0x55550001 || !pdn.ENBU_IP.Equal(net.ParseIP("192.0.2.55").To4()) {
		ue.Unlock()
		t.Fatalf("pdn tunnel not updated after MBR result: %+v", pdn)
	}
	if bearer := ue.DedicatedBearers[9]; bearer == nil || bearer.ENBS1UTEID != 0x44440001 || !bearer.ENBS1UIP.Equal(net.ParseIP("192.0.2.44").To4()) {
		ue.Unlock()
		t.Fatalf("dedicated bearer tunnel not updated after MBR result: %+v", bearer)
	}
	ue.Unlock()
}

func TestERABModificationIndicationUnknownEBIFailsConfirm(t *testing.T) {
	mockS11 := newMBRMock(nil)
	srv := newTestServer(mockS11)
	const addr = "10.0.0.32:36412"
	ch := setupSendCapture(srv, addr)

	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070591"
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMConnected
	ue.ENBGlobalID = addr
	ue.ENBS1APID = 62
	mmeID := ue.MMEUES1APID
	enbID := ue.ENBS1APID
	ue.Unlock()

	srv.handleERABModificationIndication(addr, &pdu.PDU{
		Type:          pdu.PDUTypeInitiatingMessage,
		ProcedureCode: pdu.ProcERABModificationIndication,
		Criticality:   aper.CriticalityReject,
	}, buildERABModificationIndicationIEs(mmeID, enbID,
		[]erabModificationIndicationItem{{EBI: 9, TEID: 0x44440001, IP: net.ParseIP("192.0.2.44").To4()}},
		nil,
	))

	if len(mockS11.reqs) != 0 {
		t.Fatalf("unexpected Modify Bearer calls: %d", len(mockS11.reqs))
	}
	msg := readCapturedPDU(t, ch)
	iesOut, err := decodeProcedureIEsCompat(msg.Value)
	if err != nil {
		t.Fatalf("decode confirm IEs: %v", err)
	}
	var sawFailed bool
	for _, ie := range iesOut {
		if ie.ID == pdu.IEERABFailedToModifyListBearerModConf {
			sawFailed = true
		}
	}
	if !sawFailed {
		t.Fatal("confirm missing failed list")
	}
}

func TestERABModificationIndicationWrongPairSendsErrorIndication(t *testing.T) {
	srv := newTestServer(nil)
	const addr = "10.0.0.33:36412"
	ch := setupSendCapture(srv, addr)

	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.IMSI = "311435000070592"
	ue.EMMState = emm.StateRegistered
	ue.ECMState = emm.ECMConnected
	ue.ENBGlobalID = addr
	ue.ENBS1APID = 63
	mmeID := ue.MMEUES1APID
	ue.Unlock()

	srv.handleERABModificationIndication(addr, &pdu.PDU{
		Type:          pdu.PDUTypeInitiatingMessage,
		ProcedureCode: pdu.ProcERABModificationIndication,
		Criticality:   aper.CriticalityReject,
	}, buildERABModificationIndicationIEs(mmeID, 9999,
		[]erabModificationIndicationItem{{EBI: 9, TEID: 0x44440001, IP: net.ParseIP("192.0.2.44").To4()}},
		nil,
	))

	msg := readCapturedPDU(t, ch)
	if msg.ProcedureCode != pdu.ProcErrorIndication {
		t.Fatalf("procedureCode: got %d, want ErrorIndication", msg.ProcedureCode)
	}
	assertErrorIndicationCause(t, msg, ies.CauseGroupRadioNetwork, ies.CauseRadioNetworkUnknownPairUES1APID)
}

func buildERABModificationIndicationIEs(mmeUEID, enbUEID uint32, modified []erabModificationIndicationItem, notModified []erabModificationIndicationItem) []pdu.ProtocolIE {
	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeMMEUEApID(mmeUEID)},
		{ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(enbUEID)},
		{ID: pdu.IEERABToBeModifiedListBearerModInd, Criticality: aper.CriticalityReject, Value: encodeERABModificationIndicationListForTest(modified, pdu.IEERABToBeModifiedItemBearerModInd)},
	}
	if len(notModified) > 0 {
		ieList = append(ieList, pdu.ProtocolIE{
			ID:          pdu.IEERABNotToBeModifiedListBearerModInd,
			Criticality: aper.CriticalityReject,
			Value:       encodeERABModificationIndicationListForTest(notModified, pdu.IEERABNotToBeModifiedItemBearerModInd),
		})
	}
	return ieList
}

func encodeERABModificationIndicationListForTest(items []erabModificationIndicationItem, itemIE uint16) []byte {
	w := aper.NewBitWriter()
	_ = aper.EncodeConstrainedWholeNumber(w, int64(len(items)), 1, 256)
	w.AlignToByte()
	for _, item := range items {
		body := encodeERABModificationIndicationItemForTest(item)
		w.WriteOctets(encodeSingleContainerIEForTest(itemIE, aper.CriticalityReject, body))
	}
	return w.Bytes()
}

func encodeERABModificationIndicationItemForTest(item erabModificationIndicationItem) []byte {
	w := aper.NewBitWriter()
	w.WriteBit(0)
	w.WriteBit(0)
	w.WriteBit(0)
	_ = aper.EncodeConstrainedWholeNumber(w, int64(item.EBI), 0, 15)
	w.WriteBit(0)
	_ = aper.EncodeConstrainedWholeNumber(w, 32, 1, 160)
	w.AlignToByte()
	ipv4 := item.IP.To4()
	if ipv4 == nil {
		ipv4 = []byte{0, 0, 0, 0}
	}
	w.WriteOctets(ipv4)
	w.AlignToByte()
	w.WriteOctet(byte(item.TEID >> 24))
	w.WriteOctet(byte(item.TEID >> 16))
	w.WriteOctet(byte(item.TEID >> 8))
	w.WriteOctet(byte(item.TEID))
	return w.Bytes()
}
