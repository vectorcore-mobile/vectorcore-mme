package s1ap

import (
	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"testing"
)

type lppaCapture struct {
	mme     uint32
	route   uint8
	payload []byte
}

func (c *lppaCapture) HandleUplinkLPPa(m uint32, r uint8, b []byte) error {
	c.mme = m
	c.route = r
	c.payload = append([]byte(nil), b...)
	return nil
}
func TestUEAssociatedLPPaRelay(t *testing.T) {
	s := newTAUTestServer()
	const remote = "192.0.2.10:36412"
	ch := setupSendCapture(s, remote)
	ue := allocateTestUE(s, remote, 0, true)
	ue.ENBS1APID = 9
	payload := []byte{1, 2, 3}
	if err := s.SendDownlinkLPPa(ue.MMEUES1APID, 7, payload); err != nil {
		t.Fatal(err)
	}
	msg := readCapturedPDU(t, ch)
	assertPDUIEs(t, msg, pdu.PDUTypeInitiatingMessage, pdu.ProcDownlinkUEAssociatedLPPaTransport, []uint16{pdu.IEMMEUES1APID, pdu.IEENBS1APID, pdu.IERoutingID, pdu.IELPPaPDU})
	cap := &lppaCapture{}
	s.SetLPPaSink(cap)
	list := []pdu.ProtocolIE{{ID: pdu.IEMMEUES1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeMMEUEApID(ue.MMEUES1APID)}, {ID: pdu.IEENBS1APID, Criticality: aper.CriticalityReject, Value: ies.EncodeENBUEApID(9)}, {ID: pdu.IERoutingID, Criticality: aper.CriticalityReject, Value: []byte{7}}, {ID: pdu.IELPPaPDU, Criticality: aper.CriticalityReject, Value: payload}}
	s.handleMessage(remote, pdu.BuildInitiatingMessage(pdu.ProcUplinkUEAssociatedLPPaTransport, aper.CriticalityIgnore, list))
	if cap.mme != ue.MMEUES1APID || cap.route != 7 || string(cap.payload) != string(payload) {
		t.Fatalf("relay=%+v", cap)
	}
}
