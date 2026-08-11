package s1ap

import (
	"testing"

	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
)

func TestInitialContextSetupIncludesSubscriberProfileIDforRFPWhenSet(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.18:36412"
	ch := setupSendCapture(srv, remoteAddr)
	ue := allocateTestUE(srv, remoteAddr, 0, true)
	ue.ENBS1APID = 0x01020a
	ue.KASME = make([]byte, 32)
	ue.UENetworkCapability = []byte{0xf0, 0xf0}
	ue.UEAMBRDown = 100000000
	ue.UEAMBRUp = 100000000
	ue.RATFrequencySelectionPriorityID = 5

	bearer := &BearerInfo{EBI: 5, SGWU_TEID: 0x01020304, SGWU_IP: []byte{10, 0, 0, 1}}
	if err := srv.SendInitialContextSetup(ue.MMEUES1APID, []byte{0x27, 0x42}, bearer); err != nil {
		t.Fatalf("SendInitialContextSetup: %v", err)
	}
	msg := readCapturedPDU(t, ch)
	ieList, err := pdu.DecodeIEContainer(msg.Value)
	if err != nil {
		t.Fatalf("DecodeIEContainer: %v", err)
	}

	var got []byte
	found := false
	for _, ie := range ieList {
		if ie.ID == pdu.IESubscriberProfileIDforRFP {
			got = ie.Value
			found = true
			break
		}
	}
	if !found {
		t.Fatal("Initial Context Setup Request missing SubscriberProfileIDforRFP IE")
	}
	gotValue, err := ies.DecodeSubscriberProfileIDforRFP(got)
	if err != nil {
		t.Fatalf("DecodeSubscriberProfileIDforRFP: %v", err)
	}
	if gotValue != 5 {
		t.Fatalf("SubscriberProfileIDforRFP got %d, want 5", gotValue)
	}
}

func TestInitialContextSetupOmitsSubscriberProfileIDforRFPWhenUnset(t *testing.T) {
	srv := newTAUTestServer()
	const remoteAddr = "192.0.2.19:36412"
	ch := setupSendCapture(srv, remoteAddr)
	ue := allocateTestUE(srv, remoteAddr, 0, true)
	ue.ENBS1APID = 0x01020b
	ue.KASME = make([]byte, 32)
	ue.UENetworkCapability = []byte{0xf0, 0xf0}
	ue.UEAMBRDown = 100000000
	ue.UEAMBRUp = 100000000

	bearer := &BearerInfo{EBI: 5, SGWU_TEID: 0x01020304, SGWU_IP: []byte{10, 0, 0, 1}}
	if err := srv.SendInitialContextSetup(ue.MMEUES1APID, []byte{0x27, 0x42}, bearer); err != nil {
		t.Fatalf("SendInitialContextSetup: %v", err)
	}
	msg := readCapturedPDU(t, ch)
	ieList, err := pdu.DecodeIEContainer(msg.Value)
	if err != nil {
		t.Fatalf("DecodeIEContainer: %v", err)
	}

	for _, ie := range ieList {
		if ie.ID == pdu.IESubscriberProfileIDforRFP {
			t.Fatal("Initial Context Setup Request unexpectedly includes SubscriberProfileIDforRFP IE")
		}
	}
}
