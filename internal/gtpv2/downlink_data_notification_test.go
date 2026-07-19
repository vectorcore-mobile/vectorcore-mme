package gtpv2

import (
	"net"
	"testing"
)

func TestDecodeDownlinkDataNotification(t *testing.T) {
	ebi := uint8(6)
	arp := uint8(8)
	delay := uint8(4)
	msg := &Message{
		Type:   MsgDownlinkDataNotification,
		TEID:   0x01020304,
		SeqNum: 0x10203,
		IEs: []IE{
			EncodeEBI(ebi, 0),
			EncodeARP(arp),
			EncodeIMSI("311435000070570"),
			EncodeFTEID(IFTypeS11S4SGW, 0x55667788, net.ParseIP("10.90.250.59"), 0),
			EncodeDelayValue(delay),
			EncodePagingServiceInfo([]byte{0xaa, 0xbb}),
		},
	}

	got, err := DecodeDownlinkDataNotification(msg)
	if err != nil {
		t.Fatalf("DecodeDownlinkDataNotification: %v", err)
	}
	if got.TEID != msg.TEID || got.SeqNum != msg.SeqNum {
		t.Fatalf("decoded header got teid=0x%x seq=0x%x, want teid=0x%x seq=0x%x", got.TEID, got.SeqNum, msg.TEID, msg.SeqNum)
	}
	if got.EBI == nil || *got.EBI != ebi {
		t.Fatalf("decoded EBI got %v, want %d", got.EBI, ebi)
	}
	if got.ARP == nil || *got.ARP != arp {
		t.Fatalf("decoded ARP got %v, want %d", got.ARP, arp)
	}
	if got.IMSI != "311435000070570" {
		t.Fatalf("decoded IMSI got %q", got.IMSI)
	}
	if got.SenderFTEID == nil || got.SenderFTEID.TEID != 0x55667788 {
		t.Fatalf("decoded SenderFTEID got %+v", got.SenderFTEID)
	}
	if got.DelayValue == nil || *got.DelayValue != delay {
		t.Fatalf("decoded DelayValue got %v, want %d", got.DelayValue, delay)
	}
	if string(got.PagingServiceInfo) != string([]byte{0xaa, 0xbb}) {
		t.Fatalf("decoded PagingServiceInfo got %x", got.PagingServiceInfo)
	}
}

func TestEncodeDecodeDownlinkDataNotificationAck(t *testing.T) {
	delay := uint8(3)
	wire := EncodeDownlinkDataNotificationAck(0x11223344, 0x010203, CauseRequestAccepted, &delay)

	msg, err := Decode(wire)
	if err != nil {
		t.Fatalf("Decode ack wire: %v", err)
	}
	if msg.Type != MsgDownlinkDataNotificationAck {
		t.Fatalf("ack type got %d, want %d", msg.Type, MsgDownlinkDataNotificationAck)
	}
	if msg.TEID != 0x11223344 || msg.SeqNum != 0x010203 {
		t.Fatalf("ack header got teid=0x%x seq=0x%x", msg.TEID, msg.SeqNum)
	}

	ack, err := DecodeDownlinkDataNotificationAck(msg)
	if err != nil {
		t.Fatalf("DecodeDownlinkDataNotificationAck: %v", err)
	}
	if ack.Cause != CauseRequestAccepted {
		t.Fatalf("ack cause got %d, want %d", ack.Cause, CauseRequestAccepted)
	}
	if ack.DelayValue == nil || *ack.DelayValue != delay {
		t.Fatalf("ack delay got %v, want %d", ack.DelayValue, delay)
	}
}

func TestEncodeDecodeDownlinkDataNotificationFailureIndication(t *testing.T) {
	wire := EncodeDownlinkDataNotificationFailureIndication(0x01020304, 0x020304, CauseUnableToPageUE, "311435000070570")

	msg, err := Decode(wire)
	if err != nil {
		t.Fatalf("Decode failure wire: %v", err)
	}
	if msg.Type != MsgDownlinkDataNotificationFail {
		t.Fatalf("failure type got %d, want %d", msg.Type, MsgDownlinkDataNotificationFail)
	}

	fi, err := DecodeDownlinkDataNotificationFailureIndication(msg)
	if err != nil {
		t.Fatalf("DecodeDownlinkDataNotificationFailureIndication: %v", err)
	}
	if fi.Cause != CauseUnableToPageUE {
		t.Fatalf("failure cause got %d, want %d", fi.Cause, CauseUnableToPageUE)
	}
	if fi.IMSI != "311435000070570" {
		t.Fatalf("failure IMSI got %q", fi.IMSI)
	}
}
