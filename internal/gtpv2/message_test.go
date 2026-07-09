package gtpv2

import (
	"bytes"
	"net"
	"testing"
)

func TestDecodeTEIDAbsentEchoRequest(t *testing.T) {
	raw := []byte{
		0x40, MsgEchoRequest, 0x00, 0x09,
		0x00, 0x00, 0x07, 0x00,
		IETypeRecovery, 0x00, 0x01, 0x00, 0x2a,
	}

	msg, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode Echo Request: %v", err)
	}
	if msg.Type != MsgEchoRequest {
		t.Fatalf("type got %d, want %d", msg.Type, MsgEchoRequest)
	}
	if msg.TEID != 0 {
		t.Fatalf("TEID got %d, want 0", msg.TEID)
	}
	if msg.SeqNum != 7 {
		t.Fatalf("seq got %d, want 7", msg.SeqNum)
	}
	rec := FindIE(msg.IEs, IETypeRecovery, 0)
	if rec == nil || !bytes.Equal(rec.Value, []byte{0x2a}) {
		t.Fatalf("Recovery IE = %+v, want value 2a", rec)
	}
}

func TestEncodeNoTEIDEchoResponse(t *testing.T) {
	wire := EncodeNoTEID(&Message{
		Type:   MsgEchoResponse,
		SeqNum: 0x010203,
		IEs:    []IE{EncodeRecovery(0x05)},
	})
	want := []byte{
		0x40, MsgEchoResponse, 0x00, 0x09,
		0x01, 0x02, 0x03, 0x00,
		IETypeRecovery, 0x00, 0x01, 0x00, 0x05,
	}
	if !bytes.Equal(wire, want) {
		t.Fatalf("Echo Response\n got %x\nwant %x", wire, want)
	}
}

func TestRel16FTEIDInterfaceTypes(t *testing.T) {
	cases := []struct {
		name string
		got  uint8
		want uint8
	}{
		{"S5/S8 SGW GTP-C", IFTypeS5S8SGWC, 6},
		{"S5/S8 PGW GTP-C", IFTypeS5S8PGWC, 7},
		{"S11 MME GTP-C", IFTypeS11MME, 10},
		{"S11/S4 SGW GTP-C", IFTypeS11S4SGW, 11},
		{"S10/N26 MME GTP-C", IFTypeS10MME, 12},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Fatalf("%s interface type got %d, want %d", tc.name, tc.got, tc.want)
		}
	}

	ie := EncodeFTEID(IFTypeS11MME, 0x11223344, net.ParseIP("10.90.250.186"), 0)
	if ie.Value[0] != 0x8a {
		t.Fatalf("S11 MME F-TEID flags/interface got 0x%02x, want 0x8a", ie.Value[0])
	}
}
