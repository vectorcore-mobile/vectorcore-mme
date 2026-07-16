package gtpv2

import (
	"bytes"
	"net"
	"strings"
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

func TestDecodeAllPiggybackedMessages(t *testing.T) {
	first := Encode(&Message{
		Type:   MsgCreateBearerResponse,
		TEID:   0x11111111,
		SeqNum: 0x101,
		IEs:    []IE{EncodeCause(CauseRequestAccepted)},
	})
	second := Encode(&Message{
		Type:   MsgModifyBearerResponse,
		TEID:   0x22222222,
		SeqNum: 0x202,
		IEs:    []IE{EncodeCause(CauseRequestAccepted)},
	})
	wire, err := EncodePiggybacked(first, second)
	if err != nil {
		t.Fatalf("EncodePiggybacked: %v", err)
	}
	msgs, err := DecodeAll(wire)
	if err != nil {
		t.Fatalf("DecodeAll: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("message count got %d, want 2", len(msgs))
	}
	if msgs[0].Type != MsgCreateBearerResponse || msgs[0].TEID != 0x11111111 || msgs[0].SeqNum != 0x101 {
		t.Fatalf("first message got type=%d teid=0x%x seq=0x%x", msgs[0].Type, msgs[0].TEID, msgs[0].SeqNum)
	}
	if msgs[1].Type != MsgModifyBearerResponse || msgs[1].TEID != 0x22222222 || msgs[1].SeqNum != 0x202 {
		t.Fatalf("second message got type=%d teid=0x%x seq=0x%x", msgs[1].Type, msgs[1].TEID, msgs[1].SeqNum)
	}
}

func TestDecodeRejectsNoTEIDLengthSmallerThanHeader(t *testing.T) {
	raw := []byte{
		0x40, MsgEchoRequest, 0x00, 0x00,
		0x30, 0x30, 0x30, 0x30,
	}

	_, err := Decode(raw)
	if err == nil {
		t.Fatal("Decode unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "smaller than header") {
		t.Fatalf("Decode error got %q, want header size rejection", err)
	}
}

func TestDecodeRejectsTEIDLengthSmallerThanHeader(t *testing.T) {
	raw := []byte{
		0x48, MsgCreateSessionRequest, 0x00, 0x04,
		0x11, 0x22, 0x33, 0x44,
		0x55, 0x66, 0x77, 0x00,
	}

	_, err := Decode(raw)
	if err == nil {
		t.Fatal("Decode unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "smaller than header") {
		t.Fatalf("Decode error got %q, want header size rejection", err)
	}
}

func TestDecodeIEsRejectsTrailingGarbage(t *testing.T) {
	_, err := DecodeIEs([]byte{
		IETypeRecovery, 0x00, 0x01, 0x00, 0x2a,
		0xff,
	})
	if err == nil {
		t.Fatal("DecodeIEs unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "trailing 1 byte") {
		t.Fatalf("DecodeIEs error got %q, want trailing byte rejection", err)
	}
}

func TestDecodeFTEIDRejectsIPv6Variants(t *testing.T) {
	cases := []struct {
		name  string
		value []byte
		want  string
	}{
		{
			name:  "ipv6 only",
			value: []byte{0x40 | IFTypeS11MME, 0x11, 0x22, 0x33, 0x44},
			want:  "IPv6 FTEID not supported",
		},
		{
			name:  "dual stack",
			value: []byte{0xc0 | IFTypeS11MME, 0x11, 0x22, 0x33, 0x44, 10, 0, 0, 1},
			want:  "IPv6 FTEID not supported",
		},
		{
			name:  "no address flags",
			value: []byte{IFTypeS11MME, 0x11, 0x22, 0x33, 0x44},
			want:  "missing address flags",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeFTEID(&IE{Type: IETypeFTEID, Instance: 0, Value: tc.value})
			if err == nil {
				t.Fatal("DecodeFTEID unexpectedly succeeded")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("DecodeFTEID error got %q, want substring %q", err, tc.want)
			}
		})
	}
}
