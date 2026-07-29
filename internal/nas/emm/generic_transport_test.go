package emm

import (
	"bytes"
	"testing"
)

func TestGenericNASTransportLPP(t *testing.T) {
	payload := []byte{1, 2, 3}
	w, e := EncodeDownlinkGenericNASTransport(GenericMessageContainerTypeLPP, payload)
	if e != nil {
		t.Fatal(e)
	}
	if w[1] != MsgDownlinkGenericNASTransport || w[2] != GenericMessageContainerTypeLPP {
		t.Fatalf("header %x", w[:3])
	}
	typ, got, e := DecodeUplinkGenericNASTransport(w[2:])
	if e != nil || typ != GenericMessageContainerTypeLPP || !bytes.Equal(got, payload) {
		t.Fatalf("typ=%d got=%x err=%v", typ, got, e)
	}
}
func TestGenericNASTransportRejectsMalformed(t *testing.T) {
	for _, b := range [][]byte{{}, {1, 0}, {2, 0, 0}, {1, 0, 2, 1}} {
		if _, _, e := DecodeUplinkGenericNASTransport(b); e == nil {
			t.Fatalf("accepted %x", b)
		}
	}
}
