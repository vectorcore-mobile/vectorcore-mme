package sls

import (
	"bytes"
	"github.com/vectorcore/mme/internal/asn1/aper"
	"testing"
)

func TestLocationRequestAPERCodecRoundTrip(t *testing.T) {
	in := PDU{Category: Initiating, Procedure: ProcedureLocationRequest, Criticality: aper.CriticalityReject, IEs: []IE{{ID: IECorrelationID, Criticality: aper.CriticalityReject, Value: []byte{0, 0, 0, 1}, Known: true}, {ID: IELocationType, Criticality: aper.CriticalityReject, Value: []byte{0}, Known: true}, {ID: IEECGI, Criticality: aper.CriticalityIgnore, Value: []byte{0, 0xf1, 0x10, 0, 0, 0, 1}, Known: true}}}
	w, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(w)
	if err != nil {
		t.Fatal(err)
	}
	if got.Category != in.Category || got.Procedure != in.Procedure || len(got.IEs) != 3 || !bytes.Equal(got.IEs[0].Value, in.IEs[0].Value) {
		t.Fatalf("decoded %#v", got)
	}
}
func TestDecodeRejectsMalformedAndUnknownRejectIE(t *testing.T) {
	if _, err := Decode([]byte{0xff}); err == nil {
		t.Fatal("accepted malformed PDU")
	}
	w, err := Encode(PDU{Category: Successful, Procedure: ProcedureLocationRequest, Criticality: aper.CriticalityReject, IEs: []IE{{ID: IECorrelationID, Criticality: aper.CriticalityReject, Value: []byte{0, 0, 0, 1}, Known: true}, {ID: 900, Criticality: aper.CriticalityReject, Value: []byte{1}}}})
	if err != nil {
		t.Fatal(err)
	}
	p := NewProvider(timeSecond, 1, &testTransport{ok: true})
	if err := p.HandleInbound(w); err == nil {
		t.Fatal("accepted unknown reject IE")
	}
}
