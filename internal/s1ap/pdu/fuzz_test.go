package pdu

import (
	"bytes"
	"testing"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/s1ap/ies"
)

func addPDUSeeds(f *testing.F) {
	f.Add(BuildInitiatingMessage(ProcS1Setup, aper.CriticalityReject, []ProtocolIE{
		{ID: IEMMEUES1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeMMEUEApID(1)},
		{ID: IEENBS1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeENBUEApID(2)},
	}))
	f.Add(BuildSuccessfulOutcome(ProcERABSetup, aper.CriticalityIgnore, []ProtocolIE{
		{ID: IEMMEUES1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeMMEUEApID(40)},
		{ID: IEENBS1APID, Criticality: aper.CriticalityIgnore, Value: ies.EncodeENBUEApID(77)},
	}))
	f.Add(EncodeIEContainer([]ProtocolIE{
		{ID: 17, Criticality: aper.CriticalityReject, Value: []byte{0x01, 0x02, 0x03}},
		{ID: 42, Criticality: aper.CriticalityIgnore, Value: []byte{0xaa, 0xbb}},
	}))
}

func FuzzPDUDecode(f *testing.F) {
	addPDUSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Decode(data)
		if err != nil {
			return
		}
		wire := Encode(p)
		rt, err := Decode(wire)
		if err != nil {
			t.Fatalf("round-trip decode failed: %v", err)
		}
		if rt.Type != p.Type || rt.ProcedureCode != p.ProcedureCode || rt.Criticality != p.Criticality {
			t.Fatalf("header mismatch after round-trip: got %+v want %+v", rt, p)
		}
		if !bytes.Equal(rt.Value, p.Value) {
			t.Fatalf("value mismatch after round-trip")
		}
		_, _ = DecodeIEContainer(p.Value)
	})
}

func FuzzPDUDecodeIEContainer(f *testing.F) {
	addPDUSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		ies, err := DecodeIEContainer(data)
		if err != nil {
			return
		}
		wire := EncodeIEContainer(ies)
		rt, err := DecodeIEContainer(wire)
		if err != nil {
			t.Fatalf("IE container round-trip decode failed: %v", err)
		}
		if len(rt) != len(ies) {
			t.Fatalf("IE count mismatch after round-trip: got %d want %d", len(rt), len(ies))
		}
	})
}
