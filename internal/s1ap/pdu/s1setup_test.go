package pdu

import (
	"testing"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/s1ap/ies"
)

func TestDecodeCapturedSrsENBS1SetupRequest(t *testing.T) {
	raw := []byte{
		0x00, 0x11, 0x00, 0x2d, 0x00, 0x00, 0x04,
		0x00, 0x3b, 0x00, 0x08, 0x00, 0x13, 0x41, 0x53, 0x00, 0x00, 0x19, 0x70,
		0x00, 0x3c, 0x40, 0x0a, 0x03, 0x80, 0x73, 0x72, 0x73, 0x65, 0x6e, 0x62, 0x30, 0x31,
		0x00, 0x40, 0x00, 0x07, 0x00, 0x00, 0x40, 0x13, 0x41, 0x53, 0x00,
		0x00, 0x89, 0x40, 0x01, 0x40,
	}

	msg, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if msg.Type != PDUTypeInitiatingMessage {
		t.Fatalf("Type: got %d, want initiatingMessage", msg.Type)
	}
	if msg.ProcedureCode != ProcS1Setup {
		t.Fatalf("ProcedureCode: got %d, want %d", msg.ProcedureCode, ProcS1Setup)
	}

	ieList, err := DecodeProcedureIEContainer(msg.Value)
	if err != nil {
		t.Fatalf("DecodeProcedureIEContainer: %v", err)
	}
	if len(ieList) != 4 {
		t.Fatalf("IE count: got %d, want 4", len(ieList))
	}

	byID := map[uint16]ProtocolIE{}
	for _, ie := range ieList {
		byID[ie.ID] = ie
	}
	for _, id := range []uint16{IEGlobal_ENB_ID, IEeNBname, IESupportedTAs, IEDefaultPagingDRX} {
		if _, ok := byID[id]; !ok {
			t.Fatalf("missing IE %d", id)
		}
	}

	global, err := ies.DecodeGlobalENBID(byID[IEGlobal_ENB_ID].Value)
	if err != nil {
		t.Fatalf("DecodeGlobalENBID: %v", err)
	}
	if global.MCC != "311" || global.MNC != "435" || global.ENB.Type != ies.ENBIDTypeMacro || global.ENB.Value != 0x197 {
		t.Fatalf("GlobalENBID: got %+v", global)
	}

	r := aper.NewBitReader(byID[IEeNBname].Value)
	name, err := aper.DecodeVisibleStringExt(r, 1, 150)
	if err != nil {
		t.Fatalf("DecodeVisibleString: %v", err)
	}
	if name != "srsenb01" {
		t.Fatalf("eNB name: got %q, want srsenb01", name)
	}
}
