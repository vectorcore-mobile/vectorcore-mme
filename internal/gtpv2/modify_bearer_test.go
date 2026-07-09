package gtpv2

import (
	"net"
	"testing"
)

func TestModifyBearerRequestEncodesENBS1UFTEID(t *testing.T) {
	req := &ModifyBearerRequest{
		SGWC_TEID: 0x11223344,
		EBI:       5,
		ENBU_TEID: 0x00000001,
		ENBU_IP:   net.ParseIP("192.168.105.34"),
		RATType:   RATTypeEUTRAN,
	}

	msg, err := Decode(req.Encode(0x010203))
	if err != nil {
		t.Fatalf("Decode MBR: %v", err)
	}
	if msg.Type != MsgModifyBearerRequest {
		t.Fatalf("message type: got %d, want %d", msg.Type, MsgModifyBearerRequest)
	}
	if msg.TEID != req.SGWC_TEID {
		t.Fatalf("header TEID: got %#x, want %#x", msg.TEID, req.SGWC_TEID)
	}
	ratIE := FindIE(msg.IEs, IETypeRATType, 0)
	if ratIE == nil || len(ratIE.Value) != 1 || ratIE.Value[0] != RATTypeEUTRAN {
		t.Fatalf("RAT Type IE got %+v, want E-UTRAN", ratIE)
	}
	bearerIE := FindIE(msg.IEs, IETypeBearerContext, 0)
	if bearerIE == nil {
		t.Fatal("missing Bearer Context IE")
	}
	children, err := FindGroupedIEs(bearerIE)
	if err != nil {
		t.Fatalf("Bearer Context decode: %v", err)
	}
	ebi, err := DecodeEBI(FindIE(children, IETypeEBI, 0))
	if err != nil {
		t.Fatalf("Decode EBI: %v", err)
	}
	if ebi != req.EBI {
		t.Fatalf("EBI: got %d, want %d", ebi, req.EBI)
	}
	fteid, err := DecodeFTEID(FindIE(children, IETypeFTEID, FTEIDInstanceSender))
	if err != nil {
		t.Fatalf("Decode eNB S1-U F-TEID: %v", err)
	}
	if fteid.InterfaceType != IFTypeS1UENB {
		t.Fatalf("F-TEID interface: got %d, want S1-U eNB %d", fteid.InterfaceType, IFTypeS1UENB)
	}
	if fteid.TEID != req.ENBU_TEID {
		t.Fatalf("eNB S1-U TEID: got %#x, want %#x", fteid.TEID, req.ENBU_TEID)
	}
	if got, want := fteid.IP.String(), "192.168.105.34"; got != want {
		t.Fatalf("eNB S1-U IPv4: got %s, want %s", got, want)
	}
}
