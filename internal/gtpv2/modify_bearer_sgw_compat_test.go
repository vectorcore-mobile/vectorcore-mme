package gtpv2

import (
	"net"
	"testing"
)

func decodeBearerContextByEBI(t *testing.T, ies []IE, wantEBI uint8) []IE {
	t.Helper()
	for i := range ies {
		ie := &ies[i]
		if ie.Type != IETypeBearerContext || ie.Instance != 0 {
			continue
		}
		children, err := FindGroupedIEs(ie)
		if err != nil {
			t.Fatalf("FindGroupedIEs: %v", err)
		}
		ebi, err := DecodeEBI(FindIE(children, IETypeEBI, 0))
		if err != nil {
			t.Fatalf("DecodeEBI: %v", err)
		}
		if ebi == wantEBI {
			return children
		}
	}
	t.Fatalf("missing Bearer Context for EBI %d", wantEBI)
	return nil
}

func TestStandaloneModifyBearerRequestMatchesSGWDecodeExpectations(t *testing.T) {
	req := &ModifyBearerRequest{
		SGWC_TEID:             0x69ace12a,
		EBI:                   6,
		ENBU_TEID:             0x6a90bd47,
		ENBU_IP:               net.ParseIP("192.168.105.247").To4(),
		RATType:               RATTypeEUTRAN,
		IncludeIndicationCRSI: true,
		OmitRATType:           true,
	}

	msg, err := Decode(req.Encode(0x000004))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if msg.Type != MsgModifyBearerRequest {
		t.Fatalf("message type got %d, want %d", msg.Type, MsgModifyBearerRequest)
	}
	if msg.TEID != req.SGWC_TEID {
		t.Fatalf("header TEID got 0x%x, want 0x%x", msg.TEID, req.SGWC_TEID)
	}
	if msg.SeqNum != 0x000004 {
		t.Fatalf("sequence got 0x%x, want 0x000004", msg.SeqNum)
	}
	if FindIE(msg.IEs, IETypeRATType, 0) != nil {
		t.Fatal("unexpected RAT Type IE present")
	}
	ind := FindIE(msg.IEs, IETypeIndication, 0)
	if ind == nil {
		t.Fatal("missing Indication IE")
	}
	wantInd := []byte{0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if len(ind.Value) != len(wantInd) {
		t.Fatalf("Indication length got %d, want %d", len(ind.Value), len(wantInd))
	}
	for i := range wantInd {
		if ind.Value[i] != wantInd[i] {
			t.Fatalf("Indication[%d] got 0x%02x, want 0x%02x", i, ind.Value[i], wantInd[i])
		}
	}

	children := decodeBearerContextByEBI(t, msg.IEs, 6)
	fteid, err := DecodeFTEID(FindIE(children, IETypeFTEID, FTEIDInstanceSender))
	if err != nil {
		t.Fatalf("DecodeFTEID: %v", err)
	}
	if fteid.InterfaceType != IFTypeS1UENB {
		t.Fatalf("F-TEID interface got %d, want %d", fteid.InterfaceType, IFTypeS1UENB)
	}
	if fteid.TEID != req.ENBU_TEID {
		t.Fatalf("eNB F-TEID TEID got 0x%x, want 0x%x", fteid.TEID, req.ENBU_TEID)
	}
	if got := fteid.IP.String(); got != "192.168.105.247" {
		t.Fatalf("eNB F-TEID IP got %s, want 192.168.105.247", got)
	}
}

func TestPiggybackedCreateBearerResponseAndModifyBearerRequestMatchSGWDecodeExpectations(t *testing.T) {
	primary := EncodeCreateBearerResponseWithMeta(
		0x69ace12a,
		0x006512,
		CauseRequestAccepted,
		[]CreateBearerBearer{
			{
				EBI:        7,
				ENBS1UTEID: 0xfb617509,
				ENBS1UIP:   net.ParseIP("192.168.105.247").To4(),
				SGWS1UTEID: 0x8139a857,
				SGWS1UIP:   net.ParseIP("10.90.250.59").To4(),
			},
			{
				EBI:        8,
				ENBS1UTEID: 0x730dff60,
				ENBS1UIP:   net.ParseIP("192.168.105.247").To4(),
				SGWS1UTEID: 0xb908e8e3,
				SGWS1UIP:   net.ParseIP("10.90.250.59").To4(),
			},
		},
		&CreateBearerResponseMeta{
			IncludeULI: true,
			ULIPLMN:    [3]byte{0x13, 0x51, 0x34},
			ULITAC:     1,
			ULIECI:     0x05300c80,
		},
	)
	secondary := (&ModifyBearerRequest{
		SGWC_TEID:             0x69ace12a,
		EBI:                   6,
		ENBU_TEID:             0x6a90bd47,
		ENBU_IP:               net.ParseIP("192.168.105.247").To4(),
		RATType:               RATTypeEUTRAN,
		IncludeIndicationCRSI: true,
		OmitRATType:           true,
	}).Encode(0x000004)

	raw, err := EncodePiggybacked(primary, secondary)
	if err != nil {
		t.Fatalf("EncodePiggybacked: %v", err)
	}
	msgs, err := DecodeAll(raw)
	if err != nil {
		t.Fatalf("DecodeAll: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("message count got %d, want 2", len(msgs))
	}

	if msgs[0].Type != MsgCreateBearerResponse {
		t.Fatalf("primary type got %d, want %d", msgs[0].Type, MsgCreateBearerResponse)
	}
	if msgs[0].TEID != 0x69ace12a || msgs[0].SeqNum != 0x006512 {
		t.Fatalf("primary header got teid=0x%x seq=0x%x", msgs[0].TEID, msgs[0].SeqNum)
	}

	secondaryMsg := msgs[1]
	if secondaryMsg.Type != MsgModifyBearerRequest {
		t.Fatalf("secondary type got %d, want %d", secondaryMsg.Type, MsgModifyBearerRequest)
	}
	if secondaryMsg.TEID != 0x69ace12a {
		t.Fatalf("secondary TEID got 0x%x, want 0x69ace12a", secondaryMsg.TEID)
	}
	if secondaryMsg.SeqNum != 0x000004 {
		t.Fatalf("secondary seq got 0x%x, want 0x000004", secondaryMsg.SeqNum)
	}
	if FindIE(secondaryMsg.IEs, IETypeRATType, 0) != nil {
		t.Fatal("unexpected RAT Type IE in piggybacked MBR")
	}
	if FindIE(secondaryMsg.IEs, IETypeIndication, 0) == nil {
		t.Fatal("missing Indication IE in piggybacked MBR")
	}

	children := decodeBearerContextByEBI(t, secondaryMsg.IEs, 6)
	fteid, err := DecodeFTEID(FindIE(children, IETypeFTEID, FTEIDInstanceSender))
	if err != nil {
		t.Fatalf("DecodeFTEID: %v", err)
	}
	if fteid.InterfaceType != IFTypeS1UENB {
		t.Fatalf("piggybacked F-TEID interface got %d, want %d", fteid.InterfaceType, IFTypeS1UENB)
	}
	if fteid.TEID != 0x6a90bd47 {
		t.Fatalf("piggybacked eNB F-TEID TEID got 0x%x, want 0x6a90bd47", fteid.TEID)
	}
	if got := fteid.IP.String(); got != "192.168.105.247" {
		t.Fatalf("piggybacked eNB F-TEID IP got %s, want 192.168.105.247", got)
	}
}
