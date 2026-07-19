package gtpv2

import (
	"bytes"
	"net"
	"testing"
)

func TestCreateSessionRequestAttachCriticalIEsRel16(t *testing.T) {
	req := &CreateSessionRequest{
		SGWAddress:       "10.90.250.59:2123",
		IMSI:             "311435300070580",
		MSISDN:           "16752012880",
		APN:              "internet",
		RATType:          RATTypeEUTRAN,
		ServingNetwork:   [3]byte{0x13, 0x51, 0x34},
		LocalS11TEID:     1,
		LocalS11IP:       net.ParseIP("10.90.250.186"),
		PGWIP:            net.ParseIP("10.90.250.92"),
		ULIPLMN:          [3]byte{0x13, 0x51, 0x34},
		ULITAC:           1,
		ULIECI:           0x00019730,
		PCO:              []byte{0x80, 0x80, 0x21, 0x10, 0x01, 0x00},
		PDNType:          PDNTypeIPv4,
		DefaultEBI:       5,
		BearerQCI:        9,
		UplinkAMBRKbps:   100000,
		DownlinkAMBRKbps: 100000,
	}

	msg, err := Decode(req.Encode(1))
	if err != nil {
		t.Fatalf("Decode CSR: %v", err)
	}
	if msg.Type != MsgCreateSessionRequest {
		t.Fatalf("type got %d, want %d", msg.Type, MsgCreateSessionRequest)
	}
	if msg.TEID != 0 {
		t.Fatalf("CSR header TEID got %d, want 0", msg.TEID)
	}

	for _, tc := range []struct {
		name     string
		ieType   uint8
		instance uint8
	}{
		{"IMSI", IETypeIMSI, 0},
		{"MSISDN", IETypeMSISDN, 0},
		{"RAT Type", IETypeRATType, 0},
		{"Serving Network", IETypeServingNetwork, 0},
		{"Sender F-TEID", IETypeFTEID, 0},
		{"PGW S5/S8 F-TEID", IETypeFTEID, 1},
		{"ULI", IETypeULI, 0},
		{"APN", IETypeAPN, 0},
		{"PDN Type", IETypePDNType, 0},
		{"PAA", IETypePAA, 0},
		{"PCO", IETypePCO, 0},
		{"APN Restriction", IETypeAPNRestriction, 0},
		{"APN-AMBR", IETypeAMBR, 0},
		{"Selection Mode", IETypeSelectionMode, 0},
		{"Bearer Context", IETypeBearerContext, 0},
	} {
		if FindIE(msg.IEs, tc.ieType, tc.instance) == nil {
			t.Fatalf("%s IE type=%d instance=%d missing", tc.name, tc.ieType, tc.instance)
		}
	}

	sn := FindIE(msg.IEs, IETypeServingNetwork, 0)
	if !bytes.Equal(sn.Value, []byte{0x13, 0x51, 0x34}) {
		t.Fatalf("Serving Network got %x, want 135134", sn.Value)
	}

	msisdn := FindIE(msg.IEs, IETypeMSISDN, 0)
	if !bytes.Equal(msisdn.Value, []byte{0x61, 0x57, 0x02, 0x21, 0x88, 0xf0}) {
		t.Fatalf("MSISDN got %x, want pure TBCD 6157022188f0", msisdn.Value)
	}

	sender, err := DecodeFTEID(FindIE(msg.IEs, IETypeFTEID, 0))
	if err != nil {
		t.Fatalf("decode sender F-TEID: %v", err)
	}
	if sender.InterfaceType != IFTypeS11MME {
		t.Fatalf("Sender F-TEID interface got %d, want %d", sender.InterfaceType, IFTypeS11MME)
	}

	pgw, err := DecodeFTEID(FindIE(msg.IEs, IETypeFTEID, 1))
	if err != nil {
		t.Fatalf("decode PGW F-TEID: %v", err)
	}
	if pgw.InterfaceType != IFTypeS5S8PGWC {
		t.Fatalf("PGW F-TEID interface got %d, want %d", pgw.InterfaceType, IFTypeS5S8PGWC)
	}
	if pgw.TEID != 0 {
		t.Fatalf("PGW F-TEID TEID got %d, want 0 for initial attach", pgw.TEID)
	}

	uli := FindIE(msg.IEs, IETypeULI, 0)
	wantULI := []byte{
		ULIFlagTAI | ULIFlagECGI,
		0x13, 0x51, 0x34, 0x00, 0x01,
		0x13, 0x51, 0x34, 0x00, 0x01, 0x97, 0x30,
	}
	if !bytes.Equal(uli.Value, wantULI) {
		t.Fatalf("ULI\n got %x\nwant %x", uli.Value, wantULI)
	}

	pco := FindIE(msg.IEs, IETypePCO, 0)
	if !bytes.Equal(pco.Value, req.PCO) {
		t.Fatalf("PCO got %x, want %x", pco.Value, req.PCO)
	}

	apnRestriction := FindIE(msg.IEs, IETypeAPNRestriction, 0)
	if !bytes.Equal(apnRestriction.Value, []byte{APNRestrictionNoRestriction}) {
		t.Fatalf("APN Restriction got %x, want 00", apnRestriction.Value)
	}

	bc := FindIE(msg.IEs, IETypeBearerContext, 0)
	children, err := FindGroupedIEs(bc)
	if err != nil {
		t.Fatalf("decode Bearer Context: %v", err)
	}
	if FindIE(children, IETypeEBI, 0) == nil {
		t.Fatal("Bearer Context missing EBI")
	}
	if FindIE(children, IETypeBearerQoS, 0) == nil {
		t.Fatal("Bearer Context missing Bearer QoS")
	}
}

func TestCreateSessionRequestIncludesAPNRestrictionWithoutPCO(t *testing.T) {
	req := &CreateSessionRequest{
		SGWAddress:       "10.90.250.59:2123",
		IMSI:             "311435300070580",
		MSISDN:           "16752012880",
		APN:              "internet",
		RATType:          RATTypeEUTRAN,
		ServingNetwork:   [3]byte{0x13, 0x51, 0x34},
		LocalS11TEID:     1,
		LocalS11IP:       net.ParseIP("10.90.250.186"),
		PGWIP:            net.ParseIP("10.90.250.92"),
		ULIPLMN:          [3]byte{0x13, 0x51, 0x34},
		ULITAC:           1,
		ULIECI:           0x00019730,
		PDNType:          PDNTypeIPv4,
		DefaultEBI:       5,
		BearerQCI:        9,
		UplinkAMBRKbps:   100000,
		DownlinkAMBRKbps: 100000,
	}

	msg, err := Decode(req.Encode(1))
	if err != nil {
		t.Fatalf("Decode CSR: %v", err)
	}
	if pco := FindIE(msg.IEs, IETypePCO, 0); pco != nil {
		t.Fatalf("PCO present without UE PCO: %x", pco.Value)
	}
	apnRestriction := FindIE(msg.IEs, IETypeAPNRestriction, 0)
	if apnRestriction == nil {
		t.Fatal("APN Restriction missing")
	}
	if !bytes.Equal(apnRestriction.Value, []byte{APNRestrictionNoRestriction}) {
		t.Fatalf("APN Restriction got %x, want 00", apnRestriction.Value)
	}
}

func TestCreateSessionRequestUsesSubscribedBearerQoSAndAMBR(t *testing.T) {
	req := &CreateSessionRequest{
		SGWAddress:              "10.90.250.59:2123",
		IMSI:                    "311435300070580",
		MSISDN:                  "16752012880",
		APN:                     "ims",
		RATType:                 RATTypeEUTRAN,
		ServingNetwork:          [3]byte{0x13, 0x51, 0x34},
		LocalS11TEID:            2,
		LocalS11IP:              net.ParseIP("10.90.250.186"),
		PGWIP:                   net.ParseIP("10.90.250.92"),
		ULIPLMN:                 [3]byte{0x13, 0x51, 0x34},
		ULITAC:                  1,
		ULIECI:                  0x00019730,
		PDNType:                 PDNTypeIPv4,
		DefaultEBI:              6,
		BearerQCI:               5,
		BearerPriorityLevel:     2,
		PreemptionCapability:    true,
		PreemptionVulnerability: false,
		UplinkAMBRKbps:          512,
		DownlinkAMBRKbps:        1024,
	}

	msg, err := Decode(req.Encode(3))
	if err != nil {
		t.Fatalf("Decode CSR: %v", err)
	}

	ambr := FindIE(msg.IEs, IETypeAMBR, 0)
	if ambr == nil || !bytes.Equal(ambr.Value, []byte{0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00}) {
		t.Fatalf("AMBR got %x, want 0000020000000400", ambr.Value)
	}

	bc := FindIE(msg.IEs, IETypeBearerContext, 0)
	children, err := FindGroupedIEs(bc)
	if err != nil {
		t.Fatalf("decode Bearer Context: %v", err)
	}
	qos := FindIE(children, IETypeBearerQoS, 0)
	if qos == nil {
		t.Fatal("Bearer Context missing Bearer QoS")
	}
	if got, want := qos.Value[1], uint8(5); got != want {
		t.Fatalf("Bearer QoS QCI got %d, want %d", got, want)
	}
	if got, want := (qos.Value[0]>>2)&0x0f, uint8(2); got != want {
		t.Fatalf("Bearer QoS priority level got %d, want %d", got, want)
	}
	if got := qos.Value[0]&0x40 != 0; got != true {
		t.Fatalf("Bearer QoS PCI bit got %t, want true", got)
	}
	if got := qos.Value[0]&0x01 != 0; got != false {
		t.Fatalf("Bearer QoS PVI bit got %t, want false", got)
	}
}

func TestDecodeCreateSessionResponsePreservesPGWPCO(t *testing.T) {
	pco := []byte{
		0x80, 0x00,
		0x0d, 0x04, 0x01, 0x01, 0x01, 0x01,
		0x00, 0x0d, 0x04, 0x01, 0x00, 0x00, 0x01,
	}
	msg := &Message{
		Type: MsgCreateSessionResponse,
		IEs: []IE{
			{Type: IETypeCause, Value: []byte{CauseRequestAccepted, 0x00}},
			EncodeFTEID(IFTypeS11S4SGW, 0x01020304, net.ParseIP("10.0.0.2"), 0),
			EncodePAA(net.IP{100, 64, 0, 10}),
			EncodePCO(pco),
			EncodeGrouped(IETypeBearerContext, 0, []IE{
				EncodeEBI(5, 0),
				EncodeFTEID(IFTypeS1USGW, 0x10203040, net.ParseIP("10.0.0.3"), 0),
			}),
		},
	}

	resp, err := DecodeCreateSessionResponse(msg)
	if err != nil {
		t.Fatalf("DecodeCreateSessionResponse: %v", err)
	}
	if !bytes.Equal(resp.PCO, pco) {
		t.Fatalf("PCO got %x, want %x", resp.PCO, pco)
	}
}

func TestDecodeCreateSessionResponseAcceptsAllSuccessfulCauses(t *testing.T) {
	causes := []uint8{
		CauseRequestAccepted,
		CauseRequestAcceptedPartially,
		CauseNewPDNTypeDueToNetworkPref,
		CauseNewPDNTypeDueToSingleAddr,
	}
	for _, cause := range causes {
		t.Run(CauseName(cause), func(t *testing.T) {
			msg := &Message{
				Type: MsgCreateSessionResponse,
				IEs: []IE{
					{Type: IETypeCause, Value: []byte{cause, 0x00}},
					EncodeFTEID(IFTypeS11S4SGW, 0x01020304, net.ParseIP("10.0.0.2"), 0),
					EncodeGrouped(IETypeBearerContext, 0, []IE{
						EncodeEBI(5, 0),
						EncodeFTEID(IFTypeS1USGW, 0x10203040, net.ParseIP("10.0.0.3"), 0),
					}),
				},
			}

			resp, err := DecodeCreateSessionResponse(msg)
			if err != nil {
				t.Fatalf("DecodeCreateSessionResponse: %v", err)
			}
			if resp.Cause != cause {
				t.Fatalf("cause got %d, want %d", resp.Cause, cause)
			}
			if resp.SGWC_TEID != 0x01020304 {
				t.Fatalf("SGW-C TEID got 0x%x, want 0x01020304", resp.SGWC_TEID)
			}
			if resp.EBI != 5 {
				t.Fatalf("EBI got %d, want 5", resp.EBI)
			}
		})
	}
}

func TestDecodeCreateSessionResponseRejectsAcceptedResponseWithoutBearerEBI(t *testing.T) {
	msg := &Message{
		Type: MsgCreateSessionResponse,
		IEs: []IE{
			{Type: IETypeCause, Value: []byte{CauseRequestAccepted, 0x00}},
			EncodeFTEID(IFTypeS11S4SGW, 0x01020304, net.ParseIP("10.0.0.2"), 0),
			EncodeGrouped(IETypeBearerContext, 0, []IE{
				EncodeFTEID(IFTypeS1USGW, 0x10203040, net.ParseIP("10.0.0.3"), 0),
			}),
		},
	}

	if _, err := DecodeCreateSessionResponse(msg); err == nil {
		t.Fatal("DecodeCreateSessionResponse succeeded without bearer EBI")
	}
}
