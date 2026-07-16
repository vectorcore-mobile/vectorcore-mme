package gtpv2

import (
	"encoding/hex"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
)

func loadHexFixture(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", path, err)
	}
	clean := strings.Join(strings.Fields(string(raw)), "")
	b, err := hex.DecodeString(clean)
	if err != nil {
		t.Fatalf("DecodeString(%s): %v", path, err)
	}
	return b
}

func TestDecodeNokiaCreateBearerMultipleContextsAllocatesEBIs(t *testing.T) {
	msg, err := Decode(loadHexFixture(t, "testdata/legacy_nokia/create_bearer_two_zero_ebi.hex"))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	req, err := DecodeCreateBearerRequest(msg)
	if err != nil {
		t.Fatalf("DecodeCreateBearerRequest: %v", err)
	}
	if req.TEID != 0x802f4007 || req.SeqNum != 0x10e {
		t.Fatalf("ids got teid=0x%x seq=0x%x", req.TEID, req.SeqNum)
	}
	if req.LinkedEBI != 6 {
		t.Fatalf("linked EBI got %d, want 6", req.LinkedEBI)
	}
	if len(req.Bearers) != 2 {
		t.Fatalf("bearers got %d, want 2", len(req.Bearers))
	}
	for i, b := range req.Bearers {
		if b.RequestedEBI != 0 || !b.NeedsEBIAllocation {
			t.Fatalf("bearer %d requested EBI got %d alloc=%v, want zero allocation", i, b.RequestedEBI, b.NeedsEBIAllocation)
		}
		if b.QCI == 0 || len(b.TFT) == 0 || b.SGWS1UTEID == 0 || !net.IP(b.SGWS1UIP).Equal(net.ParseIP("10.90.250.59").To4()) {
			t.Fatalf("bearer %d incomplete decode: %+v", i, b)
		}
	}
	if err := AssignRequestedBearerIDs(req.Bearers, map[uint8]bool{5: true, 6: true}); err != nil {
		t.Fatalf("AssignRequestedBearerIDs: %v", err)
	}
	if req.Bearers[0].EBI != 7 || req.Bearers[1].EBI != 8 {
		t.Fatalf("allocated EBIs got %d/%d, want 7/8", req.Bearers[0].EBI, req.Bearers[1].EBI)
	}
}

func TestDecodeSonimCreateBearerAllocatesNextFreeEBI(t *testing.T) {
	msg, err := Decode(loadHexFixture(t, "testdata/legacy_sonim/create_bearer_one_zero_ebi.hex"))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	req, err := DecodeCreateBearerRequest(msg)
	if err != nil {
		t.Fatalf("DecodeCreateBearerRequest: %v", err)
	}
	if req.LinkedEBI != 6 || len(req.Bearers) != 1 {
		t.Fatalf("got linked=%d bearers=%d, want linked=6 bearers=1", req.LinkedEBI, len(req.Bearers))
	}
	if req.Bearers[0].RequestedEBI != 0 || !req.Bearers[0].NeedsEBIAllocation {
		t.Fatalf("requested EBI got %d alloc=%v", req.Bearers[0].RequestedEBI, req.Bearers[0].NeedsEBIAllocation)
	}
	used := map[uint8]bool{5: true, 6: true, 7: true, 8: true, 9: true}
	if err := AssignRequestedBearerIDs(req.Bearers, used); err != nil {
		t.Fatalf("AssignRequestedBearerIDs: %v", err)
	}
	if req.Bearers[0].EBI != 10 {
		t.Fatalf("allocated EBI got %d, want 10", req.Bearers[0].EBI)
	}
}

func TestDecodeCreateBearerRequestRejectsMissingMandatoryIEs(t *testing.T) {
	baseBearer := []IE{
		EncodeEBI(0, 0),
		EncodeBearerQoS(9, 8, false, true),
		{Type: IETypeTFT, Instance: 0, Value: []byte{0x20}},
		EncodeFTEID(IFTypeS1USGW, 0x01020304, net.ParseIP("10.0.0.3"), 0),
	}

	cases := []struct {
		name string
		ies  []IE
		want error
	}{
		{
			name: "missing linked ebi",
			ies: []IE{
				EncodeGrouped(IETypeBearerContext, 0, baseBearer),
			},
			want: ErrMandatoryIEMissing,
		},
		{
			name: "missing bearer qos",
			ies: []IE{
				EncodeEBI(6, 0),
				EncodeGrouped(IETypeBearerContext, 0, []IE{
					EncodeEBI(0, 0),
					{Type: IETypeTFT, Instance: 0, Value: []byte{0x20}},
					EncodeFTEID(IFTypeS1USGW, 0x01020304, net.ParseIP("10.0.0.3"), 0),
				}),
			},
			want: ErrMandatoryIEMissing,
		},
		{
			name: "missing tft",
			ies: []IE{
				EncodeEBI(6, 0),
				EncodeGrouped(IETypeBearerContext, 0, []IE{
					EncodeEBI(0, 0),
					EncodeBearerQoS(9, 8, false, true),
					EncodeFTEID(IFTypeS1USGW, 0x01020304, net.ParseIP("10.0.0.3"), 0),
				}),
			},
			want: ErrMandatoryIEMissing,
		},
		{
			name: "missing sgw fteid",
			ies: []IE{
				EncodeEBI(6, 0),
				EncodeGrouped(IETypeBearerContext, 0, []IE{
					EncodeEBI(0, 0),
					EncodeBearerQoS(9, 8, false, true),
					{Type: IETypeTFT, Instance: 0, Value: []byte{0x20}},
				}),
			},
			want: ErrConditionalIEMissing,
		},
		{
			name: "missing pgw fteid",
			ies: []IE{
				EncodeEBI(6, 0),
				EncodeGrouped(IETypeBearerContext, 0, []IE{
					EncodeEBI(0, 0),
					EncodeBearerQoS(9, 8, false, true),
					{Type: IETypeTFT, Instance: 0, Value: []byte{0x20}},
					EncodeFTEID(IFTypeS1USGW, 0x01020304, net.ParseIP("10.0.0.3"), 0),
				}),
			},
			want: ErrConditionalIEMissing,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeCreateBearerRequest(&Message{
				Type: MsgCreateBearerRequest,
				IEs:  tc.ies,
			})
			if err == nil {
				t.Fatal("DecodeCreateBearerRequest unexpectedly succeeded")
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("error got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestDecodeCreateBearerRequestRejectsInvalidMandatoryIEs(t *testing.T) {
	_, err := DecodeCreateBearerRequest(&Message{
		Type: MsgCreateBearerRequest,
		IEs: []IE{
			EncodeEBI(6, 0),
			EncodeGrouped(IETypeBearerContext, 0, []IE{
				EncodeEBI(0, 0),
				{Type: IETypeBearerQoS, Instance: 0, Value: []byte{0x01}},
				{Type: IETypeTFT, Instance: 0, Value: []byte{0x20}},
				{Type: IETypeFTEID, Instance: 0, Value: []byte{0x40 | IFTypeS1USGW, 0x11, 0x22, 0x33, 0x44}},
			}),
		},
	})
	if err == nil {
		t.Fatal("DecodeCreateBearerRequest unexpectedly succeeded")
	}
	if !errors.Is(err, ErrMandatoryIEIncorrect) {
		t.Fatalf("error got %v, want %v", err, ErrMandatoryIEIncorrect)
	}
}

func TestDecodeUpdateBearerRequestRejectsMissingMandatoryEBI(t *testing.T) {
	_, err := DecodeUpdateBearerRequest(&Message{
		Type: MsgUpdateBearerRequest,
		IEs: []IE{
			EncodeGrouped(IETypeBearerContext, 0, []IE{
				{Type: IETypeTFT, Instance: 0, Value: []byte{0xa4, 0x04}},
			}),
		},
	})
	if err == nil {
		t.Fatal("DecodeUpdateBearerRequest unexpectedly succeeded")
	}
	if !errors.Is(err, ErrMandatoryIEMissing) {
		t.Fatalf("error got %v, want %v", err, ErrMandatoryIEMissing)
	}
}

func TestDecodeUpdateBearerRequestRejectsInvalidOptionalIEs(t *testing.T) {
	_, err := DecodeUpdateBearerRequest(&Message{
		Type: MsgUpdateBearerRequest,
		IEs: []IE{
			EncodeGrouped(IETypeBearerContext, 0, []IE{
				EncodeEBI(9, 0),
				{Type: IETypeBearerQoS, Instance: 0, Value: []byte{0x01}},
			}),
		},
	})
	if err == nil {
		t.Fatal("DecodeUpdateBearerRequest unexpectedly succeeded")
	}
	if !errors.Is(err, ErrMandatoryIEIncorrect) {
		t.Fatalf("error got %v, want %v", err, ErrMandatoryIEIncorrect)
	}
}

func TestDecodeDeleteBearerRequestRejectsMissingEBI(t *testing.T) {
	_, err := DecodeDeleteBearerRequest(&Message{
		Type: MsgDeleteBearerRequest,
		IEs:  []IE{},
	})
	if err == nil {
		t.Fatal("DecodeDeleteBearerRequest unexpectedly succeeded")
	}
	if !errors.Is(err, ErrMandatoryIEMissing) {
		t.Fatalf("error got %v, want %v", err, ErrMandatoryIEMissing)
	}
}

func TestDecodeDeleteBearerRequestRejectsGroupedContextWithoutEBI(t *testing.T) {
	_, err := DecodeDeleteBearerRequest(&Message{
		Type: MsgDeleteBearerRequest,
		IEs: []IE{
			EncodeGrouped(IETypeBearerContext, 0, []IE{
				{Type: IETypeCause, Instance: 0, Value: []byte{CauseRequestAccepted, 0}},
			}),
		},
	})
	if err == nil {
		t.Fatal("DecodeDeleteBearerRequest unexpectedly succeeded")
	}
	if !errors.Is(err, ErrMandatoryIEMissing) {
		t.Fatalf("error got %v, want %v", err, ErrMandatoryIEMissing)
	}
}

func TestCreateBearerResponseIncludesENBFTEID(t *testing.T) {
	out := EncodeCreateBearerResponse(0x12345678, 0x101, CauseRequestAccepted, []CreateBearerBearer{{
		EBI:        7,
		ENBS1UTEID: 0xaabbccdd,
		ENBS1UIP:   net.ParseIP("192.168.105.247").To4(),
	}})
	msg, err := Decode(out)
	if err != nil {
		t.Fatalf("Decode response: %v", err)
	}
	if msg.Type != MsgCreateBearerResponse || msg.TEID != 0x12345678 || msg.SeqNum != 0x101 {
		t.Fatalf("response header got type=%d teid=0x%x seq=0x%x", msg.Type, msg.TEID, msg.SeqNum)
	}
	children, err := FindGroupedIEs(FindIE(msg.IEs, IETypeBearerContext, 0))
	if err != nil {
		t.Fatalf("FindGroupedIEs: %v", err)
	}
	f, err := DecodeFTEID(FindIE(children, IETypeFTEID, 0))
	if err != nil {
		t.Fatalf("DecodeFTEID: %v", err)
	}
	if f.InterfaceType != IFTypeS1UENB || f.TEID != 0xaabbccdd || !f.IP.Equal(net.ParseIP("192.168.105.247").To4()) {
		t.Fatalf("FTEID got %+v", f)
	}
}

func TestCreateBearerResponseIncludesReferenceStyleULIAndSGWFTEID(t *testing.T) {
	out := EncodeCreateBearerResponseWithMeta(0x6d0933c3, 0x86b, CauseRequestAccepted, []CreateBearerBearer{{
		EBI:        7,
		ENBS1UTEID: 0x7788c3a0,
		ENBS1UIP:   net.ParseIP("192.168.105.247").To4(),
		SGWS1UTEID: 0x2280f13f,
		SGWS1UIP:   net.ParseIP("10.90.250.59").To4(),
	}}, &CreateBearerResponseMeta{
		IncludeULI: true,
		ULIPLMN:    [3]byte{0x13, 0x51, 0x34},
		ULITAC:     1,
		ULIECI:     0x05300c81,
	})
	msg, err := Decode(out)
	if err != nil {
		t.Fatalf("Decode response: %v", err)
	}
	if msg.TEID != 0x6d0933c3 {
		t.Fatalf("response TEID got 0x%x, want 0x6d0933c3", msg.TEID)
	}
	uli := FindIE(msg.IEs, IETypeULI, 0)
	if uli == nil {
		t.Fatal("ULI IE missing")
	}
	wantULI := EncodeULI([3]byte{0x13, 0x51, 0x34}, 1, 0x05300c81)
	if got := hex.EncodeToString(uli.Value); got != hex.EncodeToString(wantULI.Value) {
		t.Fatalf("ULI got %s, want %s", got, hex.EncodeToString(wantULI.Value))
	}
	children, err := FindGroupedIEs(FindIE(msg.IEs, IETypeBearerContext, 0))
	if err != nil {
		t.Fatalf("FindGroupedIEs: %v", err)
	}
	sgwFTEID, err := DecodeFTEID(FindIE(children, IETypeFTEID, FTEIDInstanceSGWU))
	if err != nil {
		t.Fatalf("Decode SGW FTEID: %v", err)
	}
	if sgwFTEID.InterfaceType != IFTypeS1USGW || sgwFTEID.TEID != 0x2280f13f || !sgwFTEID.IP.Equal(net.ParseIP("10.90.250.59").To4()) {
		t.Fatalf("SGW FTEID got %+v", sgwFTEID)
	}
}

func TestBearerProcedureResponsesUseShortCauseIE(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
	}{
		{
			name: "create bearer",
			raw: EncodeCreateBearerResponse(0x12345678, 0x101, CauseRequestAccepted, []CreateBearerBearer{{
				EBI: 7,
			}}),
		},
		{
			name: "update bearer",
			raw: EncodeUpdateBearerResponse(0x12345678, 0x102, CauseRequestAccepted, []UpdateBearerBearer{{
				EBI: 7,
			}}),
		},
		{
			name: "delete bearer",
			raw:  EncodeDeleteBearerResponse(0x12345678, 0x103, CauseRequestAccepted, []uint8{7}),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg, err := Decode(tc.raw)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			causeIE := FindIE(msg.IEs, IETypeCause, 0)
			if causeIE == nil || len(causeIE.Value) != 2 {
				t.Fatalf("top-level Cause IE len got %d, want 2", len(causeIE.Value))
			}
			children, err := FindGroupedIEs(FindIE(msg.IEs, IETypeBearerContext, 0))
			if err != nil {
				t.Fatalf("FindGroupedIEs: %v", err)
			}
			bearerCause := FindIE(children, IETypeCause, 0)
			if bearerCause == nil || len(bearerCause.Value) != 2 {
				t.Fatalf("bearer Cause IE len got %d, want 2", len(bearerCause.Value))
			}
		})
	}
}

func TestUpdateBearerResponseIncludesReferenceStyleULI(t *testing.T) {
	out := EncodeUpdateBearerResponseWithMeta(0xc04dad7b, 0x23a, CauseRequestAccepted, []UpdateBearerBearer{{
		EBI: 9,
	}}, &UpdateBearerResponseMeta{
		IncludeULI: true,
		ULIPLMN:    [3]byte{0x13, 0x51, 0x34},
		ULITAC:     1,
		ULIECI:     0x000c8001,
	})
	msg, err := Decode(out)
	if err != nil {
		t.Fatalf("Decode response: %v", err)
	}
	uli := FindIE(msg.IEs, IETypeULI, 0)
	if uli == nil {
		t.Fatal("ULI IE missing")
	}
	wantULI := EncodeULI([3]byte{0x13, 0x51, 0x34}, 1, 0x000c8001)
	if got := hex.EncodeToString(uli.Value); got != hex.EncodeToString(wantULI.Value) {
		t.Fatalf("ULI got %s, want %s", got, hex.EncodeToString(wantULI.Value))
	}
}

func TestDeleteBearerResponseIncludesReferenceStyleULIAndTimestamp(t *testing.T) {
	out := EncodeDeleteBearerResponseWithMeta(0xc04dad7b, 0x23e, CauseRequestAccepted, []uint8{9}, &DeleteBearerResponseMeta{
		IncludeULI:          true,
		ULIPLMN:             [3]byte{0x13, 0x51, 0x34},
		ULITAC:              1,
		ULIECI:              0x000c8001,
		IncludeULITimestamp: true,
		ULITimestamp:        0xedfe9032,
	})
	msg, err := Decode(out)
	if err != nil {
		t.Fatalf("Decode response: %v", err)
	}
	uli := FindIE(msg.IEs, IETypeULI, 0)
	if uli == nil {
		t.Fatal("ULI IE missing")
	}
	wantULI := EncodeULI([3]byte{0x13, 0x51, 0x34}, 1, 0x000c8001)
	if got := hex.EncodeToString(uli.Value); got != hex.EncodeToString(wantULI.Value) {
		t.Fatalf("ULI got %s, want %s", got, hex.EncodeToString(wantULI.Value))
	}
	uliTS := FindIE(msg.IEs, IETypeULITimestamp, 0)
	if uliTS == nil {
		t.Fatal("ULI Timestamp IE missing")
	}
	if got := hex.EncodeToString(uliTS.Value); got != "edfe9032" {
		t.Fatalf("ULI Timestamp got %s, want edfe9032", got)
	}
}

func TestDecodeNokiaUpdateBearerDeleteFilters(t *testing.T) {
	msg, err := Decode(loadHexFixture(t, "testdata/legacy_nokia/update_bearer_delete_filters.hex"))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	req, err := DecodeUpdateBearerRequest(msg)
	if err != nil {
		t.Fatalf("DecodeUpdateBearerRequest: %v", err)
	}
	if req.TEID != 0x802f4007 || req.SeqNum != 0x114 || len(req.Bearers) != 1 {
		t.Fatalf("got teid=0x%x seq=0x%x bearers=%d", req.TEID, req.SeqNum, len(req.Bearers))
	}
	b := req.Bearers[0]
	if b.EBI != 9 {
		t.Fatalf("EBI got %d, want 9", b.EBI)
	}
	wantTFT := "a404050607"
	if hex.EncodeToString(b.TFT) != wantTFT {
		t.Fatalf("TFT got %s, want %s", hex.EncodeToString(b.TFT), wantTFT)
	}
}

func TestDecodeSonimUpdateBearerReplaceFilters(t *testing.T) {
	msg, err := Decode(loadHexFixture(t, "testdata/legacy_sonim/update_bearer_replace_filters.hex"))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	req, err := DecodeUpdateBearerRequest(msg)
	if err != nil {
		t.Fatalf("DecodeUpdateBearerRequest: %v", err)
	}
	if len(req.Bearers) != 1 || req.Bearers[0].EBI != 10 {
		t.Fatalf("got bearers=%d first=%+v", len(req.Bearers), req.Bearers[0])
	}
	if len(req.Bearers[0].TFT) < 2 || req.Bearers[0].TFT[0] != 0x88 {
		t.Fatalf("unexpected TFT prefix %x", req.Bearers[0].TFT)
	}
}

func TestDecodeSonimDeleteBearerRequest(t *testing.T) {
	msg, err := Decode(loadHexFixture(t, "testdata/legacy_sonim/delete_bearer_ebi11.hex"))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	req, err := DecodeDeleteBearerRequest(msg)
	if err != nil {
		t.Fatalf("DecodeDeleteBearerRequest: %v", err)
	}
	if req.TEID != 0x80210006 || req.SeqNum != 0x130 {
		t.Fatalf("ids got teid=0x%x seq=0x%x", req.TEID, req.SeqNum)
	}
	if len(req.EBIs) != 1 || req.EBIs[0] != 11 {
		t.Fatalf("EBIs got %v, want [11]", req.EBIs)
	}
}
