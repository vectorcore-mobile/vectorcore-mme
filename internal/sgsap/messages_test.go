package sgsap

import (
	"bytes"
	"testing"

	"github.com/vectorcore/mme/internal/nas/emm"
)

func TestEncodeIMSIMatchesEPSMobileIdentityEncoding(t *testing.T) {
	// The standalone IMSI IE (§9.4.6/TS 29.018 §18.4.10) and the EPS Mobile
	// Identity IMSI encoding (TS 24.301) share the same type='001'/odd-parity/
	// BCD layout for the real-world case that matters: a 15-digit (odd
	// length) IMSI. This pins that equivalence so a future edit to either
	// codec doesn't silently diverge from the other. Real IMSIs are always
	// 15 digits, so the even-length path (exercised separately by
	// TestIMSIRoundTrip) never has to agree with emm's encoder here.
	for _, imsi := range []string{"001010123456789", "208011300000091"} {
		got := EncodeIMSI(imsi)
		want := emm.EPSMobileIdentityIMSI(imsi)
		if !bytes.Equal(got, want) {
			t.Fatalf("EncodeIMSI(%q) = %x, want %x (emm.EPSMobileIdentityIMSI)", imsi, got, want)
		}
	}
}

func TestIMSIRoundTrip(t *testing.T) {
	for _, imsi := range []string{"001010123456789", "20801130000009", "123456789012345"} {
		v := EncodeIMSI(imsi)
		got, err := DecodeIMSI(v)
		if err != nil {
			t.Fatalf("DecodeIMSI(%q): %v", imsi, err)
		}
		if got != imsi {
			t.Fatalf("IMSI round trip: got %q, want %q", got, imsi)
		}
	}
}

func TestMobileIdentityRoundTripIMSIAndTMSI(t *testing.T) {
	imsi := MobileIdentity{Kind: MobileIdentityIMSI, Digits: "001010123456789"}
	v := EncodeMobileIdentity(imsi)
	got, err := DecodeMobileIdentity(v)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != MobileIdentityIMSI || got.Digits != imsi.Digits {
		t.Fatalf("mobile identity IMSI round trip = %+v", got)
	}

	tmsi := MobileIdentity{Kind: MobileIdentityTMSI, TMSI: 0xDEADBEEF}
	v = EncodeMobileIdentity(tmsi)
	if v[0] != 0xF4 {
		t.Fatalf("TMSI mobile identity octet 1 = %#x, want 0xF4", v[0])
	}
	got, err = DecodeMobileIdentity(v)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != MobileIdentityTMSI || got.TMSI != 0xDEADBEEF {
		t.Fatalf("mobile identity TMSI round trip = %+v", got)
	}
}

func TestIMEISVRoundTrip(t *testing.T) {
	v, err := EncodeIMEISV("1234567890123456")
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeIMEISV(v)
	if err != nil {
		t.Fatal(err)
	}
	if got != "1234567890123456" {
		t.Fatalf("IMEISV round trip = %q", got)
	}
	if _, err := EncodeIMEISV("123"); err == nil {
		t.Fatal("expected error for short IMEISV")
	}
}

func TestFQDNLabelsRoundTrip(t *testing.T) {
	name := "mmec01.mmegi0001.mme.epc.mnc001.mcc001.3gppnetwork.org"
	v := encodeFQDNLabels(name)
	// First label "mmec01" is 6 octets, so the wire form starts with length 6.
	if v[0] != 6 {
		t.Fatalf("first label length = %d, want 6", v[0])
	}
	got, err := decodeFQDNLabels(v)
	if err != nil {
		t.Fatal(err)
	}
	if got != name {
		t.Fatalf("FQDN round trip = %q, want %q", got, name)
	}
}

func TestResetIndicationAndAckRoundTrip(t *testing.T) {
	mme := Reset{MMEName: "mme.example.org"}
	v := BuildResetIndication(mme)
	got, err := DecodeResetIndication(v)
	if err != nil {
		t.Fatal(err)
	}
	if got.MMEName != mme.MMEName || got.VLRName != "" {
		t.Fatalf("reset indication round trip = %+v", got)
	}

	vlr := Reset{VLRName: "vlr.example.org"}
	v = BuildResetAck(vlr)
	gotAck, err := DecodeResetAck(v)
	if err != nil {
		t.Fatal(err)
	}
	if gotAck.VLRName != vlr.VLRName || gotAck.MMEName != "" {
		t.Fatalf("reset ack round trip = %+v", gotAck)
	}

	if _, err := DecodeResetIndication(v); err == nil {
		t.Fatal("expected message type mismatch error decoding a RESET-ACK as RESET-INDICATION")
	}
}

func TestResetRejectsMessageWithNoIdentity(t *testing.T) {
	e := newEncoder(MsgResetIndication)
	if _, err := DecodeResetIndication(e.bytes()); err == nil {
		t.Fatal("expected error for reset message with neither MME nor VLR name")
	}
}

func testLAI(t *testing.T) LAI {
	t.Helper()
	plmn, err := EncodePLMN("001", "01")
	if err != nil {
		t.Fatal(err)
	}
	return LAI{PLMN: plmn, LAC: 1}
}

func testTAI(t *testing.T) TAI {
	t.Helper()
	plmn, err := EncodePLMN("001", "01")
	if err != nil {
		t.Fatal(err)
	}
	return TAI{PLMN: plmn, TAC: 1}
}

func TestLocationUpdateRequestRoundTrip(t *testing.T) {
	lai := testLAI(t)
	tai := testTAI(t)
	ecgi := ECGI{PLMN: lai.PLMN, ECI: 0x1234567 & 0x0FFFFFFF}
	tmsiValid := true
	req := LocationUpdateRequest{
		IMSI:            "001010123456789",
		MMEName:         "mme.example.org",
		UpdateType:      EPSLocationUpdateTypeNormal,
		NewLAI:          lai,
		OldLAI:          &lai,
		TMSIStatusValid: &tmsiValid,
		IMEISV:          "1234567890123456",
		TAI:             &tai,
		ECGI:            &ecgi,
	}
	v, err := BuildLocationUpdateRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := MessageType(v); err != nil || got != MsgLocationUpdateRequest {
		t.Fatalf("MessageType = %v, %v", got, err)
	}
	got, err := DecodeLocationUpdateRequest(v)
	if err != nil {
		t.Fatal(err)
	}
	if got.IMSI != req.IMSI || got.MMEName != req.MMEName || got.UpdateType != req.UpdateType {
		t.Fatalf("location update request round trip = %+v", got)
	}
	if got.NewLAI != lai || got.OldLAI == nil || *got.OldLAI != lai {
		t.Fatalf("LAI round trip: new=%+v old=%+v", got.NewLAI, got.OldLAI)
	}
	if got.TMSIStatusValid == nil || *got.TMSIStatusValid != true {
		t.Fatalf("TMSI status round trip = %+v", got.TMSIStatusValid)
	}
	if got.IMEISV != req.IMEISV {
		t.Fatalf("IMEISV round trip = %q", got.IMEISV)
	}
	if got.TAI == nil || *got.TAI != tai {
		t.Fatalf("TAI round trip = %+v", got.TAI)
	}
	if got.ECGI == nil || *got.ECGI != ecgi {
		t.Fatalf("ECGI round trip = %+v", got.ECGI)
	}
}

func TestLocationUpdateAcceptRoundTripWithNewTMSI(t *testing.T) {
	lai := testLAI(t)
	id := MobileIdentity{Kind: MobileIdentityTMSI, TMSI: 0x11223344}
	v, err := BuildLocationUpdateAccept(LocationUpdateAccept{IMSI: "001010123456789", LAI: lai, NewIdentity: &id})
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeLocationUpdateAccept(v)
	if err != nil {
		t.Fatal(err)
	}
	if got.IMSI != "001010123456789" || got.LAI != lai {
		t.Fatalf("location update accept round trip = %+v", got)
	}
	if got.NewIdentity == nil || got.NewIdentity.Kind != MobileIdentityTMSI || got.NewIdentity.TMSI != 0x11223344 {
		t.Fatalf("new identity round trip = %+v", got.NewIdentity)
	}
}

func TestLocationUpdateRejectRoundTrip(t *testing.T) {
	lai := testLAI(t)
	v, err := BuildLocationUpdateReject(LocationUpdateReject{IMSI: "001010123456789", Cause: 13, LAI: &lai})
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeLocationUpdateReject(v)
	if err != nil {
		t.Fatal(err)
	}
	if got.IMSI != "001010123456789" || got.Cause != 13 || got.LAI == nil || *got.LAI != lai {
		t.Fatalf("location update reject round trip = %+v", got)
	}
}

func TestUplinkDownlinkUnitdataRoundTrip(t *testing.T) {
	tai := testTAI(t)
	ecgi := ECGI{PLMN: tai.PLMN, ECI: 42}
	tz := byte(0x11)
	up := UplinkUnitdata{
		IMSI:                "001010123456789",
		NASMessageContainer: []byte{0x01, 0x02, 0x03},
		IMEISV:              "1234567890123456",
		UETimeZone:          &tz,
		TAI:                 &tai,
		ECGI:                &ecgi,
	}
	v, err := BuildUplinkUnitdata(up)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeUplinkUnitdata(v)
	if err != nil {
		t.Fatal(err)
	}
	if got.IMSI != up.IMSI || !bytes.Equal(got.NASMessageContainer, up.NASMessageContainer) {
		t.Fatalf("uplink unitdata round trip = %+v", got)
	}
	if got.IMEISV != up.IMEISV || got.UETimeZone == nil || *got.UETimeZone != tz {
		t.Fatalf("uplink unitdata optional fields = %+v", got)
	}
	if got.TAI == nil || *got.TAI != tai || got.ECGI == nil || *got.ECGI != ecgi {
		t.Fatalf("uplink unitdata TAI/ECGI = %+v %+v", got.TAI, got.ECGI)
	}

	dv, err := BuildDownlinkUnitdata(DownlinkUnitdata{IMSI: "001010123456789", NASMessageContainer: []byte{0xAA, 0xBB}})
	if err != nil {
		t.Fatal(err)
	}
	dgot, err := DecodeDownlinkUnitdata(dv)
	if err != nil {
		t.Fatal(err)
	}
	if dgot.IMSI != "001010123456789" || !bytes.Equal(dgot.NASMessageContainer, []byte{0xAA, 0xBB}) {
		t.Fatalf("downlink unitdata round trip = %+v", dgot)
	}
}

func TestServiceRequestRoundTrip(t *testing.T) {
	tai := testTAI(t)
	v, err := BuildServiceRequest(ServiceRequest{
		IMSI:             "001010123456789",
		ServiceIndicator: ServiceIndicatorSMS,
		TAI:              &tai,
		UEEMMMode:        UEEMMModeConnected,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeServiceRequest(v)
	if err != nil {
		t.Fatal(err)
	}
	if got.IMSI != "001010123456789" || got.ServiceIndicator != ServiceIndicatorSMS || got.UEEMMMode != UEEMMModeConnected {
		t.Fatalf("service request round trip = %+v", got)
	}
	if got.TAI == nil || *got.TAI != tai {
		t.Fatalf("service request TAI = %+v", got.TAI)
	}
}

func TestPagingRequestAndRejectRoundTrip(t *testing.T) {
	lai := testLAI(t)
	tmsi := uint32(0xAABBCCDD)
	v, err := BuildPagingRequest(PagingRequest{
		IMSI:             "001010123456789",
		VLRName:          "vlr.example.org",
		ServiceIndicator: ServiceIndicatorCSCall,
		TMSI:             &tmsi,
		LAI:              &lai,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodePagingRequest(v)
	if err != nil {
		t.Fatal(err)
	}
	if got.IMSI != "001010123456789" || got.VLRName != "vlr.example.org" || got.ServiceIndicator != ServiceIndicatorCSCall {
		t.Fatalf("paging request round trip = %+v", got)
	}
	if got.TMSI == nil || *got.TMSI != tmsi || got.LAI == nil || *got.LAI != lai {
		t.Fatalf("paging request TMSI/LAI = %+v %+v", got.TMSI, got.LAI)
	}

	rv, err := BuildPagingReject("001010123456789", CauseUEUnreachable)
	if err != nil {
		t.Fatal(err)
	}
	imsi, cause, err := DecodePagingReject(rv)
	if err != nil {
		t.Fatal(err)
	}
	if imsi != "001010123456789" || cause != CauseUEUnreachable {
		t.Fatalf("paging reject round trip = %q %v", imsi, cause)
	}
}

func TestIMSIOnlyMessagesRoundTrip(t *testing.T) {
	cases := []struct {
		name   string
		build  func(string) ([]byte, error)
		decode func([]byte) (string, error)
	}{
		{"TMSIReallocationComplete", BuildTMSIReallocationComplete, DecodeTMSIReallocationComplete},
		{"AlertRequest", BuildAlertRequest, DecodeAlertRequest},
		{"AlertAck", BuildAlertAck, DecodeAlertAck},
		{"ServiceAbortRequest", BuildServiceAbortRequest, DecodeServiceAbortRequest},
		{"EPSDetachAck", BuildEPSDetachAck, DecodeEPSDetachAck},
		{"IMSIDetachAck", BuildIMSIDetachAck, DecodeIMSIDetachAck},
		{"UEActivityIndication", BuildUEActivityIndication, DecodeUEActivityIndication},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := tc.build("001010123456789")
			if err != nil {
				t.Fatal(err)
			}
			got, err := tc.decode(v)
			if err != nil {
				t.Fatal(err)
			}
			if got != "001010123456789" {
				t.Fatalf("%s round trip = %q", tc.name, got)
			}
			if _, err := tc.build(""); err == nil {
				t.Fatalf("%s: expected error for empty IMSI", tc.name)
			}
		})
	}
}

func TestAlertRejectAndUEUnreachableRoundTrip(t *testing.T) {
	v, err := BuildAlertReject("001010123456789", CauseIMSIUnknown)
	if err != nil {
		t.Fatal(err)
	}
	imsi, cause, err := DecodeAlertReject(v)
	if err != nil {
		t.Fatal(err)
	}
	if imsi != "001010123456789" || cause != CauseIMSIUnknown {
		t.Fatalf("alert reject round trip = %q %v", imsi, cause)
	}

	uv, err := BuildUEUnreachable(UEUnreachable{IMSI: "001010123456789", Cause: CauseUEUnreachable})
	if err != nil {
		t.Fatal(err)
	}
	ugot, err := DecodeUEUnreachable(uv)
	if err != nil {
		t.Fatal(err)
	}
	if ugot.IMSI != "001010123456789" || ugot.Cause != CauseUEUnreachable {
		t.Fatalf("UE unreachable round trip = %+v", ugot)
	}
}

func TestReleaseRequestRoundTrip(t *testing.T) {
	v, err := BuildReleaseRequest("001010123456789", nil)
	if err != nil {
		t.Fatal(err)
	}
	imsi, cause, err := DecodeReleaseRequest(v)
	if err != nil {
		t.Fatal(err)
	}
	if imsi != "001010123456789" || cause != nil {
		t.Fatalf("release request (no cause) round trip = %q %v", imsi, cause)
	}

	c := CauseMessageUnknown
	v, err = BuildReleaseRequest("001010123456789", &c)
	if err != nil {
		t.Fatal(err)
	}
	imsi, cause, err = DecodeReleaseRequest(v)
	if err != nil {
		t.Fatal(err)
	}
	if imsi != "001010123456789" || cause == nil || *cause != CauseMessageUnknown {
		t.Fatalf("release request (with cause) round trip = %q %v", imsi, cause)
	}
}

func TestEPSAndIMSIDetachIndicationRoundTrip(t *testing.T) {
	v, err := BuildEPSDetachIndication(EPSDetachIndication{IMSI: "001010123456789", MMEName: "mme.example.org", DetachType: EPSDetachUEInitiated})
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeEPSDetachIndication(v)
	if err != nil {
		t.Fatal(err)
	}
	if got.IMSI != "001010123456789" || got.MMEName != "mme.example.org" || got.DetachType != EPSDetachUEInitiated {
		t.Fatalf("EPS detach indication round trip = %+v", got)
	}

	iv, err := BuildIMSIDetachIndication(IMSIDetachIndication{IMSI: "001010123456789", MMEName: "mme.example.org", DetachType: NonEPSDetachCombinedUEInitiated})
	if err != nil {
		t.Fatal(err)
	}
	igot, err := DecodeIMSIDetachIndication(iv)
	if err != nil {
		t.Fatal(err)
	}
	if igot.IMSI != "001010123456789" || igot.MMEName != "mme.example.org" || igot.DetachType != NonEPSDetachCombinedUEInitiated {
		t.Fatalf("IMSI detach indication round trip = %+v", igot)
	}
}

func TestMOCSFBIndicationRoundTrip(t *testing.T) {
	tai := testTAI(t)
	v, err := BuildMOCSFBIndication(MOCSFBIndication{IMSI: "001010123456789", TAI: &tai})
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeMOCSFBIndication(v)
	if err != nil {
		t.Fatal(err)
	}
	if got.IMSI != "001010123456789" || got.TAI == nil || *got.TAI != tai {
		t.Fatalf("MO-CSFB indication round trip = %+v", got)
	}
}

func TestMMInformationRequestRoundTrip(t *testing.T) {
	v, err := BuildMMInformationRequest(MMInformationRequest{IMSI: "001010123456789", MMInformation: []byte{0x01, 0x02, 0x03}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeMMInformationRequest(v)
	if err != nil {
		t.Fatal(err)
	}
	if got.IMSI != "001010123456789" || !bytes.Equal(got.MMInformation, []byte{0x01, 0x02, 0x03}) {
		t.Fatalf("MM information request round trip = %+v", got)
	}
}

func TestStatusRoundTrip(t *testing.T) {
	v, err := BuildStatus(Status{IMSI: "001010123456789", Cause: CauseMessageUnknown, ErroneousMessage: []byte{MsgPagingRequest, 0x01, 0x02, 0xFF}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeStatus(v)
	if err != nil {
		t.Fatal(err)
	}
	if got.IMSI != "001010123456789" || got.Cause != CauseMessageUnknown {
		t.Fatalf("status round trip = %+v", got)
	}
	if !bytes.Equal(got.ErroneousMessage, []byte{MsgPagingRequest, 0x01, 0x02, 0xFF}) {
		t.Fatalf("status erroneous message = %x", got.ErroneousMessage)
	}
}

func TestDecodeRejectsTruncatedIE(t *testing.T) {
	// A well-formed IEI/length header claiming more value bytes than remain.
	data := []byte{MsgLocationUpdateReject, ieIMSI, 0x0A, 0x01, 0x02}
	if _, err := decodePDU(data); err == nil {
		t.Fatal("expected error decoding truncated IE")
	}
}

func TestDecodeRejectsWrongMessageType(t *testing.T) {
	v, err := BuildAlertAck("001010123456789")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeLocationUpdateAccept(v); err == nil {
		t.Fatal("expected message type mismatch error")
	}
}
