package sgd

import (
	"bytes"
	"testing"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/fiorix/go-diameter/v4/diam/avp"
	"github.com/fiorix/go-diameter/v4/diam/datatype"
	"github.com/fiorix/go-diameter/v4/diam/dict"
)

func TestBuildOFRUsesStandardTBCDAddress(t *testing.T) {
	m, err := BuildOFR(MORequest{SessionID: "sid", OriginHost: "mme.example", OriginRealm: "example", DestinationRealm: "example", IMSI: "001010123456789", SCAddress: "+15551230000", SMRPUI: []byte{1, 2, 3}})
	if err != nil {
		t.Fatal(err)
	}
	if m.Header.ApplicationID != ApplicationID || m.Header.CommandCode != CommandMOForwardShortMessage {
		t.Fatalf("unexpected OFR header: %+v", m.Header)
	}
	var a *diam.AVP
	for _, candidate := range m.AVP {
		if candidate.Code == avpSCAddress {
			a = candidate
			break
		}
	}
	if a == nil || !bytes.Equal([]byte(a.Data.(datatype.OctetString)), []byte{0x51, 0x55, 0x21, 0x03, 0x00, 0xf0}) {
		t.Fatalf("SC-Address = %#v", a)
	}
}

func TestBuildOFRSupportsCiscoASCIIDigitsSCAddress(t *testing.T) {
	m, err := BuildOFR(MORequest{SessionID: "sid", OriginHost: "mme.example", OriginRealm: "example", DestinationRealm: "example", IMSI: "001010123456789", SCAddress: "+15551230000", SCAddressEncoding: "ascii_digits", SMRPUI: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range m.AVP {
		if a.Code == avpSCAddress && string(a.Data.(datatype.OctetString)) != "15551230000" {
			t.Fatalf("Cisco SC-Address = %x", a.Data)
		}
	}
}

func TestBuildOFRMSISDNIsPlainTBCD(t *testing.T) {
	cases := []struct {
		msisdn string
		want   []byte
	}{
		// TS 29.329 §6.3.2: TBCD only, no length or TON/NPI octet.
		{"+15551230000", []byte{0x51, 0x55, 0x21, 0x03, 0x00, 0xf0}}, // odd digit count: F filler
		{"491711234567", []byte{0x94, 0x71, 0x11, 0x32, 0x54, 0x76}}, // even digit count: no filler
	}
	for _, tc := range cases {
		m, err := BuildOFR(MORequest{SessionID: "sid", OriginHost: "mme.example", OriginRealm: "example", DestinationRealm: "example", IMSI: "001010123456789", MSISDN: tc.msisdn, SCAddress: "+15551230000", SMRPUI: []byte{1}})
		if err != nil {
			t.Fatal(err)
		}
		a := findAVP(m, avpMSISDN, VendorID)
		if a == nil || !bytes.Equal([]byte(a.Data.(datatype.OctetString)), tc.want) {
			t.Fatalf("MSISDN %s AVP = %#v, want %x", tc.msisdn, a, tc.want)
		}
	}
	if _, err := BuildOFR(MORequest{SessionID: "sid", OriginHost: "mme.example", OriginRealm: "example", DestinationRealm: "example", IMSI: "001010123456789", MSISDN: "+1555abc", SCAddress: "+15551230000", SMRPUI: []byte{1}}); err == nil {
		t.Fatal("BuildOFR accepted a non-E.164 MSISDN")
	}
}

func TestDecodeTFRRejectsMalformedAndPreservesPayload(t *testing.T) {
	m := diam.NewRequest(CommandMTForwardShortMessage, ApplicationID, dict.Default)
	m.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String("sid"))
	m.NewAVP(avp.UserName, avp.Mbit, 0, datatype.UTF8String("001010123456789"))
	m.NewAVP(avpSCAddress, avp.Vbit|avp.Mbit, VendorID, datatype.OctetString([]byte{0x51}))
	payload := []byte{0x01, 0xaa, 0xbb}
	m.NewAVP(avpSMRPUI, avp.Vbit|avp.Mbit, VendorID, datatype.OctetString(payload))
	got, err := DecodeTFR(m)
	if err != nil || !bytes.Equal(got.SMRPUI, payload) {
		t.Fatalf("DecodeTFR = %#v, %v", got, err)
	}
	m.AVP = m.AVP[:len(m.AVP)-1]
	if _, err := DecodeTFR(m); err == nil {
		t.Fatal("DecodeTFR accepted missing SM-RP-UI")
	}
}

func TestBuildALRAndDecodeALA(t *testing.T) {
	req, err := BuildALR(AlertRequest{SessionID: "alert-1", OriginHost: "mme.example", OriginRealm: "example", DestinationRealm: "example", IMSI: "001010123456789", MSISDN: "+15551230000", SCAddress: "+15551230000", SCAddressEncoding: "ascii_digits"})
	if err != nil {
		t.Fatal(err)
	}
	if a := findAVP(req, avpMSISDN, VendorID); a == nil || !bytes.Equal([]byte(a.Data.(datatype.OctetString)), []byte{0x51, 0x55, 0x21, 0x03, 0x00, 0xf0}) {
		t.Fatalf("ALR MSISDN AVP = %#v, want plain TBCD", a)
	}
	if req.Header.ApplicationID != ApplicationID || req.Header.CommandCode != CommandAlertServiceCentre || req.Header.CommandFlags&diam.RequestFlag == 0 {
		t.Fatalf("unexpected ALR header: %+v", req.Header)
	}
	ans := req.Answer(diam.Success)
	if got, err := DecodeALA(ans); err != nil || got != diam.Success {
		t.Fatalf("DecodeALA = %d, %v", got, err)
	}
}

func TestDictionaryRegistersSGdCommandsAndDecodesOFA(t *testing.T) {
	for _, command := range []uint32{CommandMOForwardShortMessage, CommandMTForwardShortMessage, CommandAlertServiceCentre} {
		if _, err := dict.Default.FindCommand(ApplicationID, command); err != nil {
			t.Fatalf("SGd command %d is not registered: %v", command, err)
		}
	}
	req, err := BuildOFR(MORequest{SessionID: "ofr-1", OriginHost: "mme.example", OriginRealm: "example", DestinationRealm: "example", IMSI: "001010123456789", SCAddress: "+15551230000", SMRPUI: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := req.Answer(diam.Success).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	answer, err := diam.ReadMessage(bytes.NewReader(wire), dict.Default)
	if err != nil {
		t.Fatalf("read OFA through shared dictionary: %v", err)
	}
	decoded, err := DecodeOFA(answer)
	if err != nil || decoded.ResultCode != diam.Success {
		t.Fatalf("DecodeOFA = %#v, %v", decoded, err)
	}
}

// TestBuildTFAEncodesOutcomes round-trips each TFA shape through the wire and
// the SGd dictionary, as the SMSC would read it.
func TestBuildTFAEncodesOutcomes(t *testing.T) {
	req := diam.NewRequest(CommandMTForwardShortMessage, ApplicationID, dict.Default)
	req.Header.HopByHopID, req.Header.EndToEndID = 5, 6
	roundTrip := func(t *testing.T, o MTOutcome) *diam.Message {
		t.Helper()
		ans, err := BuildTFA(req, "mme.example", "example", o)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := ans.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		m, err := diam.ReadMessage(bytes.NewReader(wire), dict.Default)
		if err != nil {
			t.Fatalf("decode TFA: %v", err)
		}
		if m.Header.HopByHopID != 5 || m.Header.EndToEndID != 6 || m.Header.CommandFlags&diam.ErrorFlag != 0 {
			t.Fatalf("TFA header = %+v", m.Header)
		}
		return m
	}
	experimental := func(t *testing.T, m *diam.Message) uint32 {
		t.Helper()
		if findAVP(m, avp.ResultCode, 0) != nil {
			t.Fatal("TFA carries Result-Code alongside Experimental-Result")
		}
		er := findAVP(m, avp.ExperimentalResult, 0)
		if er == nil {
			t.Fatal("TFA missing Experimental-Result")
		}
		var vendor, code uint32
		for _, c := range er.Data.(*diam.GroupedAVP).AVP {
			switch c.Code {
			case avp.VendorID:
				vendor = uint32(c.Data.(datatype.Unsigned32))
			case avp.ExperimentalResultCode:
				code = uint32(c.Data.(datatype.Unsigned32))
			}
		}
		if vendor != VendorID {
			t.Fatalf("Experimental-Result Vendor-Id = %d", vendor)
		}
		return code
	}

	t.Run("success", func(t *testing.T) {
		m := roundTrip(t, MTDelivered([]byte{0x00, 0x00}))
		rc := findAVP(m, avp.ResultCode, 0)
		if rc == nil || uint32(rc.Data.(datatype.Unsigned32)) != diam.Success || findAVP(m, avp.ExperimentalResult, 0) != nil {
			t.Fatalf("success TFA = %v", m)
		}
		if ui := findAVP(m, avpSMRPUI, VendorID); ui == nil || !bytes.Equal([]byte(ui.Data.(datatype.OctetString)), []byte{0, 0}) {
			t.Fatalf("SM-RP-UI = %v", ui)
		}
	})
	t.Run("absent user", func(t *testing.T) {
		m := roundTrip(t, MTAbsentUser(AbsentDiagNoPagingResponse))
		if code := experimental(t, m); code != ResultErrorAbsentUser {
			t.Fatalf("code = %d", code)
		}
		d := findAVP(m, avpAbsentUserDiagnosticSM, VendorID)
		if d == nil || uint32(d.Data.(datatype.Unsigned32)) != AbsentDiagNoPagingResponse || d.Flags&avp.Vbit == 0 {
			t.Fatalf("Absent-User-Diagnostic-SM = %v", d)
		}
	})
	t.Run("busy", func(t *testing.T) {
		if code := experimental(t, roundTrip(t, MTUserBusy())); code != ResultErrorUserBusyForMTSMS {
			t.Fatalf("code = %d", code)
		}
	})
	t.Run("delivery failure", func(t *testing.T) {
		report := []byte{0x00, 0xd2, 0x00}
		m := roundTrip(t, MTDeliveryFailure(DeliveryFailureMemoryCapacityExceeded, report))
		if code := experimental(t, m); code != ResultErrorSMDeliveryFailure {
			t.Fatalf("code = %d", code)
		}
		g := findAVP(m, avpSMDeliveryFailureCause, VendorID)
		if g == nil {
			t.Fatal("missing SM-Delivery-Failure-Cause")
		}
		var cause int32 = -1
		var info []byte
		for _, c := range g.Data.(*diam.GroupedAVP).AVP {
			switch c.Code {
			case avpSMEnumeratedDeliveryFailureCause:
				cause = int32(c.Data.(datatype.Enumerated))
			case avpSMDiagnosticInfo:
				info = []byte(c.Data.(datatype.OctetString))
			}
		}
		if cause != int32(DeliveryFailureMemoryCapacityExceeded) || !bytes.Equal(info, report) {
			t.Fatalf("SM-Delivery-Failure-Cause = cause %d info %x", cause, info)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		if _, err := BuildTFA(req, "mme.example", "example", MTOutcome{}); err == nil {
			t.Fatal("BuildTFA accepted an outcome with no result code")
		}
		if _, err := BuildTFA(req, "mme.example", "example", MTOutcome{ResultCode: diam.Success, ExperimentalResultCode: ResultErrorAbsentUser}); err == nil {
			t.Fatal("BuildTFA accepted both result codes")
		}
	})
}
