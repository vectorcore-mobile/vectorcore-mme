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

func TestBuildOFRIncludesReferenceMSISDNEncoding(t *testing.T) {
	m, err := BuildOFR(MORequest{SessionID: "sid", OriginHost: "mme.example", OriginRealm: "example", DestinationRealm: "example", IMSI: "001010123456789", MSISDN: "+15551230000", SCAddress: "+15551230000", SMRPUI: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	a := findAVP(m, avpMSISDN, VendorID)
	if a == nil || !bytes.Equal([]byte(a.Data.(datatype.OctetString)), []byte{7, 0x91, 0x51, 0x55, 0x21, 0x03, 0x00, 0xf0}) {
		t.Fatalf("MSISDN AVP = %#v", a)
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
	req, err := BuildALR(AlertRequest{SessionID: "alert-1", OriginHost: "mme.example", OriginRealm: "example", DestinationRealm: "example", IMSI: "001010123456789", SCAddress: "+15551230000", SCAddressEncoding: "ascii_digits"})
	if err != nil {
		t.Fatal(err)
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
