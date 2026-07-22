package s13

import (
	"errors"
	"testing"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/fiorix/go-diameter/v4/diam/avp"
	"github.com/fiorix/go-diameter/v4/diam/datatype"
	"github.com/vectorcore/mme/internal/config"
)

func TestBuildECRIMEISV(t *testing.T) {
	m, err := BuildECR("mme;1", "mme.example", "example", "eir.example", "", "001010123456789", "0150930051491618")
	if err != nil {
		t.Fatal(err)
	}
	if m.Header.CommandCode != CommandCode || m.Header.ApplicationID != ApplicationID || m.Header.CommandFlags&diam.RequestFlag == 0 {
		t.Fatalf("unexpected ECR header: %#v", m.Header)
	}
	terminal, err := m.FindAVP(avp.TerminalInformation, VendorID)
	if err != nil {
		t.Fatal(err)
	}
	group := terminal.Data.(*diam.GroupedAVP)
	if got := string(group.AVP[0].Data.(datatype.UTF8String)); got != "015093005149164" {
		t.Fatalf("IMEI got %q", got)
	}
	if got := string(group.AVP[1].Data.(datatype.UTF8String)); got != "18" {
		t.Fatalf("software version got %q", got)
	}
	if _, err := m.FindAVP(avp.DestinationHost, 0); err == nil {
		t.Fatal("unexpected Destination-Host")
	}
}

func TestBuildECRRejectsMalformedIdentity(t *testing.T) {
	if _, err := BuildECR("s", "h", "r", "d", "", "", "not-an-imei"); err == nil {
		t.Fatal("expected malformed identity error")
	}
}

func TestNormalizeIMEIStripsNASCheckDigit(t *testing.T) {
	imei, sv, err := NormalizeIdentity("015093005149164")
	if err != nil || imei != "015093005149164" || sv != "" {
		t.Fatalf("got imei=%q sv=%q err=%v", imei, sv, err)
	}
}

func TestIMEISVToIMEIPreservesLeadingZero(t *testing.T) {
	imei, err := IMEISVToIMEI("0150930051491618")
	if err != nil || imei != "015093005149164" || len(imei) != 15 || imei[0] != '0' {
		t.Fatalf("got IMEI %q, err=%v", imei, err)
	}
	if err := ValidateIMEI(imei); err != nil {
		t.Fatal(err)
	}
}

func TestIMEISVToIMEIRejectsInvalidInput(t *testing.T) {
	for _, value := range []string{"", "150930051491618", "015093005149161", "01509300514916189", "01509300514916A8"} {
		if _, err := IMEISVToIMEI(value); err == nil {
			t.Fatalf("%q accepted", value)
		}
	}
}

func TestMaskIMEI(t *testing.T) {
	if got := MaskIMEI("015093005149164"); got != "015093******164" {
		t.Fatalf("got %q", got)
	}
	if got := MaskIMEI("bad"); got != "<invalid-imei>" {
		t.Fatalf("got %q", got)
	}
}

func TestDecodeECAAndPolicy(t *testing.T) {
	m := diam.NewRequest(CommandCode, ApplicationID, nil).Answer(diam.Success)
	m.NewAVP(avp.EquipmentStatus, avp.Mbit|avp.Vbit, VendorID, datatype.Enumerated(Blacklisted))
	r := DecodeECA(m)
	if !r.Verified || r.Status != Blacklisted {
		t.Fatalf("unexpected result: %+v", r)
	}
	cfg := config.S13Config{FailurePolicy: "allow", WhitelistPolicy: "allow", BlacklistPolicy: "reject", GreylistPolicy: "allow"}
	if Allow(cfg, r) {
		t.Fatal("blacklisted equipment was allowed")
	}
	if Allow(cfg, Result{Err: errors.New("unavailable")}) == false {
		t.Fatal("fail-open policy did not allow unavailable EIR")
	}
}

func TestDecodeECARejectsUnknownStatus(t *testing.T) {
	m := diam.NewRequest(CommandCode, ApplicationID, nil).Answer(diam.Success)
	m.NewAVP(avp.EquipmentStatus, avp.Mbit|avp.Vbit, VendorID, datatype.Enumerated(99))
	if r := DecodeECA(m); r.Verified || r.Err == nil {
		t.Fatalf("unknown status accepted: %+v", r)
	}
}
