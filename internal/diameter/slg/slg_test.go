package slg

import (
	"testing"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/fiorix/go-diameter/v4/diam/avp"
	"github.com/fiorix/go-diameter/v4/diam/datatype"
)

func validPLR(t *testing.T) *diam.Message {
	t.Helper()
	m, err := BuildPLR(ProvideLocationRequest{SessionID: "slg;1", OriginHost: "gmlc.example", OriginRealm: "example", DestinationHost: "mme.example", DestinationRealm: "example", SubscriberID: "311435123456789", LocationType: LocationTypeCurrent, LCSClientType: 0})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestPLRRoundTripAndPLAExperimentalResult(t *testing.T) {
	m := validPLR(t)
	req, protocolErr := DecodePLR(m)
	if protocolErr != nil {
		t.Fatal(protocolErr)
	}
	if req.SubscriberID != "311435123456789" || req.DestinationHost != "mme.example" {
		t.Fatalf("decoded PLR = %+v", req)
	}
	answer, err := BuildPLA(m, "mme.example", "example", 0, ExperimentalPositioningFailed, nil)
	if err != nil {
		t.Fatal(err)
	}
	if answer.Header.CommandFlags&diam.RequestFlag != 0 || answer.Header.CommandFlags&diam.ProxiableFlag == 0 {
		t.Fatalf("PLA flags = %#x", answer.Header.CommandFlags)
	}
	if len(allAVPs(answer, avp.ResultCode, 0)) != 0 || len(allAVPs(answer, avp.ExperimentalResult, 0)) != 1 {
		t.Fatal("PLA must contain exactly Experimental-Result")
	}
	if answer.Header.HopByHopID != m.Header.HopByHopID || answer.Header.EndToEndID != m.Header.EndToEndID {
		t.Fatal("PLA lost request correlation")
	}
}

func TestPLRRejectsDuplicateAndMissingMandatoryAVP(t *testing.T) {
	m := validPLR(t)
	m.NewAVP(avp.UserName, avp.Mbit, 0, datatype.UTF8String("311435987654321"))
	if _, err := DecodePLR(m); err == nil || err.ResultCode != diam.InvalidAVPValue {
		t.Fatalf("duplicate User-Name error = %#v", err)
	}
	m = validPLR(t)
	m.AVP = m.AVP[1:]
	if _, err := DecodePLR(m); err == nil || err.ResultCode != diam.MissingAVP {
		t.Fatalf("missing Session-Id error = %#v", err)
	}
}

func TestPLRRecognisesAlternativeTargetIdentitiesAndAllowsOneOfEach(t *testing.T) {
	m := validPLR(t)
	for i, a := range m.AVP {
		if a.Code == avp.UserName {
			m.AVP = append(m.AVP[:i], m.AVP[i+1:]...)
			break
		}
	}
	m.NewAVP(AVPIMEI, avp.Vbit|avp.Mbit, VendorID, datatype.UTF8String("490154203237518"))
	req, protocolErr := DecodePLR(m)
	if protocolErr != nil || req.SubscriberIDType != SubscriberIdentityIMEI {
		t.Fatalf("decoded alternative identity = %+v, %v", req, protocolErr)
	}
	m.NewAVP(avp.UserName, avp.Mbit, 0, datatype.UTF8String("311435123456789"))
	req, protocolErr = DecodePLR(m)
	if protocolErr != nil || req.IMSI != "311435123456789" || req.IMEI != "490154203237518" {
		t.Fatalf("decoded identity alternatives = %+v, %v", req, protocolErr)
	}
	m.NewAVP(avp.UserName, avp.Mbit, 0, datatype.UTF8String("311435987654321"))
	if _, err := DecodePLR(m); err == nil || err.ResultCode != diam.InvalidAVPValue {
		t.Fatalf("duplicate User-Name error = %#v", err)
	}
}

func TestPLRRejectsInvalid3GPPAVPVendor(t *testing.T) {
	m := validPLR(t)
	for _, a := range m.AVP {
		if a.Code == AVPSLgLocationType {
			a.VendorID = 0
			a.Flags &^= avp.Vbit
			break
		}
	}
	if _, err := DecodePLR(m); err == nil || err.ResultCode != diam.InvalidAVPValue {
		t.Fatalf("invalid vendor error = %#v", err)
	}
}

func TestPLRPeriodicLDRValidation(t *testing.T) {
	valid := func(amount, interval uint32) *diam.Message {
		m := validPLR(t)
		m.NewAVP(AVPDeferredLocationType, avp.Vbit|avp.Mbit, VendorID, datatype.Unsigned32(DeferredLocationTypePeriodicLDR))
		m.NewAVP(AVPPeriodicLDRInformation, avp.Vbit|avp.Mbit, VendorID, &diam.GroupedAVP{AVP: []*diam.AVP{
			diam.NewAVP(AVPReportingAmount, avp.Vbit|avp.Mbit, VendorID, datatype.Unsigned32(amount)),
			diam.NewAVP(AVPReportingInterval, avp.Vbit|avp.Mbit, VendorID, datatype.Unsigned32(interval)),
		}})
		return m
	}
	for _, tc := range []struct {
		name             string
		amount, interval uint32
		ok               bool
	}{
		{"minimum", 1, 1, true}, {"maximum span", 1, 8639999, true}, {"amount maximum", 8639999, 1, true},
		{"zero amount", 0, 1, false}, {"zero interval", 1, 0, false}, {"span", 2, 4320000, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := DecodePLR(valid(tc.amount, tc.interval))
			if tc.ok {
				if err != nil || req.PeriodicLDR == nil || req.PeriodicLDR.ReportingAmount != tc.amount || req.PeriodicLDR.ReportingIntervalSeconds != tc.interval {
					t.Fatalf("decoded=%+v err=%v", req, err)
				}
			} else if err == nil {
				t.Fatal("invalid periodic policy accepted")
			}
		})
	}
	noInfo := validPLR(t)
	noInfo.NewAVP(AVPDeferredLocationType, avp.Vbit|avp.Mbit, VendorID, datatype.Unsigned32(DeferredLocationTypePeriodicLDR))
	if _, err := DecodePLR(noInfo); err == nil {
		t.Fatal("periodic bit without info accepted")
	}
	withoutBit := valid(1, 1)
	withoutBit.AVP = append(withoutBit.AVP[:len(withoutBit.AVP)-2], withoutBit.AVP[len(withoutBit.AVP)-1:]...)
	if _, err := DecodePLR(withoutBit); err == nil {
		t.Fatal("periodic info without bit accepted")
	}
	duplicate := valid(1, 1)
	group := duplicate.AVP[len(duplicate.AVP)-1].Data.(*diam.GroupedAVP)
	group.AVP = append(group.AVP, diam.NewAVP(AVPReportingAmount, avp.Vbit|avp.Mbit, VendorID, datatype.Unsigned32(1)))
	if _, err := DecodePLR(duplicate); err == nil {
		t.Fatal("duplicate Reporting-Amount accepted")
	}
}

func TestLRRLRACodec(t *testing.T) {
	lrr, err := BuildLRR(LocationReportRequest{SessionID: "slg;2", OriginHost: "mme.example", OriginRealm: "example", DestinationHost: "gmlc.example", DestinationRealm: "example", LocationEvent: 0, IMSI: "001010123456789", IMEI: "490154203237518", ECGI: []byte{0x00, 0xf1, 0x10, 0x00, 0x12, 0x34, 0x56}, LocationEstimate: []byte{0, 0, 0, 0, 0x80, 0, 0}})
	if err != nil {
		t.Fatal(err)
	}
	if lrr.Header.CommandCode != CommandLocationReport || lrr.Header.CommandFlags&diam.RequestFlag == 0 || lrr.Header.CommandFlags&diam.ProxiableFlag == 0 {
		t.Fatalf("LRR header = %+v", lrr.Header)
	}
	if estimate := allAVPs(lrr, avp.LocationEstimate, 0); len(estimate) != 1 {
		t.Fatal("LRR missing Location-Estimate")
	}
	if decoded, protocolErr := DecodeLRR(lrr); protocolErr != nil || decoded.DestinationHost != "gmlc.example" || decoded.IMSI != "001010123456789" || decoded.IMEI != "490154203237518" || string(decoded.ECGI) != string([]byte{0x00, 0xf1, 0x10, 0x00, 0x12, 0x34, 0x56}) {
		t.Fatalf("DecodeLRR = %+v, %v", decoded, protocolErr)
	}
	lra, err := BuildLRA(lrr, "gmlc.example", "example", diam.Success, 0)
	if err != nil {
		t.Fatal(err)
	}
	result, experimental, err := DecodeLRA(lra)
	if err != nil || result != diam.Success || experimental != 0 {
		t.Fatalf("DecodeLRA = %d/%d, %v", result, experimental, err)
	}
}

func TestLRRRejectsMalformedOptionalLocationData(t *testing.T) {
	lrr, err := BuildLRR(LocationReportRequest{SessionID: "slg;optional", OriginHost: "mme.example", OriginRealm: "example", DestinationHost: "gmlc.example", DestinationRealm: "example", LocationEvent: 0})
	if err != nil {
		t.Fatal(err)
	}
	lrr.NewAVP(AVPECGI, avp.Vbit|avp.Mbit, VendorID, datatype.OctetString([]byte{1, 2, 3}))
	if _, protocolErr := DecodeLRR(lrr); protocolErr == nil || protocolErr.ResultCode != diam.InvalidAVPValue {
		t.Fatalf("malformed ECGI error = %#v", protocolErr)
	}
}

func TestLRRRejectsInvalidLocationEvent(t *testing.T) {
	if _, err := BuildLRR(LocationReportRequest{SessionID: "s", OriginHost: "mme.example", OriginRealm: "example", DestinationHost: "gmlc.example", DestinationRealm: "example", LocationEvent: 7}); err == nil {
		t.Fatal("invalid Location-Event must be rejected")
	}
}

func TestLRARejectsNon3GPPExperimentalResult(t *testing.T) {
	lrr, err := BuildLRR(LocationReportRequest{SessionID: "slg;experimental", OriginHost: "mme.example", OriginRealm: "example", DestinationHost: "gmlc.example", DestinationRealm: "example", LocationEvent: 0})
	if err != nil {
		t.Fatal(err)
	}
	lra, err := BuildLRA(lrr, "gmlc.example", "example", 0, ExperimentalPositioningFailed)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range lra.AVP {
		if a.Code != avp.ExperimentalResult {
			continue
		}
		group := a.Data.(*diam.GroupedAVP)
		for _, child := range group.AVP {
			if child.Code == avp.VendorID {
				child.Data = datatype.Unsigned32(999)
			}
		}
	}
	if _, _, err := DecodeLRA(lra); err == nil {
		t.Fatal("non-3GPP Experimental-Result must be rejected")
	}
}
