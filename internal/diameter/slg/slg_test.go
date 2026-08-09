package slg

import (
	"bytes"
	"testing"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/fiorix/go-diameter/v4/diam/avp"
	"github.com/fiorix/go-diameter/v4/diam/datatype"
	"github.com/fiorix/go-diameter/v4/diam/dict"
)

// wireRoundTrip serializes m to raw bytes and re-parses them through
// dict.Default, exercising the same dictionary-driven AVP-type resolution a
// real inbound PLR goes through on the wire. BuildPLR's in-memory
// *diam.GroupedAVP values bypass this entirely, so a decode test that only
// ever calls DecodePLR(BuildPLR(...)) cannot catch a missing dictionary
// entry — the actual production failure mode for a Grouped AVP.
func wireRoundTrip(t *testing.T, m *diam.Message) *diam.Message {
	t.Helper()
	var buf bytes.Buffer
	if _, err := m.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	out, err := diam.ReadMessage(&buf, dict.Default)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

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

func TestPLABuildsEUTRANPositioningDataAndAccuracyIndicator(t *testing.T) {
	m := validPLR(t)
	positioningData := []byte{0xAA, 0xBB}
	answer, err := BuildPLAWithLocation(m, "mme.example", "example", diam.Success, 0, nil, nil, []byte{1, 2, 3, 4, 5, 6, 7}, PLAExtras{
		PositioningData:             positioningData,
		AccuracyFulfilmentIndicator: 1,
		AccuracyFulfilmentPresent:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	pd := allAVPs(answer, AVPEUTRANPositioningData, VendorID)
	if len(pd) != 1 {
		t.Fatalf("EUTRAN-Positioning-Data AVP count = %d", len(pd))
	}
	if got, ok := pd[0].Data.(datatype.OctetString); !ok || string(got) != string(positioningData) {
		t.Fatalf("EUTRAN-Positioning-Data = %v", pd[0].Data)
	}
	afi := allAVPs(answer, AVPAccuracyFulfilmentIndicator, VendorID)
	if len(afi) != 1 {
		t.Fatalf("Accuracy-Fulfilment-Indicator AVP count = %d", len(afi))
	}
	if got, ok := afi[0].Data.(datatype.Enumerated); !ok || uint32(got) != 1 {
		t.Fatalf("Accuracy-Fulfilment-Indicator = %v", afi[0].Data)
	}
	// Extras are rejected on a non-successful answer.
	if _, err := BuildPLAWithLocation(m, "mme.example", "example", 0, ExperimentalPositioningFailed, nil, nil, nil, PLAExtras{AccuracyFulfilmentPresent: true}); err == nil {
		t.Fatal("expected error for extras on unsuccessful PLA")
	}
}

func TestPLRDecodesPrivacyCheck(t *testing.T) {
	req := ProvideLocationRequest{SessionID: "slg;2", OriginHost: "gmlc.example", OriginRealm: "example", DestinationHost: "mme.example", DestinationRealm: "example", SubscriberID: "311435123456789", LocationType: LocationTypeCurrent, LCSClientType: LCSClientTypeValueAddedServices}
	v := LCSPrivacyCheckAllowedWithNotification
	req.PrivacyCheck = &v
	m, err := BuildPLR(req)
	if err != nil {
		t.Fatal(err)
	}
	m = wireRoundTrip(t, m)
	decoded, protocolErr := DecodePLR(m)
	if protocolErr != nil {
		t.Fatal(protocolErr)
	}
	if decoded.PrivacyCheck == nil || *decoded.PrivacyCheck != LCSPrivacyCheckAllowedWithNotification {
		t.Fatalf("PrivacyCheck = %v", decoded.PrivacyCheck)
	}
}

func TestPLRPrivacyCheckAbsentByDefault(t *testing.T) {
	m := validPLR(t)
	req, protocolErr := DecodePLR(m)
	if protocolErr != nil {
		t.Fatal(protocolErr)
	}
	if req.PrivacyCheck != nil {
		t.Fatalf("PrivacyCheck = %v, want nil", req.PrivacyCheck)
	}
}

func TestPLRRejectsPrivacyCheckSessionAndNonSessionBothPresent(t *testing.T) {
	m := validPLR(t)
	grouped := func() *diam.GroupedAVP {
		return &diam.GroupedAVP{AVP: []*diam.AVP{diam.NewAVP(AVPLCSPrivacyCheck, avp.Vbit|avp.Mbit, VendorID, datatype.Enumerated(0))}}
	}
	m.NewAVP(AVPLCSPrivacyCheckSession, avp.Vbit|avp.Mbit, VendorID, grouped())
	m.NewAVP(AVPLCSPrivacyCheckNonSession, avp.Vbit|avp.Mbit, VendorID, grouped())
	m = wireRoundTrip(t, m)
	_, protocolErr := DecodePLR(m)
	if protocolErr == nil {
		t.Fatal("expected error for both Session and Non-Session LCS-Privacy-Check present")
	}
	if protocolErr.Reason != "LCS-Privacy-Check-Session and -Non-Session both present" {
		t.Fatalf("reason = %q, want the specific both-present reason (not masked by a dictionary/decode error)", protocolErr.Reason)
	}
}

func TestPLRRejectsInvalidPrivacyCheckValue(t *testing.T) {
	m := validPLR(t)
	m.NewAVP(AVPLCSPrivacyCheckNonSession, avp.Vbit|avp.Mbit, VendorID, &diam.GroupedAVP{AVP: []*diam.AVP{
		diam.NewAVP(AVPLCSPrivacyCheck, avp.Vbit|avp.Mbit, VendorID, datatype.Enumerated(5)),
	}})
	m = wireRoundTrip(t, m)
	_, protocolErr := DecodePLR(m)
	if protocolErr == nil {
		t.Fatal("expected error for out-of-range LCS-Privacy-Check value")
	}
	if protocolErr.Reason != "invalid LCS-Privacy-Check" {
		t.Fatalf("reason = %q, want the specific invalid-value reason (not masked by a dictionary/decode error)", protocolErr.Reason)
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
