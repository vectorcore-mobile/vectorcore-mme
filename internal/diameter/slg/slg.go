// Package slg implements the TS 29.172 Release 16 SLg Diameter wire codec.
// It contains no peer, routing, UE, paging, privacy, or positioning policy.
package slg

import (
	"fmt"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/fiorix/go-diameter/v4/diam/avp"
	"github.com/fiorix/go-diameter/v4/diam/datatype"
	"github.com/fiorix/go-diameter/v4/diam/dict"
)

const (
	ApplicationID uint32 = 16777255
	VendorID      uint32 = 10415

	CommandProvideLocation uint32 = 8388620 // PLR / PLA
	CommandLocationReport  uint32 = 8388621 // LRR / LRA

	AVPSLgLocationType              uint32 = 2500
	AVPLCSEPSClientName             uint32 = 2501
	AVPECGI                         uint32 = 2517
	AVPLocationEvent                uint32 = 2518
	AVPMSISDN                       uint32 = 701
	AVPIMEI                         uint32 = 1402
	AVPDeferredLocationType         uint32 = 2532
	AVPPeriodicLDRInformation       uint32 = 2540
	AVPReportingAmount              uint32 = 2541
	AVPReportingInterval            uint32 = 2542
	DeferredLocationTypePeriodicLDR uint32 = 1 << 4
	maxPeriodicReportingSpan        uint32 = 8639999

	// TS 29.172, clause 7.2.1. Only an explicit, supported value can be
	// processed by the location service; unknown enumerations are rejected.
	LocationTypeCurrent                      uint32 = 0
	LocationTypeCurrentOrLastKnown           uint32 = 1
	LocationTypeInitial                      uint32 = 2
	LocationTypeActivateDeferred             uint32 = 3
	LocationTypeCancelDeferred               uint32 = 4
	LocationTypeNotificationVerificationOnly uint32 = 5

	ExperimentalUserUnknown       uint32 = 5001
	ExperimentalUnreachableUser   uint32 = 4221
	ExperimentalSuspendedUser     uint32 = 4222
	ExperimentalDetachedUser      uint32 = 4223
	ExperimentalPositioningDenied uint32 = 4224
	ExperimentalPositioningFailed uint32 = 4225

	LocationEventEmergencyCallOrigination uint32 = 0
	LocationEventEmergencyCallRelease     uint32 = 1
	LocationEventMOLR                     uint32 = 2
	LocationEventEmergencyCallHandover    uint32 = 3
	LocationEventDeferredMTLRResponse     uint32 = 4
	LocationEventDeferredMOLRTTTP         uint32 = 5
	LocationEventDelayedLocationReporting uint32 = 6
)

// ProvideLocationRequest is the protocol-independent subset that the MME can
// currently validate and pass to a location service. SubscriberID is an IMSI
// carried in User-Name; other TS 29.172 identity forms are parsed separately
// by future indexed lookup support and are never resolved by context scans.
type ProvideLocationRequest struct {
	SessionID        string
	OriginHost       string
	OriginRealm      string
	DestinationHost  string
	DestinationRealm string
	SubscriberID     string
	SubscriberIDType SubscriberIdentityType
	// TS 29.172 permits User-Name, MSISDN, and IMEI to be supplied together.
	// Keep each form so the local indexed subscriber context can verify that
	// they identify the same UE; do not discard alternatives while decoding.
	IMSI                 string
	MSISDN               []byte
	IMEI                 string
	LocationType         uint32
	LCSClientType        uint32
	DeferredLocationType uint32
	PeriodicLDR          *PeriodicLDRInfo
}

// PeriodicLDRInfo is a decoded, validated Release-16 periodic policy. Values
// remain in seconds at the Diameter boundary; domain code converts once when a
// scheduler is introduced.
type PeriodicLDRInfo struct{ ReportingAmount, ReportingIntervalSeconds uint32 }

type SubscriberIdentityType string

const (
	SubscriberIdentityIMSI   SubscriberIdentityType = "imsi"
	SubscriberIdentityMSISDN SubscriberIdentityType = "msisdn"
	SubscriberIdentityIMEI   SubscriberIdentityType = "imei"
)

// LocationReportRequest is the protocol-independent subset of an LRR that the
// MME can truthfully produce: routing, an event, target identities, and a
// confirmed ECGI. It deliberately has no coordinate or accuracy fields.
type LocationReportRequest struct {
	SessionID        string
	OriginHost       string
	OriginRealm      string
	DestinationHost  string
	DestinationRealm string
	LocationEvent    uint32
	IMSI             string
	MSISDN           []byte
	IMEI             string
	ECGI             []byte
	LocationEstimate []byte
}

// LocationReportAnswer is the typed LRA result used to bind an answer to the
// GMLC identity selected for the corresponding LRR.
type LocationReportAnswer struct {
	SessionID        string
	OriginHost       string
	OriginRealm      string
	ResultCode       uint32
	ExperimentalCode uint32
}

// ProtocolError identifies a malformed Diameter/SLg request. Base Diameter
// errors carry Result-Code; TS 29.172 procedure errors use Experimental-Result.
type ProtocolError struct {
	ResultCode       uint32
	ExperimentalCode uint32
	FailedAVP        *diam.AVP
	Reason           string
}

func (e *ProtocolError) Error() string { return "slg: " + e.Reason }

func baseError(code uint32, reason string, failed *diam.AVP) *ProtocolError {
	return &ProtocolError{ResultCode: code, FailedAVP: failed, Reason: reason}
}

// DecodePLR validates the mandatory TS 29.172 PLR envelope and the bounded
// fields needed before local subscriber lookup. It deliberately does not
// infer location semantics from stale MME state.
func DecodePLR(m *diam.Message) (*ProvideLocationRequest, *ProtocolError) {
	if m == nil || m.Header.ApplicationID != ApplicationID || m.Header.CommandCode != CommandProvideLocation || m.Header.CommandFlags&diam.RequestFlag == 0 || m.Header.CommandFlags&diam.ProxiableFlag == 0 {
		return nil, baseError(diam.InvalidAVPValue, "invalid PLR header or command flags", nil)
	}
	get := func(code, vendor uint32, name string) (*diam.AVP, *ProtocolError) {
		values := allAVPs(m, code, vendor)
		if len(values) == 0 {
			for _, candidate := range m.AVP {
				if candidate.Code == code && candidate.VendorID != vendor {
					return nil, baseError(diam.InvalidAVPValue, "invalid vendor for "+name, candidate)
				}
			}
			return nil, baseError(diam.MissingAVP, "missing "+name, nil)
		}
		if len(values) != 1 {
			return nil, baseError(diam.InvalidAVPValue, "duplicate "+name, values[1])
		}
		return values[0], nil
	}
	sid, e := get(avp.SessionID, 0, "Session-Id")
	if e != nil {
		return nil, e
	}
	auth, e := get(avp.AuthSessionState, 0, "Auth-Session-State")
	if e != nil {
		return nil, e
	}
	oh, e := get(avp.OriginHost, 0, "Origin-Host")
	if e != nil {
		return nil, e
	}
	or, e := get(avp.OriginRealm, 0, "Origin-Realm")
	if e != nil {
		return nil, e
	}
	dh, e := get(avp.DestinationHost, 0, "Destination-Host")
	if e != nil {
		return nil, e
	}
	dr, e := get(avp.DestinationRealm, 0, "Destination-Realm")
	if e != nil {
		return nil, e
	}
	lt, e := get(AVPSLgLocationType, VendorID, "SLg-Location-Type")
	if e != nil {
		return nil, e
	}
	clientName, e := get(AVPLCSEPSClientName, VendorID, "LCS-EPS-Client-Name")
	if e != nil {
		return nil, e
	}
	clientType, e := get(avp.LCSClientType, 0, "LCS-Client-Type")
	if e != nil {
		return nil, e
	}
	userNames := allAVPs(m, avp.UserName, 0)
	msisdns := allAVPs(m, AVPMSISDN, VendorID)
	imeis := allAVPs(m, AVPIMEI, VendorID)
	if len(userNames)+len(msisdns)+len(imeis) == 0 {
		return nil, baseError(diam.MissingAVP, "missing target subscriber identity", nil)
	}
	for _, identity := range []struct {
		name   string
		values []*diam.AVP
	}{
		{name: "User-Name", values: userNames},
		{name: "MSISDN", values: msisdns},
		{name: "IMEI", values: imeis},
	} {
		name, values := identity.name, identity.values
		if len(values) > 1 {
			return nil, baseError(diam.InvalidAVPValue, "duplicate "+name, values[1])
		}
	}

	if v, ok := auth.Data.(datatype.Enumerated); !ok || uint32(v) != 1 {
		return nil, baseError(diam.InvalidAVPValue, "Auth-Session-State must be NO_STATE_MAINTAINED", auth)
	}
	if _, ok := clientName.Data.(*diam.GroupedAVP); !ok {
		return nil, baseError(diam.InvalidAVPValue, "invalid LCS-EPS-Client-Name", clientName)
	}
	locationType, ok := lt.Data.(datatype.Enumerated)
	if !ok || uint32(locationType) > LocationTypeNotificationVerificationOnly {
		return nil, baseError(diam.InvalidAVPValue, "invalid SLg-Location-Type", lt)
	}
	ct, ok := clientType.Data.(datatype.Enumerated)
	if !ok {
		return nil, baseError(diam.InvalidAVPValue, "invalid LCS-Client-Type", clientType)
	}
	toString := func(a *diam.AVP, name string) (string, *ProtocolError) {
		var value string
		switch v := a.Data.(type) {
		case datatype.UTF8String:
			value = string(v)
		case datatype.DiameterIdentity:
			value = string(v)
		default:
			return "", baseError(diam.InvalidAVPValue, "invalid "+name, a)
		}
		if value == "" {
			return "", baseError(diam.InvalidAVPValue, "invalid "+name, a)
		}
		return value, nil
	}
	request := &ProvideLocationRequest{LocationType: uint32(locationType), LCSClientType: uint32(ct)}
	if request.SessionID, e = toString(sid, "Session-Id"); e != nil {
		return nil, e
	}
	if request.OriginHost, e = toString(oh, "Origin-Host"); e != nil {
		return nil, e
	}
	if request.OriginRealm, e = toString(or, "Origin-Realm"); e != nil {
		return nil, e
	}
	if request.DestinationHost, e = toString(dh, "Destination-Host"); e != nil {
		return nil, e
	}
	if request.DestinationRealm, e = toString(dr, "Destination-Realm"); e != nil {
		return nil, e
	}
	if len(userNames) == 1 {
		if request.IMSI, e = toString(userNames[0], "User-Name"); e != nil {
			return nil, e
		}
		request.SubscriberID, request.SubscriberIDType = request.IMSI, SubscriberIdentityIMSI
	}
	if len(msisdns) == 1 {
		v, ok := msisdns[0].Data.(datatype.OctetString)
		if !ok || len(v) == 0 {
			return nil, baseError(diam.InvalidAVPValue, "invalid MSISDN", msisdns[0])
		}
		request.MSISDN = append([]byte(nil), v...)
		if request.SubscriberID == "" {
			request.SubscriberID, request.SubscriberIDType = string(v), SubscriberIdentityMSISDN
		}
	}
	if len(imeis) == 1 {
		if request.IMEI, e = toString(imeis[0], "IMEI"); e != nil {
			return nil, e
		}
		if request.SubscriberID == "" {
			request.SubscriberID, request.SubscriberIDType = request.IMEI, SubscriberIdentityIMEI
		}
	}
	deferred := allAVPs(m, AVPDeferredLocationType, VendorID)
	periodic := allAVPs(m, AVPPeriodicLDRInformation, VendorID)
	if len(deferred) > 1 || len(periodic) > 1 {
		bad := deferred
		if len(periodic) > 1 {
			bad = periodic
		}
		return nil, baseError(diam.InvalidAVPValue, "duplicate deferred location policy AVP", bad[1])
	}
	for _, a := range m.AVP {
		if (a.Code == AVPDeferredLocationType || a.Code == AVPPeriodicLDRInformation) && a.VendorID != VendorID {
			return nil, baseError(diam.InvalidAVPValue, "invalid vendor for deferred location policy", a)
		}
	}
	if len(deferred) == 1 {
		v, ok := deferred[0].Data.(datatype.Unsigned32)
		if !ok {
			return nil, baseError(diam.InvalidAVPValue, "invalid Deferred-Location-Type", deferred[0])
		}
		request.DeferredLocationType = uint32(v)
	}
	periodicBit := request.DeferredLocationType&DeferredLocationTypePeriodicLDR != 0
	if periodicBit != (len(periodic) == 1) {
		if len(periodic) == 1 {
			return nil, baseError(diam.InvalidAVPValue, "Periodic-LDR-Information without Periodic-LDR bit", periodic[0])
		}
		return nil, baseError(diam.MissingAVP, "Periodic-LDR bit requires Periodic-LDR-Information", deferred[0])
	}
	if len(periodic) == 1 {
		info, e := decodePeriodicLDR(periodic[0])
		if e != nil {
			return nil, e
		}
		request.PeriodicLDR = info
	}
	return request, nil
}

func decodePeriodicLDR(a *diam.AVP) (*PeriodicLDRInfo, *ProtocolError) {
	g, ok := a.Data.(*diam.GroupedAVP)
	if !ok {
		return nil, baseError(diam.InvalidAVPValue, "invalid Periodic-LDR-Information", a)
	}
	var amount, interval *diam.AVP
	for _, child := range g.AVP {
		if child.Code == AVPReportingAmount || child.Code == AVPReportingInterval {
			if child.VendorID != VendorID {
				return nil, baseError(diam.InvalidAVPValue, "invalid vendor in Periodic-LDR-Information", child)
			}
			if child.Code == AVPReportingAmount {
				if amount != nil {
					return nil, baseError(diam.InvalidAVPValue, "duplicate Reporting-Amount", child)
				}
				amount = child
			} else {
				if interval != nil {
					return nil, baseError(diam.InvalidAVPValue, "duplicate Reporting-Interval", child)
				}
				interval = child
			}
		}
	}
	if amount == nil {
		return nil, baseError(diam.MissingAVP, "missing Reporting-Amount", a)
	}
	if interval == nil {
		return nil, baseError(diam.MissingAVP, "missing Reporting-Interval", a)
	}
	amountValue, ok := amount.Data.(datatype.Unsigned32)
	if !ok {
		return nil, baseError(diam.InvalidAVPValue, "invalid Reporting-Amount", amount)
	}
	intervalValue, ok := interval.Data.(datatype.Unsigned32)
	if !ok {
		return nil, baseError(diam.InvalidAVPValue, "invalid Reporting-Interval", interval)
	}
	if uint32(amountValue) == 0 || uint32(amountValue) > maxPeriodicReportingSpan {
		return nil, baseError(diam.InvalidAVPValue, "Reporting-Amount out of range", amount)
	}
	if uint32(intervalValue) == 0 || uint32(intervalValue) > maxPeriodicReportingSpan {
		return nil, baseError(diam.InvalidAVPValue, "Reporting-Interval out of range", interval)
	}
	if uint64(amountValue)*uint64(intervalValue) > uint64(maxPeriodicReportingSpan) {
		return nil, baseError(diam.InvalidAVPValue, "periodic reporting span exceeds maximum", a)
	}
	return &PeriodicLDRInfo{ReportingAmount: uint32(amountValue), ReportingIntervalSeconds: uint32(intervalValue)}, nil
}

// BuildPLA produces an answer preserving the request Hop-by-Hop and End-to-End
// identifiers. Exactly one of Result-Code and Experimental-Result is emitted.
func BuildPLA(request *diam.Message, originHost, originRealm string, resultCode, experimentalCode uint32, failed *diam.AVP) (*diam.Message, error) {
	return BuildPLAWithECGI(request, originHost, originRealm, resultCode, experimentalCode, failed, nil)
}

// BuildPLAWithECGI optionally adds the TS 29.172 ECGI AVP. The value is the
// seven-octet ECGI wire coding from TS 29.274 §8.21.5, not a coordinate or
// Location-Estimate. It is legal only on a successful answer.
func BuildPLAWithECGI(request *diam.Message, originHost, originRealm string, resultCode, experimentalCode uint32, failed *diam.AVP, ecgi []byte) (*diam.Message, error) {
	return BuildPLAWithLocation(request, originHost, originRealm, resultCode, experimentalCode, failed, ecgi, nil)
}

// BuildPLAWithLocation adds only provider-confirmed location output. The MME
// treats Location-Estimate as opaque GAD data and never synthesizes it.
func BuildPLAWithLocation(request *diam.Message, originHost, originRealm string, resultCode, experimentalCode uint32, failed *diam.AVP, ecgi, locationEstimate []byte) (*diam.Message, error) {
	if request == nil || originHost == "" || originRealm == "" {
		return nil, fmt.Errorf("slg: missing PLA request or origin identity")
	}
	if resultCode == 0 && experimentalCode == 0 {
		resultCode = diam.Success
	}
	if resultCode != 0 && experimentalCode != 0 {
		return nil, fmt.Errorf("slg: PLA cannot contain Result-Code and Experimental-Result")
	}
	if len(ecgi) != 0 && (resultCode != diam.Success || experimentalCode != 0 || len(ecgi) != 7) {
		return nil, fmt.Errorf("slg: ECGI requires successful PLA and seven octets")
	}
	if len(locationEstimate) != 0 && (resultCode != diam.Success || experimentalCode != 0) {
		return nil, fmt.Errorf("slg: Location-Estimate requires successful PLA")
	}
	answer := request.Answer(0)
	// Session-Id is mandatory in every answer and must be copied exactly from
	// the request rather than regenerated.
	if session := allAVPs(request, avp.SessionID, 0); len(session) == 1 {
		answer.NewAVP(avp.SessionID, avp.Mbit, 0, session[0].Data)
	}
	if experimentalCode != 0 {
		answer.NewAVP(avp.ExperimentalResult, avp.Mbit, 0, &diam.GroupedAVP{AVP: []*diam.AVP{
			diam.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(VendorID)),
			diam.NewAVP(avp.ExperimentalResultCode, avp.Mbit, 0, datatype.Unsigned32(experimentalCode)),
		}})
	} else {
		answer.NewAVP(avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(resultCode))
	}
	answer.NewAVP(avp.AuthSessionState, avp.Mbit, 0, datatype.Enumerated(1))
	answer.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity(originHost))
	answer.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity(originRealm))
	// A proxy uses Proxy-Info to retain the return path.  Echo every instance
	// from the request, as required for an answer travelling back through it.
	for _, proxy := range allAVPs(request, avp.ProxyInfo, 0) {
		answer.NewAVP(avp.ProxyInfo, proxy.Flags, proxy.VendorID, proxy.Data)
	}
	if len(ecgi) != 0 {
		answer.NewAVP(AVPECGI, avp.Vbit|avp.Mbit, VendorID, datatype.OctetString(append([]byte(nil), ecgi...)))
	}
	if len(locationEstimate) != 0 {
		answer.NewAVP(avp.LocationEstimate, avp.Mbit, 0, datatype.OctetString(append([]byte(nil), locationEstimate...)))
	}
	if failed != nil {
		answer.NewAVP(avp.FailedAVP, avp.Mbit, 0, &diam.GroupedAVP{AVP: []*diam.AVP{failed}})
	}
	return answer, nil
}

// BuildPLR is used by the standalone test peer and codec tests. It emits the
// minimal mandatory Release 16 PLR AVPs and always uses NO_STATE_MAINTAINED.
func BuildPLR(req ProvideLocationRequest) (*diam.Message, error) {
	if req.SessionID == "" || req.OriginHost == "" || req.OriginRealm == "" || req.DestinationHost == "" || req.DestinationRealm == "" || req.SubscriberID == "" {
		return nil, fmt.Errorf("slg: missing mandatory PLR routing or subscriber field")
	}
	if req.LocationType > LocationTypeNotificationVerificationOnly {
		return nil, fmt.Errorf("slg: invalid location type")
	}
	m := diam.NewRequest(CommandProvideLocation, ApplicationID, dict.Default)
	m.Header.CommandFlags |= diam.ProxiableFlag
	m.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String(req.SessionID))
	m.NewAVP(avp.AuthSessionState, avp.Mbit, 0, datatype.Enumerated(1))
	m.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity(req.OriginHost))
	m.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity(req.OriginRealm))
	m.NewAVP(avp.DestinationHost, avp.Mbit, 0, datatype.DiameterIdentity(req.DestinationHost))
	m.NewAVP(avp.DestinationRealm, avp.Mbit, 0, datatype.DiameterIdentity(req.DestinationRealm))
	m.NewAVP(AVPSLgLocationType, avp.Vbit|avp.Mbit, VendorID, datatype.Enumerated(req.LocationType))
	m.NewAVP(AVPLCSEPSClientName, avp.Vbit|avp.Mbit, VendorID, &diam.GroupedAVP{})
	m.NewAVP(avp.LCSClientType, avp.Mbit, 0, datatype.Enumerated(req.LCSClientType))
	if req.DeferredLocationType != 0 {
		m.NewAVP(AVPDeferredLocationType, avp.Vbit|avp.Mbit, VendorID, datatype.Unsigned32(req.DeferredLocationType))
	}
	if req.PeriodicLDR != nil {
		m.NewAVP(AVPPeriodicLDRInformation, avp.Vbit|avp.Mbit, VendorID, &diam.GroupedAVP{AVP: []*diam.AVP{
			diam.NewAVP(AVPReportingAmount, avp.Vbit|avp.Mbit, VendorID, datatype.Unsigned32(req.PeriodicLDR.ReportingAmount)),
			diam.NewAVP(AVPReportingInterval, avp.Vbit|avp.Mbit, VendorID, datatype.Unsigned32(req.PeriodicLDR.ReportingIntervalSeconds)),
		}})
	}
	m.NewAVP(avp.UserName, avp.Mbit, 0, datatype.UTF8String(req.SubscriberID))
	return m, nil
}

// BuildLRR encodes the common LRR envelope used by codec interoperation tests.
// A caller must add the remaining procedure-specific TS 29.172 AVPs before an
// LRR is ever enabled for runtime transmission.
func BuildLRR(req LocationReportRequest) (*diam.Message, error) {
	if req.SessionID == "" || req.OriginHost == "" || req.OriginRealm == "" || req.DestinationHost == "" || req.DestinationRealm == "" {
		return nil, fmt.Errorf("slg: missing mandatory LRR routing field")
	}
	if req.LocationEvent > LocationEventDelayedLocationReporting {
		return nil, fmt.Errorf("slg: invalid Location-Event")
	}
	if len(req.ECGI) != 0 && len(req.ECGI) != 7 {
		return nil, fmt.Errorf("slg: ECGI must contain seven octets")
	}
	if len(req.LocationEstimate) != 0 && len(req.LocationEstimate) != 7 {
		return nil, fmt.Errorf("slg: LRR Location-Estimate must contain supported seven-octet Ellipsoid Point")
	}
	m := diam.NewRequest(CommandLocationReport, ApplicationID, dict.Default)
	m.Header.CommandFlags |= diam.ProxiableFlag
	m.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String(req.SessionID))
	m.NewAVP(avp.AuthSessionState, avp.Mbit, 0, datatype.Enumerated(1))
	m.NewAVP(avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity(req.OriginHost))
	m.NewAVP(avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity(req.OriginRealm))
	m.NewAVP(avp.DestinationHost, avp.Mbit, 0, datatype.DiameterIdentity(req.DestinationHost))
	m.NewAVP(avp.DestinationRealm, avp.Mbit, 0, datatype.DiameterIdentity(req.DestinationRealm))
	m.NewAVP(AVPLocationEvent, avp.Vbit|avp.Mbit, VendorID, datatype.Enumerated(req.LocationEvent))
	if req.IMSI != "" {
		m.NewAVP(avp.UserName, avp.Mbit, 0, datatype.UTF8String(req.IMSI))
	}
	if len(req.MSISDN) != 0 {
		m.NewAVP(AVPMSISDN, avp.Vbit|avp.Mbit, VendorID, datatype.OctetString(append([]byte(nil), req.MSISDN...)))
	}
	if req.IMEI != "" {
		m.NewAVP(AVPIMEI, avp.Vbit|avp.Mbit, VendorID, datatype.UTF8String(req.IMEI))
	}
	if len(req.ECGI) != 0 {
		m.NewAVP(AVPECGI, avp.Vbit|avp.Mbit, VendorID, datatype.OctetString(append([]byte(nil), req.ECGI...)))
	}
	if len(req.LocationEstimate) != 0 {
		m.NewAVP(avp.LocationEstimate, avp.Mbit, 0, datatype.OctetString(append([]byte(nil), req.LocationEstimate...)))
	}
	return m, nil
}

// DecodeLRR validates the common mandatory LRR envelope. Runtime handling is
// deliberately not registered until reporting trigger state exists, but this
// permits independent wire interoperability and strict LRA correlation tests.
func DecodeLRR(m *diam.Message) (*LocationReportRequest, *ProtocolError) {
	if m == nil || m.Header.ApplicationID != ApplicationID || m.Header.CommandCode != CommandLocationReport || m.Header.CommandFlags&diam.RequestFlag == 0 || m.Header.CommandFlags&diam.ProxiableFlag == 0 {
		return nil, baseError(diam.InvalidAVPValue, "invalid LRR header or command flags", nil)
	}
	get := func(code, vendor uint32, name string) (*diam.AVP, *ProtocolError) {
		values := allAVPs(m, code, vendor)
		if len(values) == 0 {
			for _, candidate := range m.AVP {
				if candidate.Code == code && candidate.VendorID != vendor {
					return nil, baseError(diam.InvalidAVPValue, "invalid vendor for "+name, candidate)
				}
			}
			return nil, baseError(diam.MissingAVP, "missing "+name, nil)
		}
		if len(values) != 1 {
			return nil, baseError(diam.InvalidAVPValue, "duplicate "+name, values[1])
		}
		return values[0], nil
	}
	sid, e := get(avp.SessionID, 0, "Session-Id")
	if e != nil {
		return nil, e
	}
	auth, e := get(avp.AuthSessionState, 0, "Auth-Session-State")
	if e != nil {
		return nil, e
	}
	oh, e := get(avp.OriginHost, 0, "Origin-Host")
	if e != nil {
		return nil, e
	}
	or, e := get(avp.OriginRealm, 0, "Origin-Realm")
	if e != nil {
		return nil, e
	}
	dh, e := get(avp.DestinationHost, 0, "Destination-Host")
	if e != nil {
		return nil, e
	}
	dr, e := get(avp.DestinationRealm, 0, "Destination-Realm")
	if e != nil {
		return nil, e
	}
	event, e := get(AVPLocationEvent, VendorID, "Location-Event")
	if e != nil {
		return nil, e
	}
	if v, ok := auth.Data.(datatype.Enumerated); !ok || uint32(v) != 1 {
		return nil, baseError(diam.InvalidAVPValue, "Auth-Session-State must be NO_STATE_MAINTAINED", auth)
	}
	toIdentity := func(a *diam.AVP, name string) (string, *ProtocolError) {
		v, ok := a.Data.(datatype.DiameterIdentity)
		if !ok || string(v) == "" {
			return "", baseError(diam.InvalidAVPValue, "invalid "+name, a)
		}
		return string(v), nil
	}
	toSession := func(a *diam.AVP) (string, *ProtocolError) {
		v, ok := a.Data.(datatype.UTF8String)
		if !ok || string(v) == "" {
			return "", baseError(diam.InvalidAVPValue, "invalid Session-Id", a)
		}
		return string(v), nil
	}
	v, ok := event.Data.(datatype.Enumerated)
	if !ok || uint32(v) > LocationEventDelayedLocationReporting {
		return nil, baseError(diam.InvalidAVPValue, "invalid Location-Event", event)
	}
	out := &LocationReportRequest{LocationEvent: uint32(v)}
	if out.SessionID, e = toSession(sid); e != nil {
		return nil, e
	}
	if out.OriginHost, e = toIdentity(oh, "Origin-Host"); e != nil {
		return nil, e
	}
	if out.OriginRealm, e = toIdentity(or, "Origin-Realm"); e != nil {
		return nil, e
	}
	if out.DestinationHost, e = toIdentity(dh, "Destination-Host"); e != nil {
		return nil, e
	}
	if out.DestinationRealm, e = toIdentity(dr, "Destination-Realm"); e != nil {
		return nil, e
	}
	decodeOptionalString := func(code, vendor uint32, name string) (string, *ProtocolError) {
		values := allAVPs(m, code, vendor)
		if len(values) > 1 {
			return "", baseError(diam.InvalidAVPValue, "duplicate "+name, values[1])
		}
		if len(values) == 0 {
			return "", nil
		}
		return toSession(values[0])
	}
	if out.IMSI, e = decodeOptionalString(avp.UserName, 0, "User-Name"); e != nil {
		return nil, e
	}
	if out.IMEI, e = decodeOptionalString(AVPIMEI, VendorID, "IMEI"); e != nil {
		return nil, e
	}
	if values := allAVPs(m, AVPMSISDN, VendorID); len(values) > 1 {
		return nil, baseError(diam.InvalidAVPValue, "duplicate MSISDN", values[1])
	} else if len(values) == 1 {
		value, ok := values[0].Data.(datatype.OctetString)
		if !ok || len(value) == 0 {
			return nil, baseError(diam.InvalidAVPValue, "invalid MSISDN", values[0])
		}
		out.MSISDN = append([]byte(nil), value...)
	}
	if values := allAVPs(m, AVPECGI, VendorID); len(values) > 1 {
		return nil, baseError(diam.InvalidAVPValue, "duplicate ECGI", values[1])
	} else if len(values) == 1 {
		value, ok := values[0].Data.(datatype.OctetString)
		if !ok || len(value) != 7 {
			return nil, baseError(diam.InvalidAVPValue, "invalid ECGI", values[0])
		}
		out.ECGI = append([]byte(nil), value...)
	}
	return out, nil
}

// DecodeLRA validates an LRA's header, result form and mandatory base AVPs.
func DecodeLRA(m *diam.Message) (uint32, uint32, error) {
	answer, err := DecodeLocationReportAnswer(m)
	if err != nil {
		return 0, 0, err
	}
	return answer.ResultCode, answer.ExperimentalCode, nil
}

// DecodeLocationReportAnswer validates an LRA and preserves its sender
// identity for transaction correlation. DecodeLRA remains as a compact
// compatibility helper for callers interested only in the result form.
func DecodeLocationReportAnswer(m *diam.Message) (*LocationReportAnswer, error) {
	if m == nil || m.Header.ApplicationID != ApplicationID || m.Header.CommandCode != CommandLocationReport || m.Header.CommandFlags&diam.RequestFlag != 0 || m.Header.CommandFlags&diam.ProxiableFlag == 0 {
		return nil, fmt.Errorf("slg: invalid LRA header or command flags")
	}
	if len(allAVPs(m, avp.SessionID, 0)) != 1 || len(allAVPs(m, avp.AuthSessionState, 0)) != 1 || len(allAVPs(m, avp.OriginHost, 0)) != 1 || len(allAVPs(m, avp.OriginRealm, 0)) != 1 {
		return nil, fmt.Errorf("slg: LRA missing or duplicate mandatory base AVP")
	}
	if state, ok := allAVPs(m, avp.AuthSessionState, 0)[0].Data.(datatype.Enumerated); !ok || uint32(state) != 1 {
		return nil, fmt.Errorf("slg: invalid LRA Auth-Session-State")
	}
	answer := &LocationReportAnswer{}
	session, ok := allAVPs(m, avp.SessionID, 0)[0].Data.(datatype.UTF8String)
	if !ok || string(session) == "" {
		return nil, fmt.Errorf("slg: invalid LRA Session-Id")
	}
	answer.SessionID = string(session)
	for _, item := range []struct {
		code uint32
		name string
		dest *string
	}{{avp.OriginHost, "Origin-Host", &answer.OriginHost}, {avp.OriginRealm, "Origin-Realm", &answer.OriginRealm}} {
		value, ok := allAVPs(m, item.code, 0)[0].Data.(datatype.DiameterIdentity)
		if !ok || string(value) == "" {
			return nil, fmt.Errorf("slg: invalid LRA %s", item.name)
		}
		*item.dest = string(value)
	}
	results := allAVPs(m, avp.ResultCode, 0)
	experimental := allAVPs(m, avp.ExperimentalResult, 0)
	if len(results)+len(experimental) != 1 {
		return nil, fmt.Errorf("slg: LRA requires exactly one result form")
	}
	if len(results) == 1 {
		v, ok := results[0].Data.(datatype.Unsigned32)
		if !ok {
			return nil, fmt.Errorf("slg: invalid LRA Result-Code")
		}
		answer.ResultCode = uint32(v)
		return answer, nil
	}
	g, ok := experimental[0].Data.(*diam.GroupedAVP)
	if !ok {
		return nil, fmt.Errorf("slg: invalid LRA Experimental-Result")
	}
	var vendorID uint32
	var vendorSeen bool
	var experimentalCode uint32
	var experimentalSeen bool
	for _, a := range g.AVP {
		switch {
		case a.Code == avp.VendorID && a.VendorID == 0:
			if vendorSeen {
				return nil, fmt.Errorf("slg: duplicate LRA Experimental-Result Vendor-Id")
			}
			v, ok := a.Data.(datatype.Unsigned32)
			if !ok {
				return nil, fmt.Errorf("slg: invalid LRA Experimental-Result Vendor-Id")
			}
			vendorID, vendorSeen = uint32(v), true
		case a.Code == avp.ExperimentalResultCode && a.VendorID == 0:
			if experimentalSeen {
				return nil, fmt.Errorf("slg: duplicate LRA Experimental-Result-Code")
			}
			v, ok := a.Data.(datatype.Unsigned32)
			if !ok {
				return nil, fmt.Errorf("slg: invalid LRA Experimental-Result-Code")
			}
			experimentalCode, experimentalSeen = uint32(v), true
		}
	}
	if !vendorSeen || vendorID != VendorID {
		return nil, fmt.Errorf("slg: LRA Experimental-Result must identify 3GPP vendor %d", VendorID)
	}
	if !experimentalSeen {
		return nil, fmt.Errorf("slg: LRA missing Experimental-Result-Code")
	}
	answer.ExperimentalCode = experimentalCode
	return answer, nil
}

// BuildLRA forms a correlated LRA for test-peer interoperability. It shares
// PLA's TS 29.172 result representation.
func BuildLRA(request *diam.Message, originHost, originRealm string, resultCode, experimentalCode uint32) (*diam.Message, error) {
	if request == nil || request.Header.CommandCode != CommandLocationReport {
		return nil, fmt.Errorf("slg: invalid LRR for LRA")
	}
	return BuildPLA(request, originHost, originRealm, resultCode, experimentalCode, nil)
}

func allAVPs(m *diam.Message, code, vendor uint32) []*diam.AVP {
	var out []*diam.AVP
	for _, a := range m.AVP {
		if a.Code == code && a.VendorID == vendor {
			out = append(out, a)
		}
	}
	return out
}
