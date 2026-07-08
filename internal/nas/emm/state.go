package emm

// EMMState represents the UE's EMM (EPS Mobility Management) state on the MME side.
type EMMState uint8

const (
	StateDeregistered            EMMState = iota // EMM-DEREGISTERED
	StateRegisteredInitiated                     // EMM-REGISTERED-INITIATED (attach in progress)
	StateRegistered                              // EMM-REGISTERED
	StateDeregisteredInitiated                   // EMM-DEREGISTERED-INITIATED (detach in progress)
	StateTrackingAreaUpdating                    // EMM-TRACKING-AREA-UPDATING-INITIATED
	StateServiceRequestInitiated                 // EMM-SERVICE-REQUEST-INITIATED
)

func (s EMMState) String() string {
	switch s {
	case StateDeregistered:
		return "EMM-DEREGISTERED"
	case StateRegisteredInitiated:
		return "EMM-REGISTERED-INITIATED"
	case StateRegistered:
		return "EMM-REGISTERED"
	case StateDeregisteredInitiated:
		return "EMM-DEREGISTERED-INITIATED"
	case StateTrackingAreaUpdating:
		return "EMM-TRACKING-AREA-UPDATING-INITIATED"
	case StateServiceRequestInitiated:
		return "EMM-SERVICE-REQUEST-INITIATED"
	default:
		return "UNKNOWN"
	}
}

// ECMState represents the UE's ECM (EPS Connection Management) state.
type ECMState uint8

const (
	ECMIdle      ECMState = iota // UE has no signalling connection
	ECMConnected                 // UE has an active S1AP connection
)

func (s ECMState) String() string {
	switch s {
	case ECMIdle:
		return "ECM-IDLE"
	case ECMConnected:
		return "ECM-CONNECTED"
	default:
		return "ECM-UNKNOWN"
	}
}

// SecurityHeaderType values (3GPP TS 24.301 §9.8).
const (
	SecurityHeaderPlain              uint8 = 0x00
	SecurityHeaderIntegrityProtected uint8 = 0x01
	SecurityHeaderIntegrityAndCipher uint8 = 0x02
	SecurityHeaderNewEPSSecurityCtx  uint8 = 0x03 // integrity protected with new EPS security context
	SecurityHeaderCipherNewEPSSecCtx uint8 = 0x04 // integrity protected and ciphered with new EPS security context
	SecurityHeaderServiceRequest     uint8 = 0x0C
)

// MessageType values for EMM messages (3GPP TS 24.301 §D.2).
const (
	MsgAttachRequest               uint8 = 0x41
	MsgAttachAccept                uint8 = 0x42
	MsgAttachComplete              uint8 = 0x43
	MsgAttachReject                uint8 = 0x44
	MsgDetachRequest               uint8 = 0x45
	MsgDetachAccept                uint8 = 0x46
	MsgTrackingAreaUpdateRequest   uint8 = 0x48
	MsgTrackingAreaUpdateAccept    uint8 = 0x49
	MsgTrackingAreaUpdateComplete  uint8 = 0x4A
	MsgTrackingAreaUpdateReject    uint8 = 0x4B
	MsgExtendedServiceRequest      uint8 = 0x4C
	MsgServiceRequest              uint8 = 0x4E
	MsgServiceReject               uint8 = 0x4F
	MsgGUTIReallocationCommand     uint8 = 0x50
	MsgGUTIReallocationComplete    uint8 = 0x51
	MsgAuthenticationRequest       uint8 = 0x52
	MsgAuthenticationResponse      uint8 = 0x53
	MsgAuthenticationReject        uint8 = 0x54
	MsgAuthenticationFailure       uint8 = 0x5C
	MsgIdentityRequest             uint8 = 0x55
	MsgIdentityResponse            uint8 = 0x56
	MsgSecurityModeCommand         uint8 = 0x5D
	MsgSecurityModeComplete        uint8 = 0x5E
	MsgSecurityModeReject          uint8 = 0x5F
	MsgEMMStatus                   uint8 = 0x60
	MsgEMMInformation              uint8 = 0x61
	MsgDownlinkNASTransport        uint8 = 0x62
	MsgUplinkNASTransport          uint8 = 0x63
	MsgCSServiceNotification       uint8 = 0x64
	MsgDownlinkGenericNASTransport uint8 = 0x68
	MsgUplinkGenericNASTransport   uint8 = 0x69
)

// Protocol discriminator values (3GPP TS 24.007 §11.2.3.1.1).
const (
	PDGroupCallControl     uint8 = 0x00
	PDBroadcastCallControl uint8 = 0x01
	PDEPSSessionMgmt       uint8 = 0x02 // ESM
	PDCallControl          uint8 = 0x03
	PDSMS                  uint8 = 0x09
	PDSessNetMgmt          uint8 = 0x0A
	PDNonCallRelated       uint8 = 0x0B
	PDEPSMobilityMgmt      uint8 = 0x07 // EMM
)

// EMM cause values (3GPP TS 24.301 §9.9.3.9).
const (
	CauseIMSIUnknownInHSS                 uint8 = 0x02
	CauseIllegalUE                        uint8 = 0x03
	CauseIMEINotAccepted                  uint8 = 0x05
	CauseIllegalME                        uint8 = 0x06
	CauseEPSServicesNotAllowed            uint8 = 0x07
	CauseUEIdentityCannotBeDerived        uint8 = 0x09
	CauseImplicitlyDetached               uint8 = 0x0A
	CausePLMNNotAllowed                   uint8 = 0x0B
	CauseTrackingAreaNotAllowed           uint8 = 0x0C
	CauseRoamingNotAllowed                uint8 = 0x0D
	CauseEPSServicesNotAllowedInPLMN      uint8 = 0x0E
	CauseNoSuitableCellsInTA              uint8 = 0x0F
	CauseMSCNotReachable                  uint8 = 0x10
	CauseNetworkFailure                   uint8 = 0x11
	CauseCSFallbackCallEstNotAllowed      uint8 = 0x12
	CauseMACFailure                       uint8 = 0x14
	CauseSynchFailure                     uint8 = 0x15
	CauseCongestion                       uint8 = 0x16
	CauseUESecurityCapabMismatch          uint8 = 0x17
	CauseSecurityModeRejectedUnspecified  uint8 = 0x18
	CauseNotAuthorizedForCSG              uint8 = 0x19
	CauseNonEPSAuthenticationUnacceptable uint8 = 0x1A
	CauseCSServiceTemporarilyNotAvailable uint8 = 0x27
	CauseNoEPSBearerContextActivated      uint8 = 0x28
	CauseProtocolError                    uint8 = 0x6F
)
