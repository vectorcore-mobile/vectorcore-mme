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
	MsgServiceRequest              uint8 = 0x4D
	MsgServiceReject               uint8 = 0x4E
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

// IsKnownEMMMessageType reports whether msgType is assigned as an EPS mobility
// management message type that this package recognizes. It is used only as a
// sanity guard after successful security processing; unsupported known messages
// are still dispatched to the EMM state machine for protocol handling/logging.
func IsKnownEMMMessageType(msgType uint8) bool {
	switch msgType {
	case MsgAttachRequest,
		MsgAttachAccept,
		MsgAttachComplete,
		MsgAttachReject,
		MsgDetachRequest,
		MsgDetachAccept,
		MsgTrackingAreaUpdateRequest,
		MsgTrackingAreaUpdateAccept,
		MsgTrackingAreaUpdateComplete,
		MsgTrackingAreaUpdateReject,
		MsgExtendedServiceRequest,
		MsgServiceRequest,
		MsgServiceReject,
		MsgGUTIReallocationCommand,
		MsgGUTIReallocationComplete,
		MsgAuthenticationRequest,
		MsgAuthenticationResponse,
		MsgAuthenticationReject,
		MsgAuthenticationFailure,
		MsgIdentityRequest,
		MsgIdentityResponse,
		MsgSecurityModeCommand,
		MsgSecurityModeComplete,
		MsgSecurityModeReject,
		MsgEMMStatus,
		MsgEMMInformation,
		MsgDownlinkNASTransport,
		MsgUplinkNASTransport,
		MsgCSServiceNotification,
		MsgDownlinkGenericNASTransport,
		MsgUplinkGenericNASTransport:
		return true
	default:
		return false
	}
}

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
	CauseCSDomainNotAvailable             uint8 = 0x12
	CauseCSFallbackCallEstNotAllowed      uint8 = CauseCSDomainNotAvailable
	CauseESMFailure                       uint8 = 0x13
	CauseMACFailure                       uint8 = 0x14
	CauseSynchFailure                     uint8 = 0x15
	CauseCongestion                       uint8 = 0x16
	CauseUESecurityCapabMismatch          uint8 = 0x17
	CauseSecurityModeRejectedUnspecified  uint8 = 0x18
	CauseNotAuthorizedForCSG              uint8 = 0x19
	CauseNonEPSAuthenticationUnacceptable uint8 = 0x1A
	CauseCSServiceTemporarilyNotAvailable uint8 = 0x27
	CauseNoEPSBearerContextActivated      uint8 = 0x28
	CauseSemanticallyIncorrectMessage     uint8 = 0x5F
	CauseInvalidMandatoryInformation      uint8 = 0x60
	CauseMessageTypeNonExistent           uint8 = 0x61
	CauseMessageTypeNotCompatible         uint8 = 0x62
	CauseIENonExistent                    uint8 = 0x63
	CauseConditionalIEError               uint8 = 0x64
	CauseMessageNotCompatible             uint8 = 0x65
	CauseProtocolError                    uint8 = 0x6F
)

func CauseName(cause uint8) string {
	switch cause {
	case CauseIMSIUnknownInHSS:
		return "IMSI unknown in HSS"
	case CauseIllegalUE:
		return "Illegal UE"
	case CauseIMEINotAccepted:
		return "IMEI not accepted"
	case CauseIllegalME:
		return "Illegal ME"
	case CauseEPSServicesNotAllowed:
		return "EPS services not allowed"
	case CauseUEIdentityCannotBeDerived:
		return "UE identity cannot be derived by the network"
	case CauseImplicitlyDetached:
		return "Implicitly detached"
	case CausePLMNNotAllowed:
		return "PLMN not allowed"
	case CauseTrackingAreaNotAllowed:
		return "Tracking area not allowed"
	case CauseRoamingNotAllowed:
		return "Roaming not allowed in this tracking area"
	case CauseEPSServicesNotAllowedInPLMN:
		return "EPS services not allowed in this PLMN"
	case CauseNoSuitableCellsInTA:
		return "No suitable cells in tracking area"
	case CauseNetworkFailure:
		return "Network failure"
	case CauseCSFallbackCallEstNotAllowed:
		return "CS domain not available"
	case CauseESMFailure:
		return "ESM failure"
	case CauseMACFailure:
		return "MAC failure"
	case CauseSynchFailure:
		return "Synch failure"
	case CauseCongestion:
		return "Congestion"
	case CauseUESecurityCapabMismatch:
		return "UE security capabilities mismatch"
	case CauseSecurityModeRejectedUnspecified:
		return "Security mode rejected, unspecified"
	case CauseNotAuthorizedForCSG:
		return "Not authorized for this CSG"
	case CauseNonEPSAuthenticationUnacceptable:
		return "Non-EPS authentication unacceptable"
	case CauseCSServiceTemporarilyNotAvailable:
		return "CS service temporarily not available"
	case CauseNoEPSBearerContextActivated:
		return "No EPS bearer context activated"
	case CauseSemanticallyIncorrectMessage:
		return "Semantically incorrect message"
	case CauseInvalidMandatoryInformation:
		return "Invalid mandatory information"
	case CauseMessageTypeNonExistent:
		return "Message type non-existent or not implemented"
	case CauseMessageTypeNotCompatible:
		return "Message type not compatible with protocol state"
	case CauseIENonExistent:
		return "Information element non-existent or not implemented"
	case CauseConditionalIEError:
		return "Conditional IE error"
	case CauseMessageNotCompatible:
		return "Message not compatible with protocol state"
	case CauseProtocolError:
		return "Protocol error, unspecified"
	default:
		return "unknown"
	}
}
