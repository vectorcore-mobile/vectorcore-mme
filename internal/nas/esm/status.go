package esm

import "fmt"

type ESMStatus struct {
	Cause uint8
}

func DecodeESMStatus(data []byte) (*ESMStatus, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("esm: ESM Status too short: %d bytes", len(data))
	}
	if data[0]&0x0f != PDEPSSessionMgmt {
		return nil, fmt.Errorf("esm: unexpected protocol discriminator %d", data[0]&0x0f)
	}
	if data[2] != MsgESMStatus {
		return nil, fmt.Errorf("esm: unexpected message type %#x", data[2])
	}
	return &ESMStatus{Cause: data[3]}, nil
}

func CauseName(cause uint8) string {
	switch cause {
	case ESMCauseOperatorDetermined:
		return "Operator determined barring"
	case ESMCauseInsufficientResources:
		return "Insufficient resources"
	case ESMCauseMissingOrUnknownAPN:
		return "Missing or unknown APN"
	case ESMCauseUnknownPDNType:
		return "Unknown PDN type"
	case ESMCauseUserAuthenticationFailed:
		return "User authentication failed"
	case ESMCauseRequestRejectedBySGW:
		return "Request rejected by Serving GW or PDN GW"
	case ESMCauseRequestRejectedUnspecified:
		return "Request rejected, unspecified"
	case ESMCauseServiceOptionNotSupported:
		return "Service option not supported"
	case ESMCauseRegularDeactivation:
		return "Regular deactivation"
	case 0x2F:
		return "PTI mismatch"
	case 0x5F:
		return "Semantically incorrect message"
	case 0x60:
		return "Invalid mandatory information"
	case 0x61:
		return "Message type non-existent or not implemented"
	case 0x62:
		return "Message type not compatible with protocol state"
	case 0x63:
		return "Information element non-existent or not implemented"
	case 0x64:
		return "Conditional IE error"
	case 0x65:
		return "Message not compatible with protocol state"
	case ESMCauseProtocolError:
		return "Protocol error, unspecified"
	default:
		return "unknown"
	}
}
