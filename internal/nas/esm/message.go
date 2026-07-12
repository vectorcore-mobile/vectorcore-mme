// Package esm implements EPS Session Management NAS messages (3GPP TS 24.301).
package esm

// MessageType values for ESM messages.
const (
	MsgActivateDefaultEPSBearerContextRequest   uint8 = 0xC1
	MsgActivateDefaultEPSBearerContextAccept    uint8 = 0xC2
	MsgActivateDefaultEPSBearerContextReject    uint8 = 0xC3
	MsgActivateDedicatedEPSBearerContextRequest uint8 = 0xC5
	MsgActivateDedicatedEPSBearerContextAccept  uint8 = 0xC6
	MsgActivateDedicatedEPSBearerContextReject  uint8 = 0xC7
	MsgModifyEPSBearerContextRequest            uint8 = 0xC9
	MsgModifyEPSBearerContextAccept             uint8 = 0xCA
	MsgModifyEPSBearerContextReject             uint8 = 0xCB
	MsgDeactivateEPSBearerContextRequest        uint8 = 0xCD
	MsgDeactivateEPSBearerContextAccept         uint8 = 0xCE
	MsgPDNConnectivityRequest                   uint8 = 0xD0
	MsgPDNConnectivityReject                    uint8 = 0xD1
	MsgPDNDisconnectRequest                     uint8 = 0xD2
	MsgPDNDisconnectReject                      uint8 = 0xD3
	MsgBearerResourceAllocationRequest          uint8 = 0xD4
	MsgBearerResourceModificationRequest        uint8 = 0xD6
	MsgESMStatus                                uint8 = 0xE8
	MsgESMInformationRequest                    uint8 = 0xD9
	MsgESMInformation                           uint8 = MsgESMInformationRequest
	MsgESMInformationResponse                   uint8 = 0xDA
	MsgNotification                             uint8 = 0xDB
)

// ESMCause values.
const (
	ESMCauseOperatorDetermined         uint8 = 0x08
	ESMCauseInsufficientResources      uint8 = 0x1A
	ESMCauseMissingOrUnknownAPN        uint8 = 0x1B
	ESMCauseUnknownPDNType             uint8 = 0x1C
	ESMCauseUserAuthenticationFailed   uint8 = 0x1D
	ESMCauseRequestRejectedBySGW       uint8 = 0x1E
	ESMCauseRequestRejectedUnspecified uint8 = 0x1F
	ESMCauseServiceOptionNotSupported  uint8 = 0x21
	ESMCauseRegularDeactivation        uint8 = 0x24
	ESMCauseProtocolError              uint8 = 0x6F
)

// ProtocolDiscriminator for ESM.
const PDEPSSessionMgmt uint8 = 0x02

// ESMHeader is the 3-byte common ESM header.
type ESMHeader struct {
	ProtocolDiscriminator  uint8
	EPSBearerID            uint8
	ProcedureTransactionID uint8
	MessageType            uint8
}

// ESMMessage contains a decoded ESM message.
type ESMMessage struct {
	Header  ESMHeader
	Payload []byte
}

// Decode decodes an ESM message from the ESM container bytes.
func Decode(data []byte) (*ESMMessage, error) {
	if len(data) < 3 {
		return nil, nil
	}
	return &ESMMessage{
		Header: ESMHeader{
			ProtocolDiscriminator:  data[0] & 0x0F,
			EPSBearerID:            data[0] >> 4,
			ProcedureTransactionID: data[1],
			MessageType:            data[2],
		},
		Payload: data[3:],
	}, nil
}
