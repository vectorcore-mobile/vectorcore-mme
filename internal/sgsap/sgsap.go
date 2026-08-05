// Package sgsap contains the SGs-AP (TS 29.118) wire codec. It deliberately
// has no VLR association FSM, UE state, or SCTP transport: those belong to
// the VLR association layer and to the transport-neutral SMS/EMM services
// that consume this package, mirroring the split already used by
// internal/diameter/sgd for SMS over SGd.
package sgsap

import "fmt"

// Message type values (TS 29.118 §9.2).
const (
	MsgPagingRequest         uint8 = 0x01
	MsgPagingReject          uint8 = 0x02
	MsgServiceRequest        uint8 = 0x06
	MsgDownlinkUnitdata      uint8 = 0x07
	MsgUplinkUnitdata        uint8 = 0x08
	MsgLocationUpdateRequest uint8 = 0x09
	MsgLocationUpdateAccept  uint8 = 0x0A
	MsgLocationUpdateReject  uint8 = 0x0B
	MsgTMSIReallocComplete   uint8 = 0x0C
	MsgAlertRequest          uint8 = 0x0D
	MsgAlertAck              uint8 = 0x0E
	MsgAlertReject           uint8 = 0x0F
	MsgUEActivityIndication  uint8 = 0x10
	MsgEPSDetachIndication   uint8 = 0x11
	MsgEPSDetachAck          uint8 = 0x12
	MsgIMSIDetachIndication  uint8 = 0x13
	MsgIMSIDetachAck         uint8 = 0x14
	MsgResetIndication       uint8 = 0x15
	MsgResetAck              uint8 = 0x16
	MsgServiceAbortRequest   uint8 = 0x17
	MsgMOCSFBIndication      uint8 = 0x18
	MsgMMInformationRequest  uint8 = 0x1A
	MsgReleaseRequest        uint8 = 0x1B
	MsgStatus                uint8 = 0x1D
	MsgUEUnreachable         uint8 = 0x1F
)

// Information element identifiers (TS 29.118 §9.3).
const (
	ieIMSI                     uint8 = 0x01
	ieVLRName                  uint8 = 0x02
	ieTMSI                     uint8 = 0x03
	ieLAI                      uint8 = 0x04
	ieChannelNeeded            uint8 = 0x05
	ieEMLPPPriority            uint8 = 0x06
	ieTMSIStatus               uint8 = 0x07
	ieSGsCause                 uint8 = 0x08
	ieMMEName                  uint8 = 0x09
	ieEPSLocationUpdateType    uint8 = 0x0A
	ieGlobalCNId               uint8 = 0x0B
	ieMobileIdentity           uint8 = 0x0E
	ieRejectCause              uint8 = 0x0F
	ieIMSIDetachFromEPSType    uint8 = 0x10
	ieIMSIDetachFromNonEPSType uint8 = 0x11
	ieIMEISV                   uint8 = 0x15
	ieNASMessageContainer      uint8 = 0x16
	ieMMInformation            uint8 = 0x17
	ieErroneousMessage         uint8 = 0x1B
	ieCLI                      uint8 = 0x1C
	ieLCSClientIdentity        uint8 = 0x1D
	ieLCSIndicator             uint8 = 0x1E
	ieSSCode                   uint8 = 0x1F
	ieServiceIndicator         uint8 = 0x20
	ieUETimeZone               uint8 = 0x21
	ieMSClassmark2             uint8 = 0x22
	ieTAI                      uint8 = 0x23
	ieECGI                     uint8 = 0x24
	ieUEEMMMode                uint8 = 0x25
	ieAdditionalPagingInd      uint8 = 0x26
	ieTMSIBasedNRIContainer    uint8 = 0x27
	ieSelectedCSDomainOperator uint8 = 0x28
	ieMaxUEAvailabilityTime    uint8 = 0x29
	ieSMDeliveryTimer          uint8 = 0x2A
	ieSMDeliveryStartTime      uint8 = 0x2B
	ieAdditionalUEUnreachable  uint8 = 0x2C
	ieMaxRetransmissionTime    uint8 = 0x2D
	ieRequestedRetransTime     uint8 = 0x2E
)

// ie is one decoded TLV information element: a one-octet IEI, a one-octet
// length indicator, and the value part (TS 29.118 §9.3a).
type ie struct {
	iei   uint8
	value []byte
}

// pdu is a decoded SGsAP message: the message type octet plus every IE that
// followed it, in wire order.
type pdu struct {
	msgType uint8
	ies     []ie
}

func decodePDU(data []byte) (*pdu, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("sgsap: empty message")
	}
	p := &pdu{msgType: data[0]}
	rest := data[1:]
	for len(rest) > 0 {
		if len(rest) < 2 {
			return nil, fmt.Errorf("sgsap: truncated IE header")
		}
		iei := rest[0]
		length := int(rest[1])
		if len(rest) < 2+length {
			return nil, fmt.Errorf("sgsap: IE %#x truncated: want %d bytes, have %d", iei, length, len(rest)-2)
		}
		p.ies = append(p.ies, ie{iei: iei, value: append([]byte(nil), rest[2:2+length]...)})
		rest = rest[2+length:]
	}
	return p, nil
}

func (p *pdu) find(iei uint8) ([]byte, bool) {
	for _, e := range p.ies {
		if e.iei == iei {
			return e.value, true
		}
	}
	return nil, false
}

func (p *pdu) require(iei uint8, what string) ([]byte, error) {
	v, ok := p.find(iei)
	if !ok {
		return nil, fmt.Errorf("sgsap: missing mandatory %s IE", what)
	}
	return v, nil
}

// encoder accumulates a message body: the message type octet followed by
// appended TLV information elements, in the order callers add them.
type encoder struct {
	buf []byte
}

func newEncoder(msgType uint8) *encoder {
	return &encoder{buf: []byte{msgType}}
}

func (e *encoder) put(iei uint8, value []byte) {
	e.buf = append(e.buf, iei, byte(len(value)))
	e.buf = append(e.buf, value...)
}

func (e *encoder) bytes() []byte { return e.buf }

// MessageType returns the message type octet of an encoded SGsAP message
// without fully decoding it, for dispatch by the VLR association layer.
func MessageType(data []byte) (uint8, error) {
	if len(data) < 1 {
		return 0, fmt.Errorf("sgsap: empty message")
	}
	return data[0], nil
}
