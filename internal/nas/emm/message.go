package emm

import (
	"fmt"
)

// NASHeader is the common header for all plain NAS EMM messages.
// Security-protected messages wrap this inside a SecurityProtectedHeader.
type NASHeader struct {
	SecurityHeaderType    uint8 // bits 7:4 of byte 0
	ProtocolDiscriminator uint8 // bits 3:0 of byte 0
	MessageType           uint8 // byte 1
}

// Encode returns the 2-byte NAS header.
func (h *NASHeader) Encode() []byte {
	return []byte{
		(h.SecurityHeaderType << 4) | (h.ProtocolDiscriminator & 0x0F),
		h.MessageType,
	}
}

// SecurityProtectedNASMessage wraps a plain NAS message with MAC and sequence number.
type SecurityProtectedNASMessage struct {
	SecurityHeaderType    uint8
	ProtocolDiscriminator uint8
	MAC                   [4]byte
	SequenceNumber        uint8
	PlainNASMessage       []byte
}

// Encode encodes the security-protected NAS message.
func (m *SecurityProtectedNASMessage) Encode() []byte {
	b := make([]byte, 0, 7+len(m.PlainNASMessage))
	b = append(b, (m.SecurityHeaderType<<4)|(m.ProtocolDiscriminator&0x0F))
	b = append(b, m.MAC[:]...)
	b = append(b, m.SequenceNumber)
	b = append(b, m.PlainNASMessage...)
	return b
}

// DecodeSecurityHeader peeks at the first byte to determine the security header type.
func DecodeSecurityHeader(data []byte) (secHdrType, pd uint8, err error) {
	if len(data) < 1 {
		return 0, 0, fmt.Errorf("emm: empty NAS message")
	}
	return data[0] >> 4, data[0] & 0x0F, nil
}

// ParsePlainNASMessage parses the first two bytes (header) and returns message type.
func ParsePlainNASMessage(data []byte) (msgType uint8, payload []byte, err error) {
	if len(data) < 2 {
		return 0, nil, fmt.Errorf("emm: NAS message too short: %d bytes", len(data))
	}
	pd := data[0] & 0x0F
	if pd != PDEPSMobilityMgmt {
		return 0, nil, fmt.Errorf("emm: unexpected PD %d (want EMM %d)", pd, PDEPSMobilityMgmt)
	}
	return data[1], data[2:], nil
}

// ParseSecurityProtected parses a security-protected NAS message into MAC, SEQ, and inner message.
func ParseSecurityProtected(data []byte) (mac []byte, seq uint8, inner []byte, err error) {
	if len(data) < 7 {
		return nil, 0, nil, fmt.Errorf("emm: security-protected message too short: %d", len(data))
	}
	// data[0] = sec hdr type | PD (already checked by caller)
	mac = data[1:5]
	seq = data[5]
	inner = data[6:]
	return
}
