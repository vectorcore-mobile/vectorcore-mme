package emm

import (
	"encoding/binary"
	"fmt"
)

const (
	// ServiceTypeMobileOriginatingCSFallback is the Extended Service Request
	// service type for an MO CS fallback request.
	ServiceTypeMobileOriginatingCSFallback uint8 = 0
)

// ExtendedServiceRequest holds the decoded fields of a plain NAS Extended
// Service Request message body (after the 2-byte NAS header).
type ExtendedServiceRequest struct {
	NASKeySetIdentifier uint8
	ServiceType         uint8
	MobileIdentity      []byte
	IdentityType        uint8
	MTMSI               uint32
	GUTI                *GUTI
}

// DecodeExtendedServiceRequest decodes the subset of Extended Service Request
// fields needed for idle UE rebind from Initial UE Message.
func DecodeExtendedServiceRequest(data []byte) (*ExtendedServiceRequest, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("emm: Extended Service Request too short: %d bytes", len(data))
	}

	out := &ExtendedServiceRequest{
		NASKeySetIdentifier: (data[0] >> 4) & 0x07,
		ServiceType:         data[0] & 0x0F,
	}

	offset := 1
	mobileIDLen := int(data[offset])
	offset++
	if offset+mobileIDLen > len(data) {
		return nil, fmt.Errorf("emm: Extended Service Request mobile identity truncated")
	}

	out.MobileIdentity = append([]byte(nil), data[offset:offset+mobileIDLen]...)
	if len(out.MobileIdentity) == 0 {
		return nil, fmt.Errorf("emm: Extended Service Request missing mobile identity")
	}
	out.IdentityType = out.MobileIdentity[0] & 0x07

	switch out.IdentityType {
	case IdentityTypeTMSI:
		if len(out.MobileIdentity) < 5 {
			return nil, fmt.Errorf("emm: Extended Service Request TMSI too short: %d", len(out.MobileIdentity))
		}
		out.MTMSI = binary.BigEndian.Uint32(out.MobileIdentity[1:5])
	case IdentityTypeGUTI:
		guti, err := decodeGUTI(out.MobileIdentity)
		if err != nil {
			return nil, err
		}
		out.GUTI = guti
		out.MTMSI = guti.MTMSI
	default:
		return nil, fmt.Errorf("emm: Extended Service Request unsupported identity type %d", out.IdentityType)
	}

	return out, nil
}
