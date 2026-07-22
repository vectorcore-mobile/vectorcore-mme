package emm

import "fmt"

// IdentityRequest encodes a NAS Identity Request message.
func EncodeIdentityRequest(identityType uint8) []byte {
	return []byte{
		PDEPSMobilityMgmt | SecurityHeaderPlain<<4,
		MsgIdentityRequest,
		identityType & 0x07,
	}
}

// IdentityResponse holds the decoded NAS Identity Response.
type IdentityResponse struct {
	IdentityType uint8
	IMSI         string
	IMEI         string
}

// DecodeIdentityResponse decodes a NAS Identity Response message body.
func DecodeIdentityResponse(data []byte) (*IdentityResponse, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("emm: Identity Response too short: %d bytes", len(data))
	}
	mobileIDLen := int(data[0])
	if 1+mobileIDLen > len(data) {
		return nil, fmt.Errorf("emm: Identity Response mobile identity truncated")
	}
	mobileID := data[1 : 1+mobileIDLen]
	if len(mobileID) < 1 {
		return nil, fmt.Errorf("emm: empty mobile identity")
	}

	resp := &IdentityResponse{}
	resp.IdentityType = mobileID[0] & 0x07

	switch resp.IdentityType {
	case IdentityTypeIMSI:
		resp.IMSI = decodeIMSI(mobileID)
	case IdentityTypeIMEI, IdentityTypeIMEISV:
		resp.IMEI = decodeIMSI(mobileID) // same BCD encoding
	}
	return resp, nil
}

// DecodeEquipmentIdentity decodes the Mobile Identity value carried in the
// Security Mode Complete IMEISV IE (without the Identity Response length
// octet). It accepts only IMEI or IMEISV identities.
func DecodeEquipmentIdentity(mobileID []byte) (string, error) {
	if len(mobileID) == 0 {
		return "", fmt.Errorf("emm: empty equipment identity")
	}
	typ := mobileID[0] & 0x07
	if typ != IdentityTypeIMEI && typ != IdentityTypeIMEISV {
		return "", fmt.Errorf("emm: mobile identity type %d is not IMEI/IMEISV", typ)
	}
	return decodeIMSI(mobileID), nil
}
