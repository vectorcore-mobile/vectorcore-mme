package emm

import "fmt"

// EncodeAuthenticationRequest encodes a NAS Authentication Request.
// rand and autn are each 16 bytes. nasKSI is the key set identifier (0..6).
func EncodeAuthenticationRequest(nasKSI uint8, rand, autn []byte) ([]byte, error) {
	if len(rand) != 16 || len(autn) != 16 {
		return nil, fmt.Errorf("emm: AuthRequest: RAND and AUTN must be 16 bytes each")
	}
	b := make([]byte, 0, 35)
	b = append(b, PDEPSMobilityMgmt|SecurityHeaderPlain<<4)
	b = append(b, MsgAuthenticationRequest)
	b = append(b, nasKSI&0x07) // NAS key set identifier + spare
	b = append(b, rand...)
	// AUTN: mandatory LV field (no IEI), 1-byte length + value
	b = append(b, 0x10) // AUTN length = 16 (LV format, no IEI)
	b = append(b, autn...)
	return b, nil
}

// AuthenticationResponse holds the decoded NAS Authentication Response.
type AuthenticationResponse struct {
	RES []byte // 4..16 bytes
}

// DecodeAuthenticationResponse decodes a NAS Authentication Response body.
func DecodeAuthenticationResponse(data []byte) (*AuthenticationResponse, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("emm: AuthResponse too short: %d bytes", len(data))
	}
	resLen := int(data[0])
	if 1+resLen > len(data) {
		return nil, fmt.Errorf("emm: AuthResponse RES truncated")
	}
	return &AuthenticationResponse{RES: data[1 : 1+resLen]}, nil
}

// EncodeAuthenticationReject encodes a NAS Authentication Reject.
func EncodeAuthenticationReject() []byte {
	return []byte{
		PDEPSMobilityMgmt | SecurityHeaderPlain<<4,
		MsgAuthenticationReject,
	}
}
