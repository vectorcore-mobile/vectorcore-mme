package emm

// DetachType values (3GPP TS 24.301 §9.9.3.7).
const (
	DetachTypeSwitchOff   uint8 = 0x08 // bit 3 set = switch off
	DetachTypeNormal      uint8 = 0x01 // EPS detach
	DetachTypeIMSIDetach  uint8 = 0x02
	DetachTypeEPSAndIMSI  uint8 = 0x03
)

// DetachRequest holds the decoded NAS Detach Request (from UE).
type DetachRequest struct {
	DetachType     uint8
	SwitchOff      bool
	NASKeySetIdentifier uint8
	EPSMobileIdentity []byte
}

// DecodeDetachRequest decodes a NAS Detach Request body.
func DecodeDetachRequest(data []byte) (*DetachRequest, error) {
	if len(data) < 1 {
		return nil, nil
	}
	dr := &DetachRequest{}
	dr.SwitchOff = (data[0]>>3)&1 == 1
	dr.DetachType = data[0] & 0x07
	dr.NASKeySetIdentifier = (data[0] >> 4) & 0x07
	if len(data) > 2 {
		mobileIDLen := int(data[1])
		if 2+mobileIDLen <= len(data) {
			dr.EPSMobileIdentity = data[2 : 2+mobileIDLen]
		}
	}
	return dr, nil
}

// EncodeDetachAccept encodes a NAS Detach Accept (network to UE).
func EncodeDetachAccept() []byte {
	return []byte{
		PDEPSMobilityMgmt | SecurityHeaderPlain<<4,
		MsgDetachAccept,
	}
}

// EncodeNetworkDetachRequest encodes a NAS Detach Request (network initiated).
// detachType: 0x01 = re-attach required, 0x02 = re-attach not required, 0x03 = IMSI detach.
func EncodeNetworkDetachRequest(detachType uint8) []byte {
	return []byte{
		PDEPSMobilityMgmt | SecurityHeaderPlain<<4,
		MsgDetachRequest,
		detachType & 0x07,
	}
}
