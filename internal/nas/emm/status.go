package emm

import "fmt"

type EMMStatus struct {
	Cause uint8
}

func DecodeEMMStatus(data []byte) (*EMMStatus, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("emm: EMM Status too short: %d bytes", len(data))
	}
	return &EMMStatus{Cause: data[0]}, nil
}

func EncodeEMMStatus(cause uint8) []byte {
	return []byte{
		PDEPSMobilityMgmt | (SecurityHeaderPlain << 4),
		MsgEMMStatus,
		cause,
	}
}
