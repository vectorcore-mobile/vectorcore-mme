package esm

import "fmt"

type BearerResourceModificationRequest struct {
	EPSBearerID            uint8
	ProcedureTransactionID uint8
	LinkedEPSBearerID      uint8
	TFA                    []byte
}

func DecodeBearerResourceModificationRequest(data []byte) (*BearerResourceModificationRequest, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("esm: Bearer Resource Modification Request too short: %d", len(data))
	}
	if data[0]&0x0f != PDEPSSessionMgmt {
		return nil, fmt.Errorf("esm: unexpected protocol discriminator %d", data[0]&0x0f)
	}
	if data[2] != MsgBearerResourceModificationRequest {
		return nil, fmt.Errorf("esm: unexpected message type %#x", data[2])
	}
	req := &BearerResourceModificationRequest{
		EPSBearerID:            data[0] >> 4,
		ProcedureTransactionID: data[1],
		LinkedEPSBearerID:      data[3] & 0x0f,
	}
	if len(data) > 4 {
		req.TFA = append([]byte(nil), data[4:]...)
	}
	return req, nil
}

func EncodeBearerResourceModificationReject(pti uint8, cause uint8) []byte {
	return []byte{
		PDEPSSessionMgmt,
		pti,
		MsgBearerResourceModificationReject,
		cause,
	}
}
