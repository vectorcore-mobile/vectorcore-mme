package esm

import "fmt"

type BearerProcedureResponse struct {
	EPSBearerID            uint8
	ProcedureTransactionID uint8
	MessageType            uint8
	Cause                  uint8
	PCO                    []byte
}

func EncodeActivateDedicatedEPSBearerContextRequest(assignedEBI, linkedEBI, pti, qci uint8, tft []byte, pco []byte) []byte {
	buf := []byte{
		(assignedEBI << 4) | PDEPSSessionMgmt,
		pti,
		MsgActivateDedicatedEPSBearerContextRequest,
		linkedEBI & 0x0f,
		0x01,
		qci,
	}
	if len(tft) > 255 {
		tft = tft[:255]
	}
	buf = append(buf, byte(len(tft)))
	buf = append(buf, tft...)
	if len(pco) > 0 {
		if len(pco) > 255 {
			pco = pco[:255]
		}
		buf = append(buf, 0x27, byte(len(pco)))
		buf = append(buf, pco...)
	}
	return buf
}

func EncodeModifyEPSBearerContextRequest(ebi, pti, qci uint8, qos []byte, tft []byte, pco []byte) []byte {
	buf := []byte{(ebi << 4) | PDEPSSessionMgmt, pti, MsgModifyEPSBearerContextRequest}
	if qci != 0 {
		buf = append(buf, 0x5b, 0x01, qci)
	} else if len(qos) > 0 {
		if len(qos) > 255 {
			qos = qos[:255]
		}
		buf = append(buf, 0x5b, byte(len(qos)))
		buf = append(buf, qos...)
	}
	if len(tft) > 0 {
		if len(tft) > 255 {
			tft = tft[:255]
		}
		buf = append(buf, 0x36, byte(len(tft)))
		buf = append(buf, tft...)
	}
	if len(pco) > 0 {
		if len(pco) > 255 {
			pco = pco[:255]
		}
		buf = append(buf, 0x27, byte(len(pco)))
		buf = append(buf, pco...)
	}
	return buf
}

func EncodeDeactivateEPSBearerContextRequest(ebi, pti, cause uint8) []byte {
	return []byte{(ebi << 4) | PDEPSSessionMgmt, pti, MsgDeactivateEPSBearerContextRequest, cause}
}

func DecodeBearerProcedureResponse(data []byte) (*BearerProcedureResponse, error) {
	if len(data) < 3 {
		return nil, fmt.Errorf("esm: bearer procedure response too short: %d", len(data))
	}
	if data[0]&0x0f != PDEPSSessionMgmt {
		return nil, fmt.Errorf("esm: unexpected protocol discriminator %d", data[0]&0x0f)
	}
	resp := &BearerProcedureResponse{
		EPSBearerID:            data[0] >> 4,
		ProcedureTransactionID: data[1],
		MessageType:            data[2],
	}
	i := 3
	switch resp.MessageType {
	case MsgActivateDedicatedEPSBearerContextAccept,
		MsgModifyEPSBearerContextAccept,
		MsgDeactivateEPSBearerContextAccept:
	case MsgActivateDedicatedEPSBearerContextReject, MsgModifyEPSBearerContextReject:
		if len(data) < 4 {
			return nil, fmt.Errorf("esm: bearer procedure reject missing cause")
		}
		resp.Cause = data[3]
		i = 4
	default:
		return nil, fmt.Errorf("esm: unexpected bearer procedure message type %#x", resp.MessageType)
	}
	for i < len(data) {
		iei := data[i]
		i++
		if iei != 0x27 {
			if i >= len(data) {
				return nil, fmt.Errorf("esm: truncated optional IE %#x", iei)
			}
			l := int(data[i])
			i++
			if i+l > len(data) {
				return nil, fmt.Errorf("esm: optional IE %#x truncated", iei)
			}
			i += l
			continue
		}
		if i >= len(data) {
			return nil, fmt.Errorf("esm: truncated PCO length")
		}
		l := int(data[i])
		i++
		if i+l > len(data) {
			return nil, fmt.Errorf("esm: truncated PCO value")
		}
		resp.PCO = append([]byte(nil), data[i:i+l]...)
		i += l
	}
	return resp, nil
}
