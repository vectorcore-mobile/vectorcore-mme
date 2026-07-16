package gtpv2

import (
	"fmt"
	"net"
)

// ModifyBearerRequest holds the parameters for a GTPv2-C Modify Bearer Request
// (TS 29.274 §7.2.7). Sent on S11 after the ICS Response delivers the eNB S1-U TEID.
type ModifyBearerRequest struct {
	SGWAddress            string
	SGWC_TEID             uint32 // S-GW C-plane TEID (from CSRsp) — goes in message header
	EBI                   uint8
	ENBU_TEID             uint32
	ENBU_IP               net.IP
	RATType               uint8
	IncludeIndicationCRSI bool
	OmitRATType           bool
	// MMEC_TEID/MMEC_IP: new MME S11 C-plane F-TEID for inter-MME TAU.
	// When MMEC_TEID != 0, a Sender F-TEID IE (IFTypeS11MME) is included so the SGW
	// updates its C-plane downlink path to point at the new MME.
	MMEC_TEID uint32
	MMEC_IP   net.IP
}

type ModifyBearerResponse struct {
	Cause       uint8
	EBI         uint8
	BearerCause uint8
	SGWU_TEID   uint32
	SGWU_IP     net.IP
}

// Encode returns the wire bytes for this MBR with the given sequence number.
func (r *ModifyBearerRequest) Encode(seqNum uint32) []byte {
	// Bearer Context with eNB S1-U F-TEID (instance 0) and EBI
	bearerCtx := EncodeGrouped(IETypeBearerContext, 0, []IE{
		EncodeEBI(r.EBI, 0),
		EncodeFTEID(IFTypeS1UENB, r.ENBU_TEID, r.ENBU_IP, FTEIDInstanceSender),
	})

	ies := make([]IE, 0, 4)
	if r.IncludeIndicationCRSI {
		ies = append(ies, EncodeIndicationCRSI())
	}
	if !r.OmitRATType {
		ies = append(ies, EncodeRATType(r.RATType))
	}
	ies = append(ies, bearerCtx)
	if r.MMEC_TEID != 0 && r.MMEC_IP != nil {
		ies = append(ies, EncodeFTEID(IFTypeS11MME, r.MMEC_TEID, r.MMEC_IP, 0))
	}

	msg := &Message{
		Type:   MsgModifyBearerRequest,
		TEID:   r.SGWC_TEID,
		SeqNum: seqNum,
		IEs:    ies,
	}
	return Encode(msg)
}

// DecodeModifyBearerResponse decodes the top-level cause and any returned
// bearer-context result from a MBRsp.
func DecodeModifyBearerResponse(m *Message) (*ModifyBearerResponse, error) {
	if m.Type != MsgModifyBearerResponse {
		return nil, fmt.Errorf("gtpv2: expected MBRsp (35), got %d", m.Type)
	}
	causeIE := FindIE(m.IEs, IETypeCause, 0)
	cause, err := DecodeCause(causeIE)
	if err != nil {
		return nil, err
	}
	resp := &ModifyBearerResponse{Cause: cause}
	if bcIE := FindIE(m.IEs, IETypeBearerContext, 0); bcIE != nil {
		children, err := FindGroupedIEs(bcIE)
		if err != nil {
			return nil, err
		}
		if ebi, err := DecodeEBI(FindIE(children, IETypeEBI, 0)); err == nil {
			resp.EBI = ebi
		}
		if bearerCause, err := DecodeCause(FindIE(children, IETypeCause, 0)); err == nil {
			resp.BearerCause = bearerCause
		}
		if fteid, err := DecodeFTEID(FindIE(children, IETypeFTEID, 0)); err == nil {
			resp.SGWU_TEID = fteid.TEID
			resp.SGWU_IP = fteid.IP
		}
	}
	return resp, nil
}
