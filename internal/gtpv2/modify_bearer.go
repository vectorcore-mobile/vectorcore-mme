package gtpv2

import (
	"fmt"
	"net"
)

type ModifyBearer struct {
	EBI       uint8
	ENBU_TEID uint32
	ENBU_IP   net.IP
}

type ModifyBearerBearerResult struct {
	EBI       uint8
	Cause     uint8
	SGWU_TEID uint32
	SGWU_IP   net.IP
	Instance  uint8
}

// ModifyBearerRequest holds the parameters for a GTPv2-C Modify Bearer Request
// (TS 29.274 §7.2.7). Sent on S11 after the ICS Response delivers the eNB S1-U TEID.
type ModifyBearerRequest struct {
	SGWAddress            string
	SGWC_TEID             uint32 // S-GW C-plane TEID (from CSRsp) — goes in message header
	Bearers               []ModifyBearer
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
	// CorrelationID is local-only state used to route asynchronous MBR responses.
	CorrelationID string
}

type ModifyBearerResponse struct {
	Cause           uint8
	ModifiedBearers []ModifyBearerBearerResult
	RemovedBearers  []ModifyBearerBearerResult
	EBI             uint8
	BearerCause     uint8
	SGWU_TEID       uint32
	SGWU_IP         net.IP
}

// Encode returns the wire bytes for this MBR with the given sequence number.
func (r *ModifyBearerRequest) Encode(seqNum uint32) []byte {
	ies := make([]IE, 0, 3+len(r.bearers()))
	if r.IncludeIndicationCRSI {
		ies = append(ies, EncodeIndicationCRSI())
	}
	if !r.OmitRATType {
		ies = append(ies, EncodeRATType(r.RATType))
	}
	for _, bearer := range r.bearers() {
		ies = append(ies, EncodeGrouped(IETypeBearerContext, 0, []IE{
			EncodeEBI(bearer.EBI, 0),
			EncodeFTEID(IFTypeS1UENB, bearer.ENBU_TEID, bearer.ENBU_IP, FTEIDInstanceSender),
		}))
	}
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

func (r *ModifyBearerRequest) bearers() []ModifyBearer {
	if len(r.Bearers) > 0 {
		return r.Bearers
	}
	return []ModifyBearer{{
		EBI:       r.EBI,
		ENBU_TEID: r.ENBU_TEID,
		ENBU_IP:   r.ENBU_IP,
	}}
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
	for _, ie := range m.IEs {
		if ie.Type != IETypeBearerContext {
			continue
		}
		children, err := FindGroupedIEs(&ie)
		if err != nil {
			return nil, err
		}
		result := ModifyBearerBearerResult{Instance: ie.Instance}
		if ebi, err := DecodeEBI(FindIE(children, IETypeEBI, 0)); err == nil {
			result.EBI = ebi
		}
		if bearerCause, err := DecodeCause(FindIE(children, IETypeCause, 0)); err == nil {
			result.Cause = bearerCause
		}
		if fteid, err := DecodeFTEID(FindIE(children, IETypeFTEID, 0)); err == nil {
			result.SGWU_TEID = fteid.TEID
			result.SGWU_IP = fteid.IP
		}
		if ie.Instance == 1 {
			resp.RemovedBearers = append(resp.RemovedBearers, result)
			continue
		}
		resp.ModifiedBearers = append(resp.ModifiedBearers, result)
	}
	if len(resp.ModifiedBearers) > 0 {
		first := resp.ModifiedBearers[0]
		resp.EBI = first.EBI
		resp.BearerCause = first.Cause
		resp.SGWU_TEID = first.SGWU_TEID
		resp.SGWU_IP = append(net.IP(nil), first.SGWU_IP...)
	}
	return resp, nil
}
