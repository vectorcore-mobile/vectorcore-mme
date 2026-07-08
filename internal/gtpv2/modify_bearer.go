package gtpv2

import (
	"fmt"
	"net"
)

// ModifyBearerRequest holds the parameters for a GTPv2-C Modify Bearer Request
// (TS 29.274 §7.2.7). Sent on S11 after the ICS Response delivers the eNB S1-U TEID.
type ModifyBearerRequest struct {
	SGWAddress string
	SGWC_TEID  uint32 // S-GW C-plane TEID (from CSRsp) — goes in message header
	EBI        uint8
	ENBU_TEID  uint32
	ENBU_IP    net.IP
	RATType    uint8
	// MMEC_TEID/MMEC_IP: new MME S11 C-plane F-TEID for inter-MME TAU.
	// When MMEC_TEID != 0, a Sender F-TEID IE (IFTypeS11MME) is included so the SGW
	// updates its C-plane downlink path to point at the new MME.
	MMEC_TEID uint32
	MMEC_IP   net.IP
}

// Encode returns the wire bytes for this MBR with the given sequence number.
func (r *ModifyBearerRequest) Encode(seqNum uint32) []byte {
	// Bearer Context with eNB S1-U F-TEID (instance 0) and EBI
	bearerCtx := EncodeGrouped(IETypeBearerContext, 0, []IE{
		EncodeEBI(r.EBI, 0),
		EncodeFTEID(IFTypeS1UENB, r.ENBU_TEID, r.ENBU_IP, FTEIDInstanceSender),
	})

	ies := []IE{
		EncodeRATType(r.RATType),
		bearerCtx,
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

// DecodeModifyBearerResponse decodes the Cause from a MBRsp.
func DecodeModifyBearerResponse(m *Message) (uint8, error) {
	if m.Type != MsgModifyBearerResponse {
		return 0, fmt.Errorf("gtpv2: expected MBRsp (35), got %d", m.Type)
	}
	causeIE := FindIE(m.IEs, IETypeCause, 0)
	return DecodeCause(causeIE)
}
