package gtpv2

import (
	"fmt"
	"net"
)

// DeleteSessionRequest holds the parameters for a GTPv2-C Delete Session Request
// (TS 29.274 §7.2.9.1). Sent to S-GW on detach or UE context release.
type DeleteSessionRequest struct {
	SGWAddress          string
	SGWC_TEID           uint32 // S-GW C-plane TEID — goes in message header
	EBI                 uint8
	LocalS11TEID        uint32
	LocalS11IP          net.IP
	IncludeIndicationOI bool
	IncludeULI          bool
	ULIPLMN             [3]byte
	ULITAC              uint16
	ULIECI              uint32
	IncludeULITimestamp bool
	ULITimestamp        uint32
}

// Encode returns the wire bytes for this DSR with the given sequence number.
func (r *DeleteSessionRequest) Encode(seqNum uint32) []byte {
	ies := []IE{
		EncodeEBI(r.EBI, 0),
	}
	if r.IncludeULI {
		ies = append(ies, EncodeULI(r.ULIPLMN, r.ULITAC, r.ULIECI))
	}
	if r.IncludeIndicationOI {
		ies = append(ies, EncodeIndicationOI())
	}
	if r.LocalS11TEID != 0 && r.LocalS11IP != nil {
		ies = append(ies, EncodeFTEID(IFTypeS11MME, r.LocalS11TEID, r.LocalS11IP, FTEIDInstanceSender))
	}
	if r.IncludeULITimestamp {
		ies = append(ies, EncodeULITimestamp(r.ULITimestamp))
	}
	msg := &Message{
		Type:   MsgDeleteSessionRequest,
		TEID:   r.SGWC_TEID,
		SeqNum: seqNum,
		IEs:    ies,
	}
	return Encode(msg)
}

// DecodeDeleteSessionResponse decodes the Cause from a DSRsp.
func DecodeDeleteSessionResponse(m *Message) (uint8, error) {
	if m.Type != MsgDeleteSessionResponse {
		return 0, fmt.Errorf("gtpv2: expected DSRsp (37), got %d", m.Type)
	}
	causeIE := FindIE(m.IEs, IETypeCause, 0)
	return DecodeCause(causeIE)
}
