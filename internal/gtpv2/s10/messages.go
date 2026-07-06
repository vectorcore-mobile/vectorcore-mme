// Package s10 implements the GTPv2-C S10 interface (MME ↔ MME).
// Both the "new MME" role (sends Context Request) and the "old MME" role
// (receives Context Request, sends Context Response) run in the same Server.
package s10

import (
	"fmt"
	"net"

	"github.com/vectorcore/mme/internal/gtpv2"
)

// ContextRequest is sent by the new MME to the old MME to fetch a UE context.
type ContextRequest struct {
	SenderFTEID   gtpv2.FTEID // new MME S10 IP + local TEID
	RawTAURequest []byte      // complete NAS TAU Request PDU; old MME extracts GUTI from it
}

// ContextResponse is sent by the old MME to the new MME.
type ContextResponse struct {
	Cause         uint8
	IMSI          string
	SenderFTEID   gtpv2.FTEID // old MME S10 IP + local TEID (used as header TEID in CTX-Ack)
	MMContext     gtpv2.MMContextParams
	PDNConnection gtpv2.PDNParams
}

// ContextAcknowledge is sent by the new MME to confirm context acceptance.
type ContextAcknowledge struct {
	Cause uint8
}

// EncodeContextRequest encodes a Context Request. The GTPv2 header TEID is peerTEID
// (the old MME's S10 TEID — 0 on first contact before old MME has allocated one).
func EncodeContextRequest(req *ContextRequest, seqNum, peerTEID uint32) []byte {
	ies := []gtpv2.IE{
		gtpv2.EncodeFTEID(gtpv2.IFTypeS10MME, req.SenderFTEID.TEID, req.SenderFTEID.IP, 0),
		gtpv2.EncodeCompleteRequestMsg(req.RawTAURequest),
	}
	msg := &gtpv2.Message{
		Type:   gtpv2.MsgContextRequest,
		TEID:   peerTEID,
		SeqNum: seqNum,
		IEs:    ies,
	}
	return gtpv2.Encode(msg)
}

// DecodeContextRequest decodes the IEs of a Context Request message.
func DecodeContextRequest(m *gtpv2.Message) (*ContextRequest, error) {
	if m.Type != gtpv2.MsgContextRequest {
		return nil, fmt.Errorf("s10: expected ContextRequest (130), got %d", m.Type)
	}
	req := &ContextRequest{}
	if fteidIE := gtpv2.FindIE(m.IEs, gtpv2.IETypeFTEID, 0); fteidIE != nil {
		f, err := gtpv2.DecodeFTEID(fteidIE)
		if err != nil {
			return nil, fmt.Errorf("s10: decode Sender F-TEID: %w", err)
		}
		req.SenderFTEID = *f
	} else {
		return nil, fmt.Errorf("s10: ContextRequest missing Sender F-TEID IE")
	}
	if complIE := gtpv2.FindIE(m.IEs, gtpv2.IETypeCompleteRequestMsg, 0); complIE != nil {
		req.RawTAURequest = make([]byte, len(complIE.Value))
		copy(req.RawTAURequest, complIE.Value)
	}
	return req, nil
}

// EncodeContextResponse encodes a Context Response. peerTEID is the new MME's S10 local TEID
// (from ContextRequest.SenderFTEID.TEID), placed in the GTPv2 header so the new MME
// can correlate the response.
func EncodeContextResponse(resp *ContextResponse, seqNum, peerTEID uint32) []byte {
	ies := []gtpv2.IE{
		gtpv2.EncodeCause(resp.Cause),
	}
	if resp.IMSI != "" {
		ies = append(ies, gtpv2.EncodeIMSI(resp.IMSI))
	}
	ies = append(ies,
		gtpv2.EncodeFTEID(gtpv2.IFTypeS10MME, resp.SenderFTEID.TEID, resp.SenderFTEID.IP, 0),
		gtpv2.EncodeMMContext(resp.MMContext),
		gtpv2.EncodePDNConnection(resp.PDNConnection),
	)
	msg := &gtpv2.Message{
		Type:   gtpv2.MsgContextResponse,
		TEID:   peerTEID,
		SeqNum: seqNum,
		IEs:    ies,
	}
	return gtpv2.Encode(msg)
}

// DecodeContextResponse decodes the IEs of a Context Response message.
func DecodeContextResponse(m *gtpv2.Message) (*ContextResponse, error) {
	if m.Type != gtpv2.MsgContextResponse {
		return nil, fmt.Errorf("s10: expected ContextResponse (131), got %d", m.Type)
	}
	resp := &ContextResponse{}
	if causeIE := gtpv2.FindIE(m.IEs, gtpv2.IETypeCause, 0); causeIE != nil {
		c, err := gtpv2.DecodeCause(causeIE)
		if err != nil {
			return nil, fmt.Errorf("s10: decode Cause: %w", err)
		}
		resp.Cause = c
	}
	if imsiIE := gtpv2.FindIE(m.IEs, gtpv2.IETypeIMSI, 0); imsiIE != nil {
		imsi, err := gtpv2.DecodeIMSI(imsiIE)
		if err != nil {
			return nil, fmt.Errorf("s10: decode IMSI: %w", err)
		}
		resp.IMSI = imsi
	}
	if fteidIE := gtpv2.FindIE(m.IEs, gtpv2.IETypeFTEID, 0); fteidIE != nil {
		f, err := gtpv2.DecodeFTEID(fteidIE)
		if err != nil {
			return nil, fmt.Errorf("s10: decode Sender F-TEID: %w", err)
		}
		resp.SenderFTEID = *f
	}
	if mmIE := gtpv2.FindIE(m.IEs, gtpv2.IETypeMMContext, 0); mmIE != nil {
		p, err := gtpv2.DecodeMMContext(mmIE)
		if err != nil {
			return nil, fmt.Errorf("s10: decode MMContext: %w", err)
		}
		resp.MMContext = *p
	}
	if pdnIE := gtpv2.FindIE(m.IEs, gtpv2.IETypePDNConnection, 0); pdnIE != nil {
		p, err := gtpv2.DecodePDNConnection(pdnIE)
		if err != nil {
			return nil, fmt.Errorf("s10: decode PDNConnection: %w", err)
		}
		resp.PDNConnection = *p
	}
	return resp, nil
}

// EncodeContextAcknowledge encodes a Context Acknowledge. peerTEID is the old MME's
// S10 local TEID (from ContextResponse.SenderFTEID.TEID).
func EncodeContextAcknowledge(cause uint8, seqNum, peerTEID uint32) []byte {
	ies := []gtpv2.IE{gtpv2.EncodeCause(cause)}
	msg := &gtpv2.Message{
		Type:   gtpv2.MsgContextAcknowledge,
		TEID:   peerTEID,
		SeqNum: seqNum,
		IEs:    ies,
	}
	return gtpv2.Encode(msg)
}

// DecodeContextAcknowledge decodes a Context Acknowledge message.
func DecodeContextAcknowledge(m *gtpv2.Message) (*ContextAcknowledge, error) {
	if m.Type != gtpv2.MsgContextAcknowledge {
		return nil, fmt.Errorf("s10: expected ContextAcknowledge (132), got %d", m.Type)
	}
	ack := &ContextAcknowledge{}
	if causeIE := gtpv2.FindIE(m.IEs, gtpv2.IETypeCause, 0); causeIE != nil {
		c, err := gtpv2.DecodeCause(causeIE)
		if err != nil {
			return nil, fmt.Errorf("s10: decode Cause: %w", err)
		}
		ack.Cause = c
	}
	return ack, nil
}

// BuildSenderFTEID builds a FTEID from a UDP address (ip:port) and a locally allocated TEID.
func BuildSenderFTEID(localAddr string, teid uint32) (gtpv2.FTEID, error) {
	host, _, err := net.SplitHostPort(localAddr)
	if err != nil {
		// no port suffix — treat as bare IP
		host = localAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return gtpv2.FTEID{}, fmt.Errorf("s10: invalid local addr %q", localAddr)
	}
	return gtpv2.FTEID{InterfaceType: gtpv2.IFTypeS10MME, TEID: teid, IP: ip.To4()}, nil
}
