package gtpv2

import (
	"fmt"
	"net"
	"time"
)

// ReleaseAccessBearersRequest holds the parameters for a GTPv2-C Release Access
// Bearers Request (TS 29.274 §7.2.70).
type ReleaseAccessBearersRequest struct {
	SGWAddress      string
	SGWC_TEID       uint32
	OriginatingNode uint8
	MMES11TEID      uint32
	MMES11IP        net.IP
	APN             string
	DefaultEBI      uint8
	SessionState    string
	LastS11Procedure string
	TransactionID   string
}

// ReleaseAccessBearersResponse holds the decoded fields from a GTPv2-C Release
// Access Bearers Response.
type ReleaseAccessBearersResponse struct {
	Cause uint8
}

type ReleaseAccessBearersResult struct {
	Peer                       string
	SeqNum                     uint32
	RequestedSGWCTEID          uint32
	RequestedMMES11TEID        uint32
	ResponseHeaderTEID         uint32
	APN                        string
	DefaultEBI                 uint8
	SessionState               string
	LastSuccessfulS11Procedure string
	TransactionID              string
	SentAt                     time.Time
	Elapsed                    time.Duration
	Cause                      uint8
}

// Encode returns the wire bytes for this Release Access Bearers Request with
// the given sequence number.
func (r *ReleaseAccessBearersRequest) Encode(seqNum uint32) []byte {
	msg := &Message{
		Type:   MsgReleaseAccessBearersRequest,
		TEID:   r.SGWC_TEID,
		SeqNum: seqNum,
		IEs:    []IE{EncodeNodeType(r.OriginatingNode)},
	}
	return Encode(msg)
}

// DecodeReleaseAccessBearersResponse decodes the Cause from a RABRsp.
func DecodeReleaseAccessBearersResponse(m *Message) (*ReleaseAccessBearersResponse, error) {
	if m.Type != MsgReleaseAccessBearersResponse {
		return nil, fmt.Errorf("gtpv2: expected RABRsp (171), got %d", m.Type)
	}
	cause, err := DecodeCause(FindIE(m.IEs, IETypeCause, 0))
	if err != nil {
		return nil, err
	}
	return &ReleaseAccessBearersResponse{Cause: cause}, nil
}
