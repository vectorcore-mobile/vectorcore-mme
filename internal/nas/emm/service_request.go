package emm

import (
	"fmt"

	"github.com/vectorcore/mme/internal/nas/security"
)

// ServiceRequest holds the decoded fields of a NAS Service Request message.
type ServiceRequest struct {
	KSI      uint8  // eKSI, bits [7:5] of byte[1]
	SN       uint8  // NAS sequence number, bits [4:0] of byte[1]
	ShortMAC uint16 // short MAC, bytes[2:4] MSB first
}

// DecodeServiceRequest decodes a 4-byte NAS Service Request PDU.
// Format (TS 24.301 §9.8):
//
//	byte[0] = (0x0C << 4) | 0x07   security header 0x0C, PD = EMM
//	byte[1] = (KSI << 5) | SN
//	byte[2] = ShortMAC >> 8
//	byte[3] = ShortMAC & 0xFF
func DecodeServiceRequest(pdu []byte) (*ServiceRequest, error) {
	if len(pdu) < 4 {
		return nil, fmt.Errorf("emm: Service Request PDU too short: %d bytes", len(pdu))
	}
	if (pdu[0] >> 4) != SecurityHeaderServiceRequest {
		return nil, fmt.Errorf("emm: not a Service Request: security header %d", pdu[0]>>4)
	}
	return &ServiceRequest{
		KSI:      (pdu[1] >> 5) & 0x07,
		SN:       pdu[1] & 0x1F,
		ShortMAC: uint16(pdu[2])<<8 | uint16(pdu[3]),
	}, nil
}

// VerifyShortMAC verifies the short MAC in a Service Request PDU and returns
// the reconstructed NAS COUNT on success (TS 24.301 §4.6.3.2, TS 33.401 §6.3.3).
//
// MESSAGE for MAC computation: [byte[1], 0x00, 0x00] (NAS-PDU starting at KSI|SN byte,
// with MAC bytes zeroed). XMAC is the first 2 bytes of the 4-byte EIA output.
func VerifyShortMAC(pdu []byte, intAlg uint8, knasInt []byte, storedULCount uint32) (ok bool, count uint32) {
	if len(pdu) < 4 {
		return false, 0
	}
	sn := uint32(pdu[1] & 0x1F)
	count = (storedULCount & 0xFFFFFFE0) | sn
	if count <= storedULCount {
		count += 0x20
	}

	msg := []byte{pdu[1], 0x00, 0x00}
	mac, err := security.ComputeNASMAC(intAlg, knasInt, count, 0, 0, msg)
	if err != nil || len(mac) < 2 {
		return false, count
	}
	rxMAC := uint16(pdu[2])<<8 | uint16(pdu[3])
	xmac := uint16(mac[0])<<8 | uint16(mac[1])
	return xmac == rxMAC, count
}

// EncodeServiceReject encodes a NAS Service Reject message (TS 24.301 §8.2.24).
func EncodeServiceReject(cause uint8) []byte {
	return []byte{
		PDEPSMobilityMgmt | SecurityHeaderPlain<<4,
		MsgServiceReject,
		cause,
	}
}
