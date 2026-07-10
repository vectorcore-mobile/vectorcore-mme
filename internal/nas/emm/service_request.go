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

type ServiceRequestMACDetails struct {
	KSI                uint8
	SequenceNumber     uint8
	StoredULCount      uint32
	Overflow           uint32
	ReconstructedCount uint32
	Bearer             uint8
	Direction          uint8
	ExpectedShortMAC   []byte
	ComputedMAC        []byte
	ComputedShortMAC   []byte
	MessageForMAC      []byte
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
// MESSAGE for MAC computation is the first two Service Request octets:
// security header/protocol discriminator and KSI/sequence number. XMAC is the
// last two bytes of the 4-byte EIA output, matching srsRAN and Open5GS.
func VerifyShortMAC(pdu []byte, intAlg uint8, knasInt []byte, storedULCount uint32) (ok bool, count uint32) {
	ok, details := VerifyShortMACDetailed(pdu, intAlg, knasInt, storedULCount)
	if details == nil {
		return ok, 0
	}
	return ok, details.ReconstructedCount
}

func VerifyShortMACDetailed(pdu []byte, intAlg uint8, knasInt []byte, storedULCount uint32) (ok bool, details *ServiceRequestMACDetails) {
	if len(pdu) < 4 {
		return false, nil
	}

	ksi := (pdu[1] >> 5) & 0x07
	sn := pdu[1] & 0x1F
	count := (storedULCount & 0xFFFFFFE0) | uint32(sn)
	if count <= storedULCount {
		count += 0x20
	}

	msg := append([]byte(nil), pdu[:2]...)
	mac, err := security.ComputeNASMAC(intAlg, knasInt, count, 0, 0, msg)
	details = &ServiceRequestMACDetails{
		KSI:                ksi,
		SequenceNumber:     sn,
		StoredULCount:      storedULCount,
		Overflow:           count >> 5,
		ReconstructedCount: count,
		Bearer:             0,
		Direction:          0,
		ExpectedShortMAC:   append([]byte(nil), pdu[2:4]...),
		ComputedMAC:        append([]byte(nil), mac...),
		MessageForMAC:      msg,
	}
	if err != nil || len(mac) < 2 {
		return false, details
	}
	if len(mac) >= 4 {
		details.ComputedShortMAC = append([]byte(nil), mac[2:4]...)
	}
	return len(details.ComputedShortMAC) == 2 &&
		details.ComputedShortMAC[0] == details.ExpectedShortMAC[0] &&
		details.ComputedShortMAC[1] == details.ExpectedShortMAC[1], details
}

// EncodeServiceReject encodes a NAS Service Reject message (TS 24.301 §8.2.24).
func EncodeServiceReject(cause uint8) []byte {
	return []byte{
		PDEPSMobilityMgmt | SecurityHeaderPlain<<4,
		MsgServiceReject,
		cause,
	}
}
