package emm

import "fmt"

// TAURequest holds the decoded TAU Request fields.
type TAURequest struct {
	EPSUpdateType       uint8  // 0=TA updating, 1=combined, 3=periodic
	ActiveFlag          bool
	NASKeySetIdentifier uint8
	OldGUTI             *GUTI  // nil if identity is not a GUTI
	UENetworkCapability []byte
	LastVisitedTAI      *TAI
}

// EPS update type values (TS 24.301 §9.9.3.21).
const (
	EPSUpdateTypeTA       uint8 = 0x00 // TA updating
	EPSUpdateTypeCombined uint8 = 0x01 // combined TA/LA updating
	EPSUpdateTypePeriodic uint8 = 0x03 // periodic updating
)

// DecodeTAURequest decodes a TAU Request message body (after the 2-byte NAS header).
// Layout (TS 24.301 §8.2.29):
//
//	byte[0]:  (eKSI<<4) | (activeFlag<<3) | updateType
//	LV:       mobile identity (GUTI, S-TMSI, IMSI, …)
//	LV:       UE network capability
//	optional TLV IEs (IEI 0x52 = last visited TAI, etc.)
func DecodeTAURequest(data []byte) (*TAURequest, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("emm: TAU Request too short: %d bytes", len(data))
	}

	r := &TAURequest{}
	offset := 0

	// Byte 0: eKSI | active flag | update type
	r.NASKeySetIdentifier = (data[offset] >> 4) & 0x07
	r.ActiveFlag = (data[offset]>>3)&1 == 1
	r.EPSUpdateType = data[offset] & 0x07
	offset++

	// LV: mobile identity
	if offset >= len(data) {
		return nil, fmt.Errorf("emm: TAU Request truncated at mobile identity")
	}
	idLen := int(data[offset])
	offset++
	if offset+idLen > len(data) {
		return nil, fmt.Errorf("emm: TAU Request mobile identity truncated")
	}
	idBytes := data[offset : offset+idLen]
	offset += idLen

	if len(idBytes) > 0 {
		idType := idBytes[0] & 0x07
		if idType == IdentityTypeGUTI {
			g, err := decodeGUTI(idBytes)
			if err == nil {
				r.OldGUTI = g
			}
		}
	}

	// LV: UE network capability (mandatory per spec, but tolerate missing)
	if offset < len(data) {
		capLen := int(data[offset])
		offset++
		if offset+capLen <= len(data) {
			r.UENetworkCapability = data[offset : offset+capLen]
			offset += capLen
		}
	}

	// Optional TLV IEs
	for offset < len(data) {
		iei := data[offset]
		offset++
		if offset >= len(data) {
			break
		}
		switch iei {
		case 0x52: // Last visited registered TAI
			if offset+5 <= len(data) {
				tai, err := DecodeTAI(data[offset : offset+5])
				if err == nil {
					r.LastVisitedTAI = &tai
				}
				offset += 5
			}
		default:
			if iei&0x80 != 0 {
				// Type-1 half-octet IE — already consumed, no length byte
				continue
			}
			// Type-4/6 TLV: next byte is length
			if offset >= len(data) {
				break
			}
			ieLen := int(data[offset])
			offset++
			if offset+ieLen <= len(data) {
				offset += ieLen
			}
		}
	}

	return r, nil
}

// EncodeTAUAccept encodes a NAS TAU Accept message (TS 24.301 §8.2.26).
func EncodeTAUAccept(result uint8, t3412 uint8, taiList []TAI, guti *GUTI) []byte {
	b := make([]byte, 0, 32)

	b = append(b, PDEPSMobilityMgmt|SecurityHeaderPlain<<4)
	b = append(b, MsgTrackingAreaUpdateAccept)

	// EPS update result (bits 2:0)
	b = append(b, result&0x07)

	// T3412 value IE: IEI=0x5A, length=1, value
	b = append(b, 0x5A, 0x01, t3412)

	// TAI list IE: IEI=0x54, length, value
	taiBytes := encodeTAIList(taiList)
	if len(taiBytes) > 0 {
		b = append(b, 0x54)
		b = append(b, byte(len(taiBytes)))
		b = append(b, taiBytes...)
	}

	// GUTI reallocation IE: IEI=0x50, LV
	if guti != nil {
		b = append(b, 0x50)
		b = append(b, guti.Encode()...)
	}

	return b
}

// EncodeTAUReject encodes a NAS TAU Reject message (TS 24.301 §8.2.27).
func EncodeTAUReject(cause uint8) []byte {
	return []byte{
		PDEPSMobilityMgmt | SecurityHeaderPlain<<4,
		MsgTrackingAreaUpdateReject,
		cause,
	}
}
