package emm

import "fmt"

// TAURequest holds the decoded TAU Request fields.
type TAURequest struct {
	EPSUpdateType       uint8 // 0=TA updating, 1=combined, 3=periodic
	ActiveFlag          bool
	NASKeySetIdentifier uint8
	OldGUTI             *GUTI // nil if identity is not a GUTI
	UENetworkCapability []byte
	LastVisitedTAI      *TAI
}

// TAUAcceptParams holds the semantic inputs for a TAU Accept encoder.
type TAUAcceptParams struct {
	UpdateResult             uint8
	T3412                    uint8
	TAIList                  []TAI
	IncludeGUTI              bool
	GUTI                     *GUTI
	EPSNetworkFeatureSupport *EPSNetworkFeatureSupport
}

// TAUAccept holds decoded fields used by tests and diagnostics.
type TAUAccept struct {
	UpdateResult             uint8
	T3412                    *uint8
	TAIList                  []TAI
	GUTI                     *GUTI
	EPSNetworkFeatureSupport *EPSNetworkFeatureSupport
}

// EPS update type values (TS 24.301 §9.9.3.21).
const (
	EPSUpdateTypeTA                 uint8 = 0x00 // TA updating
	EPSUpdateTypeCombined           uint8 = 0x01 // combined TA/LA updating
	EPSUpdateTypeCombinedIMSIAttach uint8 = 0x02 // combined TA/LA updating with IMSI attach
	EPSUpdateTypePeriodic           uint8 = 0x03 // periodic updating
)

// EPS update result values (TS 24.301 §9.9.3.22).
const (
	EPSUpdateResultTAUpdated              uint8 = 0x00
	EPSUpdateResultCombinedTALAUpdated    uint8 = 0x01
	EPSUpdateResultTAUpdatedISR           uint8 = 0x02
	EPSUpdateResultCombinedTALAUpdatedISR uint8 = 0x03
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
	return EncodeTAUAcceptWithParams(TAUAcceptParams{
		UpdateResult: result,
		T3412:        t3412,
		TAIList:      taiList,
		IncludeGUTI:  guti != nil,
		GUTI:         guti,
	})
}

// EncodeTAUAcceptWithParams encodes a NAS TAU Accept from structured fields.
func EncodeTAUAcceptWithParams(params TAUAcceptParams) []byte {
	b := make([]byte, 0, 32)

	b = append(b, PDEPSMobilityMgmt|SecurityHeaderPlain<<4)
	b = append(b, MsgTrackingAreaUpdateAccept)

	// EPS update result (bits 2:0)
	b = append(b, params.UpdateResult&0x07)

	// T3412 value IE: IEI=0x5A, length=1, value
	b = append(b, 0x5A, 0x01, params.T3412)

	// TAI list IE: IEI=0x54, length, value
	taiBytes := encodeTAIList(params.TAIList)
	if len(taiBytes) > 0 {
		b = append(b, 0x54)
		b = append(b, byte(len(taiBytes)))
		b = append(b, taiBytes...)
	}

	// GUTI reallocation IE: IEI=0x50, LV
	if params.IncludeGUTI && params.GUTI != nil {
		b = append(b, 0x50)
		b = append(b, params.GUTI.Encode()...)
	}

	if params.EPSNetworkFeatureSupport != nil {
		b = append(b, EncodeEPSNetworkFeatureSupport(*params.EPSNetworkFeatureSupport)...)
	}

	return b
}

// DecodeTAUAccept decodes the subset of TAU Accept fields emitted by the encoder.
func DecodeTAUAccept(data []byte) (*TAUAccept, error) {
	if len(data) < 3 {
		return nil, fmt.Errorf("emm: TAU Accept too short: %d bytes", len(data))
	}
	pd := data[0] & 0x0F
	if pd != PDEPSMobilityMgmt || data[1] != MsgTrackingAreaUpdateAccept {
		return nil, fmt.Errorf("emm: not a TAU Accept")
	}

	out := &TAUAccept{UpdateResult: data[2] & 0x07}
	offset := 3
	for offset < len(data) {
		iei := data[offset]
		offset++
		switch iei {
		case 0x5A: // T3412 value
			if offset+2 > len(data) {
				return nil, fmt.Errorf("emm: TAU Accept truncated T3412")
			}
			if data[offset] != 1 {
				return nil, fmt.Errorf("emm: TAU Accept invalid T3412 length %d", data[offset])
			}
			v := data[offset+1]
			out.T3412 = &v
			offset += 2
		case 0x54: // TAI list
			if offset >= len(data) {
				return nil, fmt.Errorf("emm: TAU Accept truncated TAI list length")
			}
			l := int(data[offset])
			offset++
			if offset+l > len(data) {
				return nil, fmt.Errorf("emm: TAU Accept truncated TAI list")
			}
			taiList, err := decodeTAIList(data[offset : offset+l])
			if err != nil {
				return nil, err
			}
			out.TAIList = taiList
			offset += l
		case 0x50: // GUTI reallocation
			if offset >= len(data) {
				return nil, fmt.Errorf("emm: TAU Accept truncated GUTI length")
			}
			l := int(data[offset])
			if offset+1+l > len(data) {
				return nil, fmt.Errorf("emm: TAU Accept truncated GUTI")
			}
			guti, err := decodeGUTI(data[offset+1 : offset+1+l])
			if err != nil {
				return nil, err
			}
			out.GUTI = guti
			offset += 1 + l
		case 0x64: // EPS network feature support
			if offset >= len(data) {
				return nil, fmt.Errorf("emm: TAU Accept truncated EPS network feature support length")
			}
			l := int(data[offset])
			offset++
			if l < 1 || offset+l > len(data) {
				return nil, fmt.Errorf("emm: TAU Accept invalid EPS network feature support length %d", l)
			}
			out.EPSNetworkFeatureSupport = &EPSNetworkFeatureSupport{
				IMSVoiceOverPSSessionInS1Mode: data[offset]&0x01 != 0,
			}
			offset += l
		default:
			return nil, fmt.Errorf("emm: TAU Accept unsupported IEI 0x%02x at offset %d", iei, offset-1)
		}
	}
	return out, nil
}

func decodeTAIList(data []byte) ([]TAI, error) {
	if len(data) == 0 {
		return nil, nil
	}
	if len(data) < 6 {
		return nil, fmt.Errorf("emm: TAI list too short: %d bytes", len(data))
	}
	header := data[0]
	listType := (header >> 5) & 0x03
	count := int(header&0x1F) + 1
	if listType != 0 {
		return nil, fmt.Errorf("emm: unsupported TAI list type %d", listType)
	}
	expected := 1 + 3 + 2*count
	if len(data) != expected {
		return nil, fmt.Errorf("emm: TAI list length got %d want %d", len(data), expected)
	}
	var plmn [3]byte
	copy(plmn[:], data[1:4])
	taiList := make([]TAI, 0, count)
	offset := 4
	for i := 0; i < count; i++ {
		taiList = append(taiList, TAI{
			PLMN: plmn,
			TAC:  uint16(data[offset])<<8 | uint16(data[offset+1]),
		})
		offset += 2
	}
	return taiList, nil
}

// EncodeTAUReject encodes a NAS TAU Reject message (TS 24.301 §8.2.27).
func EncodeTAUReject(cause uint8) []byte {
	return []byte{
		PDEPSMobilityMgmt | SecurityHeaderPlain<<4,
		MsgTrackingAreaUpdateReject,
		cause,
	}
}
