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
	EPSBearerStatus     *EPSBearerContextStatus
}

// TAUAcceptParams holds the semantic inputs for a TAU Accept encoder.
type TAUAcceptParams struct {
	UpdateResult             uint8
	T3412                    uint8
	T3402                    *uint8
	T3423                    *uint8
	TAIList                  []TAI
	IncludeGUTI              bool
	GUTI                     *GUTI
	EPSBearerStatus          *EPSBearerContextStatus
	EPSNetworkFeatureSupport *EPSNetworkFeatureSupport
	LAI                      *LAI
	AdditionalUpdateResult   *uint8
	EMMCause                 *uint8
}

// TAUAccept holds decoded fields used by tests and diagnostics.
type TAUAccept struct {
	UpdateResult             uint8
	T3412                    *uint8
	TAIList                  []TAI
	GUTI                     *GUTI
	EPSBearerStatus          *EPSBearerContextStatus
	EPSNetworkFeatureSupport *EPSNetworkFeatureSupport
	LAI                      *LAI
	AdditionalUpdateResult   *uint8
	EMMCause                 *uint8
}

// EPSBearerContextStatus captures the active EPS bearer bitmap communicated in
// TAU and related NAS procedures. Bits 5..15 of Bitmap correspond to EBI 5..15.
type EPSBearerContextStatus struct {
	Bitmap uint16
}

func (s *EPSBearerContextStatus) HasEBI(ebi uint8) bool {
	if s == nil || ebi > 15 {
		return false
	}
	return s.Bitmap&(1<<ebi) != 0
}

func (s *EPSBearerContextStatus) ActiveEBIs() []uint8 {
	if s == nil {
		return nil
	}
	out := make([]uint8, 0, 11)
	for ebi := uint8(5); ebi <= 15; ebi++ {
		if s.HasEBI(ebi) {
			out = append(out, ebi)
		}
	}
	return out
}

func DecodeEPSBearerContextStatus(data []byte) (*EPSBearerContextStatus, error) {
	if len(data) != 2 {
		return nil, fmt.Errorf("emm: EPS bearer context status invalid length %d", len(data))
	}
	var bitmap uint16
	for ebi := uint8(5); ebi <= 7; ebi++ {
		if data[0]&(1<<ebi) != 0 {
			bitmap |= 1 << ebi
		}
	}
	for ebi := uint8(8); ebi <= 15; ebi++ {
		if data[1]&(1<<(ebi-8)) != 0 {
			bitmap |= 1 << ebi
		}
	}
	return &EPSBearerContextStatus{Bitmap: bitmap}, nil
}

func EncodeEPSBearerContextStatus(status EPSBearerContextStatus) []byte {
	var octet1 byte
	var octet2 byte
	for ebi := uint8(5); ebi <= 7; ebi++ {
		if status.Bitmap&(1<<ebi) != 0 {
			octet1 |= 1 << ebi
		}
	}
	for ebi := uint8(8); ebi <= 15; ebi++ {
		if status.Bitmap&(1<<ebi) != 0 {
			octet2 |= 1 << (ebi - 8)
		}
	}
	return []byte{octet1, octet2}
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

	AdditionalUpdateResultSMSOnly uint8 = 0x02
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

	// UE network capability. Some encodings carry this as a bare LV immediately
	// after the mobile identity; others include the explicit IEI 0x58 first.
	if offset < len(data) {
		if data[offset] == 0x58 {
			offset++
			if offset >= len(data) {
				return nil, fmt.Errorf("emm: TAU Request truncated at UE network capability length")
			}
		}
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
		case 0x00:
			// Some UEs insert a spare/zero octet between optional IEs in TAU Request.
			// Treat it as ignorable filler instead of trying to parse the following
			// byte as a TLV length, which would skip valid trailing IEs such as 0x57
			// EPS bearer context status.
			continue
		case 0x52: // Last visited registered TAI
			if offset+5 <= len(data) {
				tai, err := DecodeTAI(data[offset : offset+5])
				if err == nil {
					r.LastVisitedTAI = &tai
				}
				offset += 5
			}
		case 0x5c: // DRX parameter (fixed-length TV IE)
			if offset < len(data) {
				offset++
			}
		case 0x57: // EPS bearer context status
			ieLen := int(data[offset])
			offset++
			if offset+ieLen <= len(data) {
				status, err := DecodeEPSBearerContextStatus(data[offset : offset+ieLen])
				if err == nil {
					r.EPSBearerStatus = status
				}
				offset += ieLen
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

	// T3412 value IE: TV format, IEI=0x5A followed directly by the value.
	b = append(b, 0x5A, params.T3412)

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

	if params.EPSBearerStatus != nil {
		value := EncodeEPSBearerContextStatus(*params.EPSBearerStatus)
		b = append(b, 0x57, byte(len(value)))
		b = append(b, value...)
	}
	if params.LAI != nil {
		lai := params.LAI.Encode()
		b = append(b, 0x13, byte(len(lai)))
		b = append(b, lai...)
	}

	if params.T3402 != nil {
		b = append(b, 0x17, *params.T3402)
	}

	if params.T3423 != nil {
		b = append(b, 0x59, *params.T3423)
	}

	if params.EPSNetworkFeatureSupport != nil {
		b = append(b, EncodeEPSNetworkFeatureSupport(*params.EPSNetworkFeatureSupport)...)
	}
	if params.AdditionalUpdateResult != nil {
		// TS 24.301 §9.9.3.0A: type-1 IEI 0xF, bits 2..1 carry the result.
		b = append(b, 0xf0|(*params.AdditionalUpdateResult&0x03))
	}
	if params.EMMCause != nil {
		// EMM cause is a one-octet TV IE (IEI 0x53) in TAU Accept.
		b = append(b, 0x53, *params.EMMCause)
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
		if iei&0xf0 == 0xf0 { // Additional update result (type 1)
			v := iei & 0x03
			if v == 0x03 {
				return nil, fmt.Errorf("emm: TAU Accept reserved additional update result")
			}
			out.AdditionalUpdateResult = &v
			continue
		}
		switch iei {
		case 0x5A: // T3412 value — TV format: IEI followed directly by value
			if offset >= len(data) {
				return nil, fmt.Errorf("emm: TAU Accept truncated T3412")
			}

			v := data[offset]
			out.T3412 = &v
			offset++
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
		case 0x57: // EPS bearer context status
			if offset >= len(data) {
				return nil, fmt.Errorf("emm: TAU Accept truncated EPS bearer context status length")
			}
			l := int(data[offset])
			offset++
			if offset+l > len(data) {
				return nil, fmt.Errorf("emm: TAU Accept truncated EPS bearer context status")
			}
			status, err := DecodeEPSBearerContextStatus(data[offset : offset+l])
			if err != nil {
				return nil, err
			}
			out.EPSBearerStatus = status
			offset += l
		case 0x13: // Location area identification
			if offset >= len(data) {
				return nil, fmt.Errorf("emm: TAU Accept truncated LAI length")
			}
			l := int(data[offset])
			offset++
			if l != 5 || offset+l > len(data) {
				return nil, fmt.Errorf("emm: TAU Accept invalid LAI length %d", l)
			}
			lai, err := DecodeLAI(data[offset : offset+l])
			if err != nil {
				return nil, err
			}
			out.LAI = &lai
			offset += l
		case 0x53: // EMM cause (TV)
			if offset >= len(data) {
				return nil, fmt.Errorf("emm: TAU Accept truncated EMM cause")
			}
			v := data[offset]
			out.EMMCause = &v
			offset++
		case 0x17: // T3402 value
			if offset >= len(data) {
				return nil, fmt.Errorf("emm: TAU Accept truncated T3402")
			}
			offset++
		case 0x59: // T3423 value
			if offset >= len(data) {
				return nil, fmt.Errorf("emm: TAU Accept truncated T3423")
			}
			offset++
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
	taiList := make([]TAI, 0, maxTAIListElements)
	for offset := 0; offset < len(data); {
		if len(data)-offset < 6 {
			return nil, fmt.Errorf("emm: TAI list too short: %d bytes", len(data)-offset)
		}
		header := data[offset]
		offset++
		listType := (header >> 5) & 0x03
		count := int(header&0x1F) + 1

		switch listType {
		case taiListTypeOnePLMNNonConsecutive:
			expected := 3 + 2*count
			if len(data)-offset < expected {
				return nil, fmt.Errorf("emm: TAI list length got %d want at least %d", len(data)-offset, expected)
			}
			var plmn [3]byte
			copy(plmn[:], data[offset:offset+3])
			offset += 3
			for i := 0; i < count; i++ {
				if len(taiList) == maxTAIListElements {
					return taiList, nil
				}
				taiList = append(taiList, TAI{
					PLMN: plmn,
					TAC:  uint16(data[offset])<<8 | uint16(data[offset+1]),
				})
				offset += 2
			}
		case taiListTypeOnePLMNConsecutive:
			expected := 5
			if len(data)-offset < expected {
				return nil, fmt.Errorf("emm: TAI list length got %d want at least %d", len(data)-offset, expected)
			}
			var plmn [3]byte
			copy(plmn[:], data[offset:offset+3])
			offset += 3
			firstTAC := uint16(data[offset])<<8 | uint16(data[offset+1])
			offset += 2
			for i := 0; i < count; i++ {
				if len(taiList) == maxTAIListElements {
					return taiList, nil
				}
				taiList = append(taiList, TAI{
					PLMN: plmn,
					TAC:  firstTAC + uint16(i),
				})
			}
		case taiListTypeDifferentPLMNs:
			expected := 5 * count
			if len(data)-offset < expected {
				return nil, fmt.Errorf("emm: TAI list length got %d want at least %d", len(data)-offset, expected)
			}
			for i := 0; i < count; i++ {
				if len(taiList) == maxTAIListElements {
					return taiList, nil
				}
				var plmn [3]byte
				copy(plmn[:], data[offset:offset+3])
				offset += 3
				taiList = append(taiList, TAI{
					PLMN: plmn,
					TAC:  uint16(data[offset])<<8 | uint16(data[offset+1]),
				})
				offset += 2
			}
		default:
			return nil, fmt.Errorf("emm: unsupported TAI list type %d", listType)
		}
	}
	if len(taiList) == 0 {
		return nil, fmt.Errorf("emm: empty TAI list")
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
