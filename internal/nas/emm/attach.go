package emm

import (
	"encoding/binary"
	"fmt"
)

// AttachType values (3GPP TS 24.301 §9.9.3.3).
const (
	AttachTypeEPSOnly            uint8 = 0x01
	AttachTypeCombinedEPSAndIMSI uint8 = 0x02
	AttachTypeEPSEmergency       uint8 = 0x06
)

// EPSMobileIdentityType values.
const (
	IdentityTypeIMSI   uint8 = 0x01
	IdentityTypeIMEI   uint8 = 0x02
	IdentityTypeIMEISV uint8 = 0x03
	IdentityTypeTMSI   uint8 = 0x04
	IdentityTypeGUTI   uint8 = 0x06
)

// AttachRequest holds the decoded fields of a NAS Attach Request.
type AttachRequest struct {
	AttachType          uint8
	NASKeySetIdentifier uint8
	EPS_MobileIdentity  []byte // raw mobile identity (GUTI, IMSI, etc.)
	IdentityType        uint8  // parsed from EPS_MobileIdentity
	IMSI                string // set if IdentityType == IMSI
	GUTI                *GUTI  // set if IdentityType == GUTI
	UENetworkCapability []byte
	MSNetworkCapability []byte
	ESMContainer        []byte // contains NAS ESM message (PDN Connectivity Request)
	OldTAI              *TAI
	TAI                 *TAI // last visited TAI
	LastVisitedTAI      *TAI
	// AdditionalUpdateType is nil when the IE is absent. When present, bit 1
	// (AdditionalUpdateTypeSMSOnlyBit) set means the UE requested "SMS only"
	// rather than a full combined attach (TS 24.301 §9.9.3.0B).
	AdditionalUpdateType *uint8
}

// AdditionalUpdateTypeSMSOnlyBit is bit 1 (AUTV) of the Additional update
// type IE value: set means "SMS only", clear means "no additional
// information" (interpreted as a request for combined attach/TAU).
const AdditionalUpdateTypeSMSOnlyBit uint8 = 0x01

// AttachComplete holds the decoded Attach Complete body.
type AttachComplete struct {
	ESMContainer []byte
}

type AttachAcceptParams struct {
	AttachResult             uint8
	T3412                    uint8
	T3402                    *uint8
	T3423                    *uint8
	TAIList                  []TAI
	GUTI                     *GUTI
	ESMContainer             []byte
	EPSNetworkFeatureSupport *EPSNetworkFeatureSupport
	AdditionalUpdateResult   *uint8
	// LAI is the real SGs-assigned location area identification (TS 24.301
	// §8.2.1.3), included only for a genuine combined attach where an SGs
	// Location Update actually succeeded. It is deliberately distinct from
	// the SGd-only "combined" result, which never carries a LAI.
	LAI *LAI
	// NewTMSI is a VLR-assigned TMSI (from SGsAP-LOCATION-UPDATE-ACCEPT)
	// relayed to the UE via the "MS identity" IE, TS 29.118 §5.2.2.3. Only
	// meaningful alongside LAI - a CS-domain identity means nothing to a UE
	// without an SGs association.
	NewTMSI *uint32
}

// DecodeAttachRequest decodes a NAS Attach Request message body (after the 2-byte header).
func DecodeAttachRequest(data []byte) (*AttachRequest, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("emm: Attach Request too short: %d bytes", len(data))
	}

	ar := &AttachRequest{}
	offset := 0

	// Byte 0: EPS attach type (bits 2:0) + NAS key set identifier (bits 6:4)
	ar.AttachType = data[offset] & 0x07
	ar.NASKeySetIdentifier = (data[offset] >> 4) & 0x07
	offset++

	// Old GUTI or IMSI (EPS mobile identity)
	if offset >= len(data) {
		return nil, fmt.Errorf("emm: Attach Request truncated at mobile identity")
	}
	mobileIDLen := int(data[offset])
	offset++
	if offset+mobileIDLen > len(data) {
		return nil, fmt.Errorf("emm: Attach Request mobile identity truncated")
	}
	ar.EPS_MobileIdentity = data[offset : offset+mobileIDLen]
	ar.IdentityType = ar.EPS_MobileIdentity[0] & 0x07

	switch ar.IdentityType {
	case IdentityTypeIMSI:
		ar.IMSI = decodeIMSI(ar.EPS_MobileIdentity)
	case IdentityTypeGUTI:
		g, err := decodeGUTI(ar.EPS_MobileIdentity)
		if err == nil {
			ar.GUTI = g
		}
	}
	offset += mobileIDLen

	// UE network capability (mandatory)
	if offset >= len(data) {
		return nil, fmt.Errorf("emm: Attach Request truncated at UE network capability")
	}
	capLen := int(data[offset])
	offset++
	if offset+capLen > len(data) {
		return nil, fmt.Errorf("emm: UE network capability truncated")
	}
	ar.UENetworkCapability = data[offset : offset+capLen]
	offset += capLen

	// ESM message container (mandatory)
	if offset+2 > len(data) {
		return nil, fmt.Errorf("emm: Attach Request truncated before ESM container")
	}
	esmLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if offset+esmLen > len(data) {
		return nil, fmt.Errorf("emm: ESM container truncated")
	}
	ar.ESMContainer = data[offset : offset+esmLen]
	offset += esmLen

	optionalStart := offset

	// Optional IEs (parse what we need, skip the rest)
	for offset < len(data) {
		iei := data[offset]
		offset++
		if iei&0xf0 == 0xf0 {
			// Additional update type: type-1 half-octet IE, IEI 0xF. Already
			// fully consumed by the single IEI byte - checked before the
			// bounds guard below, which only applies to IEs that need a
			// following value/length byte.
			v := iei & 0x0F
			ar.AdditionalUpdateType = &v
			continue
		}
		if offset >= len(data) {
			break
		}
		switch iei {
		case 0x52: // Last visited registered TAI
			if offset+5 <= len(data) {
				tai, err := DecodeTAI(data[offset : offset+5])
				if err == nil {
					ar.LastVisitedTAI = &tai
				}
				offset += 5
			}
		case 0x31: // MS network capability
			ieLen := int(data[offset])
			offset++
			if offset+ieLen <= len(data) {
				ar.MSNetworkCapability = append([]byte(nil), data[offset:offset+ieLen]...)
				offset += ieLen
			}
		case 0x5c: // DRX parameter, fixed 2-octet value
			if offset+2 <= len(data) {
				offset += 2
			}
		default:
			// Type-1 IEs: IEI in high nibble (0xC0-0xF0), value in low nibble, no length byte.
			if iei&0x80 != 0 {
				// high bit set → type-1 half-octet IE (1 byte total, already consumed)
				continue
			}
			// Type-4/6 TLV: next byte is length
			if offset >= len(data) {
				break
			}
			ieLen := int(data[offset])
			offset++
			if offset+ieLen > len(data) {
				break
			}
			offset += ieLen
		}
	}
	if len(ar.MSNetworkCapability) == 0 {
		ar.MSNetworkCapability = findMSNetworkCapability(data[optionalStart:])
	}

	return ar, nil
}

func findMSNetworkCapability(optional []byte) []byte {
	for i := 0; i+2 <= len(optional); i++ {
		if optional[i] != 0x31 {
			continue
		}
		ieLen := int(optional[i+1])
		if ieLen < 3 || ieLen > 9 || i+2+ieLen > len(optional) {
			continue
		}
		return append([]byte(nil), optional[i+2:i+2+ieLen]...)
	}
	return nil
}

// DecodeAttachComplete decodes a NAS Attach Complete message body (after the
// EMM header). The body contains a mandatory ESM message container.
func DecodeAttachComplete(data []byte) (*AttachComplete, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("emm: Attach Complete truncated before ESM container")
	}
	esmLen := int(binary.BigEndian.Uint16(data[0:2]))
	if len(data) < 2+esmLen {
		return nil, fmt.Errorf("emm: Attach Complete ESM container truncated")
	}
	return &AttachComplete{ESMContainer: append([]byte(nil), data[2:2+esmLen]...)}, nil
}

// EncodeAttachAccept encodes a NAS Attach Accept message.
// For Phase 1, ESMContainer contains a PDN Connectivity Reject (no bearer).
func EncodeAttachAccept(
	attachResult uint8,
	taiList []TAI,
	guti *GUTI,
	esmContainer []byte,
) []byte {
	return EncodeAttachAcceptWithParams(AttachAcceptParams{
		AttachResult: attachResult,
		T3412:        0x49,
		TAIList:      taiList,
		GUTI:         guti,
		ESMContainer: esmContainer,
	})
}

func EncodeAttachAcceptWithParams(params AttachAcceptParams) []byte {
	b := make([]byte, 0, 64)

	// Header: PD=EMM, security header=plain, message type=Attach Accept
	b = append(b, PDEPSMobilityMgmt|SecurityHeaderPlain<<4)
	b = append(b, MsgAttachAccept)

	// EPS attach result (bits 2:0)
	b = append(b, params.AttachResult&0x07)

	// T3412 timer value (periodic TAU timer) is mandatory in Attach Accept.
	b = append(b, params.T3412)

	// TAI list (mandatory) - we encode as partial TAI list type 0x00
	taiBytes := encodeTAIList(params.TAIList)
	b = append(b, byte(len(taiBytes)))
	b = append(b, taiBytes...)

	// ESM message container (mandatory)
	esmLen := make([]byte, 2)
	binary.BigEndian.PutUint16(esmLen, uint16(len(params.ESMContainer)))
	b = append(b, esmLen...)
	b = append(b, params.ESMContainer...)

	// GUTI (optional, IEI 0x50)
	if params.GUTI != nil {
		b = append(b, 0x50)
		gutiBytes := params.GUTI.Encode()
		b = append(b, gutiBytes...)
	}

	// Location area identification (optional, IEI 0x13). TS 24.301 Table
	// 8.2.1.1 marks this IE format TV, length 6 (IEI + fixed 5-octet value,
	// no length octet) - unlike GUTI/MS identity, which are TLV. Encoded the
	// same way as the sibling TAU Accept LAI IE (internal/nas/emm/tau.go).
	if params.LAI != nil {
		b = append(b, 0x13)
		b = append(b, params.LAI.Encode()...)
	}

	// MS identity (optional, IEI 0x23, TLV per TS 24.301 Table 8.2.1.1).
	// Relays a VLR-assigned TMSI (TS 29.118 §5.2.2.3).
	if params.NewTMSI != nil {
		msIdentity := EncodeMSIdentityTMSI(*params.NewTMSI)
		b = append(b, 0x23, byte(len(msIdentity)))
		b = append(b, msIdentity...)
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
		// TS 24.301 §9.9.3.0A: type-1 IEI 0xF; value zero is explicit F0.
		b = append(b, 0xf0|(*params.AdditionalUpdateResult&0x03))
	}

	return b
}

// EncodeAttachReject encodes a NAS Attach Reject message.
func EncodeAttachReject(cause uint8) []byte {
	return []byte{
		PDEPSMobilityMgmt | SecurityHeaderPlain<<4,
		MsgAttachReject,
		cause,
	}
}

const (
	taiListTypeOnePLMNNonConsecutive uint8 = 0
	taiListTypeOnePLMNConsecutive    uint8 = 1
	taiListTypeDifferentPLMNs        uint8 = 2
	maxTAIListElements               int   = 16
)

// encodeTAIList encodes a NAS Tracking Area Identity list using one or more
// partial TAI sublists as defined in TS 24.301 §9.9.3.33. It preserves the
// input order and emits compact type 01 runs for consecutive TAC sequences.
func encodeTAIList(tais []TAI) []byte {
	if len(tais) == 0 {
		return nil
	}
	if len(tais) > maxTAIListElements {
		tais = tais[:maxTAIListElements]
	}

	b := make([]byte, 0, 1+len(tais)*5)
	for i := 0; i < len(tais); {
		if run := consecutiveTAIRunLength(tais, i); run >= 2 {
			b = appendTAIListType01(b, tais[i], run)
			i += run
			continue
		}

		end := i + 1
		for end < len(tais) && end-i < maxTAIListElements {
			if tais[end].PLMN != tais[i].PLMN {
				break
			}
			if consecutiveTAIRunLength(tais, end) >= 2 {
				break
			}
			end++
		}
		b = appendTAIListType00(b, tais[i:end])
		i = end
	}
	return b
}

func appendTAIListType00(dst []byte, tais []TAI) []byte {
	dst = append(dst, byte(taiListTypeOnePLMNNonConsecutive<<5)|byte(len(tais)-1))
	dst = append(dst, tais[0].PLMN[:]...)
	for _, tai := range tais {
		dst = append(dst, byte(tai.TAC>>8), byte(tai.TAC))
	}
	return dst
}

func appendTAIListType01(dst []byte, first TAI, count int) []byte {
	dst = append(dst, byte(taiListTypeOnePLMNConsecutive<<5)|byte(count-1))
	dst = append(dst, first.PLMN[:]...)
	dst = append(dst, byte(first.TAC>>8), byte(first.TAC))
	return dst
}

func consecutiveTAIRunLength(tais []TAI, start int) int {
	run := 1
	for start+run < len(tais) && run < maxTAIListElements {
		prev := tais[start+run-1]
		next := tais[start+run]
		if next.PLMN != prev.PLMN || next.TAC != prev.TAC+1 {
			break
		}
		run++
	}
	return run
}

// decodeIMSI extracts an IMSI string from the mobile identity IE.
// For odd-length IMSIs, a trailing byte whose high nibble is 0xF is a spurious
// filler byte added by some encoders — the byte is skipped entirely in that case.
// For even-length IMSIs the final 0xF high nibble is the standard filler; only
// the low nibble (the last digit) is appended.
func decodeIMSI(data []byte) string {
	if len(data) < 1 {
		return ""
	}
	odd := (data[0]>>3)&1 == 1
	digits := make([]byte, 0, 16)
	// The first digit is always carried in bits 8..5 of octet 1. The
	// odd/even bit describes the number of identity digits; it does not make a
	// leading zero padding. Dropping it broke even-length IMEISVs such as 03… .
	digits = append(digits, '0'+(data[0]>>4))
	for i := 1; i < len(data); i++ {
		lo := data[i] & 0x0F
		hi := data[i] >> 4
		// In odd encoding a trailing 0xF high nibble is a spurious extra byte; skip it.
		if odd && i == len(data)-1 && hi == 0x0F {
			break
		}
		if lo != 0x0F {
			digits = append(digits, '0'+lo)
		}
		if hi != 0x0F {
			digits = append(digits, '0'+hi)
		}
	}
	return string(digits)
}

// decodeGUTI extracts a GUTI from the mobile identity IE.
func decodeGUTI(data []byte) (*GUTI, error) {
	// Byte 0: identity type bits should be 0x06
	if len(data) < 11 {
		return nil, fmt.Errorf("emm: GUTI IE too short: %d", len(data))
	}
	g := &GUTI{}
	copy(g.PLMN[:], data[1:4])
	g.MMEGI = binary.BigEndian.Uint16(data[4:6])
	g.MMEC = data[6]
	g.MTMSI = binary.BigEndian.Uint32(data[7:11])
	return g, nil
}
