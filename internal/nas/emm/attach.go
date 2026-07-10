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
	ESMContainer        []byte // contains NAS ESM message (PDN Connectivity Request)
	OldTAI              *TAI
	TAI                 *TAI // last visited TAI
	LastVisitedTAI      *TAI
}

// AttachComplete holds the decoded Attach Complete body.
type AttachComplete struct {
	ESMContainer []byte
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

	// Optional IEs (parse what we need, skip the rest)
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
					ar.LastVisitedTAI = &tai
				}
				offset += 5
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

	return ar, nil
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
	b := make([]byte, 0, 64)

	// Header: PD=EMM, security header=plain, message type=Attach Accept
	b = append(b, PDEPSMobilityMgmt|SecurityHeaderPlain<<4)
	b = append(b, MsgAttachAccept)

	// EPS attach result (bits 2:0)
	b = append(b, attachResult&0x07)

	// T3412 timer value (periodic TAU timer) — 54 minutes default (0x23 = binary 00100011 = 3*6 hours = 18 hours? Let's use 0xA8 = 5 min * 1 = 5 min unit)
	// Timer value: unit=minutes (bits 7:5 = 010), value (bits 4:0 = 00001) → 1 minute
	b = append(b, 0x21) // binary 0010 0001 = 1 minute

	// TAI list (mandatory) - we encode as partial TAI list type 0x00
	taiBytes := encodeTAIList(taiList)
	b = append(b, byte(len(taiBytes)))
	b = append(b, taiBytes...)

	// ESM message container (mandatory)
	esmLen := make([]byte, 2)
	binary.BigEndian.PutUint16(esmLen, uint16(len(esmContainer)))
	b = append(b, esmLen...)
	b = append(b, esmContainer...)

	// GUTI (optional, IEI 0x50)
	if guti != nil {
		b = append(b, 0x50)
		gutiBytes := guti.Encode()
		b = append(b, gutiBytes...)
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

// encodeTAIList encodes a list of TAIs as partial TAI list type 0x00
// (list of TAIs belonging to the same PLMN).
func encodeTAIList(tais []TAI) []byte {
	if len(tais) == 0 {
		return nil
	}
	// Type 0x00: list of TACs with the same PLMN
	// Format: type/number (1B) | PLMN (3B) | TAC1 (2B) | TAC2 (2B) | ...
	b := make([]byte, 0, 4+len(tais)*2)
	b = append(b, byte(0x00|(len(tais)-1)&0x1F)) // type=00, num elements-1
	b = append(b, tais[0].PLMN[:]...)
	for _, t := range tais {
		b = append(b, byte(t.TAC>>8), byte(t.TAC))
	}
	return b
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
	digits := make([]byte, 0, 15)
	if odd {
		digits = append(digits, '0'+data[0]>>4)
	}
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
	if len(data) < 10 {
		return nil, fmt.Errorf("emm: GUTI IE too short: %d", len(data))
	}
	g := &GUTI{}
	copy(g.PLMN[:], data[1:4])
	g.MMEGI = binary.BigEndian.Uint16(data[4:6])
	g.MMEC = data[6]
	g.MTMSI = binary.BigEndian.Uint32(data[7:11])
	return g, nil
}
