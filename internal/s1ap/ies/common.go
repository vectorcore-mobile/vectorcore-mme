// Package ies provides encode/decode helpers for S1AP Information Elements.
// Each function encodes or decodes the IE value bytes (not the ProtocolIE wrapper).
package ies

import (
	"encoding/binary"
	"fmt"
	"strconv"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/nas/emm"
)

// ── UE S1AP IDs ──────────────────────────────────────────────────────────────

// EncodeMMEUEApID encodes a MME-UE-S1AP-ID (0..4294967295).
func EncodeMMEUEApID(id uint32) []byte {
	w := aper.NewBitWriter()
	_ = aper.EncodeConstrainedWholeNumber(w, int64(id), 0, 4294967295)
	return w.Bytes()
}

// DecodeMMEUEApID decodes a MME-UE-S1AP-ID.
func DecodeMMEUEApID(data []byte) (uint32, error) {
	v, err := decodeExactConstrainedWholeNumber(data, 0, 4294967295)
	if err == nil {
		return uint32(v), nil
	}
	if len(data) == 4 {
		return binary.BigEndian.Uint32(data), nil
	}
	return 0, err
}

// EncodeENBUEApID encodes an ENB-UE-S1AP-ID (0..16777215).
func EncodeENBUEApID(id uint32) []byte {
	w := aper.NewBitWriter()
	_ = aper.EncodeConstrainedWholeNumber(w, int64(id), 0, 16777215)
	return w.Bytes()
}

// DecodeENBUEApID decodes an ENB-UE-S1AP-ID.
func DecodeENBUEApID(data []byte) (uint32, error) {
	v, err := decodeExactConstrainedWholeNumber(data, 0, 16777215)
	if err == nil {
		return uint32(v), nil
	}
	// Some Ericsson S1AP stacks have been observed to send the open type as
	// a zero-padded 32-bit integer. Accept it at the IE boundary, but keep the
	// canonical APER encoder above.
	if len(data) == 4 && data[0] == 0 {
		id := binary.BigEndian.Uint32(data)
		if id <= 16777215 {
			return id, nil
		}
	}
	if len(data) == 3 {
		id := uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2])
		return id, nil
	}
	return 0, err
}

// EncodeUES1APIDPair encodes UE-S1AP-IDs as the root uE-S1AP-ID-pair CHOICE.
func EncodeUES1APIDPair(mmeUEID, enbUEID uint32) []byte {
	w := aper.NewBitWriter()
	w.WriteBit(0) // CHOICE: no extension
	w.WriteBit(0) // CHOICE index: uE-S1AP-ID-pair
	w.WriteBit(0) // UE-S1AP-ID-pair SEQUENCE: no extension additions
	w.WriteBit(0) // iE-Extensions absent
	_ = aper.EncodeConstrainedWholeNumber(w, int64(mmeUEID), 0, 4294967295)
	_ = aper.EncodeConstrainedWholeNumber(w, int64(enbUEID), 0, 16777215)
	return w.Bytes()
}

// DecodeUES1APIDPair decodes UE-S1AP-IDs when the pair CHOICE arm is present.
func DecodeUES1APIDPair(data []byte) (mmeUEID uint32, enbUEID uint32, err error) {
	r := aper.NewBitReader(data)
	choiceExt, err := r.ReadBit()
	if err != nil {
		return 0, 0, fmt.Errorf("decode UE-S1AP-IDs choice extension: %w", err)
	}
	choice, err := r.ReadBit()
	if err != nil {
		return 0, 0, fmt.Errorf("decode UE-S1AP-IDs choice index: %w", err)
	}
	if choiceExt != 0 || choice != 0 {
		return 0, 0, fmt.Errorf("decode UE-S1AP-IDs: unsupported choice ext=%d index=%d", choiceExt, choice)
	}
	seqExt, err := r.ReadBit()
	if err != nil {
		return 0, 0, fmt.Errorf("decode UE-S1AP-ID-pair sequence extension: %w", err)
	}
	if seqExt != 0 {
		return 0, 0, fmt.Errorf("decode UE-S1AP-ID-pair: unsupported sequence extension")
	}
	ieExtPresent, err := r.ReadBit()
	if err != nil {
		return 0, 0, fmt.Errorf("decode UE-S1AP-ID-pair optional bitmap: %w", err)
	}
	if ieExtPresent != 0 {
		return 0, 0, fmt.Errorf("decode UE-S1AP-ID-pair: unsupported iE-Extensions")
	}
	mmeID, err := aper.DecodeConstrainedWholeNumber(r, 0, 4294967295)
	if err != nil {
		return 0, 0, fmt.Errorf("decode MME-UE-S1AP-ID: %w", err)
	}
	enbID, err := aper.DecodeConstrainedWholeNumber(r, 0, 16777215)
	if err != nil {
		return 0, 0, fmt.Errorf("decode eNB-UE-S1AP-ID: %w", err)
	}
	if r.Remaining() != 0 {
		return 0, 0, fmt.Errorf("decode UE-S1AP-ID-pair: %d trailing bits", r.Remaining())
	}
	return uint32(mmeID), uint32(enbID), nil
}

func decodeExactConstrainedWholeNumber(data []byte, lb, ub int64) (int64, error) {
	r := aper.NewBitReader(data)
	v, err := aper.DecodeConstrainedWholeNumber(r, lb, ub)
	if err != nil {
		return 0, err
	}
	if r.Remaining() != 0 {
		return 0, fmt.Errorf("aper: constrained integer has %d trailing bits", r.Remaining())
	}
	return v, nil
}

// ── PLMN Identity ─────────────────────────────────────────────────────────────

// EncodePLMN encodes a PLMN identity from MCC and MNC strings (BIT STRING, 24 bits).
func EncodePLMN(mcc, mnc string) ([]byte, error) {
	if len(mcc) != 3 {
		return nil, fmt.Errorf("ies: MCC must be 3 digits")
	}
	if len(mnc) != 2 && len(mnc) != 3 {
		return nil, fmt.Errorf("ies: MNC must be 2 or 3 digits")
	}
	d := func(s string, i int) byte { return s[i] - '0' }
	plmn := make([]byte, 3)
	plmn[0] = d(mcc, 1)<<4 | d(mcc, 0)
	if len(mnc) == 2 {
		plmn[1] = 0xF0 | d(mcc, 2)
		plmn[2] = d(mnc, 1)<<4 | d(mnc, 0)
	} else {
		plmn[1] = d(mnc, 0)<<4 | d(mcc, 2)
		plmn[2] = d(mnc, 2)<<4 | d(mnc, 1)
	}
	// Encoded as OCTET STRING of exactly 3 bytes (fixed-length, no length determinant)
	return plmn, nil
}

// DecodePLMN decodes a 3-byte PLMN identity to (mcc, mnc).
func DecodePLMN(data []byte) (mcc, mnc string, err error) {
	if len(data) < 3 {
		return "", "", fmt.Errorf("ies: PLMN too short: %d bytes", len(data))
	}
	d1 := data[0] & 0x0F
	d2 := (data[0] >> 4) & 0x0F
	d3 := data[1] & 0x0F
	d4 := (data[1] >> 4) & 0x0F
	d5 := data[2] & 0x0F
	d6 := (data[2] >> 4) & 0x0F
	valid := func(d byte) bool { return d <= 9 }
	if !valid(d1) || !valid(d2) || !valid(d3) || !valid(d5) || !valid(d6) || (d4 != 0x0f && !valid(d4)) {
		return "", "", fmt.Errorf("ies: invalid PLMN digit encoding %02x%02x%02x", data[0], data[1], data[2])
	}
	mcc = fmt.Sprintf("%d%d%d", d1, d2, d3)
	if d4 == 0x0F {
		mnc = fmt.Sprintf("%d%d", d5, d6)
	} else {
		mnc = fmt.Sprintf("%d%d%d", d4, d5, d6)
	}
	return
}

// ── TAI ───────────────────────────────────────────────────────────────────────

// TAI represents a Tracking Area Identity.
type TAI struct {
	MCC string
	MNC string
	TAC uint16
}

// EncodeTAI encodes a TAI IE value (PLMN 3 bytes + TAC 2 bytes).
func EncodeTAI(t TAI) ([]byte, error) {
	plmn, err := EncodePLMN(t.MCC, t.MNC)
	if err != nil {
		return nil, err
	}
	b := make([]byte, 5)
	copy(b[:3], plmn)
	binary.BigEndian.PutUint16(b[3:], t.TAC)
	return b, nil
}

// DecodeTAI decodes a TAI from 5 bytes.
func DecodeTAI(data []byte) (TAI, error) {
	if len(data) < 5 {
		return TAI{}, fmt.Errorf("ies: TAI too short: %d bytes", len(data))
	}
	mcc, mnc, err := DecodePLMN(data[:3])
	if err != nil {
		return TAI{}, err
	}
	return TAI{
		MCC: mcc,
		MNC: mnc,
		TAC: binary.BigEndian.Uint16(data[3:5]),
	}, nil
}

// ── ECGI ──────────────────────────────────────────────────────────────────────

// ECGI represents an E-UTRAN Cell Global Identifier.
type ECGI struct {
	MCC  string
	MNC  string
	ECGI uint32 // 28-bit cell identity
}

// EncodeECGI encodes an ECGI IE value.
func EncodeECGI(e ECGI) ([]byte, error) {
	plmn, err := EncodePLMN(e.MCC, e.MNC)
	if err != nil {
		return nil, err
	}
	b := make([]byte, 7)
	copy(b[:3], plmn)
	// Cell identity: 28 bits in 4 bytes (top 4 bits of byte 3 are spare=0)
	cell := e.ECGI & 0x0FFFFFFF
	b[3] = byte(cell >> 20)
	b[4] = byte(cell >> 12)
	b[5] = byte(cell >> 4)
	b[6] = byte(cell&0x0F) << 4
	return b, nil
}

// DecodeECGI decodes an ECGI from 7 bytes.
func DecodeECGI(data []byte) (ECGI, error) {
	if len(data) < 7 {
		return ECGI{}, fmt.Errorf("ies: ECGI too short: %d bytes", len(data))
	}
	mcc, mnc, err := DecodePLMN(data[:3])
	if err != nil {
		return ECGI{}, err
	}
	cell := uint32(data[3])<<20 | uint32(data[4])<<12 | uint32(data[5])<<4 | uint32(data[6]>>4)
	return ECGI{MCC: mcc, MNC: mnc, ECGI: cell}, nil
}

// ── ENB ID ────────────────────────────────────────────────────────────────────

// ENBIDType distinguishes macro vs home eNB.
type ENBIDType uint8

const (
	ENBIDTypeMacro ENBIDType = 0
	ENBIDTypeHome  ENBIDType = 1
)

// ENBID represents an eNB identity.
type ENBID struct {
	Type  ENBIDType
	Value uint32 // macro: 20 bits, home: 28 bits
}

// GlobalENBID represents a Global eNB ID.
type GlobalENBID struct {
	MCC     string
	MNC     string
	PLMNRaw [3]byte
	ENB     ENBID
}

// Serialise returns a compact string representation for use as a map key.
func (g GlobalENBID) Serialise() string {
	return fmt.Sprintf("%s%s-%d-%d", g.MCC, g.MNC, g.ENB.Type, g.ENB.Value)
}

// DecodeGlobalENBID decodes a Global-ENB-ID IE value.
// Structure: SEQUENCE header + PLMN(3) + choice(macro/home) + eNB identity.
func DecodeGlobalENBID(data []byte) (GlobalENBID, error) {
	if len(data) < 5 {
		return GlobalENBID{}, fmt.Errorf("ies: GlobalENBID too short: %d bytes", len(data))
	}

	seq := aper.NewBitReader(data)
	extBit, err := seq.ReadBit()
	if err != nil {
		return GlobalENBID{}, err
	}
	if extBit == 1 {
		return GlobalENBID{}, fmt.Errorf("ies: GlobalENBID extension not supported")
	}
	if _, err := seq.ReadBit(); err != nil { // iE-Extensions absent/present
		return GlobalENBID{}, err
	}
	seq.AlignToByte()
	body, err := seq.ReadOctets(seq.Remaining() / 8)
	if err != nil {
		return GlobalENBID{}, err
	}
	if len(body) < 4 {
		return GlobalENBID{}, fmt.Errorf("ies: GlobalENBID body too short: %d bytes", len(body))
	}

	mcc, mnc, err := DecodePLMN(body[:3])
	if err != nil {
		return GlobalENBID{}, err
	}
	var plmnRaw [3]byte
	copy(plmnRaw[:], body[:3])

	// CHOICE: extension bit + 1-bit index (0=macro, 1=home), then BIT STRING
	r := aper.NewBitReader(body[3:])
	choiceExtBit, _ := r.ReadBit()
	if choiceExtBit == 1 {
		return GlobalENBID{}, fmt.Errorf("ies: GlobalENBID extension not supported")
	}
	choiceIdx, _ := r.ReadBit()

	var enbID ENBID
	if choiceIdx == 0 {
		// Macro ENB ID: BIT STRING (SIZE (20))
		bs, err := aper.DecodeBitString(r, 20, 20)
		if err != nil {
			return GlobalENBID{}, fmt.Errorf("ies: macro ENB ID: %w", err)
		}
		enbID = ENBID{Type: ENBIDTypeMacro, Value: uint32(bs.Bytes[0])<<12 | uint32(bs.Bytes[1])<<4 | uint32(bs.Bytes[2]>>4)}
	} else {
		// Home ENB ID: BIT STRING (SIZE (28))
		bs, err := aper.DecodeBitString(r, 28, 28)
		if err != nil {
			return GlobalENBID{}, fmt.Errorf("ies: home ENB ID: %w", err)
		}
		enbID = ENBID{Type: ENBIDTypeHome,
			Value: uint32(bs.Bytes[0])<<20 | uint32(bs.Bytes[1])<<12 | uint32(bs.Bytes[2])<<4 | uint32(bs.Bytes[3]>>4)}
	}

	return GlobalENBID{MCC: mcc, MNC: mnc, PLMNRaw: plmnRaw, ENB: enbID}, nil
}

// ── Cause ──────────────────────────────────────────────────────────────────────

// CauseGroup represents the S1AP Cause choice group.
type CauseGroup uint8

const (
	CauseGroupRadioNetwork CauseGroup = 0
	CauseGroupTransport    CauseGroup = 1
	CauseGroupNAS          CauseGroup = 2
	CauseGroupProtocol     CauseGroup = 3
	CauseGroupMisc         CauseGroup = 4
)

// Cause values by group.
const (
	CauseRadioNetworkUnspecified                    uint8 = 0
	CauseRadioNetworkNormalRelease                  uint8 = 1
	CauseRadioNetworkLoadBalancingRequired          uint8 = 2
	CauseRadioNetworkSuccessfulHandover             uint8 = 2  // tx2relocoverall-expiry=1, successful-handover=2
	CauseRadioNetworkUserInactivity                 uint8 = 20 // user-inactivity=20
	CauseRadioNetworkHOCancelled                    uint8 = 4  // handover-cancelled=4
	CauseRadioNetworkUnknownTargetID                uint8 = 11 // unknown-targetID=11
	CauseRadioNetworkUnknownMMEUES1APID             uint8 = 13 // unknown-mme-ue-s1ap-id=13
	CauseRadioNetworkUnknownENBUES1APID             uint8 = 14 // unknown-enb-ue-s1ap-id=14
	CauseRadioNetworkUnknownPairUES1APID            uint8 = 15 // unknown-pair-ue-s1ap-id=15
	CauseNASNormalRelease                           uint8 = 0
	CauseNASAuthentication                          uint8 = 1
	CauseNASDetach                                  uint8 = 2
	CauseNASUnspecified                             uint8 = 3
	CauseProtocolTransferSyntaxError                uint8 = 0
	CauseProtocolAbstractSyntaxErrorReject          uint8 = 1
	CauseProtocolAbstractSyntaxErrorIgnoreAndNotify uint8 = 2
	CauseProtocolSemanticError                      uint8 = 4
	CauseProtocolFalselyConstructedMessage          uint8 = 5
	CauseMiscControlProcessingOverload              uint8 = 0
	CauseMiscUnknownPLMN                            uint8 = 5
	CauseMiscUnspecified                            uint8 = 4
)

// WriteCause writes a Cause IE value's bits directly onto w, continuing from
// its current bit position with no alignment padding. Cause is a small,
// closed CHOICE — it must never be octet-aligned when embedded inline inside
// a larger APER-encoded structure (e.g. E-RABItem's SEQUENCE); doing so
// inserts a stray bit that shifts everything encoded after it, corrupting
// the group/value on the wire. Use this whenever a Cause is one field among
// several being packed onto a shared BitWriter. For a standalone Cause IE
// value, use EncodeCause instead.
func WriteCause(w *aper.BitWriter, group CauseGroup, value uint8) {
	// Cause is a CHOICE with extension marker, 5 root alternatives.
	w.WriteBit(0) // extension bit
	w.WriteBits(uint64(group), 3)
	w.WriteBit(0) // ENUMERATED extension bit
	w.WriteBits(uint64(value), causeRootBits(group))
}

// EncodeCause encodes a standalone Cause IE value (CHOICE with 5 alternatives).
func EncodeCause(group CauseGroup, value uint8) []byte {
	w := aper.NewBitWriter()
	WriteCause(w, group, value)
	return w.Bytes()
}

// ReadCause reads a Cause IE value's bits directly from r, continuing from
// its current bit position with no alignment padding. Symmetric counterpart
// to WriteCause — use this whenever a Cause is embedded inline inside a
// larger APER-encoded structure being decoded from a shared BitReader (e.g.
// E-RABItem); aligning first would misread bits shifted in by an earlier,
// already-consumed field.
func ReadCause(r *aper.BitReader) (CauseGroup, uint8, error) {
	if _, err := r.ReadBit(); err != nil {
		return 0, 0, err
	}
	group, err := r.ReadBits(3)
	if err != nil {
		return 0, 0, err
	}
	groupID := CauseGroup(group)
	if _, err := r.ReadBit(); err != nil {
		return 0, 0, err
	}
	value, err := r.ReadBits(causeRootBits(groupID))
	if err != nil {
		return 0, 0, err
	}
	return groupID, uint8(value), nil
}

// DecodeCause decodes a standalone Cause IE value encoded by EncodeCause.
func DecodeCause(data []byte) (CauseGroup, uint8, error) {
	r := aper.NewBitReader(data)
	groupID, value, err := ReadCause(r)
	if err != nil {
		return 0, 0, err
	}
	if len(data) == 2 && data[0]&0x0f == 0 && data[1]&0x07 == 0 {
		shifted := data[1] >> 3
		if shifted > value && CauseName(groupID, shifted) != "unknown" {
			value = shifted
		}
	}
	return groupID, value, nil
}

func causeRootBits(group CauseGroup) int {
	switch group {
	case CauseGroupTransport:
		return 1 // CauseTransport ::= ENUMERATED {0..1,...}
	case CauseGroupNAS:
		return 2 // CauseNas ::= ENUMERATED {0..3,...}
	case CauseGroupRadioNetwork:
		return 6 // CauseRadioNetwork root in TS 36.413 Rel-16 / asn1c: 0..35
	case CauseGroupProtocol:
		return 3 // CauseProtocol ::= ENUMERATED {0..6,...}
	case CauseGroupMisc:
		return 3 // CauseMisc ::= ENUMERATED {0..5,...}
	default:
		return 8
	}
}

// CauseGroupName returns the TS 36.413 Cause CHOICE alternative name.
func CauseGroupName(group CauseGroup) string {
	switch group {
	case CauseGroupRadioNetwork:
		return "radioNetwork"
	case CauseGroupTransport:
		return "transport"
	case CauseGroupNAS:
		return "nas"
	case CauseGroupProtocol:
		return "protocol"
	case CauseGroupMisc:
		return "misc"
	default:
		return "unknown"
	}
}

// CauseName returns a human-readable TS 36.413 cause name for common attach path causes.
func CauseName(group CauseGroup, value uint8) string {
	switch group {
	case CauseGroupRadioNetwork:
		switch value {
		case 0:
			return "unspecified"
		case 1:
			return "tx2relocoverall-expiry"
		case 2:
			return "successful-handover"
		case 3:
			return "release-due-to-eutran-generated-reason"
		case 4:
			return "handover-cancelled"
		case 11:
			return "unknown-targetID"
		case 13:
			return "unknown-mme-ue-s1ap-id"
		case 14:
			return "unknown-enb-ue-s1ap-id"
		case 15:
			return "unknown-pair-ue-s1ap-id"
		case 20:
			return "user-inactivity"
		case 21:
			return "radio-connection-with-ue-lost"
		case 25:
			return "radio-resources-not-available"
		case 26:
			return "failure-in-radio-interface-procedure"
		case 28:
			return "interrat-redirection"
		case 29:
			return "interaction-with-other-procedure"
		case 30:
			return "unknown-E-RAB-ID"
		}
	case CauseGroupTransport:
		if value == 0 {
			return "transport-resource-unavailable"
		}
		if value == 1 {
			return "unspecified"
		}
	case CauseGroupNAS:
		switch value {
		case 0:
			return "normal-release"
		case 1:
			return "authentication-failure"
		case 2:
			return "detach"
		case 3:
			return "unspecified"
		}
	case CauseGroupProtocol:
		switch value {
		case 0:
			return "transfer-syntax-error"
		case 1:
			return "abstract-syntax-error-reject"
		case 2:
			return "abstract-syntax-error-ignore-and-notify"
		case 3:
			return "message-not-compatible-with-receiver-state"
		case 4:
			return "semantic-error"
		case 5:
			return "abstract-syntax-error-falsely-constructed-message"
		case 6:
			return "unspecified"
		}
	case CauseGroupMisc:
		switch value {
		case 0:
			return "control-processing-overload"
		case 1:
			return "not-enough-user-plane-processing-resources"
		case 2:
			return "hardware-failure"
		case 3:
			return "om-intervention"
		case 4:
			return "unspecified"
		case 5:
			return "unknown-PLMN"
		}
	}
	return "unknown"
}

// ── Security Key (KeNB) ────────────────────────────────────────────────────────

// EncodeSecurityKey encodes the KeNB as a 256-bit BIT STRING.
func EncodeSecurityKey(kenb []byte) []byte {
	if len(kenb) < 32 {
		padded := make([]byte, 32)
		copy(padded, kenb)
		kenb = padded
	}
	w := aper.NewBitWriter()
	bs := aper.BitString{Bytes: kenb[:32], NumBits: 256}
	_ = aper.EncodeBitString(w, bs, 256, 256)
	return w.Bytes()
}

// EncodeUEAggregateMaxBitrate encodes the UE Aggregate Maximum Bit Rate IE.
// uplink and downlink are in bits/second.
func EncodeUEAggregateMaxBitrate(downlink, uplink uint64) []byte {
	w := aper.NewBitWriter()
	// UEAggregateMaximumBitrate ::= SEQUENCE {
	//   uEaggregateMaximumBitRateDL BitRate,
	//   uEaggregateMaximumBitRateUL BitRate,
	//   iE-Extensions ... OPTIONAL,
	//   ...
	// }
	w.WriteBit(0) // extension additions absent
	w.WriteBit(0) // iE-Extensions absent
	encodeBitRate(w, downlink)
	encodeBitRate(w, uplink)
	return w.Bytes()
}

func encodeBitRate(w *aper.BitWriter, bitrate uint64) {
	const maxBitRate = 10000000000
	if bitrate > maxBitRate {
		bitrate = maxBitRate
	}
	// BitRate ::= INTEGER (0..10000000000). This is a large constrained
	// whole number in APER, so it carries the constrained integer length
	// determinant before the non-negative-binary-integer value octets.
	_ = aper.EncodeConstrainedWholeNumber(w, int64(bitrate), 0, maxBitRate)
}

// EncodeUESecurityCapabilities encodes the UE Security Capabilities IE.
// ueNetCapability is the raw UE network capability bytes from the Attach Request.
func EncodeUESecurityCapabilities(encAlgsByte, intAlgsByte uint8) []byte {
	w := aper.NewBitWriter()
	// UESecurityCapabilities ::= SEQUENCE {
	//   encryptionAlgorithms EncryptionAlgorithms,
	//   integrityProtectionAlgorithms IntegrityProtectionAlgorithms,
	//   iE-Extensions ... OPTIONAL,
	//   ...
	// }
	w.WriteBit(0) // extension additions absent
	w.WriteBit(0) // iE-Extensions absent
	encodeExtensibleFixed16AlgorithmBitString(w, encAlgsByte)
	encodeExtensibleFixed16AlgorithmBitString(w, intAlgsByte)
	return w.Bytes()
}

func encodeExtensibleFixed16AlgorithmBitString(w *aper.BitWriter, algsByte uint8) {
	// EncryptionAlgorithms / IntegrityProtectionAlgorithms are
	// BIT STRING (SIZE(16,...)). For the root SIZE(16) case APER emits the
	// extension bit, no length determinant, and then the 16 value bits.
	//
	// Open5GS maps the NAS EEA/EIA bitmap into the high octet shifted left
	// by one bit, leaving the S1AP spare bit clear.
	w.WriteBit(0) // fixed-size root, no extension
	shifted := uint16(algsByte) << 1
	w.WriteBits(uint64(shifted)<<8, 16)
}

// EncodeNASPDU encodes a NAS PDU IE value (OCTET STRING).
func EncodeNASPDU(nas []byte) []byte {
	w := aper.NewBitWriter()
	_ = aper.EncodeOctetString(w, nas, 0, -1)
	return w.Bytes()
}

// DecodeNASPDU decodes a NAS PDU from an IE value.
func DecodeNASPDU(data []byte) ([]byte, error) {
	r := aper.NewBitReader(data)
	return aper.DecodeOctetString(r, 0, -1)
}

// EncodeUERadioCapability encodes a UE-RadioCapability IE value (OCTET STRING).
func EncodeUERadioCapability(capability []byte) []byte {
	return EncodeNASPDU(capability)
}

// DecodeUERadioCapability decodes a UE-RadioCapability IE value (OCTET STRING).
func DecodeUERadioCapability(data []byte) ([]byte, error) {
	return DecodeNASPDU(data)
}

// EncodePagingDRX encodes the DefaultPagingDRX IE (ENUMERATED).
// Values: 0=rf32, 1=rf64, 2=rf128, 3=rf256
func EncodePagingDRX(drx uint8) []byte {
	w := aper.NewBitWriter()
	// ENUMERATED with extension marker, 4 root alternatives
	w.WriteBit(0) // no extension
	_ = aper.EncodeConstrainedWholeNumber(w, int64(drx), 0, 3)
	return w.Bytes()
}

// DecodePagingDRX decodes the DefaultPagingDRX IE (ENUMERATED).
func DecodePagingDRX(data []byte) (uint8, error) {
	r := aper.NewBitReader(data)
	ext, err := r.ReadBit()
	if err != nil {
		return 0, err
	}
	if ext != 0 {
		return 0, fmt.Errorf("ies: PagingDRX extension not supported")
	}
	v, err := aper.DecodeConstrainedWholeNumber(r, 0, 3)
	if err != nil {
		return 0, err
	}
	for r.Remaining() > 0 {
		bit, err := r.ReadBit()
		if err != nil {
			return 0, err
		}
		if bit != 0 {
			return 0, fmt.Errorf("ies: PagingDRX has non-zero trailing padding")
		}
	}
	return uint8(v), nil
}

const (
	TimeToWaitV1s  uint8 = 0
	TimeToWaitV2s  uint8 = 1
	TimeToWaitV5s  uint8 = 2
	TimeToWaitV10s uint8 = 3
	TimeToWaitV20s uint8 = 4
	TimeToWaitV60s uint8 = 5
)

// EncodeTimeToWait encodes the TimeToWait IE (ENUMERATED).
func EncodeTimeToWait(v uint8) []byte {
	w := aper.NewBitWriter()
	aper.EncodeEnumerated(w, int(v), 6)
	return w.Bytes()
}

// EncodeCNDomain encodes the CNDomain IE (ENUMERATED).
// Values: 0=ps, 1=cs.
func EncodeCNDomain(domain uint8) []byte {
	w := aper.NewBitWriter()
	w.WriteBit(0) // no extension
	_ = aper.EncodeConstrainedWholeNumber(w, int64(domain), 0, 1)
	return w.Bytes()
}

// EncodeCSFallbackIndicator encodes the CSFallbackIndicator IE: an
// ENUMERATED with an extension marker (TS 36.413 §9.2.3.21) whose only root
// value is cs-fallback-required. cs-fallback-high-priority is an extension
// addition (APER extended-enumerated encoding) and is deliberately not
// supported; every CSFB paging/redirection in this MME uses "required".
func EncodeCSFallbackIndicator() []byte {
	w := aper.NewBitWriter()
	w.WriteBit(0) // extension bit: root value selected
	// The root list has exactly one value (cs-fallback-required), so
	// selecting it needs zero further bits.
	return w.Bytes()
}

// EncodeRelativeMMECapacity encodes RelativeMMECapacity INTEGER (0..255).
func EncodeRelativeMMECapacity(v uint8) []byte {
	w := aper.NewBitWriter()
	_ = aper.EncodeConstrainedWholeNumber(w, int64(v), 0, 255)
	return w.Bytes()
}

// EncodeRRCEstablishmentCause encodes the RRC-Establishment-Cause IE.
func EncodeRRCEstablishmentCause(cause uint8) []byte {
	w := aper.NewBitWriter()
	// ENUMERATED with extension: mo-Signalling(3), emergency(0), mt-Access(1), etc.
	// We just store the value
	w.WriteBit(0) // no extension
	_ = aper.EncodeConstrainedWholeNumber(w, int64(cause), 0, 7)
	return w.Bytes()
}

// DecodeRRCEstablishmentCause decodes the RRC-Establishment-Cause IE.
func DecodeRRCEstablishmentCause(data []byte) (uint8, error) {
	r := aper.NewBitReader(data)
	extBit, err := r.ReadBit()
	if err != nil {
		return 0, err
	}
	if extBit == 1 {
		v, err := aper.DecodeNormallySmallNonnegativeWholeNumber(r)
		return uint8(v), err
	}
	v, err := aper.DecodeConstrainedWholeNumber(r, 0, 7)
	return uint8(v), err
}

// ── S-TMSI ────────────────────────────────────────────────────────────────────

// DecodeSTMSI decodes the S-TMSI IE value (TS 36.413 §9.2.3.11).
// Wire format: S-TMSI SEQUENCE preamble followed by MMEC BIT STRING SIZE(8)
// and M-TMSI BIT STRING SIZE(32), bit-packed in APER.
func DecodeSTMSI(data []byte) (mmec uint8, mtmsi uint32, err error) {
	if len(data) >= 6 {
		r := aper.NewBitReader(data)
		if _, err := r.ReadBit(); err != nil {
			return 0, 0, err
		}
		if _, err := r.ReadBit(); err != nil {
			return 0, 0, err
		}
		mmecBits, err := r.ReadBits(8)
		if err != nil {
			return 0, 0, err
		}
		r.AlignToByte()
		mtmsiBits, err := r.ReadBits(32)
		if err != nil {
			return 0, 0, err
		}
		return uint8(mmecBits), uint32(mtmsiBits), nil
	}
	if len(data) < 5 {
		return 0, 0, fmt.Errorf("ies: S-TMSI IE too short: %d bytes", len(data))
	}
	return data[0], binary.BigEndian.Uint32(data[1:5]), nil
}

// ── Paging IEs ───────────────────────────────────────────────────────────────

// EncodeUEIdentityIndexValue encodes a numeric UE identity modulo 1024 as the
// 10-bit Paging Frame index (TS 36.413 references TS 36.304). It is left
// aligned in two octets; the low six bits are spare.
func EncodeUEIdentityIndexValue(identity uint32) []byte {
	v := uint16(identity & 0x03ff)
	return []byte{byte(v >> 2), byte((v & 0x03) << 6)}
}

// EncodeUEIdentityIndexValueFromIMSI is the S1AP Paging form. The paging
// resource index is IMSI modulo 1024, even when UEPagingID uses an S-TMSI.
func EncodeUEIdentityIndexValueFromIMSI(imsi string) []byte {
	n, err := strconv.ParseUint(imsi, 10, 64)
	if err != nil {
		return EncodeUEIdentityIndexValue(0)
	}
	return EncodeUEIdentityIndexValue(uint32(n & 0x03ff))
}

// EncodeUEPagingIDSTMSI encodes the UE-PagingID IE as CHOICE s-TMSI.
//
// CHOICE encoding (ext=0, index=0) is immediately followed by the S-TMSI
// SEQUENCE header.  The SEQUENCE's extension and optional-presence bits share
// the first octet with the CHOICE. MMEC itself follows immediately after those
// four header bits; APER aligns only before the M-TMSI BIT STRING. Aligning
// before MMEC inserts a spurious shift, which Ericsson rejects as transfer
// syntax.
func EncodeUEPagingIDSTMSI(mmec uint8, mtmsi uint32) []byte {
	w := aper.NewBitWriter()
	w.WriteBit(0) // CHOICE extension marker = 0
	w.WriteBit(0) // CHOICE index = 0 (s-TMSI)
	w.WriteBit(0) // SEQUENCE extension marker = 0
	w.WriteBit(0) // iE-Extensions absent
	w.WriteBits(uint64(mmec), 8)
	w.AlignToByte()
	mtmsiBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(mtmsiBytes, mtmsi)
	w.WriteOctets(mtmsiBytes)
	return w.Bytes()
}

// EncodeHandoverType encodes a HandoverType IE value.
// ENUMERATED with extension marker, 5 root alternatives (intralte=0..gerantolte=4).
func EncodeHandoverType(v uint8) []byte {
	w := aper.NewBitWriter()
	w.WriteBit(0) // no extension
	_ = aper.EncodeConstrainedWholeNumber(w, int64(v), 0, 4)
	return w.Bytes()
}

// EncodeGlobalENBID encodes a Global-ENB-ID IE value.
// Wire format mirrors DecodeGlobalENBID: SEQUENCE header + PLMN(3B) + eNB-ID CHOICE(ext=0, type) + BIT STRING.
func EncodeGlobalENBID(g GlobalENBID) ([]byte, error) {
	plmn, err := EncodePLMN(g.MCC, g.MNC)
	if err != nil {
		return nil, err
	}
	w := aper.NewBitWriter()
	w.WriteBit(0) // Global-ENB-ID SEQUENCE extension = 0
	w.WriteBit(0) // iE-Extensions absent
	w.AlignToByte()
	w.WriteOctets(plmn)
	w.WriteBit(0) // eNB-ID CHOICE extension = 0
	if g.ENB.Type == ENBIDTypeMacro {
		w.WriteBit(0) // choice = 0 (macro, 20 bits)
		_ = aper.EncodeBitString(w, aper.BitString{
			Bytes:   []byte{byte(g.ENB.Value >> 12), byte(g.ENB.Value >> 4), byte(g.ENB.Value << 4)},
			NumBits: 20,
		}, 20, 20)
	} else {
		w.WriteBit(1) // choice = 1 (home, 28 bits)
		_ = aper.EncodeBitString(w, aper.BitString{
			Bytes:   []byte{byte(g.ENB.Value >> 20), byte(g.ENB.Value >> 12), byte(g.ENB.Value >> 4), byte(g.ENB.Value << 4)},
			NumBits: 28,
		}, 28, 28)
	}
	return w.Bytes(), nil
}

// EncodePagingTAIList encodes Paging's TAIList.  Unlike other TAI lists,
// Paging TAIList is a SEQUENCE OF ProtocolIE-SingleContainer { TAIItemIEs },
// not a direct SEQUENCE OF TAI.  Each item therefore has IE ID 47 (TAIItem),
// criticality ignore, and an open-type wrapped TAIItem value.
func EncodePagingTAIList(tais []emm.TAI) []byte {
	if len(tais) == 0 {
		return nil
	}
	w := aper.NewBitWriter()
	_ = aper.EncodeConstrainedWholeNumber(w, int64(len(tais)), 1, 256)
	for _, tai := range tais {
		_ = aper.EncodeConstrainedWholeNumber(w, 47, 0, 65535) // id-TAIItem
		aper.EncodeCriticality(w, aper.CriticalityIgnore)
		aper.WriteOpenType(w, encodePagingTAIItem(tai))
	}
	return w.Bytes()
}

func encodePagingTAIItem(tai emm.TAI) []byte {
	w := aper.NewBitWriter()
	w.WriteBit(0) // TAIItem SEQUENCE extension marker = 0
	w.WriteBit(0) // TAIItem iE-Extensions absent
	w.WriteBit(0) // TAI SEQUENCE extension marker = 0
	w.WriteBit(0) // TAI iE-Extensions absent
	w.AlignToByte()
	// The Ericsson S1 Setup capture uses the legacy S1AP PLMN ordering already
	// represented by EncodePLMN.  The UE's TAI is retained in NAS TBCD order;
	// normalize it through digits before emitting the S1AP TAIItem.
	plmn := pagingS1APPLMN(tai.PLMN)
	w.WriteOctets(plmn)
	tacBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(tacBytes, tai.TAC)
	w.WriteOctets(tacBytes)
	return w.Bytes()
}

func pagingS1APPLMN(nasPLMN [3]byte) []byte {
	d1, d2 := nasPLMN[0]&0x0f, nasPLMN[0]>>4
	d3, d4 := nasPLMN[1]&0x0f, nasPLMN[1]>>4
	d5, d6 := nasPLMN[2]&0x0f, nasPLMN[2]>>4
	valid := func(d byte) bool { return d <= 9 }
	if !valid(d1) || !valid(d2) || !valid(d3) || !valid(d5) || !valid(d6) || (d4 != 0x0f && !valid(d4)) {
		return nasPLMN[:]
	}
	mcc := fmt.Sprintf("%d%d%d", d1, d2, d3)
	mnc := ""
	if d4 == 0x0f {
		mnc = fmt.Sprintf("%d%d", d5, d6)
	} else {
		mnc = fmt.Sprintf("%d%d%d", d5, d6, d4)
	}
	if wire, err := EncodePLMN(mcc, mnc); err == nil {
		return wire
	}
	return nasPLMN[:]
}
