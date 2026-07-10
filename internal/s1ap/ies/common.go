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
	r := aper.NewBitReader(data)
	v, err := aper.DecodeConstrainedWholeNumber(r, 0, 4294967295)
	return uint32(v), err
}

// EncodeENBUEApID encodes an ENB-UE-S1AP-ID (0..16777215).
func EncodeENBUEApID(id uint32) []byte {
	w := aper.NewBitWriter()
	_ = aper.EncodeConstrainedWholeNumber(w, int64(id), 0, 16777215)
	return w.Bytes()
}

// DecodeENBUEApID decodes an ENB-UE-S1AP-ID.
func DecodeENBUEApID(data []byte) (uint32, error) {
	r := aper.NewBitReader(data)
	v, err := aper.DecodeConstrainedWholeNumber(r, 0, 16777215)
	return uint32(v), err
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
	CauseRadioNetworkUnspecified           uint8 = 0
	CauseRadioNetworkNormalRelease         uint8 = 1
	CauseRadioNetworkLoadBalancingRequired uint8 = 2
	CauseRadioNetworkSuccessfulHandover    uint8 = 2  // tx2relocoverall-expiry=1, successful-handover=2
	CauseRadioNetworkHOCancelled           uint8 = 4  // handover-cancelled=4
	CauseRadioNetworkUnknownTargetID       uint8 = 11 // unknown-targetID=11
	CauseNASNormalRelease                  uint8 = 0
	CauseNASAuthentication                 uint8 = 1
	CauseNASDetach                         uint8 = 2
	CauseNASUnspecified                    uint8 = 3
	CauseMiscControlProcessingOverload     uint8 = 0
	CauseMiscUnspecified                   uint8 = 5
)

// EncodeCause encodes a Cause IE value (CHOICE with 5 alternatives).
func EncodeCause(group CauseGroup, value uint8) []byte {
	w := aper.NewBitWriter()
	// Cause is a CHOICE with extension marker, 5 root alternatives
	// Extension bit = 0, choice index = group (3 bits needed? Let's check: 5 alternatives → bitsNeeded(5)=3)
	w.WriteBit(0) // extension bit
	w.WriteBits(uint64(group), 3)
	// The cause value in each group: variable sizes, e.g. RadioNetwork has ~40 values
	// For simplicity we use 8-bit unconstrained for the value within the group
	w.AlignToByte()
	w.WriteOctet(value)
	return w.Bytes()
}

// DecodeCause decodes a Cause IE value encoded by EncodeCause.
func DecodeCause(data []byte) (CauseGroup, uint8, error) {
	r := aper.NewBitReader(data)
	if _, err := r.ReadBit(); err != nil {
		return 0, 0, err
	}
	group, err := r.ReadBits(3)
	if err != nil {
		return 0, 0, err
	}
	r.AlignToByte()
	value, err := r.ReadOctet()
	if err != nil {
		return 0, 0, err
	}
	return CauseGroup(group), value, nil
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
	// BitRate ::= INTEGER (0..10000000000) spans 34 bits. Inside the
	// UEAggregateMaximumBitrate SEQUENCE, the constrained integer bits are
	// packed directly after the SEQUENCE preamble bits.
	w.WriteBits(bitrate, 34)
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
	// srsRAN/Open5GS store these fixed bitstrings as two octets where the
	// second octet is the low-order/spare byte and the first octet carries
	// EEA/EIA0..7. Their APER packer writes the high stored octet first.
	w.WriteBit(0) // fixed-size root, no extension
	w.WriteBits(0, 8)
	w.WriteBits(uint64(algsByte), 8)
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

// EncodeUEIdentityIndexValue encodes the UE Identity Index Value IE.
// Value = IMSI (as integer) % 1024, packed into a 10-bit BIT STRING (2 bytes,
// top-10-bit aligned: bit[15..6] hold the value, bits[5..0] = 0).
func EncodeUEIdentityIndexValue(imsi string) []byte {
	n, _ := strconv.ParseUint(imsi, 10, 64)
	v := uint16(n % 1024)
	return []byte{byte(v >> 2), byte((v & 0x03) << 6)}
}

// EncodeUEPagingIDSTMSI encodes the UE-PagingID IE as CHOICE s-TMSI.
//
// CHOICE encoding (ext=0, index=0): 0b00, then align.
// S-TMSI SEQUENCE: ext=0, iE-Extensions absent (0 bit), align, MMEC (1B), M-TMSI (4B).
func EncodeUEPagingIDSTMSI(mmec uint8, mtmsi uint32) []byte {
	w := aper.NewBitWriter()
	w.WriteBit(0) // CHOICE extension marker = 0
	w.WriteBit(0) // CHOICE index = 0 (s-TMSI)
	w.AlignToByte()
	w.WriteBit(0) // SEQUENCE extension marker = 0
	w.WriteBit(0) // iE-Extensions absent
	w.AlignToByte()
	w.WriteOctet(mmec)
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

// EncodePagingTAIList encodes the TAI List for Paging IE (SEQUENCE OF TAI).
//
// Outer: ext=0 (1 bit), count-1 as 8-bit constrained (0..255), align.
// Per TAI: ext=0 (1 bit), iE-Extensions absent (1 bit), align, PLMN (3B), TAC (2B).
func EncodePagingTAIList(tais []emm.TAI) []byte {
	if len(tais) == 0 {
		return nil
	}
	w := aper.NewBitWriter()
	w.WriteBit(0) // SEQUENCE OF extension marker = 0
	_ = aper.EncodeConstrainedWholeNumber(w, int64(len(tais)-1), 0, 255)
	w.AlignToByte()
	for _, tai := range tais {
		w.WriteBit(0) // TAI SEQUENCE extension marker = 0
		w.WriteBit(0) // iE-Extensions absent
		w.AlignToByte()
		w.WriteOctets(tai.PLMN[:])
		tacBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(tacBytes, tai.TAC)
		w.WriteOctets(tacBytes)
	}
	return w.Bytes()
}
