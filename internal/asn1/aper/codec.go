// Package aper implements the ASN.1 Aligned Packed Encoding Rules (X.691).
//
// Rather than a fully generic reflection-based codec, this package exposes the
// primitive building blocks used by the S1AP layer:
//   - BitReader / BitWriter for bit-level I/O
//   - Constrained / semi-constrained integer encoding
//   - Unconstrained and open-type length encoding
//   - OCTET STRING and BIT STRING encoding
//
// S1AP message types build on these primitives directly, encoding each IE
// according to the 3GPP TS 36.413 ASN.1 schema.
package aper

import "fmt"

// Criticality mirrors S1AP Criticality ENUMERATED {reject(0), ignore(1), notify(2)}.
type Criticality uint8

const (
	CriticalityReject Criticality = 0
	CriticalityIgnore Criticality = 1
	CriticalityNotify Criticality = 2
)

func (c Criticality) String() string {
	switch c {
	case CriticalityReject:
		return "reject"
	case CriticalityIgnore:
		return "ignore"
	case CriticalityNotify:
		return "notify"
	}
	return fmt.Sprintf("Criticality(%d)", c)
}

// EncodeCriticality encodes Criticality as a 2-bit constrained ENUMERATED.
func EncodeCriticality(w *BitWriter, c Criticality) {
	// ENUMERATED {reject, ignore, notify}, no extension marker in practice → 2 bits
	w.WriteBits(uint64(c), 2)
}

// DecodeCriticality decodes a 2-bit Criticality value.
func DecodeCriticality(r *BitReader) (Criticality, error) {
	v, err := r.ReadBits(2)
	if err != nil {
		return 0, err
	}
	if v > 2 {
		return 0, fmt.Errorf("aper: unknown criticality value %d", v)
	}
	return Criticality(v), nil
}

// EncodeEnumerated encodes a root ENUMERATED value (no extension marker).
// rootCount is the number of root alternatives; v is the index (0-based).
func EncodeEnumerated(w *BitWriter, v int, rootCount int) {
	_ = EncodeConstrainedWholeNumber(w, int64(v), 0, int64(rootCount-1))
}

// DecodeEnumerated decodes a root ENUMERATED value.
func DecodeEnumerated(r *BitReader, rootCount int) (int, error) {
	v, err := DecodeConstrainedWholeNumber(r, 0, int64(rootCount-1))
	return int(v), err
}

// EncodeEnumeratedExt encodes an ENUMERATED with an extension marker.
// If v < rootCount it is a root value; otherwise it is an extension addition.
func EncodeEnumeratedExt(w *BitWriter, v int, rootCount int) {
	if v < rootCount {
		w.WriteBit(0) // extension bit = 0 (root)
		EncodeEnumerated(w, v, rootCount)
	} else {
		w.WriteBit(1) // extension bit = 1
		EncodeNormallySmallNonnegativeWholeNumber(w, int64(v-rootCount))
	}
}

// DecodeEnumeratedExt decodes an ENUMERATED with an extension marker.
func DecodeEnumeratedExt(r *BitReader, rootCount int) (int, error) {
	ext, err := r.ReadBit()
	if err != nil {
		return 0, err
	}
	if ext == 0 {
		return DecodeEnumerated(r, rootCount)
	}
	idx, err := DecodeNormallySmallNonnegativeWholeNumber(r)
	if err != nil {
		return 0, err
	}
	return rootCount + int(idx), nil
}

// EncodeBoolean encodes a BOOLEAN as a single bit.
func EncodeBoolean(w *BitWriter, v bool) {
	if v {
		w.WriteBit(1)
	} else {
		w.WriteBit(0)
	}
}

// DecodeBoolean decodes a BOOLEAN from a single bit.
func DecodeBoolean(r *BitReader) (bool, error) {
	b, err := r.ReadBit()
	return b == 1, err
}
