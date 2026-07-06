package aper

import (
	"fmt"
	"math/bits"
)

// bitsNeeded returns the number of bits needed to represent a value in [0, rangeVal-1].
func bitsNeeded(rangeVal int64) int {
	if rangeVal <= 1 {
		return 0
	}
	return bits.Len64(uint64(rangeVal - 1))
}

// EncodeConstrainedWholeNumber encodes v in [lb, ub] per X.691 §12.
// For S1AP: called for ProcedureCode (0..255), IE IDs (0..65535), etc.
func EncodeConstrainedWholeNumber(w *BitWriter, v, lb, ub int64) error {
	if v < lb || v > ub {
		return fmt.Errorf("aper: value %d out of range [%d, %d]", v, lb, ub)
	}
	rangeVal := ub - lb + 1
	n := bitsNeeded(rangeVal)
	if n == 0 {
		return nil // only one possible value, no bits needed
	}
	val := uint64(v - lb)
	if rangeVal <= 255 {
		// bit-field, no alignment
		w.WriteBits(val, n)
	} else if rangeVal == 256 {
		// one octet, octet-aligned
		w.AlignToByte()
		w.WriteBits(val, 8)
	} else if rangeVal <= 65536 {
		// two octets, octet-aligned
		w.AlignToByte()
		w.WriteBits(val, 16)
	} else {
		// constrained whole number with variable-length encoding
		// encode as minimally-sized unsigned integer
		byteLen := (n + 7) / 8
		w.AlignToByte()
		// length determinant: (byteLen-1) in 2 bits when byteLen <= 4
		w.WriteBits(uint64(byteLen-1), 2)
		w.WriteBits(val, byteLen*8)
	}
	return nil
}

// DecodeConstrainedWholeNumber decodes a constrained integer in [lb, ub].
func DecodeConstrainedWholeNumber(r *BitReader, lb, ub int64) (int64, error) {
	rangeVal := ub - lb + 1
	n := bitsNeeded(rangeVal)
	if n == 0 {
		return lb, nil
	}
	var val uint64
	var err error
	if rangeVal <= 255 {
		val, err = r.ReadBits(n)
	} else if rangeVal == 256 {
		r.AlignToByte()
		val, err = r.ReadBits(8)
	} else if rangeVal <= 65536 {
		r.AlignToByte()
		val, err = r.ReadBits(16)
	} else {
		r.AlignToByte()
		lenBits, e := r.ReadBits(2)
		if e != nil {
			return 0, e
		}
		byteLen := int(lenBits) + 1
		val, err = r.ReadBits(byteLen * 8)
	}
	if err != nil {
		return 0, err
	}
	result := lb + int64(val)
	if result > ub {
		return 0, fmt.Errorf("aper: decoded value %d exceeds upper bound %d", result, ub)
	}
	return result, nil
}

// EncodeSemiConstrainedWholeNumber encodes v >= lb with no upper bound (X.691 §12.2.4).
// Used for unconstrained lengths and large integers.
func EncodeSemiConstrainedWholeNumber(w *BitWriter, v, lb int64) {
	n := uint64(v - lb)
	byteLen := 1
	if n > 0 {
		byteLen = (bits.Len64(n) + 7) / 8
	}
	w.AlignToByte()
	w.WriteOctet(byte(byteLen))
	w.WriteBits(n, byteLen*8)
}

// DecodeSemiConstrainedWholeNumber decodes v >= lb.
func DecodeSemiConstrainedWholeNumber(r *BitReader, lb int64) (int64, error) {
	r.AlignToByte()
	lenByte, err := r.ReadOctet()
	if err != nil {
		return 0, err
	}
	byteLen := int(lenByte)
	if byteLen == 0 {
		return lb, nil
	}
	val, err := r.ReadBits(byteLen * 8)
	if err != nil {
		return 0, err
	}
	return lb + int64(val), nil
}

// EncodeNormallySmallNonnegativeWholeNumber encodes a non-negative integer that is
// expected to be small (X.691 §12.7). Used for extension additions in ENUMERATED.
func EncodeNormallySmallNonnegativeWholeNumber(w *BitWriter, v int64) {
	if v < 64 {
		w.WriteBit(0)         // small (< 64)
		w.WriteBits(uint64(v), 6)
	} else {
		w.WriteBit(1) // large
		EncodeSemiConstrainedWholeNumber(w, v, 0)
	}
}

// DecodeNormallySmallNonnegativeWholeNumber decodes the compact representation.
func DecodeNormallySmallNonnegativeWholeNumber(r *BitReader) (int64, error) {
	flag, err := r.ReadBit()
	if err != nil {
		return 0, err
	}
	if flag == 0 {
		v, err := r.ReadBits(6)
		return int64(v), err
	}
	return DecodeSemiConstrainedWholeNumber(r, 0)
}
