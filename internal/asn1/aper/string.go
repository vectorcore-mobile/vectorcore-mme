package aper

import "fmt"

// DecodeOctetString decodes an OCTET STRING with optional size constraints.
// Use minLen=maxLen=-1 for unconstrained, or set bounds for constrained.
func DecodeOctetString(r *BitReader, minLen, maxLen int) ([]byte, error) {
	var length int
	var err error

	if minLen == maxLen && minLen >= 0 {
		// Fixed-length: no length determinant encoded
		length = minLen
	} else {
		length, err = DecodeLength(r, maxInt(0, minLen), maxLen)
		if err != nil {
			return nil, fmt.Errorf("aper: OctetString length: %w", err)
		}
	}

	if length == 0 {
		return []byte{}, nil
	}

	r.AlignToByte()
	data, err := r.ReadOctets(length)
	if err != nil {
		return nil, fmt.Errorf("aper: OctetString data: %w", err)
	}
	return data, nil
}

// EncodeOctetString encodes an OCTET STRING.
func EncodeOctetString(w *BitWriter, data []byte, minLen, maxLen int) error {
	length := len(data)
	if minLen == maxLen && minLen >= 0 {
		if length != minLen {
			return fmt.Errorf("aper: fixed-length OCTET STRING: got %d, want %d", length, minLen)
		}
		// no length determinant
	} else {
		if err := EncodeLength(w, length, maxInt(0, minLen), maxLen); err != nil {
			return err
		}
	}
	if length > 0 {
		w.AlignToByte()
		w.WriteOctets(data)
	}
	return nil
}

// BitString represents an ASN.1 BIT STRING.
type BitString struct {
	Bytes   []byte
	NumBits int // total number of significant bits
}

// DecodeBitString decodes a BIT STRING with optional size constraints (in bits).
func DecodeBitString(r *BitReader, minBits, maxBits int) (BitString, error) {
	var numBits int
	var err error

	if minBits == maxBits && minBits >= 0 {
		numBits = minBits
	} else {
		numBits, err = DecodeLength(r, maxInt(0, minBits), maxBits)
		if err != nil {
			return BitString{}, fmt.Errorf("aper: BitString length: %w", err)
		}
	}

	if numBits == 0 {
		return BitString{}, nil
	}

	byteLen := (numBits + 7) / 8
	r.AlignToByte()
	data, err := r.ReadOctets(byteLen)
	if err != nil {
		return BitString{}, fmt.Errorf("aper: BitString data: %w", err)
	}
	return BitString{Bytes: data, NumBits: numBits}, nil
}

// EncodeBitString encodes a BIT STRING.
func EncodeBitString(w *BitWriter, bs BitString, minBits, maxBits int) error {
	if minBits == maxBits && minBits >= 0 {
		if bs.NumBits != minBits {
			return fmt.Errorf("aper: fixed-length BIT STRING: got %d, want %d", bs.NumBits, minBits)
		}
	} else {
		if err := EncodeLength(w, bs.NumBits, maxInt(0, minBits), maxBits); err != nil {
			return err
		}
	}
	if bs.NumBits > 0 {
		byteLen := (bs.NumBits + 7) / 8
		w.AlignToByte()
		w.WriteOctets(bs.Bytes[:byteLen])
	}
	return nil
}

// DecodeUTF8String decodes a UTF8String (treated as OCTET STRING in APER).
func DecodeUTF8String(r *BitReader, minLen, maxLen int) (string, error) {
	data, err := DecodeOctetString(r, minLen, maxLen)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// EncodeUTF8String encodes a UTF8String.
func EncodeUTF8String(w *BitWriter, s string, minLen, maxLen int) error {
	return EncodeOctetString(w, []byte(s), minLen, maxLen)
}

// DecodeVisibleString decodes a VisibleString (7-bit ASCII range, treated as UTF8 in APER).
func DecodeVisibleString(r *BitReader, minLen, maxLen int) (string, error) {
	return DecodeUTF8String(r, minLen, maxLen)
}

// DecodeVisibleStringExt decodes an extensible VisibleString with a root size
// constraint. Extension additions fall back to an unconstrained octet string.
func DecodeVisibleStringExt(r *BitReader, minLen, maxLen int) (string, error) {
	ext, err := r.ReadBit()
	if err != nil {
		return "", err
	}
	if ext == 0 {
		return DecodeVisibleString(r, minLen, maxLen)
	}
	return DecodeVisibleString(r, -1, -1)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
