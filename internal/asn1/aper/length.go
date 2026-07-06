package aper

import (
	"fmt"
	"io"
)

const (
	MaxASN1Length = 65535

	// Fragmentation threshold (X.691 §10.7)
	fragThreshold = 16384
)

// EncodeLength encodes a length determinant for a SEQUENCE OF or string.
//
//   - If lb == ub (fixed length): no bits written.
//   - If ub <= 65535 (constrained): encoded as constrained whole number.
//   - Otherwise: unconstrained form (same as EncodeUnconstrainedLength).
func EncodeLength(w *BitWriter, length, lb, ub int) error {
	if lb == ub {
		return nil // fixed length — nothing to encode
	}
	if ub >= 0 && ub <= MaxASN1Length {
		return EncodeConstrainedWholeNumber(w, int64(length), int64(lb), int64(ub))
	}
	return EncodeUnconstrainedLength(w, length)
}

// DecodeLength decodes a length determinant (non-fragmenting, length <= 16383).
func DecodeLength(r *BitReader, lb, ub int) (int, error) {
	if lb == ub {
		return lb, nil
	}
	if ub >= 0 && ub <= MaxASN1Length {
		v, err := DecodeConstrainedWholeNumber(r, int64(lb), int64(ub))
		return int(v), err
	}
	return DecodeUnconstrainedLength(r)
}

// EncodeUnconstrainedLength encodes an unconstrained length (X.691 §10.7.1).
// Handles short (< 128), long (128..16383), and fragmented (> 16383) forms.
// For S1AP OPEN TYPEs length is almost always < 16383, so fragmentation is rare.
func EncodeUnconstrainedLength(w *BitWriter, length int) error {
	w.AlignToByte()
	if length < 128 {
		w.WriteOctet(byte(length))
	} else if length < 16384 {
		w.WriteOctet(byte(0x80 | (length >> 8)))
		w.WriteOctet(byte(length & 0xFF))
	} else {
		// fragmented: write 0xC? markers
		remaining := length
		for remaining >= fragThreshold {
			chunks := remaining / fragThreshold
			if chunks > 4 {
				chunks = 4
			}
			w.WriteOctet(byte(0xC0 | chunks))
			remaining -= chunks * fragThreshold
		}
		// encode leftover as short/long
		if err := EncodeUnconstrainedLength(w, remaining); err != nil {
			return err
		}
	}
	return nil
}

// DecodeUnconstrainedLength decodes an unconstrained length (X.691 §10.7).
// Returns (length, fragmenting) — for fragmented encoding, this returns one
// fragment's length and the caller must loop.
func DecodeUnconstrainedLength(r *BitReader) (int, error) {
	r.AlignToByte()
	b0, err := r.ReadOctet()
	if err != nil {
		return 0, err
	}
	if b0&0x80 == 0 {
		// short form: 7 bits
		return int(b0), nil
	}
	if b0&0xC0 == 0x80 {
		// long form: next byte
		b1, err := r.ReadOctet()
		if err != nil {
			return 0, err
		}
		return int(b0&0x3F)<<8 | int(b1), nil
	}
	// fragmented: b0 = 0xC? where ? is number of 16384-byte chunks
	chunks := int(b0 & 0x3F)
	if chunks == 0 || chunks > 4 {
		return 0, fmt.Errorf("aper: invalid fragment count %d", chunks)
	}
	return chunks * fragThreshold, nil
}

// ReadOpenType reads an OPEN TYPE value (octet-aligned, length-prefixed).
// Handles fragmented lengths.
func ReadOpenType(r *BitReader) ([]byte, error) {
	r.AlignToByte()
	var result []byte
	for {
		b0, err := r.ReadOctet()
		if err != nil {
			return nil, err
		}
		var chunkLen int
		fragmented := false
		if b0&0xC0 == 0xC0 {
			chunks := int(b0 & 0x3F)
			if chunks == 0 || chunks > 4 {
				return nil, fmt.Errorf("aper: invalid open type fragment count %d", chunks)
			}
			chunkLen = chunks * fragThreshold
			fragmented = true
		} else if b0&0x80 == 0 {
			chunkLen = int(b0)
		} else {
			b1, err := r.ReadOctet()
			if err != nil {
				return nil, err
			}
			chunkLen = int(b0&0x3F)<<8 | int(b1)
		}
		if chunkLen == 0 {
			break
		}
		chunk, err := r.ReadOctets(chunkLen)
		if err != nil {
			if err == io.ErrUnexpectedEOF {
				return nil, fmt.Errorf("aper: open type truncated, wanted %d bytes", chunkLen)
			}
			return nil, err
		}
		result = append(result, chunk...)
		if !fragmented {
			break
		}
	}
	return result, nil
}

// WriteOpenType writes a byte slice as an OPEN TYPE (octet-aligned, length-prefixed).
func WriteOpenType(w *BitWriter, data []byte) {
	w.AlignToByte()
	remaining := data
	for len(remaining) >= fragThreshold {
		chunks := len(remaining) / fragThreshold
		if chunks > 4 {
			chunks = 4
		}
		w.WriteOctet(byte(0xC0 | chunks))
		n := chunks * fragThreshold
		w.WriteOctets(remaining[:n])
		remaining = remaining[n:]
	}
	// final (or only) non-fragmented chunk
	n := len(remaining)
	if n < 128 {
		w.WriteOctet(byte(n))
	} else {
		w.WriteOctet(byte(0x80 | (n >> 8)))
		w.WriteOctet(byte(n & 0xFF))
	}
	w.WriteOctets(remaining)
}
