package aper

import (
	"fmt"
	"io"
)

// BitReader reads bits MSB-first from a byte slice (aligned PER style).
type BitReader struct {
	data   []byte
	bitPos int // global bit offset (0 = MSB of data[0])
}

func NewBitReader(data []byte) *BitReader {
	return &BitReader{data: data}
}

// BitsRead returns the number of bits consumed so far.
func (r *BitReader) BitsRead() int { return r.bitPos }

// BytesConsumed returns the number of whole bytes fully consumed.
func (r *BitReader) BytesConsumed() int { return r.bitPos / 8 }

// ReadBit reads a single bit (0 or 1).
func (r *BitReader) ReadBit() (uint8, error) {
	if r.bitPos >= len(r.data)*8 {
		return 0, io.ErrUnexpectedEOF
	}
	b := r.data[r.bitPos/8]
	shift := 7 - (r.bitPos % 8)
	r.bitPos++
	return (b >> shift) & 1, nil
}

// ReadBits reads up to 64 bits (MSB first). n must be 1..64.
func (r *BitReader) ReadBits(n int) (uint64, error) {
	if n < 1 || n > 64 {
		return 0, fmt.Errorf("aper: ReadBits: n=%d out of range", n)
	}
	if r.bitPos+n > len(r.data)*8 {
		return 0, io.ErrUnexpectedEOF
	}
	var v uint64
	for i := 0; i < n; i++ {
		b, _ := r.ReadBit()
		v = (v << 1) | uint64(b)
	}
	return v, nil
}

// AlignToByte advances to the next byte boundary (discards padding bits).
func (r *BitReader) AlignToByte() {
	if rem := r.bitPos % 8; rem != 0 {
		r.bitPos += 8 - rem
	}
}

// ReadOctet reads exactly one byte (octet-aligned).
func (r *BitReader) ReadOctet() (byte, error) {
	r.AlignToByte()
	idx := r.bitPos / 8
	if idx >= len(r.data) {
		return 0, io.ErrUnexpectedEOF
	}
	r.bitPos += 8
	return r.data[idx], nil
}

// ReadOctets reads n bytes (octet-aligned).
func (r *BitReader) ReadOctets(n int) ([]byte, error) {
	r.AlignToByte()
	start := r.bitPos / 8
	if start+n > len(r.data) {
		return nil, io.ErrUnexpectedEOF
	}
	out := make([]byte, n)
	copy(out, r.data[start:start+n])
	r.bitPos += n * 8
	return out, nil
}

// Remaining returns the number of bits not yet consumed.
func (r *BitReader) Remaining() int {
	return len(r.data)*8 - r.bitPos
}
