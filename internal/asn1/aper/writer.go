package aper

import "fmt"

// BitWriter writes bits MSB-first into a growing byte slice.
type BitWriter struct {
	buf    []byte
	bitPos int // number of bits written
}

func NewBitWriter() *BitWriter {
	return &BitWriter{}
}

// WriteBit writes a single bit (0 or 1).
func (w *BitWriter) WriteBit(bit uint8) {
	byteIdx := w.bitPos / 8
	if byteIdx >= len(w.buf) {
		w.buf = append(w.buf, 0)
	}
	shift := 7 - (w.bitPos % 8)
	if bit != 0 {
		w.buf[byteIdx] |= 1 << shift
	}
	w.bitPos++
}

// WriteBits writes the low-order n bits of v, MSB first. n must be 1..64.
func (w *BitWriter) WriteBits(v uint64, n int) {
	if n < 1 || n > 64 {
		panic(fmt.Sprintf("aper: WriteBits: n=%d out of range", n))
	}
	for i := n - 1; i >= 0; i-- {
		w.WriteBit(uint8((v >> i) & 1))
	}
}

// AlignToByte pads to the next byte boundary with zero bits.
func (w *BitWriter) AlignToByte() {
	if rem := w.bitPos % 8; rem != 0 {
		w.WriteBits(0, 8-rem)
	}
}

// WriteOctet writes one byte (octet-aligned).
func (w *BitWriter) WriteOctet(b byte) {
	w.AlignToByte()
	w.buf = append(w.buf, b)
	w.bitPos += 8
}

// WriteOctets writes a byte slice (octet-aligned).
func (w *BitWriter) WriteOctets(data []byte) {
	w.AlignToByte()
	w.buf = append(w.buf, data...)
	w.bitPos += len(data) * 8
}

// BitsWritten returns the number of bits written.
func (w *BitWriter) BitsWritten() int { return w.bitPos }

// Bytes returns the underlying buffer, flushed to a whole number of octets.
func (w *BitWriter) Bytes() []byte {
	w.AlignToByte()
	return w.buf
}
