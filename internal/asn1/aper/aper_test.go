package aper_test

import (
	"testing"

	"github.com/vectorcore/mme/internal/asn1/aper"
)

// ---- constrained integer round-trips ----

func TestConstrainedInteger(t *testing.T) {
	cases := []struct {
		v, lb, ub int64
	}{
		{0, 0, 0},        // single value, 0 bits
		{1, 0, 1},        // 1 bit
		{3, 0, 3},        // 2 bits
		{255, 0, 255},    // 8-bit aligned (range=256)
		{127, 0, 127},    // 7-bit field (range=128)
		{0, 0, 255},      // min of 8-bit aligned
		{100, 0, 65535},  // 16-bit aligned
		{65535, 0, 65535},
		{7, 0, 65535},
	}
	for _, c := range cases {
		w := aper.NewBitWriter()
		if err := aper.EncodeConstrainedWholeNumber(w, c.v, c.lb, c.ub); err != nil {
			t.Fatalf("encode v=%d lb=%d ub=%d: %v", c.v, c.lb, c.ub, err)
		}
		r := aper.NewBitReader(w.Bytes())
		got, err := aper.DecodeConstrainedWholeNumber(r, c.lb, c.ub)
		if err != nil {
			t.Fatalf("decode v=%d lb=%d ub=%d: %v", c.v, c.lb, c.ub, err)
		}
		if got != c.v {
			t.Errorf("round-trip v=%d lb=%d ub=%d: got %d", c.v, c.lb, c.ub, got)
		}
	}
}

// ---- unconstrained length round-trips ----

func TestUnconstrainedLength(t *testing.T) {
	for _, n := range []int{0, 1, 127, 128, 1000, 16383, 16384, 32768} {
		w := aper.NewBitWriter()
		if err := aper.EncodeUnconstrainedLength(w, n); err != nil {
			t.Fatalf("encode length %d: %v", n, err)
		}
		r := aper.NewBitReader(w.Bytes())
		// For fragmented lengths, ReadOpenType is the proper interface.
		// For non-fragmented, DecodeUnconstrainedLength returns the length.
		if n < 16384 {
			got, err := aper.DecodeUnconstrainedLength(r)
			if err != nil {
				t.Fatalf("decode length %d: %v", n, err)
			}
			if got != n {
				t.Errorf("round-trip length %d: got %d", n, got)
			}
		}
	}
}

// ---- open type round-trips ----

func TestOpenType(t *testing.T) {
	payloads := [][]byte{
		{},
		{0x01},
		make([]byte, 127),
		make([]byte, 128),
		make([]byte, 255),
		make([]byte, 1000),
	}
	for i, p := range payloads {
		for j := range p {
			p[j] = byte(j % 256)
		}
		w := aper.NewBitWriter()
		aper.WriteOpenType(w, p)
		r := aper.NewBitReader(w.Bytes())
		got, err := aper.ReadOpenType(r)
		if err != nil {
			t.Fatalf("payload[%d] len=%d: %v", i, len(p), err)
		}
		if len(got) != len(p) {
			t.Errorf("payload[%d]: len want %d got %d", i, len(p), len(got))
			continue
		}
		for j := range p {
			if got[j] != p[j] {
				t.Errorf("payload[%d] byte[%d]: want %02x got %02x", i, j, p[j], got[j])
				break
			}
		}
	}
}

// ---- OCTET STRING round-trips ----

func TestOctetString(t *testing.T) {
	cases := []struct {
		data       []byte
		minLen, maxLen int
	}{
		{[]byte{0xDE, 0xAD}, 2, 2},   // fixed
		{[]byte{0xBE, 0xEF}, 0, 10},  // constrained variable
		{[]byte{}, 0, 100},
		{make([]byte, 50), 0, 100},
	}
	for _, c := range cases {
		w := aper.NewBitWriter()
		if err := aper.EncodeOctetString(w, c.data, c.minLen, c.maxLen); err != nil {
			t.Fatalf("encode: %v", err)
		}
		r := aper.NewBitReader(w.Bytes())
		got, err := aper.DecodeOctetString(r, c.minLen, c.maxLen)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(got) != len(c.data) {
			t.Errorf("length: want %d got %d", len(c.data), len(got))
			continue
		}
		for i := range c.data {
			if got[i] != c.data[i] {
				t.Errorf("byte[%d]: want %02x got %02x", i, c.data[i], got[i])
				break
			}
		}
	}
}

// ---- BIT STRING round-trips ----

func TestBitString(t *testing.T) {
	bs := aper.BitString{Bytes: []byte{0xAB, 0xCD}, NumBits: 16}
	w := aper.NewBitWriter()
	if err := aper.EncodeBitString(w, bs, 16, 16); err != nil {
		t.Fatal(err)
	}
	r := aper.NewBitReader(w.Bytes())
	got, err := aper.DecodeBitString(r, 16, 16)
	if err != nil {
		t.Fatal(err)
	}
	if got.NumBits != bs.NumBits || got.Bytes[0] != bs.Bytes[0] || got.Bytes[1] != bs.Bytes[1] {
		t.Errorf("got %v, want %v", got, bs)
	}
}

// ---- ENUMERATED round-trips ----

func TestEnumerated(t *testing.T) {
	for _, v := range []int{0, 1, 2} {
		w := aper.NewBitWriter()
		aper.EncodeEnumerated(w, v, 3)
		r := aper.NewBitReader(w.Bytes())
		got, err := aper.DecodeEnumerated(r, 3)
		if err != nil {
			t.Fatal(err)
		}
		if got != v {
			t.Errorf("got %d want %d", got, v)
		}
	}
}

// ---- criticality round-trips ----

func TestCriticality(t *testing.T) {
	for _, c := range []aper.Criticality{aper.CriticalityReject, aper.CriticalityIgnore, aper.CriticalityNotify} {
		w := aper.NewBitWriter()
		aper.EncodeCriticality(w, c)
		r := aper.NewBitReader(w.Bytes())
		got, err := aper.DecodeCriticality(r)
		if err != nil {
			t.Fatal(err)
		}
		if got != c {
			t.Errorf("got %v want %v", got, c)
		}
	}
}
