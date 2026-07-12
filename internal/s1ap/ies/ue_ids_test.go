package ies_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/vectorcore/mme/internal/s1ap/ies"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex %q: %v", s, err)
	}
	return b
}

func TestMMEUEApIDEncodingRel16ConstrainedInteger(t *testing.T) {
	cases := []struct {
		name string
		id   uint32
		hex  string
	}{
		{name: "zero", id: 0, hex: "0000"},
		{name: "one", id: 1, hex: "0001"},
		{name: "255", id: 255, hex: "00ff"},
		{name: "256", id: 256, hex: "400100"},
		{name: "65535", id: 65535, hex: "40ffff"},
		{name: "65536", id: 65536, hex: "80010000"},
		{name: "max", id: 4294967295, hex: "c0ffffffff"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encoded := ies.EncodeMMEUEApID(tc.id)
			want := mustHex(t, tc.hex)
			if !bytes.Equal(encoded, want) {
				t.Fatalf("EncodeMMEUEApID(%d): got %x, want %x", tc.id, encoded, want)
			}
			decoded, err := ies.DecodeMMEUEApID(encoded)
			if err != nil {
				t.Fatalf("DecodeMMEUEApID: %v", err)
			}
			if decoded != tc.id {
				t.Fatalf("DecodeMMEUEApID: got %d, want %d", decoded, tc.id)
			}
		})
	}
}

func TestENBUEApIDEncodingRel16ConstrainedInteger(t *testing.T) {
	cases := []struct {
		name string
		id   uint32
		hex  string
	}{
		{name: "zero", id: 0, hex: "0000"},
		{name: "one", id: 1, hex: "0001"},
		{name: "255", id: 255, hex: "00ff"},
		{name: "256", id: 256, hex: "400100"},
		{name: "65535", id: 65535, hex: "40ffff"},
		{name: "65536", id: 65536, hex: "80010000"},
		{name: "max", id: 16777215, hex: "80ffffff"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encoded := ies.EncodeENBUEApID(tc.id)
			want := mustHex(t, tc.hex)
			if !bytes.Equal(encoded, want) {
				t.Fatalf("EncodeENBUEApID(%d): got %x, want %x", tc.id, encoded, want)
			}
			decoded, err := ies.DecodeENBUEApID(encoded)
			if err != nil {
				t.Fatalf("DecodeENBUEApID: %v", err)
			}
			if decoded != tc.id {
				t.Fatalf("DecodeENBUEApID: got %d, want %d", decoded, tc.id)
			}
		})
	}
}

func TestENBUEApIDDecodeInteropVectors(t *testing.T) {
	cases := []struct {
		name string
		hex  string
		want uint32
	}{
		{name: "canonical value 1", hex: "0001", want: 1},
		{name: "fixed 24-bit padded value 1", hex: "000001", want: 1},
		{name: "Ericsson 32-bit padded value 1", hex: "00000001", want: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ies.DecodeENBUEApID(mustHex(t, tc.hex))
			if err != nil {
				t.Fatalf("DecodeENBUEApID(%s): %v", tc.hex, err)
			}
			if got != tc.want {
				t.Fatalf("DecodeENBUEApID(%s): got %d, want %d", tc.hex, got, tc.want)
			}
		})
	}
}

func TestUES1APIDPairEncoding(t *testing.T) {
	cases := []struct {
		name  string
		mmeID uint32
		enbID uint32
		hex   string
	}{
		{name: "zero zero", mmeID: 0, enbID: 0, hex: "00000000"},
		{name: "one one", mmeID: 1, enbID: 1, hex: "00010001"},
		{name: "wide MME", mmeID: 65536, enbID: 1, hex: "080100000001"},
		{name: "wide eNB", mmeID: 1, enbID: 65536, hex: "000180010000"},
		{name: "max max", mmeID: 4294967295, enbID: 16777215, hex: "0cffffffff80ffffff"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encoded := ies.EncodeUES1APIDPair(tc.mmeID, tc.enbID)
			want := mustHex(t, tc.hex)
			if !bytes.Equal(encoded, want) {
				t.Fatalf("EncodeUES1APIDPair: got %x, want %x", encoded, want)
			}
			mmeID, enbID, err := ies.DecodeUES1APIDPair(encoded)
			if err != nil {
				t.Fatalf("DecodeUES1APIDPair: %v", err)
			}
			if mmeID != tc.mmeID || enbID != tc.enbID {
				t.Fatalf("DecodeUES1APIDPair: got %d/%d, want %d/%d", mmeID, enbID, tc.mmeID, tc.enbID)
			}
		})
	}
}

func TestUES1APIDPairKnownBadAlignedChoiceValue(t *testing.T) {
	mmeID, enbID, err := ies.DecodeUES1APIDPair(mustHex(t, "000000010001"))
	if err == nil {
		t.Fatalf("known-bad aligned value decoded as %d/%d; expected a trailing-bit error", mmeID, enbID)
	}
}

func FuzzDecodeUEIDHelpers(f *testing.F) {
	for _, seed := range []string{"0001", "00000001", "00010001", "000000010001", "c0ffffffff"} {
		b, err := hex.DecodeString(seed)
		if err != nil {
			panic(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ies.DecodeMMEUEApID(data)
		_, _ = ies.DecodeENBUEApID(data)
		_, _, _ = ies.DecodeUES1APIDPair(data)
	})
}
