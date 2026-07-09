package ies_test

import (
	"bytes"
	"testing"

	"github.com/vectorcore/mme/internal/s1ap/ies"
)

func TestENBUEApIDEncodingRel16ConstrainedInteger(t *testing.T) {
	encoded := ies.EncodeENBUEApID(1)
	want := []byte{0x00, 0x01}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("EncodeENBUEApID(1): got %x, want %x", encoded, want)
	}
	decoded, err := ies.DecodeENBUEApID(encoded)
	if err != nil {
		t.Fatalf("DecodeENBUEApID: %v", err)
	}
	if decoded != 1 {
		t.Fatalf("DecodeENBUEApID: got %d, want 1", decoded)
	}
}

func TestMMEUEApIDEncodingRel16ConstrainedInteger(t *testing.T) {
	encoded := ies.EncodeMMEUEApID(1)
	want := []byte{0x00, 0x01}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("EncodeMMEUEApID(1): got %x, want %x", encoded, want)
	}
	decoded, err := ies.DecodeMMEUEApID(encoded)
	if err != nil {
		t.Fatalf("DecodeMMEUEApID: %v", err)
	}
	if decoded != 1 {
		t.Fatalf("DecodeMMEUEApID: got %d, want 1", decoded)
	}
}
