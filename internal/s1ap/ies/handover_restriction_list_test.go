package ies_test

import (
	"bytes"
	"testing"

	"github.com/vectorcore/mme/internal/s1ap/ies"
)

func TestEncodeHandoverRestrictionListWithNRRestriction(t *testing.T) {
	plmn := [3]byte{0x00, 0xf1, 0x10}
	got := ies.EncodeHandoverRestrictionList(plmn, true)
	// Verified against an independent reference PER encoder (pycrate's
	// compiled 3GPP S1AP ASN.1 module — not this package's own codec) and,
	// separately, confirmed to decode cleanly under Wireshark's S1AP
	// dissector. Two earlier versions of this test asserted different, wrong
	// byte sequences that matched real encoder bugs (an off-by-one
	// length-determinant lower bound, and — the more serious one — an
	// erroneous extra open-type wrapper around the whole iE-Extensions
	// SEQUENCE OF) rather than the actual wire format a spec-correct S1AP
	// peer expects. This package's own round-trip test alone never caught
	// either bug, since both sides of the round trip shared the same
	// mistake — see handover_restriction_list.go.
	want := []byte{0x04, 0x00, 0xf1, 0x10, 0x00, 0x00, 0x01, 0x05, 0x40, 0x01, 0x00}
	if !bytes.Equal(got, want) {
		t.Fatalf("EncodeHandoverRestrictionList got %x, want %x", got, want)
	}
}

func TestEncodeHandoverRestrictionListWithoutRestriction(t *testing.T) {
	plmn := [3]byte{0x00, 0xf1, 0x10}
	got := ies.EncodeHandoverRestrictionList(plmn, false)
	want := []byte{0x00, 0x00, 0xf1, 0x10}
	if !bytes.Equal(got, want) {
		t.Fatalf("EncodeHandoverRestrictionList got %x, want %x", got, want)
	}
}

func TestHandoverRestrictionListRoundTrip(t *testing.T) {
	tests := []struct {
		name       string
		restricted bool
	}{
		{name: "NR restricted", restricted: true},
		{name: "not restricted", restricted: false},
	}
	plmn := [3]byte{0x00, 0xf1, 0x10}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := ies.EncodeHandoverRestrictionList(plmn, tt.restricted)
			gotPLMN, gotRestricted, err := ies.DecodeHandoverRestrictionList(encoded)
			if err != nil {
				t.Fatalf("DecodeHandoverRestrictionList: %v", err)
			}
			if gotPLMN != plmn {
				t.Fatalf("servingPLMN got %x, want %x", gotPLMN, plmn)
			}
			if gotRestricted != tt.restricted {
				t.Fatalf("nrRestricted got %v, want %v", gotRestricted, tt.restricted)
			}
		})
	}
}

func TestDecodeHandoverRestrictionListRejectsUnsupportedOptionalFields(t *testing.T) {
	// equivalentPLMNs presence bit set (bit 2 = 1): 0b01000000 = 0x40.
	data := []byte{0x40, 0x00, 0xf1, 0x10}
	if _, _, err := ies.DecodeHandoverRestrictionList(data); err == nil {
		t.Fatal("expected error decoding an equivalentPLMNs list, got nil")
	}
}
