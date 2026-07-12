package ies_test

import (
	"bytes"
	"testing"

	"github.com/vectorcore/mme/internal/s1ap/ies"
)

func TestEncodeUEAggregateMaxBitrateRel16(t *testing.T) {
	got := ies.EncodeUEAggregateMaxBitrate(100000000, 100000000)
	want := []byte{
		0x18, 0x05, 0xf5, 0xe1, 0x00,
		0x60, 0x05, 0xf5, 0xe1, 0x00,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("EncodeUEAggregateMaxBitrate got %x, want %x", got, want)
	}
	if len(got) != 10 {
		t.Fatalf("EncodeUEAggregateMaxBitrate length got %d, want 10", len(got))
	}
}

func TestEncodeUESecurityCapabilitiesRel16(t *testing.T) {
	tests := []struct {
		name string
		eea  uint8
		eia  uint8
		want []byte
	}{
		{
			name: "srsUE f0/70 capability",
			eea:  0xf0,
			eia:  0x70,
			want: []byte{0x1c, 0x00, 0x0e, 0x00, 0x00},
		},
		{
			name: "real UE f0/f0 capability",
			eea:  0xf0,
			eia:  0xf0,
			want: []byte{0x1c, 0x00, 0x0e, 0x00, 0x00},
		},
		{
			name: "real UE f0/40 capability",
			eea:  0xf0,
			eia:  0x40,
			want: []byte{0x1c, 0x00, 0x08, 0x00, 0x00},
		},
		{
			name: "empty capability",
			eea:  0x00,
			eia:  0x00,
			want: []byte{0x00, 0x00, 0x00, 0x00, 0x00},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ies.EncodeUESecurityCapabilities(tt.eea, tt.eia)
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("EncodeUESecurityCapabilities got %x, want %x", got, tt.want)
			}
		})
	}
}
