package ies_test

import (
	"bytes"
	"testing"

	"github.com/vectorcore/mme/internal/s1ap/ies"
)

func TestEncodeUEAggregateMaxBitrateRel16(t *testing.T) {
	got := ies.EncodeUEAggregateMaxBitrate(100000000, 100000000)
	want := []byte{
		0x00, 0x5f, 0x5e, 0x10, 0x00,
		0x17, 0xd7, 0x84, 0x00,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("EncodeUEAggregateMaxBitrate got %x, want %x", got, want)
	}
	if len(got) != 9 {
		t.Fatalf("EncodeUEAggregateMaxBitrate length got %d, want 9", len(got))
	}
	if bytes.Contains(got, []byte{0x03, 0x05, 0xf5, 0xe1, 0x00}) {
		t.Fatalf("UEAggregateMaximumBitrate contains length-prefixed BitRate encoding: %x", got)
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
			want: []byte{0x00, 0x1e, 0x00, 0x07, 0x00},
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
