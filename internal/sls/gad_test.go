package sls

import (
	"encoding/hex"
	"testing"
)

// TestConvertLocationEstimateToGADRealUEFixture guards a real bug found live:
// MME relayed E-SMLC's LCS-AP Location-Estimate IE value (APER-encoded
// Geographical-Area) straight into the Diameter SLg Location-Estimate AVP
// unconverted. The PLA reported success, but the GMLC's TS 23.032 GAD
// decoder rejected the bytes as malformed, since the two carry the same
// shape/coordinate data in genuinely different wire formats. These exact
// bytes are the point-With-Uncertainty Geographical-Area E-SMLC sent for a
// real UE-reported A-GNSS fix (IMSI ...070572): 32.6225N, 86.295257W,
// uncertainty code 15.
func TestConvertLocationEstimateToGADRealUEFixture(t *testing.T) {
	raw, err := hex.DecodeString("10402e65788042a2711e")
	if err != nil {
		t.Fatal(err)
	}
	gad, err := ConvertLocationEstimateToGAD(raw)
	if err != nil {
		t.Fatalf("conversion failed: %v", err)
	}
	if len(gad) != 8 {
		t.Fatalf("unexpected GAD length: %d", len(gad))
	}
	if gad[0] != 0x01 {
		t.Fatalf("unexpected shape byte: %#x", gad[0])
	}
	latMag := uint32(gad[1])<<16 | uint32(gad[2])<<8 | uint32(gad[3])
	sign := latMag&0x800000 != 0
	lat := float64(latMag&0x7fffff) * 90.0 / float64((1<<23)-1)
	if sign {
		lat = -lat
	}
	lonRaw := int32(uint32(gad[4])<<24|uint32(gad[5])<<16|uint32(gad[6])<<8) >> 8
	lon := float64(lonRaw) * 360.0 / float64(1<<24)
	if diff := lat - 32.6225; diff < -1e-3 || diff > 1e-3 {
		t.Fatalf("unexpected latitude: %f", lat)
	}
	if diff := lon - (-86.295257); diff < -1e-3 || diff > 1e-3 {
		t.Fatalf("unexpected longitude: %f", lon)
	}
	if gad[7] != 15 {
		t.Fatalf("unexpected uncertainty code: %d", gad[7])
	}
}

func TestConvertLocationEstimateToGADRejectsUnsupportedShape(t *testing.T) {
	// Root CHOICE index 0 (plain "point", no uncertainty): ext=0, idx bits
	// 000, which this converter must reject rather than silently misparse.
	raw := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := ConvertLocationEstimateToGAD(raw); err != ErrUnsupportedGeographicalArea {
		t.Fatalf("got %v, want ErrUnsupportedGeographicalArea", err)
	}
}

