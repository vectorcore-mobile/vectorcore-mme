package gtpv2

import "testing"

func TestParseBearerQoS(t *testing.T) {
	raw := []byte{
		0x21, 0x05,
		0x00, 0x00, 0x00, 0x04, 0x00,
		0x00, 0x00, 0x00, 0x08, 0x00,
		0x00, 0x00, 0x00, 0x0c, 0x00,
		0x00, 0x00, 0x00, 0x10, 0x00,
	}

	got, err := ParseBearerQoS(raw)
	if err != nil {
		t.Fatalf("ParseBearerQoS error: %v", err)
	}
	if got.PriorityLevel != 8 {
		t.Fatalf("PriorityLevel got %d, want 8", got.PriorityLevel)
	}
	// 0x21: PCI bit clear (capability enabled), PVI bit set (vulnerability
	// disabled), TS 29.274 §8.15.
	if !got.PreemptionCapability {
		t.Fatal("PreemptionCapability got false, want true")
	}
	if got.PreemptionVulnerability {
		t.Fatal("PreemptionVulnerability got true, want false")
	}
	if got.QCI != 5 {
		t.Fatalf("QCI got %d, want 5", got.QCI)
	}
	if got.UplinkMBR != 1024000 || got.DownlinkMBR != 2048000 || got.UplinkGBR != 3072000 || got.DownlinkGBR != 4096000 {
		t.Fatalf("rates got ul_mbr=%d dl_mbr=%d ul_gbr=%d dl_gbr=%d, want 1024000/2048000/3072000/4096000",
			got.UplinkMBR, got.DownlinkMBR, got.UplinkGBR, got.DownlinkGBR)
	}
}

func TestParseBearerQoSTooShort(t *testing.T) {
	if _, err := ParseBearerQoS([]byte{0x00, 0x01}); err == nil {
		t.Fatal("ParseBearerQoS short input: got nil error, want error")
	}
}

// Lab capture: a subscription with pre-emption capability and vulnerability
// both disabled went out in the Create Session Request as ARP 0x1c, which
// decodes as both enabled.
func TestEncodeBearerQoSPreemptionFlagPolarity(t *testing.T) {
	for _, tc := range []struct {
		name     string
		pci, pvi bool
		wantARP  byte
	}{
		{name: "both disabled", pci: false, pvi: false, wantARP: 0x5d},
		{name: "both enabled", pci: true, pvi: true, wantARP: 0x1c},
		{name: "capability only", pci: true, pvi: false, wantARP: 0x1d},
		{name: "vulnerability only", pci: false, pvi: true, wantARP: 0x5c},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ie := EncodeBearerQoS(7, 7, tc.pci, tc.pvi)
			if got := ie.Value[0]; got != tc.wantARP {
				t.Fatalf("ARP octet got %#02x, want %#02x", got, tc.wantARP)
			}
			parsed, err := ParseBearerQoS(ie.Value)
			if err != nil {
				t.Fatalf("ParseBearerQoS: %v", err)
			}
			if parsed.PreemptionCapability != tc.pci || parsed.PreemptionVulnerability != tc.pvi || parsed.PriorityLevel != 7 || parsed.QCI != 7 {
				t.Fatalf("round trip got %+v, want pci=%t pvi=%t pl=7 qci=7", parsed, tc.pci, tc.pvi)
			}
		})
	}
}
