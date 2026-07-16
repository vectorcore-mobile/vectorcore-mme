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
	if got.PreemptionCapability {
		t.Fatal("PreemptionCapability got true, want false")
	}
	if !got.PreemptionVulnerability {
		t.Fatal("PreemptionVulnerability got false, want true")
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
