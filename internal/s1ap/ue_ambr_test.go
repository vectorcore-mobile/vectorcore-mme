package s1ap

import (
	"bytes"
	"net"
	"testing"

	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/uecontext"
)

func TestEffectiveUEAMBRUsesApplicablePDNs(t *testing.T) {
	ue := uecontext.NewContext(1)
	ue.UEAMBRDown = 100_000_000
	ue.UEAMBRUp = 100_000_000
	ue.PDNs = map[string]*uecontext.PDNContext{
		"internet": {APN: "internet", DefaultEBI: 5, State: "active", APNAMBRDown: 200_000_000, APNAMBRUp: 50_000_000},
		"mms":      {APN: "mms", DefaultEBI: 9, State: "deleted", APNAMBRDown: 128_000, APNAMBRUp: 128_000},
	}
	got := effectiveUEAMBR(ue)
	if got.Downlink != 100_000_000 || got.Uplink != 50_000_000 {
		t.Fatalf("internet-only effective AMBR got DL/UL=%d/%d, want 100000000/50000000", got.Downlink, got.Uplink)
	}

	ims := &uecontext.PDNContext{APN: "ims", DefaultEBI: 6, State: "activating", APNAMBRDown: 1_530_000, APNAMBRUp: 3_850_000}
	got = effectiveUEAMBR(ue, ims)
	if got.Downlink != 100_000_000 || got.Uplink != 53_850_000 {
		t.Fatalf("internet+IMS effective AMBR got DL/UL=%d/%d, want 100000000/53850000", got.Downlink, got.Uplink)
	}

	ue.PDNs["ims"] = ims
	got = effectiveUEAMBR(ue, ims)
	if got.Uplink != 53_850_000 || len(got.PDNs) != 2 {
		t.Fatalf("duplicate pending IMS got UL=%d PDNs=%d, want 53850000 and 2", got.Uplink, len(got.PDNs))
	}

	ims.State = "pdn-disconnect-delete-session-pending"
	got = effectiveUEAMBR(ue)
	if got.Downlink != 100_000_000 || got.Uplink != 50_000_000 {
		t.Fatalf("deleted IMS effective AMBR got DL/UL=%d/%d, want 100000000/50000000", got.Downlink, got.Uplink)
	}
}

func TestEffectiveUEAMBRIdleFallbackAndOverflow(t *testing.T) {
	ue := uecontext.NewContext(1)
	ue.UEAMBRDown = 1_000_000
	ue.UEAMBRUp = 1_000_000
	ue.PDNs = map[string]*uecontext.PDNContext{
		"ims": {APN: "ims", DefaultEBI: 6, State: "idle", APNAMBRDown: 2_000_000, APNAMBRUp: 500_000},
	}
	got := effectiveUEAMBR(ue)
	if got.Downlink != 1_000_000 || got.Uplink != 500_000 {
		t.Fatalf("idle IMS effective AMBR got DL/UL=%d/%d, want 1000000/500000", got.Downlink, got.Uplink)
	}

	ue.UEAMBRDown = 0
	ue.UEAMBRUp = 0
	got = effectiveUEAMBR(ue)
	if got.Downlink != 2_000_000 || got.Uplink != 500_000 {
		t.Fatalf("missing subscribed AMBR fallback got DL/UL=%d/%d, want 2000000/500000", got.Downlink, got.Uplink)
	}
	if saturatingAdd(^uint64(0)-1, 10) != ^uint64(0) {
		t.Fatal("saturating add did not cap overflow")
	}
}

func TestEffectiveUEAMBRBuildsIMSERABSetupValue(t *testing.T) {
	ue := uecontext.NewContext(1)
	ue.UEAMBRDown = 100_000_000
	ue.UEAMBRUp = 100_000_000
	ue.PDNs = map[string]*uecontext.PDNContext{
		"internet": {APN: "internet", DefaultEBI: 5, State: "active", APNAMBRDown: 200_000_000, APNAMBRUp: 50_000_000},
		"ims":      {APN: "ims", DefaultEBI: 6, State: "activating", APNAMBRDown: 1_530_000, APNAMBRUp: 3_850_000},
	}
	effective := effectiveUEAMBR(ue)
	raw, _, err := BuildERABSetupRequest(1, 2, &UEAggregateMaximumBitrate{Downlink: effective.Downlink, Uplink: effective.Uplink}, []ERABSetupItem{{
		EBI: 6, QCI: 5, ARPPriority: 1, SGWS1UIPv4: net.ParseIP("10.90.250.59"), SGWS1UTEID: 1, NASPDU: []byte{0x27, 0x62, 0x00, 0xc1},
	}})
	if err != nil {
		t.Fatalf("BuildERABSetupRequest: %v", err)
	}
	decoded := decodeERABSetupRequest(t, raw)
	want := ies.EncodeUEAggregateMaxBitrate(100_000_000, 53_850_000)
	if !bytes.Equal(decoded.UEAMBR, want) {
		t.Fatalf("IMS E-RAB UE-AMBR got %x, want %x", decoded.UEAMBR, want)
	}
}
