package s6a

import (
	"testing"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/fiorix/go-diameter/v4/diam/avp"
	"github.com/fiorix/go-diameter/v4/diam/datatype"
	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/uecontext"
)

func testDiameterConfig() config.DiameterConfig {
	return config.DiameterConfig{OriginHost: "mme.example.net", OriginRealm: "example.net", Peers: []config.DiameterPeerConfig{{Name: "peer", Address: "127.0.0.1:3868"}}}
}

func TestBuildAIRUsesConfiguredRoutingAndRequestedVectors(t *testing.T) {
	h := NewHandlers(
		config.S6aConfig{
			AIR: config.S6aAIRConfig{
				RequestedVectors:           3,
				ImmediateResponsePreferred: false,
			},
		},
		testDiameterConfig(),
		config.NFConfig{OriginHost: "mme.example.net", OriginRealm: "example.net"},
		uecontext.NewManager(),
		nil,
		zap.NewNop(),
	)

	msg := h.buildAIR("sid", "001010123456789", [3]byte{0x00, 0xf1, 0x10}, "hss.remote.net", "remote.net")

	hostAVP := findAVP(msg, avp.DestinationHost)
	if hostAVP == nil {
		t.Fatal("Destination-Host missing")
	}
	if got := string(hostAVP.Data.(datatype.DiameterIdentity)); got != "hss.remote.net" {
		t.Fatalf("Destination-Host got %q, want %q", got, "hss.remote.net")
	}
	realmAVP := findAVP(msg, avp.DestinationRealm)
	if realmAVP == nil {
		t.Fatal("Destination-Realm missing")
	}
	if got := string(realmAVP.Data.(datatype.DiameterIdentity)); got != "remote.net" {
		t.Fatalf("Destination-Realm got %q, want %q", got, "remote.net")
	}

	grouped := findAVP(msg, avp.RequestedEUTRANAuthenticationInfo)
	if grouped == nil {
		t.Fatal("Requested-EUTRAN-Authentication-Info missing")
	}
	group, ok := grouped.Data.(*diam.GroupedAVP)
	if !ok {
		t.Fatalf("Requested-EUTRAN-Authentication-Info type %T, want *diam.GroupedAVP", grouped.Data)
	}
	if got := findGroupedUnsigned32(group, avp.NumberOfRequestedVectors); got != 3 {
		t.Fatalf("Number-Of-Requested-Vectors got %d, want 3", got)
	}
	if got := findGroupedUnsigned32(group, avp.ImmediateResponsePreferred); got != 0 {
		t.Fatalf("Immediate-Response-Preferred got %d, want 0", got)
	}
}

func TestBuildAIROmitsDestinationHostForRelay(t *testing.T) {
	h := NewHandlers(
		config.S6aConfig{
			AIR: config.S6aAIRConfig{
				RequestedVectors:           1,
				ImmediateResponsePreferred: true,
			},
		},
		testDiameterConfig(),
		config.NFConfig{OriginHost: "mme.example.net", OriginRealm: "example.net"},
		uecontext.NewManager(),
		nil,
		zap.NewNop(),
	)

	msg := h.buildAIR("sid", "001010123456789", [3]byte{0x00, 0xf1, 0x10}, "", "remote.net")

	if findAVP(msg, avp.DestinationHost) != nil {
		t.Fatal("Destination-Host present, want omitted")
	}
	if findAVP(msg, avp.DestinationRealm) == nil {
		t.Fatal("Destination-Realm missing")
	}
}

func findGroupedUnsigned32(group *diam.GroupedAVP, code uint32) uint32 {
	for _, candidate := range group.AVP {
		if uint32(candidate.Code) != code {
			continue
		}
		value, ok := candidate.Data.(datatype.Unsigned32)
		if !ok {
			return 0
		}
		return uint32(value)
	}
	return 0
}
