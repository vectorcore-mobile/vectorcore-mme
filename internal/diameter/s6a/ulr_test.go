package s6a

import (
	"testing"

	"github.com/fiorix/go-diameter/v4/diam/avp"
	"github.com/fiorix/go-diameter/v4/diam/datatype"
	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/uecontext"
)

func TestBuildULRUsesConfiguredFlags(t *testing.T) {
	h := NewHandlers(
		config.S6aConfig{
			Routing: config.S6aRoutingConfig{SendDestinationHost: true},
			ULR:     config.S6aULRConfig{Flags: 18},
		},
		config.NFConfig{OriginHost: "mme.example.net", OriginRealm: "example.net"},
		uecontext.NewManager(),
		nil,
		zap.NewNop(),
	)

	msg := h.buildULR("sid", "001010123456789", [3]byte{0x00, 0xf1, 0x10}, "hss.remote.net", "remote.net")

	flagsAVP := findAVP(msg, avp.ULRFlags)
	if flagsAVP == nil {
		t.Fatal("ULR-Flags missing")
	}
	if got := uint32(flagsAVP.Data.(datatype.Unsigned32)); got != 18 {
		t.Fatalf("ULR-Flags got %d, want 18", got)
	}
}

func TestBuildULROmitsDestinationHostWhenDisabled(t *testing.T) {
	h := NewHandlers(
		config.S6aConfig{
			Routing: config.S6aRoutingConfig{SendDestinationHost: false},
			ULR:     config.S6aULRConfig{Flags: 2},
		},
		config.NFConfig{OriginHost: "mme.example.net", OriginRealm: "example.net"},
		uecontext.NewManager(),
		nil,
		zap.NewNop(),
	)

	msg := h.buildULR("sid", "001010123456789", [3]byte{0x00, 0xf1, 0x10}, "hss.remote.net", "remote.net")

	if findAVP(msg, avp.DestinationHost) != nil {
		t.Fatal("Destination-Host present, want omitted")
	}
	realmAVP := findAVP(msg, avp.DestinationRealm)
	if realmAVP == nil {
		t.Fatal("Destination-Realm missing")
	}
	if got := string(realmAVP.Data.(datatype.DiameterIdentity)); got != "remote.net" {
		t.Fatalf("Destination-Realm got %q, want %q", got, "remote.net")
	}
}
