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
			ULR: config.S6aULRConfig{Flags: 18},
		},
		testDiameterConfig(),
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

func TestBuildULROmitsDestinationHostForRelay(t *testing.T) {
	h := NewHandlers(
		config.S6aConfig{
			ULR: config.S6aULRConfig{Flags: 2},
		},
		testDiameterConfig(),
		config.NFConfig{OriginHost: "mme.example.net", OriginRealm: "example.net"},
		uecontext.NewManager(),
		nil,
		zap.NewNop(),
	)

	msg := h.buildULR("sid", "001010123456789", [3]byte{0x00, 0xf1, 0x10}, "", "remote.net")

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

func TestBuildULRRequestsSMSRegistrationWhenSGdEnabled(t *testing.T) {
	h := NewHandlers(config.S6aConfig{ULR: config.S6aULRConfig{Flags: 2}}, testDiameterConfig(),
		config.NFConfig{OriginHost: "mme.example.net", OriginRealm: "example.net"}, uecontext.NewManager(), nil, zap.NewNop())
	h.SetSGdConfig(config.SGdConfig{Enabled: true, SubscribeEPSOnlyAttach: true, MMENumberForMTSMS: "+15551230001"})
	msg := h.buildULR("sid", "001010123456789", [3]byte{0x00, 0xf1, 0x10}, "", "remote.net")
	flags := findAVP(msg, avp.ULRFlags)
	if flags == nil || uint32(flags.Data.(datatype.Unsigned32)) != 0x82 {
		t.Fatalf("ULR-Flags = %#v, want SMS-only indication", flags)
	}
	if got := findAVP(msg, 1645); got == nil || string(got.Data.(datatype.OctetString)) != string([]byte{0x51, 0x55, 0x21, 0x03, 0x00, 0xf1}) {
		t.Fatalf("MME-Number-for-MT-SMS = %#v", got)
	}
	if got := findAVP(msg, 1648); got == nil || got.Data.(datatype.Enumerated) != 0 {
		t.Fatalf("SMS-Register-Request = %#v", got)
	}
	if findAVP(msg, avp.SupportedFeatures) == nil {
		t.Fatal("Supported-Features missing")
	}
}

func TestBuildULROmitsSMSRegistrationWhenDisabled(t *testing.T) {
	h := NewHandlers(config.S6aConfig{ULR: config.S6aULRConfig{Flags: 2}}, testDiameterConfig(),
		config.NFConfig{OriginHost: "mme.example.net", OriginRealm: "example.net"}, uecontext.NewManager(), nil, zap.NewNop())
	msg := h.buildULR("sid", "001010123456789", [3]byte{0x00, 0xf1, 0x10}, "", "remote.net")
	for _, code := range []uint32{1645, 1648, avp.SupportedFeatures} {
		if findAVP(msg, code) != nil {
			t.Fatalf("unexpected AVP %d", code)
		}
	}
}
