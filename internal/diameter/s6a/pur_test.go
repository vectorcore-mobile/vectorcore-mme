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

func TestSendPURDisabledSkipsConnectionLookup(t *testing.T) {
	h := NewHandlers(
		config.S6aConfig{SendPUROnDetach: false},
		config.NFConfig{OriginHost: "mme.example.net", OriginRealm: "example.net"},
		uecontext.NewManager(),
		nil,
		zap.NewNop(),
	)

	if err := h.SendPUR("001010123456789"); err != nil {
		t.Fatalf("SendPUR disabled got error: %v", err)
	}
}

func TestBuildPURUsesPeerRealm(t *testing.T) {
	h := NewHandlers(
		config.S6aConfig{
			SendPUROnDetach: true,
			Routing:         config.S6aRoutingConfig{SendDestinationHost: true},
		},
		config.NFConfig{OriginHost: "mme.example.net", OriginRealm: "example.net"},
		uecontext.NewManager(),
		nil,
		zap.NewNop(),
	)

	msg := h.buildPUR("001010123456789", "hss.remote.net", "remote.net")

	var got struct {
		DestinationHost  datatype.DiameterIdentity `avp:"Destination-Host"`
		DestinationRealm datatype.DiameterIdentity `avp:"Destination-Realm"`
		UserName         datatype.UTF8String       `avp:"User-Name"`
	}
	if err := msg.Unmarshal(&got); err != nil {
		t.Fatalf("Unmarshal PUR AVPs: %v", err)
	}
	if got.DestinationHost != "hss.remote.net" {
		t.Fatalf("Destination-Host got %q, want %q", got.DestinationHost, "hss.remote.net")
	}
	if got.DestinationRealm != "remote.net" {
		t.Fatalf("Destination-Realm got %q, want %q", got.DestinationRealm, "remote.net")
	}
	if got.UserName != "001010123456789" {
		t.Fatalf("User-Name got %q, want %q", got.UserName, "001010123456789")
	}
	if len(msg.AVP) < 7 {
		t.Fatalf("PUR AVP count got %d, want at least 7", len(msg.AVP))
	}
	if msg.AVP[3].Code != avp.DestinationHost || msg.AVP[4].Code != avp.DestinationRealm {
		t.Fatalf("PUR AVP ordering got codes [%d %d], want [%d %d]", msg.AVP[3].Code, msg.AVP[4].Code, avp.DestinationHost, avp.DestinationRealm)
	}
}

func TestBuildPUROmitsDestinationHostWhenDisabled(t *testing.T) {
	h := NewHandlers(
		config.S6aConfig{
			SendPUROnDetach: true,
			Routing:         config.S6aRoutingConfig{SendDestinationHost: false},
		},
		config.NFConfig{OriginHost: "mme.example.net", OriginRealm: "example.net"},
		uecontext.NewManager(),
		nil,
		zap.NewNop(),
	)

	msg := h.buildPUR("001010123456789", "hss.remote.net", "remote.net")

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

func findAVP(msg *diam.Message, code uint32) *diam.AVP {
	for _, candidate := range msg.AVP {
		if uint32(candidate.Code) == code {
			return candidate
		}
	}
	return nil
}
