package s6a

import (
	"testing"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/fiorix/go-diameter/v4/diam/avp"
	"github.com/fiorix/go-diameter/v4/diam/datatype"
	"github.com/fiorix/go-diameter/v4/diam/dict"
	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/gateway"
	"github.com/vectorcore/mme/internal/uecontext"
)

func buildTestULAWithNAM(sessionID string, networkAccessMode int32) *diam.Message {
	m := diam.NewRequest(diam.UpdateLocation, appIDS6a, dict.Default)
	m.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String(sessionID))
	m.NewAVP(avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(diam.Success))
	m.NewAVP(avp.SubscriptionData, avp.Vbit|avp.Mbit, vendor3GPP, &diam.GroupedAVP{
		AVP: []*diam.AVP{
			diam.NewAVP(avp.NetworkAccessMode, avp.Vbit|avp.Mbit, vendor3GPP, datatype.Enumerated(networkAccessMode)),
		},
	})
	return m
}

func TestHandleULADecodesNetworkAccessModePSOnly(t *testing.T) {
	result := &capturingResultHandler{}
	h := NewHandlers(
		config.S6aConfig{},
		testDiameterConfig(),
		config.NFConfig{OriginHost: "mme.example.net", OriginRealm: "example.net"},
		uecontext.NewManager(),
		result,
		zap.NewNop(),
	)

	const mmeUEID = uint32(44)
	h.pendingULR.Store("sid-nam-1", mmeUEID)

	msg := buildTestULAWithNAM("sid-nam-1", int32(gateway.NAMOnlyPacket))
	h.handleULA(nil, msg)

	if !result.called {
		t.Fatal("HandleULAResultWithSubscriberProfile not called")
	}
	if result.profile == nil {
		t.Fatal("profile is nil")
	}
	if !result.profile.NetworkAccessMode.PSOnly() {
		t.Error("PSOnly() got false, want true")
	}
}

func TestHandleULADecodesNetworkAccessModePacketAndCircuit(t *testing.T) {
	result := &capturingResultHandler{}
	h := NewHandlers(
		config.S6aConfig{},
		testDiameterConfig(),
		config.NFConfig{OriginHost: "mme.example.net", OriginRealm: "example.net"},
		uecontext.NewManager(),
		result,
		zap.NewNop(),
	)

	const mmeUEID = uint32(45)
	h.pendingULR.Store("sid-nam-2", mmeUEID)

	msg := buildTestULAWithNAM("sid-nam-2", int32(gateway.NAMPacketAndCircuit))
	h.handleULA(nil, msg)

	if !result.called {
		t.Fatal("HandleULAResultWithSubscriberProfile not called")
	}
	if result.profile.NetworkAccessMode.PSOnly() {
		t.Error("PSOnly() got true, want false")
	}
}
