package s6a

import (
	"testing"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/fiorix/go-diameter/v4/diam/avp"
	"github.com/fiorix/go-diameter/v4/diam/datatype"
	"github.com/fiorix/go-diameter/v4/diam/dict"
	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/uecontext"
)

func buildTestULAWithAPNOIReplacement(sessionID, oi string) *diam.Message {
	m := diam.NewRequest(diam.UpdateLocation, appIDS6a, dict.Default)
	m.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String(sessionID))
	m.NewAVP(avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(diam.Success))
	m.NewAVP(avp.SubscriptionData, avp.Vbit|avp.Mbit, vendor3GPP, &diam.GroupedAVP{
		AVP: []*diam.AVP{
			diam.NewAVP(avp.APNOIReplacement, avp.Vbit, vendor3GPP, datatype.UTF8String(oi)),
		},
	})
	return m
}

func TestHandleULADecodesUELevelAPNOIReplacement(t *testing.T) {
	result := &capturingResultHandler{}
	h := NewHandlers(
		config.S6aConfig{},
		testDiameterConfig(),
		config.NFConfig{OriginHost: "mme.example.net", OriginRealm: "example.net"},
		uecontext.NewManager(),
		result,
		zap.NewNop(),
	)

	const mmeUEID = uint32(50)
	h.pendingULR.Store("sid-oi-1", mmeUEID)

	msg := buildTestULAWithAPNOIReplacement("sid-oi-1", "ue-level.example.net")
	h.handleULA(nil, msg)

	if !result.called {
		t.Fatal("HandleULAResultWithSubscriberProfile not called")
	}
	if result.profile.APNOIReplacement != "ue-level.example.net" {
		t.Errorf("APNOIReplacement got %q, want %q", result.profile.APNOIReplacement, "ue-level.example.net")
	}
}
