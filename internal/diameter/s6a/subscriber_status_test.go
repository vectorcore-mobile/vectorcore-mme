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

func buildTestULAWithSubscriberStatus(sessionID string, subscriberStatus int32, odb uint32) *diam.Message {
	m := diam.NewRequest(diam.UpdateLocation, appIDS6a, dict.Default)
	m.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String(sessionID))
	m.NewAVP(avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(diam.Success))
	m.NewAVP(avp.SubscriptionData, avp.Vbit|avp.Mbit, vendor3GPP, &diam.GroupedAVP{
		AVP: []*diam.AVP{
			diam.NewAVP(avp.SubscriberStatus, avp.Vbit|avp.Mbit, vendor3GPP, datatype.Enumerated(subscriberStatus)),
			diam.NewAVP(avp.OperatorDeterminedBarring, avp.Vbit|avp.Mbit, vendor3GPP, datatype.Unsigned32(odb)),
		},
	})
	return m
}

func TestHandleULADecodesSubscriberStatusBarred(t *testing.T) {
	result := &capturingResultHandler{}
	h := NewHandlers(
		config.S6aConfig{},
		testDiameterConfig(),
		config.NFConfig{OriginHost: "mme.example.net", OriginRealm: "example.net"},
		uecontext.NewManager(),
		result,
		zap.NewNop(),
	)

	const mmeUEID = uint32(47)
	h.pendingULR.Store("sid-status-1", mmeUEID)

	msg := buildTestULAWithSubscriberStatus("sid-status-1", int32(gateway.SubscriberStatusOperatorDeterminedBarring), uint32(gateway.ODBAllPacketOrientedServicesBarred))
	h.handleULA(nil, msg)

	if !result.called {
		t.Fatal("HandleULAResultWithSubscriberProfile not called")
	}
	if !result.profile.SubscriberStatus.Barred() {
		t.Error("Barred() got false, want true")
	}
	if !result.profile.OperatorDeterminedBarring.AllPacketOrientedServicesBarred() {
		t.Error("AllPacketOrientedServicesBarred() got false, want true")
	}
}

func TestHandleULADecodesSubscriberStatusServiceGranted(t *testing.T) {
	result := &capturingResultHandler{}
	h := NewHandlers(
		config.S6aConfig{},
		testDiameterConfig(),
		config.NFConfig{OriginHost: "mme.example.net", OriginRealm: "example.net"},
		uecontext.NewManager(),
		result,
		zap.NewNop(),
	)

	const mmeUEID = uint32(48)
	h.pendingULR.Store("sid-status-2", mmeUEID)

	msg := buildTestULAWithSubscriberStatus("sid-status-2", int32(gateway.SubscriberStatusServiceGranted), 0)
	h.handleULA(nil, msg)

	if !result.called {
		t.Fatal("HandleULAResultWithSubscriberProfile not called")
	}
	if result.profile.SubscriberStatus.Barred() {
		t.Error("Barred() got true, want false")
	}
}
