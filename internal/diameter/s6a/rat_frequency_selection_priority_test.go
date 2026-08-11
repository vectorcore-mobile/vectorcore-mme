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

func buildTestULAWithRFSP(sessionID string, rfsp uint32) *diam.Message {
	m := diam.NewRequest(diam.UpdateLocation, appIDS6a, dict.Default)
	m.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String(sessionID))
	m.NewAVP(avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(diam.Success))
	m.NewAVP(avp.SubscriptionData, avp.Vbit|avp.Mbit, vendor3GPP, &diam.GroupedAVP{
		AVP: []*diam.AVP{
			diam.NewAVP(avp.RATFrequencySelectionPriorityID, avp.Vbit, vendor3GPP, datatype.Unsigned32(rfsp)),
		},
	})
	return m
}

func TestHandleULADecodesRATFrequencySelectionPriorityID(t *testing.T) {
	result := &capturingResultHandler{}
	h := NewHandlers(
		config.S6aConfig{},
		testDiameterConfig(),
		config.NFConfig{OriginHost: "mme.example.net", OriginRealm: "example.net"},
		uecontext.NewManager(),
		result,
		zap.NewNop(),
	)

	const mmeUEID = uint32(49)
	h.pendingULR.Store("sid-rfsp-1", mmeUEID)

	msg := buildTestULAWithRFSP("sid-rfsp-1", 5)
	h.handleULA(nil, msg)

	if !result.called {
		t.Fatal("HandleULAResultWithSubscriberProfile not called")
	}
	if result.profile.RATFrequencySelectionPriorityID != 5 {
		t.Errorf("RATFrequencySelectionPriorityID got %d, want 5", result.profile.RATFrequencySelectionPriorityID)
	}
}
