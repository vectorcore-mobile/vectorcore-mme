package s6a

import (
	"bytes"
	"testing"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/fiorix/go-diameter/v4/diam/avp"
	"github.com/fiorix/go-diameter/v4/diam/datatype"
	"github.com/fiorix/go-diameter/v4/diam/dict"
	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/uecontext"
)

func buildTestULAWithZoneCodes(sessionID string, zoneCodes ...[]byte) *diam.Message {
	m := diam.NewRequest(diam.UpdateLocation, appIDS6a, dict.Default)
	m.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String(sessionID))
	m.NewAVP(avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(diam.Success))
	subAVPs := make([]*diam.AVP, 0, len(zoneCodes))
	for _, zc := range zoneCodes {
		subAVPs = append(subAVPs, diam.NewAVP(avp.RegionalSubscriptionZoneCode, avp.Vbit, vendor3GPP, datatype.OctetString(zc)))
	}
	m.NewAVP(avp.SubscriptionData, avp.Vbit|avp.Mbit, vendor3GPP, &diam.GroupedAVP{AVP: subAVPs})
	return m
}

func TestHandleULADecodesRegionalSubscriptionZoneCodes(t *testing.T) {
	result := &capturingResultHandler{}
	h := NewHandlers(
		config.S6aConfig{},
		testDiameterConfig(),
		config.NFConfig{OriginHost: "mme.example.net", OriginRealm: "example.net"},
		uecontext.NewManager(),
		result,
		zap.NewNop(),
	)

	const mmeUEID = uint32(52)
	h.pendingULR.Store("sid-zone-1", mmeUEID)

	msg := buildTestULAWithZoneCodes("sid-zone-1", []byte{0x01, 0x02}, []byte{0x03, 0x04})
	h.handleULA(nil, msg)

	if !result.called {
		t.Fatal("HandleULAResultWithSubscriberProfile not called")
	}
	if len(result.profile.RegionalSubscriptionZoneCodes) != 2 {
		t.Fatalf("RegionalSubscriptionZoneCodes count got %d, want 2", len(result.profile.RegionalSubscriptionZoneCodes))
	}
	if !bytes.Equal(result.profile.RegionalSubscriptionZoneCodes[0], []byte{0x01, 0x02}) {
		t.Errorf("zone code[0] got %x, want %x", result.profile.RegionalSubscriptionZoneCodes[0], []byte{0x01, 0x02})
	}
	if !bytes.Equal(result.profile.RegionalSubscriptionZoneCodes[1], []byte{0x03, 0x04}) {
		t.Errorf("zone code[1] got %x, want %x", result.profile.RegionalSubscriptionZoneCodes[1], []byte{0x03, 0x04})
	}
}

func buildTestIDRWithZoneCodes(imsi string, zoneCodes ...[]byte) *diam.Message {
	m := diam.NewRequest(diam.InsertSubscriberData, appIDS6a, dict.Default)
	m.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String("idr-zone-sid"))
	m.NewAVP(avp.AuthSessionState, avp.Mbit, 0, datatype.Enumerated(1))
	m.NewAVP(avp.UserName, avp.Mbit, 0, datatype.UTF8String(imsi))
	subAVPs := make([]*diam.AVP, 0, len(zoneCodes))
	for _, zc := range zoneCodes {
		subAVPs = append(subAVPs, diam.NewAVP(avp.RegionalSubscriptionZoneCode, avp.Vbit, vendor3GPP, datatype.OctetString(zc)))
	}
	m.NewAVP(avp.SubscriptionData, avp.Vbit|avp.Mbit, vendor3GPP, &diam.GroupedAVP{AVP: subAVPs})
	return m
}

func TestHandleIDRStoresRegionalSubscriptionZoneCodes(t *testing.T) {
	const imsi = "001010123456789"
	ueManager := uecontext.NewManager()
	ue := ueManager.Allocate()
	ue.Lock()
	ue.IMSI = imsi
	ue.Unlock()
	ueManager.Register(ue)

	h := NewHandlers(
		config.S6aConfig{},
		testDiameterConfig(),
		config.NFConfig{OriginHost: "mme.example.net", OriginRealm: "example.net"},
		ueManager,
		nil,
		zap.NewNop(),
	)

	msg := buildTestIDRWithZoneCodes(imsi, []byte{0xAA})
	h.handleIDR(discardConn{}, msg)

	got, ok := ueManager.GetByIMSI(imsi)
	if !ok {
		t.Fatal("UE not found after IDR")
	}
	if len(got.RegionalSubscriptionZoneCodes) != 1 || !bytes.Equal(got.RegionalSubscriptionZoneCodes[0], []byte{0xAA}) {
		t.Fatalf("RegionalSubscriptionZoneCodes got %v, want [[0xAA]]", got.RegionalSubscriptionZoneCodes)
	}
}
