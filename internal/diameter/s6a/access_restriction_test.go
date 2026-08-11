package s6a

import (
	"context"
	"crypto/tls"
	"net"
	"testing"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/fiorix/go-diameter/v4/diam/avp"
	"github.com/fiorix/go-diameter/v4/diam/datatype"
	"github.com/fiorix/go-diameter/v4/diam/dict"
	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/gateway"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/uecontext"
)

// discardConn is a minimal diam.Conn that discards anything written to it,
// for handlers (like handleIDR) that answer on the connection as a side
// effect of processing an inbound request.
type discardConn struct{}

func (discardConn) Write(b []byte) (int, error)                    { return len(b), nil }
func (discardConn) WriteStream(b []byte, stream uint) (int, error) { return len(b), nil }
func (discardConn) Close()                                         {}
func (discardConn) LocalAddr() net.Addr                            { return &net.TCPAddr{} }
func (discardConn) RemoteAddr() net.Addr                           { return &net.TCPAddr{} }
func (discardConn) TLS() *tls.ConnectionState                      { return nil }
func (discardConn) Dictionary() *dict.Parser                       { return dict.Default }
func (discardConn) Context() context.Context                       { return context.Background() }
func (discardConn) SetContext(ctx context.Context)                 {}
func (discardConn) Connection() net.Conn                           { return nil }

// capturingResultHandler records the profile passed to
// HandleULAResultWithSubscriberProfile so tests can assert on the decoded
// Access-Restriction-Data.
type capturingResultHandler struct {
	profile *gateway.SubscriberProfile
	err     error
	called  bool
}

func (c *capturingResultHandler) HandleAIAResult(mmeUEID uint32, rand, xres, autn, kasme []byte, err error) {
}

func (c *capturingResultHandler) HandleULAResultWithSubscriberProfile(mmeUEID uint32, msisdn string, profile *gateway.SubscriberProfile, err error) {
	c.called = true
	c.profile = profile
	c.err = err
}

func buildTestULA(sessionID string, accessRestrictionData uint32) *diam.Message {
	m := diam.NewRequest(diam.UpdateLocation, appIDS6a, dict.Default)
	m.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String(sessionID))
	m.NewAVP(avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(diam.Success))
	m.NewAVP(avp.SubscriptionData, avp.Vbit|avp.Mbit, vendor3GPP, &diam.GroupedAVP{
		AVP: []*diam.AVP{
			diam.NewAVP(avp.AccessRestrictionData, avp.Vbit|avp.Mbit, vendor3GPP, datatype.Unsigned32(accessRestrictionData)),
		},
	})
	return m
}

func TestHandleULADecodesAccessRestrictionData(t *testing.T) {
	result := &capturingResultHandler{}
	h := NewHandlers(
		config.S6aConfig{},
		testDiameterConfig(),
		config.NFConfig{OriginHost: "mme.example.net", OriginRealm: "example.net"},
		uecontext.NewManager(),
		result,
		zap.NewNop(),
	)

	const mmeUEID = uint32(42)
	h.pendingULR.Store("sid-1", mmeUEID)

	msg := buildTestULA("sid-1", uint32(gateway.AccessRestrictWBEUTRAN|gateway.AccessRestrictNRAsSecondaryRATInEUTRAN))
	h.handleULA(nil, msg)

	if !result.called {
		t.Fatal("HandleULAResultWithSubscriberProfile not called")
	}
	if result.err != nil {
		t.Fatalf("unexpected error: %v", result.err)
	}
	if result.profile == nil {
		t.Fatal("profile is nil")
	}
	if !result.profile.AccessRestrictionData.WBEUTRANNotAllowed() {
		t.Error("WBEUTRANNotAllowed() got false, want true")
	}
	if !result.profile.AccessRestrictionData.NRAsSecondaryRATInEUTRANNotAllowed() {
		t.Error("NRAsSecondaryRATInEUTRANNotAllowed() got false, want true")
	}
	if result.profile.AccessRestrictionData.UTRANNotAllowed() {
		t.Error("UTRANNotAllowed() got true, want false")
	}
}

func TestHandleULADecodesZeroAccessRestrictionDataAsUnrestricted(t *testing.T) {
	result := &capturingResultHandler{}
	h := NewHandlers(
		config.S6aConfig{},
		testDiameterConfig(),
		config.NFConfig{OriginHost: "mme.example.net", OriginRealm: "example.net"},
		uecontext.NewManager(),
		result,
		zap.NewNop(),
	)

	const mmeUEID = uint32(43)
	h.pendingULR.Store("sid-2", mmeUEID)

	msg := buildTestULA("sid-2", 0)
	h.handleULA(nil, msg)

	if !result.called {
		t.Fatal("HandleULAResultWithSubscriberProfile not called")
	}
	if result.profile.AccessRestrictionData.WBEUTRANNotAllowed() {
		t.Error("WBEUTRANNotAllowed() got true, want false")
	}
}

func buildTestIDR(imsi string, accessRestrictionData uint32) *diam.Message {
	m := diam.NewRequest(diam.InsertSubscriberData, appIDS6a, dict.Default)
	m.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String("idr-sid"))
	m.NewAVP(avp.AuthSessionState, avp.Mbit, 0, datatype.Enumerated(1))
	m.NewAVP(avp.UserName, avp.Mbit, 0, datatype.UTF8String(imsi))
	m.NewAVP(avp.SubscriptionData, avp.Vbit|avp.Mbit, vendor3GPP, &diam.GroupedAVP{
		AVP: []*diam.AVP{
			diam.NewAVP(avp.AccessRestrictionData, avp.Vbit|avp.Mbit, vendor3GPP, datatype.Unsigned32(accessRestrictionData)),
		},
	})
	return m
}

func TestHandleIDRTriggersDetachWhenWBEUTRANNewlyRestricted(t *testing.T) {
	const imsi = "001010123456789"
	ueManager := uecontext.NewManager()
	ue := ueManager.Allocate()
	ue.Lock()
	ue.IMSI = imsi
	ue.EMMState = emm.StateRegistered
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

	var detached *uecontext.Context
	h.SetDetachFn(func(ue *uecontext.Context) { detached = ue })

	msg := buildTestIDR(imsi, uint32(gateway.AccessRestrictWBEUTRAN))
	h.handleIDR(discardConn{}, msg)

	if detached == nil {
		t.Fatal("detachFn not called, want detach triggered")
	}
	if _, ok := ueManager.GetByIMSI(imsi); ok {
		t.Error("UE still present in manager, want removed")
	}
}

func TestHandleIDRDoesNotDetachWhenNotRestricted(t *testing.T) {
	const imsi = "001010123456789"
	ueManager := uecontext.NewManager()
	ue := ueManager.Allocate()
	ue.Lock()
	ue.IMSI = imsi
	ue.EMMState = emm.StateRegistered
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

	var detached *uecontext.Context
	h.SetDetachFn(func(ue *uecontext.Context) { detached = ue })

	msg := buildTestIDR(imsi, uint32(gateway.AccessRestrictGERAN))
	h.handleIDR(discardConn{}, msg)

	if detached != nil {
		t.Error("detachFn called, want no detach for a non-WB-E-UTRAN restriction")
	}
	got, ok := ueManager.GetByIMSI(imsi)
	if !ok {
		t.Fatal("UE removed from manager, want still present")
	}
	if !got.AccessRestrictionData.GERANNotAllowed() {
		t.Error("stored AccessRestrictionData missing GERANNotAllowed bit")
	}
}
