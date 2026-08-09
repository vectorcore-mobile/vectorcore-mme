package s6a

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/diameter/slg"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/lcsnotify"
	"github.com/vectorcore/mme/internal/uecontext"
	"go.uber.org/zap"
)

type fakeLCSNotifier struct {
	granted bool
	err     error
	calls   []lcsnotify.NotificationType
	waited  []bool
}

func (f *fakeLCSNotifier) SendLocationNotification(_ uint32, notificationType lcsnotify.NotificationType, wait bool, _ time.Duration) (bool, error) {
	f.calls = append(f.calls, notificationType)
	f.waited = append(f.waited, wait)
	return f.granted, f.err
}

func newTestHandlers() *Handlers {
	h := NewHandlers(config.S6aConfig{}, config.DiameterConfig{}, config.NFConfig{}, uecontext.NewManager(), nil, zap.NewNop())
	h.SetSLgConfig(config.SLgConfig{TransactionTimeout: time.Second, ReportTimeout: time.Second, TransactionCapacity: 8, NotificationTimeout: time.Second})
	return h
}

func TestApplyPrivacyCheckNotificationAllowedWithNotification(t *testing.T) {
	h := newTestHandlers()
	fake := &fakeLCSNotifier{granted: false, err: errors.New("irrelevant")} // response is ignored for this value
	h.SetLCSNotifier(fake)
	if !h.applyPrivacyCheckNotification(1, slg.LCSPrivacyCheckAllowedWithNotification, "sid") {
		t.Fatal("want proceed=true regardless of response")
	}
	if len(fake.calls) != 1 || fake.calls[0] != lcsnotify.NotifyLocationAllowed || fake.waited[0] {
		t.Fatalf("unexpected call: %+v waited=%v", fake.calls, fake.waited)
	}
}

func TestApplyPrivacyCheckNotificationAllowedIfNoResponse(t *testing.T) {
	h := newTestHandlers()
	for _, tc := range []struct {
		name    string
		granted bool
		err     error
		want    bool
	}{
		{"explicit grant", true, nil, true},
		{"explicit denial", false, nil, false},
		{"no response (timeout)", false, context.DeadlineExceeded, true},
		{"no notifier configured", false, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "no notifier configured" {
				h.SetLCSNotifier(nil)
			} else {
				h.SetLCSNotifier(&fakeLCSNotifier{granted: tc.granted, err: tc.err})
			}
			got := h.applyPrivacyCheckNotification(1, slg.LCSPrivacyCheckAllowedIfNoResponse, "sid")
			if got != tc.want {
				t.Fatalf("got=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestApplyPrivacyCheckNotificationRestrictedIfNoResponse(t *testing.T) {
	h := newTestHandlers()
	for _, tc := range []struct {
		name    string
		granted bool
		err     error
		want    bool
	}{
		{"explicit grant", true, nil, true},
		{"explicit denial", false, nil, false},
		{"no response (timeout)", false, context.DeadlineExceeded, false},
		{"no notifier configured", false, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "no notifier configured" {
				h.SetLCSNotifier(nil)
			} else {
				h.SetLCSNotifier(&fakeLCSNotifier{granted: tc.granted, err: tc.err})
			}
			got := h.applyPrivacyCheckNotification(1, slg.LCSPrivacyCheckRestrictedIfNoResponse, "sid")
			if got != tc.want {
				t.Fatalf("got=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestApplyPrivacyCheckNotificationWaitsOnlyForNoResponseVariants(t *testing.T) {
	h := newTestHandlers()
	fake := &fakeLCSNotifier{granted: true}
	h.SetLCSNotifier(fake)
	h.applyPrivacyCheckNotification(1, slg.LCSPrivacyCheckAllowedIfNoResponse, "sid")
	h.applyPrivacyCheckNotification(1, slg.LCSPrivacyCheckRestrictedIfNoResponse, "sid")
	if len(fake.waited) != 2 || !fake.waited[0] || !fake.waited[1] {
		t.Fatalf("want both no-response variants to wait: %v", fake.waited)
	}
	if fake.calls[0] != lcsnotify.NotifyAndVerifyLocationAllowedIfNoResponse || fake.calls[1] != lcsnotify.NotifyAndVerifyLocationNotAllowedIfNoResponse {
		t.Fatalf("unexpected notification types: %v", fake.calls)
	}
}

func TestSLgTBCDAndIdentityResolution(t *testing.T) {
	manager := uecontext.NewManager()
	ue := manager.Allocate()
	manager.UpdateIMSI(ue, "001010123456789")
	ue.Lock()
	ue.MSISDN = "15551234567"
	ue.EMMState = emm.StateRegistered
	ue.Unlock()
	h := NewHandlers(config.S6aConfig{}, config.DiameterConfig{}, config.NFConfig{}, manager, nil, zap.NewNop())
	for _, tc := range []struct {
		name string
		req  slg.ProvideLocationRequest
		want uint32
	}{
		{"imsi", slg.ProvideLocationRequest{IMSI: "001010123456789"}, 0},
		{"msisdn", slg.ProvideLocationRequest{MSISDN: []byte{0x51, 0x55, 0x21, 0x43, 0x65, 0xf7}}, 0},
		{"matching", slg.ProvideLocationRequest{IMSI: "001010123456789", MSISDN: []byte{0x51, 0x55, 0x21, 0x43, 0x65, 0xf7}}, 0},
		{"contradictory", slg.ProvideLocationRequest{IMSI: "001010123456789", MSISDN: []byte{0x51, 0x55, 0x21, 0x43, 0x65, 0xf6}}, uint32(diam.InvalidAVPValue)},
		{"invalid tbcd", slg.ProvideLocationRequest{MSISDN: []byte{0xfa}}, uint32(diam.InvalidAVPValue)},
		{"missing", slg.ProvideLocationRequest{}, uint32(diam.MissingAVP)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, result, _ := h.resolveSLgUE(&tc.req)
			if result != tc.want {
				t.Fatalf("result=%d want=%d", result, tc.want)
			}
		})
	}
}

func TestSLgTransactionsCancelAndNoPersistence(t *testing.T) {
	store := newSLgTransactions(1)
	ctx, err := store.Begin("one", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Begin("one", time.Second); err == nil {
		t.Fatal("duplicate was accepted")
	}
	store.End("one")
	select {
	case <-ctx.Done():
	default:
		t.Fatal("completion did not cancel transaction")
	}
	if _, err := store.Begin("two", time.Second); err != nil {
		t.Fatal(err)
	}
	store.Close()
	if _, err := store.Begin("three", time.Second); err == nil {
		t.Fatal("closed store accepted transaction")
	}
	if context.Cause(ctx) == nil {
		t.Fatal("transaction has no cancellation cause")
	}
}
