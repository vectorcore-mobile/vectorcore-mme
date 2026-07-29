package s6a

import (
	"context"
	"testing"
	"time"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/diameter/slg"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/uecontext"
	"go.uber.org/zap"
)

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
