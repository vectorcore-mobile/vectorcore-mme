package s6a

import (
	"testing"
	"time"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/fiorix/go-diameter/v4/diam/avp"
	"github.com/fiorix/go-diameter/v4/diam/datatype"
	"github.com/fiorix/go-diameter/v4/diam/dict"
	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/config"
)

func TestBuildNORCarriesAlertReason(t *testing.T) {
	h := &Handlers{diameterCfg: config.DiameterConfig{OriginHost: "mme.test", OriginRealm: "test"}}
	m := h.buildNOR("mme.test;1", "001010123456789", "hss.test", "test", AlertReasonUEMemoryAvailable)
	if m.Header.CommandCode != diam.Notify || m.Header.ApplicationID != appIDS6a || m.Header.CommandFlags&diam.RequestFlag == 0 {
		t.Fatalf("NOR header = %+v", m.Header)
	}
	if _, err := m.Serialize(); err != nil {
		t.Fatalf("serialize NOR: %v", err)
	}
	want := map[uint32]bool{avp.SessionID: false, avp.AuthSessionState: false, avp.OriginHost: false, avp.OriginRealm: false,
		avp.DestinationHost: false, avp.DestinationRealm: false, avp.UserName: false}
	var reason *diam.AVP
	for _, a := range m.AVP {
		if a.Code == avpAlertReason && a.VendorID == vendor3GPP {
			reason = a
		}
		if _, ok := want[a.Code]; ok && a.VendorID == 0 {
			want[a.Code] = true
		}
	}
	for code, seen := range want {
		if !seen {
			t.Errorf("NOR missing AVP %d", code)
		}
	}
	if reason == nil || reason.Flags&avp.Vbit == 0 || reason.Flags&avp.Mbit == 0 ||
		int32(reason.Data.(datatype.Enumerated)) != AlertReasonUEMemoryAvailable {
		t.Fatalf("Alert-Reason = %+v, want M/V vendor 10415 value 1", reason)
	}
	if user, _ := m.FindAVP(avp.UserName, 0); user == nil || string(user.Data.(datatype.UTF8String)) != "001010123456789" {
		t.Fatalf("User-Name = %v", user)
	}
}

func TestHandleNOACorrelatesResult(t *testing.T) {
	cases := []struct {
		name  string
		build func(*diam.Message)
		want  uint32
	}{
		{"success", func(m *diam.Message) {
			m.NewAVP(avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(diam.Success))
		}, diam.Success},
		{"experimental user unknown", func(m *diam.Message) {
			m.NewAVP(avp.ExperimentalResult, avp.Mbit, 0, &diam.GroupedAVP{AVP: []*diam.AVP{
				diam.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(vendor3GPP)),
				diam.NewAVP(avp.ExperimentalResultCode, avp.Mbit, 0, datatype.Unsigned32(5001)),
			}})
		}, 5001},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handlers{log: zap.NewNop()}
			ch := make(chan uint32, 1)
			h.pendingNOR.Store("mme.test;nor", ch)
			m := diam.NewMessage(diam.Notify, 0, appIDS6a, 1, 1, dict.Default)
			m.NewAVP(avp.SessionID, avp.Mbit, 0, datatype.UTF8String("mme.test;nor"))
			tc.build(m)
			h.handleNOA(discardConn{}, m)
			select {
			case got := <-ch:
				if got != tc.want {
					t.Fatalf("NOA result = %d, want %d", got, tc.want)
				}
			case <-time.After(time.Second):
				t.Fatal("NOA not correlated")
			}
		})
	}
}
