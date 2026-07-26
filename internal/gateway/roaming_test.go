package gateway

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/vectorcore/mme/internal/plmn"
	"go.uber.org/zap"
)

func TestSelectS8PGWUsesHPLMNAndNeverStaticFallback(t *testing.T) {
	cfg := testConfig("127.0.0.1:9", "local.invalid")
	sel := NewSelector(cfg, zap.NewNop())
	home := plmn.PLMN{MCC: "001", MNC: "01"}
	query := "internet.apn.epc.mnc001.mcc001.3gppnetwork.org"
	sel.lookupNAPTRFn = func(_ context.Context, name string) ([]*dns.NAPTR, time.Duration, error) {
		if name != query {
			t.Fatalf("query = %q", name)
		}
		return []*dns.NAPTR{{Flags: "a", Service: ServicePGWS8GT, Replacement: "pgw.home."}}, time.Minute, nil
	}
	sel.lookupAddrFn = func(_ context.Context, host string) ([]net.IP, time.Duration, error) {
		if host != "pgw.home" {
			t.Fatalf("host = %q", host)
		}
		return []net.IP{net.ParseIP("192.0.2.9")}, time.Minute, nil
	}
	got, err := sel.SelectPGWFor(context.Background(), PGWRequest{APN: "internet", HPLMN: home, Interface: LogicalInterfaceS8})
	if err != nil || got.Service != ServicePGWS8GT || got.Interface != "s8-gtp" || got.Source != SourceDNSLive {
		t.Fatalf("selection = %+v, %v", got, err)
	}
}

func TestS8PGWInvalidReplacementAndDNSFailureDoNotFallback(t *testing.T) {
	sel := NewSelector(testConfig("127.0.0.1:9", "local.invalid"), zap.NewNop())
	home := plmn.PLMN{MCC: "310", MNC: "260"}
	if _, err := sel.SelectPGWFor(context.Background(), PGWRequest{APN: "internet", HPLMN: home, Interface: LogicalInterfaceS8, APNOIReplacement: "bad value"}); err == nil {
		t.Fatal("malformed replacement accepted")
	}
	sel.lookupNAPTRFn = func(context.Context, string) ([]*dns.NAPTR, time.Duration, error) {
		return nil, 0, context.DeadlineExceeded
	}
	if _, err := sel.SelectPGWFor(context.Background(), PGWRequest{APN: "internet", HPLMN: home, Interface: LogicalInterfaceS8}); err == nil {
		t.Fatal("S8 DNS failure fell back to local static PGW")
	}
}
