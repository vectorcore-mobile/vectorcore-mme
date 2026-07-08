package gateway

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/config"
)

func TestRootDomainDerivesPaddedMNC(t *testing.T) {
	nf := config.NFConfig{MCC: "001", MNC: "01"}
	if got, want := RootDomain(nf, ""), "epc.mnc001.mcc001.3gppnetwork.org"; got != want {
		t.Fatalf("RootDomain() = %q, want %q", got, want)
	}
	nf.MCC = "311"
	nf.MNC = "435"
	if got, want := RootDomain(nf, ""), "epc.mnc435.mcc311.3gppnetwork.org"; got != want {
		t.Fatalf("RootDomain() = %q, want %q", got, want)
	}
}

func TestSGWQueryNameUsesLowByteHighByteTAC(t *testing.T) {
	got := SGWQueryName(1, "epc.mnc435.mcc311.3gppnetwork.org")
	want := "tac-lb01.tac-hb00.epc.mnc435.mcc311.3gppnetwork.org"
	if got != want {
		t.Fatalf("SGWQueryName() = %q, want %q", got, want)
	}
}

func TestSelectSGWUsesMatchingNAPTRAndCaches(t *testing.T) {
	root := "epc.mnc435.mcc311.3gppnetwork.org"
	query := SGWQueryName(1, root)
	target := "sgw-02-s11." + root
	naptrCount := 0
	sel := NewSelector(testConfig("127.0.0.1:53", root), zap.NewNop())
	sel.lookupNAPTRFn = func(ctx context.Context, name string) ([]*dns.NAPTR, time.Duration, error) {
		if name == query {
			naptrCount++
			return []*dns.NAPTR{
				{Hdr: dns.RR_Header{Name: dns.Fqdn(query), Rrtype: dns.TypeNAPTR, Class: dns.ClassINET, Ttl: 120}, Order: 100, Preference: 5, Flags: "a", Service: "x-3gpp-sgw:x-s5-gtp", Replacement: dns.Fqdn("wrong." + root)},
				{Hdr: dns.RR_Header{Name: dns.Fqdn(query), Rrtype: dns.TypeNAPTR, Class: dns.ClassINET, Ttl: 120}, Order: 100, Preference: 10, Flags: "a", Service: ServiceSGWS11, Replacement: dns.Fqdn(target)},
			}, 120 * time.Second, nil
		}
		t.Fatalf("unexpected NAPTR query %q", name)
		return nil, 0, nil
	}
	sel.lookupAddrFn = func(ctx context.Context, host string) ([]net.IP, time.Duration, error) {
		if host != target {
			t.Fatalf("unexpected address query %q", host)
		}
		return []net.IP{net.ParseIP("10.90.250.20")}, 90 * time.Second, nil
	}
	first, err := sel.SelectSGW(context.Background(), 1)
	if err != nil {
		t.Fatalf("SelectSGW first failed: %v", err)
	}
	if first.Source != SourceDNSLive || first.UDPAddr() != "10.90.250.20:2123" {
		t.Fatalf("first selection = source %s addr %s", first.Source, first.UDPAddr())
	}
	second, err := sel.SelectSGW(context.Background(), 1)
	if err != nil {
		t.Fatalf("SelectSGW second failed: %v", err)
	}
	if second.Source != SourceDNSCache {
		t.Fatalf("second source = %s, want %s", second.Source, SourceDNSCache)
	}
	if naptrCount != 1 {
		t.Fatalf("NAPTR query count = %d, want 1", naptrCount)
	}
}

func TestSelectPGWFallsBackToStaticWhenDNSHasNoMatchingService(t *testing.T) {
	root := "epc.mnc435.mcc311.3gppnetwork.org"
	query := PGWQueryName("ims", root)
	target := "pgw-02." + root
	cfg := testConfig("127.0.0.1:53", root)
	cfg.GatewaySelection.PGW.PGWAddress = "127.0.0.4"
	sel := NewSelector(cfg, zap.NewNop())
	sel.lookupNAPTRFn = func(ctx context.Context, name string) ([]*dns.NAPTR, time.Duration, error) {
		if name == query {
			return []*dns.NAPTR{
				{Hdr: dns.RR_Header{Name: dns.Fqdn(query), Rrtype: dns.TypeNAPTR, Class: dns.ClassINET, Ttl: 120}, Order: 100, Preference: 10, Flags: "a", Service: "x-3gpp-pgw:x-s2b-gtp", Replacement: dns.Fqdn(target)},
			}, 120 * time.Second, nil
		}
		t.Fatalf("unexpected NAPTR query %q", name)
		return nil, 0, nil
	}
	got, err := sel.SelectPGW(context.Background(), "ims", nil)
	if err != nil {
		t.Fatalf("SelectPGW failed: %v", err)
	}
	if got.Source != SourceStaticYAML || got.UDPAddr() != "127.0.0.4:2123" {
		t.Fatalf("fallback = source %s addr %s", got.Source, got.UDPAddr())
	}
}

func TestSelectPGWPrefersS6AAddress(t *testing.T) {
	cfg := testConfig("127.0.0.1:9", "epc.mnc435.mcc311.3gppnetwork.org")
	sel := NewSelector(cfg, zap.NewNop())
	got, err := sel.SelectPGW(context.Background(), "ims", &APNConfiguration{
		ServiceSelection:    "ims",
		MIPHomeAgentAddress: net.ParseIP("192.168.105.97"),
		MIPHomeAgentHost:    "pgw-ignored.example",
	})
	if err != nil {
		t.Fatalf("SelectPGW failed: %v", err)
	}
	if got.Source != SourceS6A || got.UDPAddr() != "192.168.105.97:2123" || got.Field != "MIP-Home-Agent-Address" {
		t.Fatalf("selection = source %s addr %s field %s", got.Source, got.UDPAddr(), got.Field)
	}
}

func TestStaticAddressDefaultsPort(t *testing.T) {
	got, err := selectionFromAddress(NodePGW, "127.0.0.4", "s5-gtp", SourceStaticYAML)
	if err != nil {
		t.Fatalf("selectionFromAddress IPv4 failed: %v", err)
	}
	if got.UDPAddr() != "127.0.0.4:2123" {
		t.Fatalf("IPv4 default port addr = %s", got.UDPAddr())
	}
	got, err = selectionFromAddress(NodePGW, "2001:db8::1", "s5-gtp", SourceStaticYAML)
	if err != nil {
		t.Fatalf("selectionFromAddress IPv6 failed: %v", err)
	}
	if got.UDPAddr() != "[2001:db8::1]:2123" {
		t.Fatalf("IPv6 default port addr = %s", got.UDPAddr())
	}
}

func testConfig(dnsServer, root string) config.Config {
	return config.Config{
		NF: config.NFConfig{MCC: "311", MNC: "435"},
		GatewaySelection: config.GatewaySelectionConfig{
			DNS: config.GatewaySelectionDNSConfig{
				Enabled:    true,
				RootDomain: root,
				SGWEnabled: true,
				PGWEnabled: true,
				Resolver: config.GatewaySelectionResolverConfig{
					Servers: []string{dnsServer},
					Timeout: 100 * time.Millisecond,
					Retries: 1,
				},
				Cache: config.GatewaySelectionCacheConfig{
					Enabled:     true,
					MinTTL:      30 * time.Second,
					MaxTTL:      300 * time.Second,
					NegativeTTL: 10 * time.Second,
				},
			},
			SGW: config.GatewaySelectionSGWConfig{SGWAddress: "127.0.0.3:2123"},
			PGW: config.GatewaySelectionPGWConfig{PGWAddress: "127.0.0.4:2123", PreferS6AStatic: true},
		},
	}
}
