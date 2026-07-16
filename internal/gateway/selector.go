package gateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/config"
)

const (
	NodeSGW = "sgw"
	NodePGW = "pgw"

	SourceS6A        = "s6a"
	SourceDNSLive    = "dns_live"
	SourceDNSCache   = "dns_cache"
	SourceStaticYAML = "static_yaml"
	SourceFailure    = "failure"

	ServiceSGWS11  = "x-3gpp-sgw:x-s11"
	ServicePGWS5GT = "x-3gpp-pgw:x-s5-gtp"

	defaultGTPCPort = 2123
)

type APNConfiguration struct {
	ContextIdentifier       uint32
	ServiceSelection        string
	MIPHomeAgentAddress     net.IP
	MIPHomeAgentHost        string
	PDNGWAllocationType     *int32
	PDNType                 uint8
	QCI                     uint8
	ARPPriority             uint8
	PreemptionCapability    bool
	PreemptionVulnerability bool
	APNAMBRDown             uint32
	APNAMBRUp               uint32
}

type SubscriberProfile struct {
	DefaultContextID uint32
	APNs             map[string]APNConfiguration
	UEAMBRDown       uint32
	UEAMBRUp         uint32
}

func (p *SubscriberProfile) DefaultAPNConfiguration() *APNConfiguration {
	if p == nil {
		return nil
	}
	for _, cfg := range p.APNs {
		if p.DefaultContextID != 0 && cfg.ContextIdentifier != p.DefaultContextID {
			continue
		}
		if strings.TrimSpace(cfg.ServiceSelection) == "" {
			continue
		}
		c := cfg
		return &c
	}
	for _, cfg := range p.APNs {
		if strings.TrimSpace(cfg.ServiceSelection) == "" {
			continue
		}
		c := cfg
		return &c
	}
	return nil
}

type Selection struct {
	NodeType    string
	Address     net.IP
	Port        int
	Hostname    string
	Interface   string
	Source      string
	QueryName   string
	Service     string
	Target      string
	CacheExpiry time.Time
	NAPTROrder  uint16
	NAPTRPref   uint16
	Field       string
}

// DNSCacheEntry is a serializable snapshot of one gateway DNS cache entry.
type DNSCacheEntry struct {
	NodeType        string    `json:"node_type"`
	QueryName       string    `json:"query_name"`
	Service         string    `json:"service"`
	PreferIPv6      bool      `json:"prefer_ipv6"`
	Source          string    `json:"source,omitempty"`
	Address         string    `json:"address,omitempty"`
	Port            int       `json:"port,omitempty"`
	UDPAddress      string    `json:"udp_address,omitempty"`
	Hostname        string    `json:"hostname,omitempty"`
	Interface       string    `json:"interface,omitempty"`
	Target          string    `json:"target,omitempty"`
	NAPTROrder      uint16    `json:"naptr_order,omitempty"`
	NAPTRPreference uint16    `json:"naptr_preference,omitempty"`
	Error           string    `json:"error,omitempty"`
	ExpiresAt       time.Time `json:"expires_at"`
	TTLSeconds      float64   `json:"ttl_seconds"`
	Expired         bool      `json:"expired"`
}

func (s *Selection) UDPAddr() string {
	if s == nil || s.Address == nil {
		return ""
	}
	port := s.Port
	if port == 0 {
		port = defaultGTPCPort
	}
	return net.JoinHostPort(s.Address.String(), strconv.Itoa(port))
}

type Selector struct {
	cfg           config.Config
	log           *zap.Logger
	cache         *dnsCache
	now           func() time.Time
	lookupNAPTRFn func(ctx context.Context, name string) ([]*dns.NAPTR, time.Duration, error)
	lookupAddrFn  func(ctx context.Context, host string) ([]net.IP, time.Duration, error)
}

func NewSelector(cfg config.Config, log *zap.Logger) *Selector {
	s := &Selector{
		cfg:   cfg,
		log:   log,
		cache: newDNSCache(),
		now:   time.Now,
	}
	s.lookupNAPTRFn = s.exchangeNAPTR
	s.lookupAddrFn = s.exchangeAddr
	return s
}

func (s *Selector) DNSCacheSnapshot() []DNSCacheEntry {
	if s == nil || s.cache == nil {
		return nil
	}
	return s.cache.snapshot(s.now())
}

func (s *Selector) FlushDNSCache() int {
	if s == nil || s.cache == nil {
		return 0
	}
	return s.cache.clear()
}

func (s *Selector) SelectSGW(ctx context.Context, tac uint16) (*Selection, error) {
	dnsCfg := s.cfg.GatewaySelection.DNS
	if dnsCfg.Enabled && dnsCfg.SGWEnabled {
		query := SGWQueryName(tac, RootDomain(s.cfg.NF, dnsCfg.RootDomain))
		if sel, err := s.resolveNAPTR(ctx, NodeSGW, query, ServiceSGWS11, "s11"); err == nil {
			s.logSelection(sel)
			return sel, nil
		} else {
			s.log.Warn("gateway selection: SGW DNS failed", zap.String("query", query), zap.Error(err))
		}
	}
	if sel, err := selectionFromAddress(NodeSGW, s.cfg.GatewaySelection.SGW.SGWAddress, "s11", SourceStaticYAML); err == nil {
		s.logSelection(sel)
		return sel, nil
	}
	err := errors.New("SGW selection failed: DNS disabled/failed and no configured SGW address available")
	s.log.Warn("gateway selection failed", zap.String("node_type", "SGW"), zap.String("source", SourceFailure), zap.Error(err))
	return nil, err
}

func (s *Selector) SelectPGW(ctx context.Context, apn string, apnCfg *APNConfiguration) (*Selection, error) {
	if s.cfg.GatewaySelection.PGW.PreferS6AStatic && apnCfg != nil {
		if ip := normalizeIP(apnCfg.MIPHomeAgentAddress); ip != nil {
			sel := &Selection{NodeType: NodePGW, Address: ip, Port: defaultGTPCPort, Interface: "s5-gtp", Source: SourceS6A, Field: "MIP-Home-Agent-Address"}
			s.logSelection(sel)
			return sel, nil
		}
		if strings.TrimSpace(apnCfg.MIPHomeAgentHost) != "" {
			ip, err := s.resolveHostOnly(ctx, apnCfg.MIPHomeAgentHost)
			if err == nil {
				sel := &Selection{NodeType: NodePGW, Address: ip, Port: defaultGTPCPort, Hostname: strings.TrimSuffix(apnCfg.MIPHomeAgentHost, "."), Interface: "s5-gtp", Source: SourceS6A, Field: "MIP-Home-Agent-Host"}
				s.logSelection(sel)
				return sel, nil
			}
			s.log.Warn("gateway selection: S6a PGW host resolution failed", zap.String("host", apnCfg.MIPHomeAgentHost), zap.Error(err))
		}
	}

	dnsCfg := s.cfg.GatewaySelection.DNS
	if dnsCfg.Enabled && dnsCfg.PGWEnabled {
		query := PGWQueryName(apn, RootDomain(s.cfg.NF, dnsCfg.RootDomain))
		if sel, err := s.resolveNAPTR(ctx, NodePGW, query, ServicePGWS5GT, "s5-gtp"); err == nil {
			s.logSelection(sel)
			return sel, nil
		} else {
			s.log.Warn("gateway selection: PGW DNS failed", zap.String("query", query), zap.Error(err))
		}
	}
	if sel, err := selectionFromAddress(NodePGW, s.cfg.GatewaySelection.PGW.PGWAddress, "s5-gtp", SourceStaticYAML); err == nil {
		s.logSelection(sel)
		return sel, nil
	}
	err := errors.New("PGW selection failed: no S6a PGW, DNS disabled/failed, and no configured PGW address available")
	s.log.Warn("gateway selection failed", zap.String("node_type", "PGW"), zap.String("source", SourceFailure), zap.Error(err))
	return nil, err
}

func RootDomain(nf config.NFConfig, explicit string) string {
	if strings.TrimSpace(explicit) != "" {
		return strings.TrimSuffix(strings.TrimSpace(explicit), ".")
	}
	mnc := nf.MNC
	if len(mnc) < 3 {
		mnc = strings.Repeat("0", 3-len(mnc)) + mnc
	}
	return fmt.Sprintf("epc.mnc%s.mcc%s.3gppnetwork.org", mnc, nf.MCC)
}

func SGWQueryName(tac uint16, root string) string {
	lb := byte(tac & 0xff)
	hb := byte((tac >> 8) & 0xff)
	return fmt.Sprintf("tac-lb%02x.tac-hb%02x.tac.%s", lb, hb, strings.TrimSuffix(root, "."))
}

func PGWQueryName(apn, root string) string {
	return fmt.Sprintf("%s.apn.%s", strings.TrimSuffix(strings.TrimSpace(apn), "."), strings.TrimSuffix(root, "."))
}

func (s *Selector) resolveNAPTR(ctx context.Context, nodeType, query, serviceFilter, iface string) (*Selection, error) {
	preferIPv6 := s.cfg.GatewaySelection.DNS.Resolver.PreferIPv6
	key := cacheKey{NodeType: nodeType, QueryName: query, Service: serviceFilter, PreferIPv6: preferIPv6}
	if s.cfg.GatewaySelection.DNS.Cache.Enabled {
		if entry, ok := s.cache.get(key, s.now()); ok {
			if entry.Err != "" {
				return nil, errors.New(entry.Err)
			}
			sel := entry.Selection
			sel.Source = SourceDNSCache
			return &sel, nil
		}
	}

	sel, ttl, err := s.lookupNAPTR(ctx, nodeType, query, serviceFilter, iface)
	expiry := s.now().Add(s.boundPositiveTTL(ttl))
	if err != nil {
		if s.cfg.GatewaySelection.DNS.Cache.Enabled {
			s.cache.set(key, cacheEntry{Err: err.Error(), Expiry: s.now().Add(s.negativeTTL())})
		}
		return nil, err
	}
	sel.Source = SourceDNSLive
	sel.CacheExpiry = expiry
	if s.cfg.GatewaySelection.DNS.Cache.Enabled {
		cacheSel := *sel
		s.cache.set(key, cacheEntry{Selection: cacheSel, Expiry: expiry})
	}
	return sel, nil
}

func (s *Selector) lookupNAPTR(ctx context.Context, nodeType, query, serviceFilter, iface string) (*Selection, time.Duration, error) {
	naptrs, naptrTTL, err := s.lookupNAPTRFn(ctx, query)
	if err != nil {
		return nil, 0, err
	}
	filtered := naptrs[:0]
	for _, rr := range naptrs {
		if serviceMatches(rr.Service, serviceFilter) && strings.EqualFold(rr.Flags, "a") && rr.Replacement != "." {
			filtered = append(filtered, rr)
		}
	}
	if len(filtered) == 0 {
		return nil, 0, fmt.Errorf("no matching NAPTR for %s", serviceFilter)
	}
	sort.SliceStable(filtered, func(i, j int) bool {
		if filtered[i].Order != filtered[j].Order {
			return filtered[i].Order < filtered[j].Order
		}
		return filtered[i].Preference < filtered[j].Preference
	})
	chosen := filtered[0]
	target := strings.TrimSuffix(chosen.Replacement, ".")
	ips, addrTTL, err := s.lookupAddrFn(ctx, target)
	if err != nil {
		return nil, 0, err
	}
	ip := chooseIP(ips, s.cfg.GatewaySelection.DNS.Resolver.PreferIPv6)
	if ip == nil {
		return nil, 0, fmt.Errorf("NAPTR replacement host %s has no A/AAAA", target)
	}
	ttl := minDuration(naptrTTL, addrTTL)
	return &Selection{
		NodeType:   nodeType,
		Address:    ip,
		Port:       defaultGTPCPort,
		Hostname:   target,
		Interface:  iface,
		QueryName:  query,
		Service:    serviceFilter,
		Target:     target,
		NAPTROrder: chosen.Order,
		NAPTRPref:  chosen.Preference,
	}, ttl, nil
}

func (s *Selector) exchangeNAPTR(ctx context.Context, name string) ([]*dns.NAPTR, time.Duration, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), dns.TypeNAPTR)
	resp, err := s.exchange(ctx, msg)
	if err != nil {
		return nil, 0, err
	}
	if resp.Rcode == dns.RcodeNameError {
		return nil, 0, fmt.Errorf("NXDOMAIN for %s", name)
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, 0, fmt.Errorf("DNS NAPTR lookup failed for %s: rcode=%s", name, dns.RcodeToString[resp.Rcode])
	}
	var out []*dns.NAPTR
	ttl := time.Duration(0)
	for _, rr := range resp.Answer {
		naptr, ok := rr.(*dns.NAPTR)
		if !ok {
			continue
		}
		out = append(out, naptr)
		rrTTL := time.Duration(naptr.Hdr.Ttl) * time.Second
		if ttl == 0 || rrTTL < ttl {
			ttl = rrTTL
		}
	}
	if len(out) == 0 {
		return nil, 0, fmt.Errorf("no NAPTR answers for %s", name)
	}
	return out, ttl, nil
}

func (s *Selector) exchangeAddr(ctx context.Context, host string) ([]net.IP, time.Duration, error) {
	types := []uint16{dns.TypeA, dns.TypeAAAA}
	var ips []net.IP
	ttl := time.Duration(0)
	for _, qtype := range types {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(host), qtype)
		resp, err := s.exchange(ctx, msg)
		if err != nil {
			continue
		}
		if resp.Rcode != dns.RcodeSuccess {
			continue
		}
		for _, rr := range resp.Answer {
			switch a := rr.(type) {
			case *dns.A:
				ips = append(ips, a.A)
				rrTTL := time.Duration(a.Hdr.Ttl) * time.Second
				if ttl == 0 || rrTTL < ttl {
					ttl = rrTTL
				}
			case *dns.AAAA:
				ips = append(ips, a.AAAA)
				rrTTL := time.Duration(a.Hdr.Ttl) * time.Second
				if ttl == 0 || rrTTL < ttl {
					ttl = rrTTL
				}
			}
		}
	}
	if len(ips) == 0 {
		return nil, 0, fmt.Errorf("host %s has no A/AAAA", host)
	}
	return ips, ttl, nil
}

func (s *Selector) exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	servers := s.cfg.GatewaySelection.DNS.Resolver.Servers
	if len(servers) == 0 {
		cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			return nil, err
		}
		for _, server := range cfg.Servers {
			servers = append(servers, net.JoinHostPort(server, cfg.Port))
		}
	}
	timeout := s.cfg.GatewaySelection.DNS.Resolver.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	retries := s.cfg.GatewaySelection.DNS.Resolver.Retries
	if retries <= 0 {
		retries = 1
	}
	var lastErr error
	for attempt := 0; attempt < retries; attempt++ {
		for _, server := range servers {
			addr := server
			if _, _, err := net.SplitHostPort(server); err != nil {
				addr = net.JoinHostPort(server, "53")
			}
			client := &dns.Client{Net: "udp", Timeout: timeout}
			resp, _, err := client.ExchangeContext(ctx, msg.Copy(), addr)
			if err == nil {
				return resp, nil
			}
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no DNS servers configured")
	}
	return nil, lastErr
}

func (s *Selector) resolveHostOnly(ctx context.Context, host string) (net.IP, error) {
	ips, _, err := s.lookupAddrFn(ctx, strings.TrimSuffix(host, "."))
	if err != nil {
		return nil, err
	}
	if ip := chooseIP(ips, s.cfg.GatewaySelection.DNS.Resolver.PreferIPv6); ip != nil {
		return ip, nil
	}
	return nil, fmt.Errorf("host %s has no usable A/AAAA", host)
}

func (s *Selector) boundPositiveTTL(ttl time.Duration) time.Duration {
	cacheCfg := s.cfg.GatewaySelection.DNS.Cache
	if ttl <= 0 {
		ttl = cacheCfg.MinTTL
	}
	if cacheCfg.MinTTL > 0 && ttl < cacheCfg.MinTTL {
		ttl = cacheCfg.MinTTL
	}
	if cacheCfg.MaxTTL > 0 && ttl > cacheCfg.MaxTTL {
		ttl = cacheCfg.MaxTTL
	}
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return ttl
}

func (s *Selector) negativeTTL() time.Duration {
	ttl := s.cfg.GatewaySelection.DNS.Cache.NegativeTTL
	if ttl <= 0 {
		return 10 * time.Second
	}
	return ttl
}

func (s *Selector) logSelection(sel *Selection) {
	if s.log == nil || sel == nil {
		return
	}
	fields := []zap.Field{
		zap.String("node_type", strings.ToUpper(sel.NodeType)),
		zap.String("selected_address", sel.UDPAddr()),
		zap.String("source", sel.Source),
	}
	if sel.Hostname != "" {
		fields = append(fields, zap.String("hostname", sel.Hostname))
	}
	if sel.QueryName != "" {
		fields = append(fields, zap.String("query", sel.QueryName))
	}
	if sel.Service != "" {
		fields = append(fields, zap.String("service", sel.Service))
	}
	if sel.Target != "" {
		fields = append(fields, zap.String("target", sel.Target))
	}
	if !sel.CacheExpiry.IsZero() {
		fields = append(fields, zap.Time("cache_expiry", sel.CacheExpiry))
	}
	if sel.Field != "" {
		fields = append(fields, zap.String("field", sel.Field))
	}
	s.log.Info("selected gateway", fields...)
}

func selectionFromAddress(nodeType, raw, iface, source string) (*Selection, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("empty static address")
	}
	host, port, err := splitHostPortDefault(raw, defaultGTPCPort)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		ips, err := net.LookupIP(host)
		if err != nil {
			return nil, err
		}
		ip = chooseIP(ips, false)
	}
	ip = normalizeIP(ip)
	if ip == nil {
		return nil, fmt.Errorf("address %q has no usable IP", raw)
	}
	return &Selection{NodeType: nodeType, Address: ip, Port: port, Hostname: host, Interface: iface, Source: source}, nil
}

func splitHostPortDefault(raw string, defaultPort int) (string, int, error) {
	host, portText, err := net.SplitHostPort(raw)
	if err != nil {
		if net.ParseIP(raw) != nil || strings.Contains(err.Error(), "missing port in address") {
			return strings.Trim(raw, "[]"), defaultPort, nil
		}
		return "", 0, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

func serviceMatches(service, filter string) bool {
	parts := strings.Split(strings.ToLower(service), ":")
	want := strings.Split(strings.ToLower(filter), ":")
	if len(parts) < len(want) {
		return false
	}
	for i := range want {
		if parts[i] != want[i] {
			return false
		}
	}
	return true
}

func chooseIP(ips []net.IP, preferIPv6 bool) net.IP {
	var first4, first6 net.IP
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil && first4 == nil {
			first4 = append(net.IP(nil), ip4...)
			continue
		}
		if ip16 := ip.To16(); ip16 != nil && ip.To4() == nil && first6 == nil {
			first6 = append(net.IP(nil), ip16...)
		}
	}
	if preferIPv6 && first6 != nil {
		return first6
	}
	if first4 != nil {
		return first4
	}
	return first6
}

func normalizeIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	if ip4 := ip.To4(); ip4 != nil {
		return append(net.IP(nil), ip4...)
	}
	if ip16 := ip.To16(); ip16 != nil {
		return append(net.IP(nil), ip16...)
	}
	return nil
}

func minDuration(a, b time.Duration) time.Duration {
	if a <= 0 {
		return b
	}
	if b <= 0 || a < b {
		return a
	}
	return b
}

type cacheKey struct {
	NodeType   string
	QueryName  string
	Service    string
	PreferIPv6 bool
}

type cacheEntry struct {
	Selection Selection
	Err       string
	Expiry    time.Time
}

type dnsCache struct {
	mu      sync.Mutex
	entries map[cacheKey]cacheEntry
}

func newDNSCache() *dnsCache {
	return &dnsCache{entries: make(map[cacheKey]cacheEntry)}
}

func (c *dnsCache) get(key cacheKey, now time.Time) (cacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return cacheEntry{}, false
	}
	if !entry.Expiry.After(now) {
		delete(c.entries, key)
		return cacheEntry{}, false
	}
	return entry, true
}

func (c *dnsCache) set(key cacheKey, entry cacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = entry
}

func (c *dnsCache) snapshot(now time.Time) []DNSCacheEntry {
	c.mu.Lock()
	defer c.mu.Unlock()

	out := make([]DNSCacheEntry, 0, len(c.entries))
	for key, entry := range c.entries {
		expired := !entry.Expiry.After(now)
		if expired {
			delete(c.entries, key)
			continue
		}
		sel := entry.Selection
		item := DNSCacheEntry{
			NodeType:        key.NodeType,
			QueryName:       key.QueryName,
			Service:         key.Service,
			PreferIPv6:      key.PreferIPv6,
			Source:          sel.Source,
			Port:            sel.Port,
			Hostname:        sel.Hostname,
			Interface:       sel.Interface,
			Target:          sel.Target,
			NAPTROrder:      sel.NAPTROrder,
			NAPTRPreference: sel.NAPTRPref,
			Error:           entry.Err,
			ExpiresAt:       entry.Expiry,
			TTLSeconds:      entry.Expiry.Sub(now).Seconds(),
			Expired:         expired,
		}
		if sel.Address != nil {
			item.Address = sel.Address.String()
			item.UDPAddress = sel.UDPAddr()
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].NodeType != out[j].NodeType {
			return out[i].NodeType < out[j].NodeType
		}
		if out[i].QueryName != out[j].QueryName {
			return out[i].QueryName < out[j].QueryName
		}
		if out[i].Service != out[j].Service {
			return out[i].Service < out[j].Service
		}
		return !out[i].PreferIPv6 && out[j].PreferIPv6
	})
	return out
}

func (c *dnsCache) clear() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(c.entries)
	c.entries = make(map[cacheKey]cacheEntry)
	return n
}
