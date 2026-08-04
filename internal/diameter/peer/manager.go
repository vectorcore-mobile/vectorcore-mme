// Package peer provides shared Diameter peer connectivity and route selection.
package peer

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/fiorix/go-diameter/v4/diam/avp"
	"github.com/fiorix/go-diameter/v4/diam/datatype"
	"github.com/fiorix/go-diameter/v4/diam/dict"
	"github.com/fiorix/go-diameter/v4/diam/sm"
	"github.com/fiorix/go-diameter/v4/diam/sm/smpeer"
	"github.com/ishidawataru/sctp"
	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/transportqos"
)

const RelayApplicationID uint32 = 0xffffffff

type State string

const (
	Disconnected State = "Disconnected"
	Connecting   State = "Connecting"
	CEAPending   State = "CEA-Pending"
	Ready        State = "Ready"
	Suspect      State = "Suspect"
	Down         State = "Down"
)

// Peer is a selected, ready peer. DestinationHost is empty for relay routes.
type Peer struct {
	Name            string
	Address         string
	Transport       string
	OriginHost      string
	OriginRealm     string
	Priority        *int
	ConfigOrder     int
	SelectionType   string
	DestinationHost string
	Connection      diam.Conn
}

type record struct {
	config      config.DiameterPeerConfig
	order       int
	state       State
	conn        diam.Conn
	originHost  string
	originRealm string
	apps        map[uint32]bool
	lastDWA     time.Time
	failures    uint64
}

// Factory creates a fresh state machine for each Diameter connection. The
// supplied hook must be installed as Settings.OnCER so inbound capability
// advertisements are observed before the state machine sends CEA.
type Factory func(onCER diam.HandlerFunc) *sm.StateMachine

type Manager struct {
	cfg        config.DiameterConfig
	log        *zap.Logger
	factory    Factory
	mu         sync.RWMutex
	peers      []*record
	s13Enabled bool
	sgdEnabled bool
	slgEnabled bool

	listener  net.Listener
	done      chan struct{}
	closeOnce sync.Once
}

func New(cfg config.DiameterConfig, log *zap.Logger, factory Factory) *Manager {
	m := &Manager{cfg: cfg, log: log, factory: factory, done: make(chan struct{})}
	for i, p := range cfg.Peers {
		m.peers = append(m.peers, &record{config: p, order: i, state: Disconnected, apps: make(map[uint32]bool)})
	}
	return m
}

// SetS13Enabled selects whether newly negotiated CER/CEA capabilities include
// the S13 application. It must be called before Start.
func (m *Manager) SetS13Enabled(enabled bool) { m.s13Enabled = enabled }

// SetSGdEnabled selects whether newly negotiated CER/CEA capabilities include
// the SGd application. It must be called before Start.
func (m *Manager) SetSGdEnabled(enabled bool) { m.sgdEnabled = enabled }

// SetSLgEnabled selects whether CER/CEA advertises the 3GPP SLg application.
// It must be called before Start.
func (m *Manager) SetSLgEnabled(enabled bool) { m.slgEnabled = enabled }

// Start maintains every configured outbound peer and optional listeners.
// It blocks until Close is called.
func (m *Manager) Start() error {
	for _, p := range m.peers {
		go m.connectLoop(p)
	}
	if m.cfg.BindAddress != "" {
		go m.listen(m.cfg.BindTransport)
	}
	<-m.done
	return nil
}

// Close stops accepting new peer connections, closes the inbound listener
// (if any) and every established peer connection, and signals connectLoop
// goroutines to stop retrying. Safe to call multiple times.
func (m *Manager) Close() error {
	m.closeOnce.Do(func() { close(m.done) })

	m.mu.Lock()
	ln := m.listener
	m.listener = nil
	conns := make([]diam.Conn, 0, len(m.peers))
	for _, p := range m.peers {
		if p.conn != nil {
			conns = append(conns, p.conn)
			p.conn = nil
			p.state = Disconnected
		}
	}
	m.mu.Unlock()

	var err error
	if ln != nil {
		err = ln.Close()
	}
	for _, c := range conns {
		c.Close()
	}
	return err
}

func (m *Manager) retryDelay() time.Duration {
	if m.cfg.RetryDelay > 0 {
		return m.cfg.RetryDelay
	}
	return 5 * time.Second
}

func (m *Manager) connectLoop(p *record) {
	for {
		select {
		case <-m.done:
			return
		default:
		}
		m.setState(p, Connecting)
		mux := m.factory(nil)
		cli := m.client(mux)
		m.setState(p, CEAPending)
		conn, err := m.dial(cli, p.config)
		if err != nil {
			m.mu.Lock()
			p.failures++
			p.state = Down
			m.mu.Unlock()
			m.log.Warn("diameter: peer connection failed", zap.String("peer_name", p.config.Name), zap.String("peer_address", p.config.Address), zap.String("transport", p.config.Transport), zap.Error(err))
			select {
			case <-time.After(m.retryDelay()):
			case <-m.done:
				return
			}
			continue
		}
		if tos, configured, _ := transportqos.TOS(m.cfg.QoS.DSCP); configured {
			m.log.Info("diameter: outbound QoS configured", zap.String("transport", p.config.Transport), zap.String("peer_name", p.config.Name), zap.String("peer_address", p.config.Address), zap.Int("dscp", *m.cfg.QoS.DSCP), zap.String("tos", fmt.Sprintf("0x%02x", tos)))
		}
		m.learn(p, conn)
		if notifier, ok := conn.(diam.CloseNotifier); ok {
			select {
			case <-notifier.CloseNotify():
			case <-m.done:
				return
			}
		} else {
			<-m.done
			return
		}
		m.mu.Lock()
		if p.conn == conn {
			p.conn = nil
			p.state = Down
		}
		m.mu.Unlock()
		m.log.Warn("diameter: peer disconnected", zap.String("peer_name", p.config.Name), zap.String("peer_address", p.config.Address))
		select {
		case <-time.After(m.retryDelay()):
		case <-m.done:
			return
		}
	}
}

func (m *Manager) client(mux *sm.StateMachine) *sm.Client {
	const vendor3GPP = 10415
	const appS6a = 16777251
	const appS13 = 16777252
	const appSGd = 16777313
	const appSLg = 16777255
	apps := []*diam.AVP{vendorSpecificAuthApplication(vendor3GPP, appS6a)}
	if m.s13Enabled {
		apps = append(apps, vendorSpecificAuthApplication(vendor3GPP, appS13))
	}
	if m.sgdEnabled {
		apps = append(apps, vendorSpecificAuthApplication(vendor3GPP, appSGd))
	}
	if m.slgEnabled {
		apps = append(apps, vendorSpecificAuthApplication(vendor3GPP, appSLg))
	}
	return &sm.Client{Dict: dict.Default, Handler: mux, MaxRetransmits: 3, RetransmitInterval: time.Second, EnableWatchdog: true, WatchdogInterval: 5 * time.Second,
		SupportedVendorID:           []*diam.AVP{diam.NewAVP(avp.SupportedVendorID, avp.Mbit, 0, datatype.Unsigned32(vendor3GPP))},
		VendorSpecificApplicationID: apps,
	}
}

func vendorSpecificAuthApplication(vendor, application uint32) *diam.AVP {
	return diam.NewAVP(avp.VendorSpecificApplicationID, avp.Mbit, 0, &diam.GroupedAVP{AVP: []*diam.AVP{
		diam.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(vendor)),
		diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(application)),
	}})
}

func (m *Manager) dial(cli *sm.Client, p config.DiameterPeerConfig) (diam.Conn, error) {
	if p.Transport == "sctp" {
		// go-diameter's SCTP dialer wraps the association as a Diameter
		// MultistreamConn, requests SCTP streams, and sets Diameter PPID 46.
		// Bind the association to the route-selected local IP. Without this,
		// Linux can advertise every local SCTP address (for example a Docker
		// bridge) and peers that key admission by source IP may reject it.
		local, err := routeLocalAddress(p.Address)
		if err != nil {
			return nil, fmt.Errorf("resolve SCTP local address for %s: %w", p.Address, err)
		}
		laddr, err := sctp.ResolveSCTPAddr("sctp", local)
		if err != nil {
			return nil, fmt.Errorf("resolve SCTP local address for %s: %w", p.Address, err)
		}
		raddr, err := sctp.ResolveSCTPAddr("sctp", p.Address)
		if err != nil {
			return nil, fmt.Errorf("resolve SCTP peer address for %s: %w", p.Address, err)
		}
		socketCfg := &sctp.SocketConfig{
			InitMsg: sctp.InitMsg{NumOstreams: diam.MaxOutboundSCTPStreams, MaxInstreams: diam.MaxInboundSCTPStreams},
			Control: func(network, address string, raw syscall.RawConn) error {
				return transportqos.Control(m.cfg.QoS.DSCP)(network, address, raw)
			},
		}
		raw, err := socketCfg.Dial("sctp", laddr, raddr)
		if err != nil {
			return nil, fmt.Errorf("dial SCTP peer %s: %w", p.Address, err)
		}
		if err := transportqos.Apply(m.cfg.QoS.DSCP, raw); err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("apply SCTP QoS for %s: %w", p.Address, err)
		}
		return cli.NewConn(diam.NewSCTPConn(raw), p.Address)
	}
	dialer := net.Dialer{Control: transportqos.Control(m.cfg.QoS.DSCP)}
	raw, err := dialer.DialContext(context.Background(), "tcp", p.Address)
	if err != nil {
		return nil, fmt.Errorf("dial TCP peer %s: %w", p.Address, err)
	}
	if err := transportqos.Apply(m.cfg.QoS.DSCP, raw); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("apply TCP QoS for %s: %w", p.Address, err)
	}
	return cli.NewConn(raw, p.Address)
}

func routeLocalAddress(remote string) (string, error) {
	conn, err := net.Dial("udp", remote)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || addr.IP == nil {
		return "", fmt.Errorf("no local IP selected for %s", remote)
	}
	return net.JoinHostPort(addr.IP.String(), "0"), nil
}

func (m *Manager) listen(transport string) {
	mux := m.factory(m.observeInboundCER)
	handler := capture{manager: m, next: mux}
	if transport == "sctp" {
		addr, err := sctp.ResolveSCTPAddr("sctp", m.cfg.BindAddress)
		if err != nil {
			m.log.Error("diameter: resolve SCTP listener", zap.Error(err))
			return
		}
		socketCfg := &sctp.SocketConfig{
			InitMsg: sctp.InitMsg{NumOstreams: diam.MaxOutboundSCTPStreams, MaxInstreams: diam.MaxInboundSCTPStreams},
			Control: func(network, address string, raw syscall.RawConn) error {
				return transportqos.Control(m.cfg.QoS.DSCP)(network, address, raw)
			},
		}
		rawListener, err := socketCfg.Listen("sctp", addr)
		if err != nil {
			m.log.Error("diameter: SCTP listen failed", zap.Error(err))
			return
		}
		ln := qosSCTPListener{SCTPListener: rawListener, dscp: m.cfg.QoS.DSCP}
		m.mu.Lock()
		m.listener = ln
		m.mu.Unlock()
		m.log.Info("diameter: listening", zap.String("transport", transport), zap.String("address", m.cfg.BindAddress))
		m.logQoS(transport)
		if err := diam.Serve(ln, handler); err != nil {
			select {
			case <-m.done:
			default:
				m.log.Error("diameter: SCTP listener stopped", zap.Error(err))
			}
		}
		return
	}
	lc := net.ListenConfig{Control: transportqos.Control(m.cfg.QoS.DSCP)}
	rawListener, err := lc.Listen(context.Background(), "tcp", m.cfg.BindAddress)
	if err != nil {
		m.log.Error("diameter: TCP listen failed", zap.Error(err))
		return
	}
	ln := qosListener{Listener: rawListener, dscp: m.cfg.QoS.DSCP}
	m.mu.Lock()
	m.listener = ln
	m.mu.Unlock()
	m.log.Info("diameter: listening", zap.String("transport", transport), zap.String("address", m.cfg.BindAddress))
	m.logQoS(transport)
	if err := diam.Serve(ln, handler); err != nil {
		select {
		case <-m.done:
		default:
			m.log.Error("diameter: TCP listener stopped", zap.Error(err))
		}
	}
}

func (m *Manager) logQoS(transport string) {
	if tos, configured, _ := transportqos.TOS(m.cfg.QoS.DSCP); configured {
		m.log.Info("diameter: outbound QoS configured", zap.String("transport", transport), zap.Int("dscp", *m.cfg.QoS.DSCP), zap.String("tos", fmt.Sprintf("0x%02x", tos)))
	}
}

func (m *Manager) observeInboundCER(c diam.Conn, msg *diam.Message) {
	if match := m.matchRemote(c); match != nil {
		m.setState(match, CEAPending)
	}
}

type capture struct {
	manager *Manager
	next    diam.Handler
}

func (c capture) ServeDIAM(conn diam.Conn, msg *diam.Message) {
	c.next.ServeDIAM(conn, msg)
	if msg.Header.CommandCode == diam.CapabilitiesExchange {
		if match := c.manager.matchRemote(conn); match != nil {
			if _, ok := smpeer.FromContext(conn.Context()); ok {
				c.manager.learn(match, conn)
			}
		}
	}
}

func (m *Manager) matchRemote(c diam.Conn) *record {
	m.mu.RLock()
	defer m.mu.RUnlock()
	remoteHost, _, _ := net.SplitHostPort(c.RemoteAddr().String())
	for _, p := range m.peers {
		host, _, _ := net.SplitHostPort(p.config.Address)
		if host == remoteHost {
			return p
		}
	}
	return nil
}

func (m *Manager) learn(p *record, c diam.Conn) {
	meta, ok := smpeer.FromContext(c.Context())
	if !ok {
		m.setState(p, Suspect)
		return
	}
	m.mu.Lock()
	p.conn, p.originHost, p.originRealm, p.state = c, string(meta.OriginHost), string(meta.OriginRealm), Ready
	p.apps = make(map[uint32]bool)
	for _, app := range meta.Applications {
		p.apps[app] = true
	}
	p.lastDWA = time.Now()
	m.mu.Unlock()
	m.logCapabilities(p)
}

func (m *Manager) logCapabilities(p *record) {
	m.mu.RLock()
	apps := make([]uint32, 0, len(p.apps))
	for app := range p.apps {
		if app != RelayApplicationID {
			apps = append(apps, app)
		}
	}
	relay := p.apps[RelayApplicationID]
	host, realm, state := p.originHost, p.originRealm, p.state
	m.mu.RUnlock()
	sort.Slice(apps, func(i, j int) bool { return apps[i] < apps[j] })
	m.log.Info("diameter: peer capabilities learned", zap.String("peer_name", p.config.Name), zap.String("peer_address", p.config.Address), zap.String("transport", p.config.Transport), zap.String("origin_host", host), zap.String("origin_realm", realm), zap.Uint32s("direct_apps", apps), zap.Bool("relay_supported", relay), zap.String("state", string(state)))
}

func (m *Manager) setState(p *record, state State) { m.mu.Lock(); p.state = state; m.mu.Unlock() }

// ReportTransactionFailure marks a peer suspect so new requests can fail over
// immediately while its connection loop recovers it.
func (m *Manager) ReportTransactionFailure(name string) {
	m.mu.Lock()
	for _, p := range m.peers {
		if p.config.Name == name {
			p.failures++
			p.state = Suspect
			conn := p.conn
			// Remove the stale reference before closing it. SelectPeer can no
			// longer hand a closed SCTP/TCP descriptor to another transaction,
			// while CloseNotify wakes the connection loop for reconnection.
			p.conn = nil
			m.mu.Unlock()
			if conn != nil {
				conn.Close()
			}
			m.log.Warn("diameter: peer invalidated after transaction write failure", zap.String("peer_name", name))
			return
		}
	}
	m.mu.Unlock()
}

// SelectPeer prefers a ready direct application peer, then a ready relay.
func (m *Manager) SelectPeer(app uint32, realm string) (*Peer, error) {
	m.mu.RLock()
	direct, relay := []*record{}, []*record{}
	connected := 0
	for _, p := range m.peers {
		if p.state != Ready || p.conn == nil {
			continue
		}
		connected++
		if p.apps[app] {
			direct = append(direct, p)
		} else if p.apps[RelayApplicationID] {
			relay = append(relay, p)
		}
	}
	m.mu.RUnlock()
	candidates, kind := direct, "direct"
	if len(candidates) == 0 {
		candidates, kind = relay, "relay"
	}
	if len(candidates) == 0 {
		m.log.Warn("diameter: no peer available", zap.Uint32("requested_app", app), zap.String("destination_realm", realm), zap.Int("connected_peers", connected), zap.Int("relay_peers", len(relay)), zap.Int("direct_candidates", len(direct)))
		return nil, fmt.Errorf("no Diameter peer available for app=%d realm=%s", app, realm)
	}
	sort.SliceStable(candidates, func(i, j int) bool { return before(candidates[i], candidates[j]) })
	p := candidates[0]
	result := &Peer{Name: p.config.Name, Address: p.config.Address, Transport: p.config.Transport, OriginHost: p.originHost, OriginRealm: p.originRealm, Priority: p.config.Priority, ConfigOrder: p.order, SelectionType: kind, Connection: p.conn}
	if kind == "direct" {
		result.DestinationHost = p.originHost
	}
	priority := -1
	if p.config.Priority != nil {
		priority = *p.config.Priority
	}
	m.log.Info("diameter: selected peer", zap.Uint32("requested_app", app), zap.String("destination_realm", realm), zap.String("selected_peer", result.Name), zap.String("selection_type", kind), zap.Int("priority", priority), zap.Int("config_order", result.ConfigOrder), zap.String("reason", "direct application route preferred over relay; priority/config order breaks ties"))
	return result, nil
}

// SelectPeerForDestination honours an explicit Destination-Host. It selects a
// direct peer only when that peer is the addressed host and advertises app;
// otherwise a relay is permitted to carry the request.
func (m *Manager) SelectPeerForDestination(app uint32, realm, destinationHost string) (*Peer, error) {
	if destinationHost == "" {
		return m.SelectPeer(app, realm)
	}
	m.mu.RLock()
	var direct, relay []*record
	for _, p := range m.peers {
		if p.state != Ready || p.conn == nil {
			continue
		}
		if p.apps[app] && strings.EqualFold(p.originHost, destinationHost) {
			direct = append(direct, p)
		} else if p.apps[RelayApplicationID] {
			relay = append(relay, p)
		}
	}
	m.mu.RUnlock()
	candidates := direct
	kind := "direct-exact-host"
	if len(candidates) == 0 {
		candidates, kind = relay, "relay"
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no Diameter peer available for app=%d realm=%s destination_host=%s", app, realm, destinationHost)
	}
	sort.SliceStable(candidates, func(i, j int) bool { return before(candidates[i], candidates[j]) })
	p := candidates[0]
	return &Peer{Name: p.config.Name, Address: p.config.Address, Transport: p.config.Transport, OriginHost: p.originHost, OriginRealm: p.originRealm, Priority: p.config.Priority, ConfigOrder: p.order, SelectionType: kind, DestinationHost: destinationHost, Connection: p.conn}, nil
}

func before(a, b *record) bool {
	if a.config.Priority != nil && b.config.Priority != nil && *a.config.Priority != *b.config.Priority {
		return *a.config.Priority < *b.config.Priority
	}
	if a.config.Priority != nil && b.config.Priority == nil {
		return true
	}
	if a.config.Priority == nil && b.config.Priority != nil {
		return false
	}
	return a.order < b.order
}
