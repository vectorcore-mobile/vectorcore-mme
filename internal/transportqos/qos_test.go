package transportqos

import (
	"context"
	"net"
	"syscall"
	"testing"

	"github.com/ishidawataru/sctp"
)

func pointer(v int) *int { return &v }

func TestTOS(t *testing.T) {
	for _, tt := range []struct {
		dscp int
		want int
	}{
		{0, 0x00}, {24, 0x60}, {40, 0xa0}, {46, 0xb8}, {63, 0xfc},
	} {
		got, configured, err := TOS(pointer(tt.dscp))
		if err != nil || !configured || got != tt.want {
			t.Fatalf("DSCP %d: got %#x configured=%v err=%v", tt.dscp, got, configured, err)
		}
	}
	if _, configured, err := TOS(nil); err != nil || configured {
		t.Fatalf("omitted DSCP configured=%v err=%v", configured, err)
	}
	for _, invalid := range []int{-1, 64} {
		if _, _, err := TOS(pointer(invalid)); err == nil {
			t.Fatalf("DSCP %d accepted", invalid)
		}
	}
}

func TestIPv4SocketTOS(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skipf("IPv4 UDP unavailable: %v", err)
	}
	defer conn.Close()
	if err := Apply(pointer(24), conn); err != nil {
		t.Fatal(err)
	}
	got, err := SocketTOS(conn, false)
	if err != nil {
		t.Fatal(err)
	}
	if got != 0x60 {
		t.Fatalf("IP_TOS = %#x, want 0x60", got)
	}
}

func TestIPv6SocketTrafficClass(t *testing.T) {
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Skipf("IPv6 UDP unavailable: %v", err)
	}
	defer conn.Close()
	if err := Apply(pointer(24), conn); err != nil {
		t.Fatal(err)
	}
	got, err := SocketTOS(conn, true)
	if err != nil {
		t.Fatal(err)
	}
	if got != 0x60 {
		t.Fatalf("IPV6_TCLASS = %#x, want 0x60", got)
	}
}

func TestTCPControlAndAcceptedSocketTOS(t *testing.T) {
	dscp := pointer(24)
	lc := net.ListenConfig{Control: Control(dscp)}
	ln, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("TCP unavailable: %v", err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	dialer := net.Dialer{Control: Control(dscp)}
	client, err := dialer.DialContext(context.Background(), "tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if got, err := SocketTOS(client, false); err != nil || got != 0x60 {
		t.Fatalf("outbound TCP IP_TOS = %#x, err=%v", got, err)
	}
	server := <-accepted
	defer server.Close()
	if err := Apply(dscp, server); err != nil {
		t.Fatal(err)
	}
	if got, err := SocketTOS(server, false); err != nil || got != 0x60 {
		t.Fatalf("accepted TCP IP_TOS = %#x, err=%v", got, err)
	}
}

func TestSCTPPreBindControl(t *testing.T) {
	dscp := pointer(24)
	addr := &sctp.SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}, Port: 0}
	cfg := &sctp.SocketConfig{Control: func(network, address string, raw syscall.RawConn) error {
		return Control(dscp)(network, address, raw)
	}}
	ln, err := cfg.Listen("sctp", addr)
	if err != nil {
		t.Skipf("kernel SCTP unavailable: %v", err)
	}
	defer ln.Close()
	if got, err := SocketTOS(ln, false); err != nil || got != 0x60 {
		t.Fatalf("SCTP listener IP_TOS = %#x, err=%v", got, err)
	}
}
