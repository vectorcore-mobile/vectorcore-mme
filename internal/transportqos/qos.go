// Package transportqos applies a configured, fixed outbound DSCP mark to MME
// control-plane sockets. It deliberately has no received-packet handling.
package transportqos

import (
	"fmt"
	"syscall"
)

// TOS returns the socket traffic-class byte for an explicitly configured DSCP.
// The bool is false when QoS is omitted, preserving the operating-system default.
func TOS(dscp *int) (int, bool, error) {
	if dscp == nil {
		return 0, false, nil
	}
	if *dscp < 0 || *dscp > 63 {
		return 0, false, fmt.Errorf("dscp must be between 0 and 63, got %d", *dscp)
	}
	return *dscp << 2, true, nil
}

// Control returns a socket-creation hook suitable for net.Dialer,
// net.ListenConfig, and sctp.SocketConfig. A nil DSCP does nothing.
func Control(dscp *int) func(network, address string, c syscall.RawConn) error {
	return func(_ string, _ string, c syscall.RawConn) error {
		return ApplyRaw(dscp, c)
	}
}

// Apply applies the configured mark to an already-created socket, for example
// an SCTP or TCP association accepted by a listener.
func Apply(dscp *int, sock any) error {
	if dscp == nil {
		return nil
	}
	sc, ok := sock.(syscall.Conn)
	if !ok {
		return fmt.Errorf("qos: %T does not expose syscall conn", sock)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return fmt.Errorf("qos: obtain socket control: %w", err)
	}
	return ApplyRaw(dscp, raw)
}
