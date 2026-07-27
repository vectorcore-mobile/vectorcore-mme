//go:build linux

package transportqos

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// ApplyRaw applies the configured mark through a raw socket control handle.
func ApplyRaw(dscp *int, raw syscall.RawConn) error {
	tos, configured, err := TOS(dscp)
	if err != nil || !configured {
		return err
	}
	var optionErr error
	if err := raw.Control(func(fd uintptr) {
		err4 := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TOS, tos)
		err6 := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_TCLASS, tos)
		if err4 != nil && err6 != nil {
			optionErr = fmt.Errorf("set IP_TOS (%v) and IPV6_TCLASS (%v)", err4, err6)
		}
	}); err != nil {
		return fmt.Errorf("qos: socket control: %w", err)
	}
	if optionErr != nil {
		return fmt.Errorf("qos: %w", optionErr)
	}
	return nil
}

// SocketTOS is test support for kernel socket-option verification.
func SocketTOS(sock any, ipv6 bool) (int, error) {
	sc, ok := sock.(syscall.Conn)
	if !ok {
		return 0, fmt.Errorf("qos: %T does not expose syscall conn", sock)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var value int
	err = raw.Control(func(fd uintptr) {
		if ipv6 {
			value, err = unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_TCLASS)
		} else {
			value, err = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TOS)
		}
	})
	return value, err
}
