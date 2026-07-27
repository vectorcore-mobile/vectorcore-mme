//go:build !linux

package transportqos

import (
	"fmt"
	"syscall"
)

func ApplyRaw(dscp *int, _ syscall.RawConn) error {
	_, configured, err := TOS(dscp)
	if err != nil || !configured {
		return err
	}
	return fmt.Errorf("qos: outbound DSCP socket marking is supported on Linux only")
}
