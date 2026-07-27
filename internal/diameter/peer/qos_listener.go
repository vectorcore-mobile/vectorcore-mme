package peer

import (
	"net"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/ishidawataru/sctp"

	"github.com/vectorcore/mme/internal/transportqos"
)

// qosListener reapplies a fixed outbound mark to accepted sockets. This does
// not inspect received packets; it makes accepted-connection response traffic
// deterministic even where listener option inheritance differs by platform.
type qosListener struct {
	net.Listener
	dscp *int
}

func (l qosListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if err := transportqos.Apply(l.dscp, conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// qosSCTPListener also supplies go-diameter's public SCTP multistream wrapper.
type qosSCTPListener struct {
	*sctp.SCTPListener
	dscp *int
}

func (l qosSCTPListener) Accept() (net.Conn, error) {
	conn, err := l.SCTPListener.AcceptSCTP()
	if err != nil {
		return nil, err
	}
	if err := transportqos.Apply(l.dscp, conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return diam.NewSCTPConn(conn), nil
}
