package vlr

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/ishidawataru/sctp"
	"go.uber.org/zap"
)

// PPID is the SGsAP payload protocol identifier (TS 29.118 §6.3: "The
// payload protocol identifier to be used for SGsAP is 0").
const PPID uint32 = 0

// maxPDUSize bounds a single SGsAP SCTP datagram. The largest defined
// message (Location Update Request with every optional IE) is well under
// this; it exists to bound the read buffer, not to reject a legitimate PDU.
const maxPDUSize = 65535

// sctpTransport is one MME-initiated outbound SCTP association to a single
// VLR (TS 29.118 §6.3: "The MME shall establish the SCTP association").
// It mirrors internal/sls's transport: dial-with-reconnect, PPID-filtered
// reads, no request/response correlation - that lives in the association
// layer above it.
type sctpTransport struct {
	address string
	port    int
	log     *zap.Logger

	mu        sync.RWMutex
	conn      *sctp.SCTPConn
	closed    bool
	write     sync.Mutex
	onMessage func([]byte)
	onConnect func()
	onLoss    func(error)
	started   sync.Once

	reconnectInterval time.Duration
}

func newSCTPTransport(address string, port int, reconnectInterval time.Duration, log *zap.Logger) *sctpTransport {
	if log == nil {
		log = zap.NewNop()
	}
	return &sctpTransport{address: address, port: port, reconnectInterval: reconnectInterval, log: log}
}

func (t *sctpTransport) setHandlers(onMessage func([]byte), onConnect func(), onLoss func(error)) {
	t.mu.Lock()
	t.onMessage = onMessage
	t.onConnect = onConnect
	t.onLoss = onLoss
	t.mu.Unlock()
}

func (t *sctpTransport) available() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.conn != nil && !t.closed
}

func (t *sctpTransport) send(ctx context.Context, b []byte) error {
	if len(b) == 0 || len(b) > maxPDUSize {
		return fmt.Errorf("vlr: message length %d out of bounds", len(b))
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	t.write.Lock()
	defer t.write.Unlock()
	t.mu.RLock()
	c := t.conn
	t.mu.RUnlock()
	if c == nil {
		return fmt.Errorf("vlr: SCTP association to %s:%d unavailable", t.address, t.port)
	}
	if _, err := c.SCTPWrite(b, &sctp.SndRcvInfo{PPID: PPID}); err != nil {
		t.lost(c, err)
		return fmt.Errorf("vlr: SCTP write: %w", err)
	}
	return nil
}

func (t *sctpTransport) start(ctx context.Context) {
	t.started.Do(func() {
		go func() {
			for ctx.Err() == nil {
				if err := t.connect(ctx); err != nil && ctx.Err() == nil {
					t.log.Warn("vlr: SCTP association unavailable", zap.String("vlr_address", t.address), zap.Int("vlr_port", t.port), zap.Error(err))
					select {
					case <-ctx.Done():
						return
					case <-time.After(t.reconnectInterval):
					}
				}
			}
		}()
	})
}

func (t *sctpTransport) connect(ctx context.Context) error {
	r := &sctp.SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP(t.address)}}, Port: t.port}
	c, err := (&sctp.SocketConfig{}).Dial("sctp", nil, r)
	if err != nil {
		return err
	}
	if err = c.SubscribeEvents(sctp.SCTP_EVENT_DATA_IO); err != nil {
		_ = c.Close()
		return err
	}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		_ = c.Close()
		return context.Canceled
	}
	t.conn = c
	onConnect := t.onConnect
	t.mu.Unlock()
	t.log.Info("vlr: SCTP association established", zap.String("vlr_address", t.address), zap.Int("vlr_port", t.port), zap.Uint32("ppid", PPID))
	if onConnect != nil {
		onConnect()
	}
	buf := make([]byte, maxPDUSize)
	for {
		n, info, e := c.SCTPRead(buf)
		if e != nil {
			t.lost(c, e)
			return e
		}
		if n < 1 || n > len(buf) || info == nil || info.PPID != PPID {
			continue
		}
		t.mu.RLock()
		h := t.onMessage
		t.mu.RUnlock()
		if h != nil {
			h(append([]byte(nil), buf[:n]...))
		}
		select {
		case <-ctx.Done():
			_ = c.Close()
			return ctx.Err()
		default:
		}
	}
}

func (t *sctpTransport) lost(c *sctp.SCTPConn, e error) {
	t.mu.Lock()
	if t.conn != c {
		t.mu.Unlock()
		return
	}
	t.conn = nil
	h := t.onLoss
	t.mu.Unlock()
	_ = c.Close()
	if h != nil {
		h(e)
	}
}

func (t *sctpTransport) close() error {
	t.mu.Lock()
	t.closed = true
	c := t.conn
	t.conn = nil
	t.mu.Unlock()
	if c != nil {
		return c.Close()
	}
	return nil
}
