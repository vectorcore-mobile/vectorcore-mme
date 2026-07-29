package sls

import (
	"context"
	"fmt"
	"github.com/ishidawataru/sctp"
	"github.com/vectorcore/mme/internal/config"
	"go.uber.org/zap"
	"net"
	"sync"
	"time"
)

type SCTPTransport struct {
	cfg       config.SLsConfig
	log       *zap.Logger
	mu        sync.RWMutex
	conn      *sctp.SCTPConn
	closed    bool
	write     sync.Mutex
	onMessage func([]byte)
	onLoss    func(error)
	started   sync.Once
}

func NewSCTPTransport(c config.SLsConfig, l *zap.Logger) *SCTPTransport {
	if l == nil {
		l = zap.NewNop()
	}
	return &SCTPTransport{cfg: c, log: l}
}
func (t *SCTPTransport) SetHandlers(m func([]byte), loss func(error)) {
	t.mu.Lock()
	t.onMessage = m
	t.onLoss = loss
	t.mu.Unlock()
}
func (t *SCTPTransport) Available() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.conn != nil && !t.closed
}
func (t *SCTPTransport) Send(ctx context.Context, b []byte) error {
	if len(b) == 0 || len(b) > t.cfg.MaxPDUSize {
		return ErrMalformed
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
		return ErrUnavailable
	}
	if _, err := c.SCTPWrite(b, &sctp.SndRcvInfo{PPID: PPID}); err != nil {
		t.lost(c, err)
		return fmt.Errorf("sls write: %w", err)
	}
	return nil
}
func (t *SCTPTransport) Start(ctx context.Context) {
	t.started.Do(func() {
		go func() {
			for ctx.Err() == nil {
				if err := t.connect(ctx); err != nil && ctx.Err() == nil {
					t.log.Warn("sls: association unavailable", zap.Error(err))
					select {
					case <-ctx.Done():
						return
					case <-time.After(t.cfg.ReconnectInterval):
					}
				}
			}
		}()
	})
}
func (t *SCTPTransport) connect(ctx context.Context) error {
	l := &sctp.SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP(t.cfg.LocalAddress)}}, Port: t.cfg.LocalPort}
	r := &sctp.SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP(t.cfg.RemoteAddress)}}, Port: t.cfg.RemotePort}
	c, err := (&sctp.SocketConfig{}).Dial("sctp", l, r)
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
	t.mu.Unlock()
	t.log.Info("sls: SCTP association established", zap.Uint32("ppid", PPID))
	buf := make([]byte, t.cfg.MaxPDUSize)
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
func (t *SCTPTransport) lost(c *sctp.SCTPConn, e error) {
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
func (t *SCTPTransport) Close() error {
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
