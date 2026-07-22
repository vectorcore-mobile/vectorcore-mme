// Package sms coordinates SMS transactions without knowing the core-side
// transport. SGd is one adapter; a future SGs-AP adapter will implement the
// same Transport interface.
package sms

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/vectorcore/mme/internal/metrics"
	nassms "github.com/vectorcore/mme/internal/nas/sms"
)

type MORequest struct {
	IMSI        string
	MSISDN      string
	RPReference uint8
	SMRPUI      []byte
}
type MOResult struct{ SMRPUI []byte }
type Transport interface {
	SendMobileOriginatedSMS(context.Context, *MORequest) (*MOResult, error)
}

// AlertTransport is optional. It keeps Alert Service Centre signalling out of
// NAS and lets a future SGs-AP adapter supply its own core-side procedure.
type AlertTransport interface {
	SendAlertServiceCentre(context.Context, *AlertRequest) error
}
type AlertRequest struct {
	IMSI   string
	MSISDN string
}

type Service struct {
	transport Transport
	mu        sync.Mutex
	pending   map[string]*PendingMT
}
type PendingMT struct {
	IMSI        string
	Correlation string
	SMRPUI      []byte
	CreatedAt   time.Time
	ExpiresAt   time.Time
	timer       *time.Timer
}

func New(transport Transport) *Service {
	return &Service{transport: transport, pending: make(map[string]*PendingMT)}
}

func (s *Service) QueueMT(imsi, correlation string, rpdu []byte, ttl time.Duration) (*PendingMT, error) {
	if s == nil || imsi == "" || len(rpdu) == 0 || len(rpdu) > nassms.MaxSMRPUI || ttl <= 0 {
		return nil, fmt.Errorf("sms: invalid pending MT")
	}
	now := time.Now().UTC()
	p := &PendingMT{IMSI: imsi, Correlation: correlation, SMRPUI: append([]byte(nil), rpdu...), CreatedAt: now, ExpiresAt: now.Add(ttl)}
	s.mu.Lock()
	defer s.mu.Unlock()
	if old := s.pending[imsi]; old != nil && old.ExpiresAt.After(now) {
		return old, nil
	}
	s.pending[imsi] = p
	s.startPendingTimerLocked(p, ttl)
	return p, nil
}
func (s *Service) TakePendingMT(imsi string) (*PendingMT, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[imsi]
	if ok && !p.ExpiresAt.After(time.Now().UTC()) {
		delete(s.pending, imsi)
		if p.timer != nil {
			p.timer.Stop()
		}
		return nil, false
	}
	if ok {
		delete(s.pending, imsi)
		if p.timer != nil {
			p.timer.Stop()
		}
	}
	return p, ok
}
func (s *Service) RemovePendingMT(imsi string) {
	s.mu.Lock()
	if p := s.pending[imsi]; p != nil && p.timer != nil {
		p.timer.Stop()
	}
	delete(s.pending, imsi)
	s.mu.Unlock()
}

func (s *Service) HasPendingMT(imsi string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.pending[imsi]
	if p == nil {
		return false
	}
	if !p.ExpiresAt.After(time.Now().UTC()) {
		delete(s.pending, imsi)
		if p.timer != nil {
			p.timer.Stop()
		}
		return false
	}
	return true
}

// NotifyUEReachable consumes a deferred-MT marker and alerts the selected
// core transport exactly once. The SMSC then retries TFR; no stale Diameter
// transaction is retained while paging completes.
func (s *Service) NotifyUEReachable(ctx context.Context, imsi, msisdn string) (bool, error) {
	p, ok := s.TakePendingMT(imsi)
	if !ok || p == nil {
		return false, nil
	}
	transport, ok := s.transport.(AlertTransport)
	if !ok {
		s.restorePending(p)
		return true, fmt.Errorf("sms: transport does not support Alert Service Centre")
	}
	if err := transport.SendAlertServiceCentre(ctx, &AlertRequest{IMSI: imsi, MSISDN: msisdn}); err != nil {
		s.restorePending(p)
		return true, err
	}
	return true, nil
}

func (s *Service) restorePending(p *PendingMT) {
	if p == nil || !p.ExpiresAt.After(time.Now().UTC()) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending[p.IMSI] == nil {
		s.pending[p.IMSI] = p
		s.startPendingTimerLocked(p, time.Until(p.ExpiresAt))
	}
}

func (s *Service) startPendingTimerLocked(p *PendingMT, ttl time.Duration) {
	if p == nil || ttl <= 0 {
		return
	}
	p.timer = time.AfterFunc(ttl, func() {
		s.mu.Lock()
		if s.pending[p.IMSI] == p {
			delete(s.pending, p.IMSI)
			metrics.SMSTimerExpirationsTotal.WithLabelValues("mt_deferred").Inc()
		}
		s.mu.Unlock()
	})
}

// HandleMO validates the UE's RP-DATA and gives the unmodified RP payload to
// the selected core transport. TPDU content is never parsed or logged here.
func (s *Service) HandleMO(ctx context.Context, imsi, msisdn string, rpdu []byte) (*MOResult, error) {
	if s == nil || s.transport == nil {
		return nil, fmt.Errorf("sms: no core transport")
	}
	rp, err := nassms.DecodeRPDataMO(rpdu)
	if err != nil {
		return nil, err
	}
	if len(rpdu) > nassms.MaxSMRPUI {
		return nil, fmt.Errorf("sms: RPDU exceeds SGd SM-RP-UI limit")
	}
	// TS 29.338 SM-RP-UI contains the TPDU. RP framing is strictly NAS-side.
	return s.transport.SendMobileOriginatedSMS(ctx, &MORequest{IMSI: imsi, MSISDN: msisdn, RPReference: rp.Reference, SMRPUI: append([]byte(nil), rp.TPDU...)})
}
