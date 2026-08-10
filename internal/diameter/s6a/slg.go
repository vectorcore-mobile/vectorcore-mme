package s6a

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/fiorix/go-diameter/v4/diam"
	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/diameter/slg"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/nas/lcsnotify"
	"github.com/vectorcore/mme/internal/sls"
	"github.com/vectorcore/mme/internal/uecontext"
)

// slgTransactions is deliberately in-memory: TS 29.172 PLR/LRR sessions use
// NO_STATE_MAINTAINED. It protects duplicate work and gives shutdown/timeout a
// single cancellation point without creating persistent subscriber state.
type slgTransactions struct {
	mu     sync.Mutex
	active map[string]context.CancelFunc
	limit  int
	closed bool
}

func newSLgTransactions(limit int) *slgTransactions {
	if limit < 1 {
		limit = 1024
	}
	return &slgTransactions{active: make(map[string]context.CancelFunc), limit: limit}
}
func (s *slgTransactions) Begin(key string, timeout time.Duration) (context.Context, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, context.Canceled
	}
	if _, exists := s.active[key]; exists {
		return nil, fmt.Errorf("duplicate SLg transaction")
	}
	if len(s.active) >= s.limit {
		return nil, fmt.Errorf("SLg transaction capacity reached")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	s.active[key] = cancel
	return ctx, nil
}
func (s *slgTransactions) End(key string) {
	s.mu.Lock()
	cancel := s.active[key]
	delete(s.active, key)
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}
func (s *slgTransactions) Close() {
	s.mu.Lock()
	s.closed = true
	active := s.active
	s.active = make(map[string]context.CancelFunc)
	s.mu.Unlock()
	for _, cancel := range active {
		cancel()
	}
}

func (h *Handlers) handlePLR(c diam.Conn, m *diam.Message) {
	req, protocolErr := slg.DecodePLR(m)
	if protocolErr != nil {
		h.log.Warn("slg: PLR decode failed", zap.String("session_id", findSessionID(m)), zap.String("reason", protocolErr.Reason))
		h.writePLA(c, m, protocolErr.ResultCode, protocolErr.ExperimentalCode, protocolErr.FailedAVP, protocolErr.Reason)
		return
	}
	h.log.Info("slg: PLR received",
		zap.String("session_id", req.SessionID),
		zap.String("origin_host", req.OriginHost),
		zap.String("imsi", req.IMSI),
		zap.Bool("msisdn_present", len(req.MSISDN) != 0),
		zap.Uint32("location_type", uint32(req.LocationType)),
	)
	if !strings.EqualFold(req.DestinationHost, h.diameterCfg.OriginHost) || !strings.EqualFold(req.DestinationRealm, h.diameterCfg.OriginRealm) {
		h.writePLA(c, m, diam.UnableToDeliver, 0, nil, "destination host/realm mismatch")
		return
	}
	ue, result, experimental := h.resolveSLgUE(req)
	if result != 0 || experimental != 0 {
		h.writePLA(c, m, result, experimental, nil, "UE resolution failed")
		return
	}
	switch req.LocationType {
	case slg.LocationTypeCurrent, slg.LocationTypeCurrentOrLastKnown:
	default:
		h.writePLA(c, m, 0, slg.ExperimentalPositioningFailed, nil, "unsupported location type")
		return
	}
	key := fmt.Sprintf("plr:%s:%s:%08x", req.OriginHost, req.SessionID, m.Header.EndToEndID)
	ctx, err := h.slgTx.Begin(key, h.slgCfg.TransactionTimeout)
	if err != nil {
		h.writePLA(c, m, diam.TooBusy, 0, nil, err.Error())
		return
	}
	if h.slsProvider == nil {
		h.slgTx.End(key)
		h.writePLA(c, m, 0, slg.ExperimentalPositioningFailed, nil, "no SLs provider configured")
		return
	}
	// TS 23.271 §9.1.15 step 4: the consent/notification procedure only
	// applies to value-added-services clients, and only when the GMLC sent
	// a privacy-check value at all.
	notifyGate := req.LCSClientType == slg.LCSClientTypeValueAddedServices && req.PrivacyCheck != nil
	if notifyGate && *req.PrivacyCheck == slg.LCSPrivacyCheckNotAllowed {
		h.slgTx.End(key)
		h.writePLA(c, m, 0, slg.ExperimentalPositioningDenied, nil, "LCS-Privacy-Check: not allowed")
		return
	}
	ue.Lock()
	ecgi := make([]byte, 7)
	copy(ecgi[:3], ue.ECGIPLMN[:])
	ecgi[3] = byte(ue.ECGIECI >> 24)
	ecgi[4] = byte(ue.ECGIECI >> 16)
	ecgi[5] = byte(ue.ECGIECI >> 8)
	ecgi[6] = byte(ue.ECGIECI)
	lppSupport := ue.LPPSupported()
	ue.Unlock()

	// RequestPosition is a round trip to SLs that can run for seconds
	// (up to TransactionTimeout). go-diameter dispatches each connection's
	// messages sequentially, so blocking the handler here would also stall
	// DWR/DWA on this shared connection and let the client-side watchdog
	// close it out from under us. Run it off the read loop instead. The
	// notification wait (bounded by NotificationTimeout) shares this
	// reasoning: it is also a blocking round trip to the UE.
	go func() {
		defer h.slgTx.End(key)
		if notifyGate && *req.PrivacyCheck != slg.LCSPrivacyCheckAllowedWithoutNotification {
			if !h.applyPrivacyCheckNotification(ue.MMEUES1APID, *req.PrivacyCheck, req.SessionID) {
				h.writePLA(c, m, 0, slg.ExperimentalPositioningDenied, nil, "LCS-Privacy-Check: UE did not consent to notification")
				return
			}
		}
		posResult, posErr := h.slsProvider.RequestPosition(ctx, key, ue.MMEUES1APID, ecgi, req.LCSClientType, lppSupport)
		if posErr != nil {
			h.log.Warn("slg: SLs positioning failed", zap.String("session_id", req.SessionID), zap.Error(posErr))
		} else if len(posResult.Estimate) == 0 {
			h.log.Warn("slg: SLs positioning returned no estimate", zap.String("session_id", req.SessionID))
		} else if gad, convErr := sls.ConvertLocationEstimateToGAD(posResult.Estimate); convErr != nil {
			// posResult.Estimate is the LCS-AP Location-Estimate IE value, APER
			// encoding of Geographical-Area — a different wire format from the
			// Diameter Location-Estimate AVP's TS 23.032 compact GAD bytes.
			// Passing it through unconverted builds a PLA that reports success
			// but carries bytes the GMLC's GAD decoder cannot parse.
			h.log.Warn("slg: location estimate conversion failed", zap.String("session_id", req.SessionID), zap.Error(convErr))
		} else {
			extra := slg.PLAExtras{PositioningData: posResult.PositioningData, AccuracyFulfilmentIndicator: posResult.AccuracyFulfilmentIndicator, AccuracyFulfilmentPresent: posResult.AccuracyFulfilmentPresent}
			answer, buildErr := slg.BuildPLAWithLocation(m, h.diameterCfg.OriginHost, h.diameterCfg.OriginRealm, diam.Success, 0, nil, nil, gad, extra)
			if buildErr != nil {
				h.log.Warn("slg: PLA build failed", zap.String("session_id", req.SessionID), zap.Error(buildErr))
			} else {
				if _, writeErr := answer.WriteTo(c); writeErr != nil {
					h.log.Warn("slg: PLA write", zap.String("session_id", req.SessionID), zap.String("reason", "positioning succeeded"), zap.Uint32("result_code", diam.Success), zap.Error(writeErr))
					return
				}
				h.log.Info("slg: PLA sent", zap.String("session_id", req.SessionID), zap.String("reason", "positioning succeeded"), zap.Uint32("result_code", diam.Success))
				return
			}
		}
		h.writePLA(c, m, 0, slg.ExperimentalPositioningFailed, nil, "positioning failed")
	}()
}

// applyPrivacyCheckNotification sends the TS 23.271 §9.1.15 step 4 LCS
// location-notification when privacyCheck requires it, and applies step 5's
// no-response rule. privacyCheck must not be LCSPrivacyCheckNotAllowed
// (handlePLR rejects that value before this is ever called) or
// LCSPrivacyCheckAllowedWithoutNotification (handlePLR skips the call
// entirely for that value). It reports whether positioning may proceed.
func (h *Handlers) applyPrivacyCheckNotification(mmeUEID uint32, privacyCheck uint32, sessionID string) bool {
	switch privacyCheck {
	case slg.LCSPrivacyCheckAllowedWithNotification:
		if h.lcsNotifier != nil {
			if _, err := h.lcsNotifier.SendLocationNotification(mmeUEID, lcsnotify.NotifyLocationAllowed, false, 0); err != nil {
				h.log.Warn("slg: LCS notification send failed", zap.String("session_id", sessionID), zap.Error(err))
			}
		}
		return true
	case slg.LCSPrivacyCheckAllowedIfNoResponse:
		if h.lcsNotifier == nil {
			return true // cannot notify: treated the same as no response, which this value allows
		}
		granted, err := h.lcsNotifier.SendLocationNotification(mmeUEID, lcsnotify.NotifyAndVerifyLocationAllowedIfNoResponse, true, h.slgCfg.NotificationTimeout)
		if err != nil {
			// Timeout or an undecodable response are both treated as "no
			// response" for this value: TS 23.271 only requires an explicit
			// denial to block positioning here.
			h.log.Info("slg: LCS notification no usable response, proceeding", zap.String("session_id", sessionID), zap.Error(err))
			return true
		}
		return granted
	case slg.LCSPrivacyCheckRestrictedIfNoResponse:
		if h.lcsNotifier == nil {
			h.log.Warn("slg: LCS notification required but unavailable", zap.String("session_id", sessionID))
			return false
		}
		granted, err := h.lcsNotifier.SendLocationNotification(mmeUEID, lcsnotify.NotifyAndVerifyLocationNotAllowedIfNoResponse, true, h.slgCfg.NotificationTimeout)
		if err != nil {
			// Timeout or an undecodable response are both treated as "no
			// response" for this value: TS 23.271 requires an explicit grant
			// to allow positioning here.
			h.log.Info("slg: LCS notification no usable response, restricting", zap.String("session_id", sessionID), zap.Error(err))
			return false
		}
		return granted
	}
	return true
}

func (h *Handlers) resolveSLgUE(req *slg.ProvideLocationRequest) (*uecontext.Context, uint32, uint32) {
	if req.IMSI != "" && !slgDigits(req.IMSI, 5, 15) {
		return nil, diam.InvalidAVPValue, 0
	}
	msisdn := ""
	if len(req.MSISDN) != 0 {
		var ok bool
		msisdn, ok = decodeSLgTBCD(req.MSISDN)
		if !ok {
			return nil, diam.InvalidAVPValue, 0
		}
	}
	var ue *uecontext.Context
	if req.IMSI != "" {
		ue, _ = h.ueManager.GetByIMSI(req.IMSI)
	} else if msisdn != "" {
		h.ueManager.Range(func(candidate *uecontext.Context) bool {
			candidate.Lock()
			match := candidate.MSISDN == msisdn
			candidate.Unlock()
			if match {
				ue = candidate
				return false
			}
			return true
		})
	} else {
		return nil, diam.MissingAVP, 0
	}
	if ue == nil {
		return nil, 0, slg.ExperimentalUserUnknown
	}
	ue.Lock()
	defer ue.Unlock()
	if msisdn != "" && ue.MSISDN != msisdn {
		return nil, diam.InvalidAVPValue, 0
	}
	if req.IMSI != "" && ue.IMSI != req.IMSI {
		return nil, diam.InvalidAVPValue, 0
	}
	if ue.EMMState != emm.StateRegistered {
		return nil, 0, slg.ExperimentalDetachedUser
	}
	return ue, 0, 0
}

func (h *Handlers) writePLA(c diam.Conn, request *diam.Message, result, experimental uint32, failed *diam.AVP, reason string) {
	sessionID := findSessionID(request)
	answer, err := slg.BuildPLA(request, h.diameterCfg.OriginHost, h.diameterCfg.OriginRealm, result, experimental, failed)
	if err != nil {
		h.log.Warn("slg: PLA build failed", zap.String("session_id", sessionID), zap.String("reason", reason), zap.Error(err))
		return
	}
	if _, writeErr := answer.WriteTo(c); writeErr != nil {
		h.log.Warn("slg: PLA write", zap.String("session_id", sessionID), zap.String("reason", reason), zap.Uint32("result_code", result), zap.Uint32("experimental_result_code", experimental), zap.Error(writeErr))
		return
	}
	h.log.Info("slg: PLA sent", zap.String("session_id", sessionID), zap.String("reason", reason), zap.Uint32("result_code", result), zap.Uint32("experimental_result_code", experimental))
}

// AbortSLgPositioning cancels any SLs positioning transaction active for
// mmeUEID, implementing s1ap.S6aClient for UE lifecycle events (detach,
// superseded transaction). Fire-and-forget: nil-safe against a disabled or
// unconfigured SLs provider, mirroring the guard already used in handlePLR.
func (h *Handlers) AbortSLgPositioning(mmeUEID uint32) {
	if h.slsProvider == nil {
		return
	}
	h.slsProvider.AbortPosition(mmeUEID)
}

// SendSLgLocationReport is the pure-Go LRR transport boundary for a future
// deferred-location trigger. It neither invents a report nor depends on SLs.
func (h *Handlers) SendSLgLocationReport(ctx context.Context, report slg.LocationReportRequest) error {
	if !h.slgCfg.Enabled {
		return fmt.Errorf("slg: disabled")
	}
	if report.DestinationHost == "" || report.DestinationRealm == "" {
		return fmt.Errorf("slg: missing GMLC destination")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if _, deadline := ctx.Deadline(); !deadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, h.slgCfg.ReportTimeout)
		defer cancel()
	}
	report.OriginHost, report.OriginRealm = h.diameterCfg.OriginHost, h.diameterCfg.OriginRealm
	if report.SessionID == "" {
		report.SessionID = h.newSessionID(report.IMSI)
	}
	m, err := slg.BuildLRR(report)
	if err != nil {
		return err
	}
	selected, err := h.peers.SelectPeerForDestination(slg.ApplicationID, report.DestinationRealm, report.DestinationHost)
	if err != nil {
		return fmt.Errorf("slg: route LRR: %w", err)
	}
	key := "lrr:" + report.SessionID
	if _, err = h.slgTx.Begin(key, h.slgCfg.ReportTimeout); err != nil {
		return err
	}
	defer h.slgTx.End(key)
	answer := make(chan error, 1)
	h.pendingLRA.Store(report.SessionID, answer)
	defer h.pendingLRA.Delete(report.SessionID)
	if _, err = m.WriteTo(selected.Connection); err != nil {
		h.reportTransactionFailure(selected)
		return fmt.Errorf("slg: write LRR: %w", err)
	}
	select {
	case err := <-answer:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *Handlers) handleLRA(_ diam.Conn, m *diam.Message) {
	answer, err := slg.DecodeLocationReportAnswer(m)
	if err != nil || answer == nil {
		return
	}
	v, ok := h.pendingLRA.Load(answer.SessionID)
	if !ok {
		return
	} // late, expired, duplicate, or already cancelled
	result := error(nil)
	if answer.ResultCode != diam.Success || answer.ExperimentalCode != 0 {
		result = fmt.Errorf("slg: LRA failure result=%d experimental=%d", answer.ResultCode, answer.ExperimentalCode)
	}
	select {
	case v.(chan error) <- result:
	default:
	}
}

func slgDigits(value string, min, max int) bool {
	if len(value) < min || len(value) > max {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func decodeSLgTBCD(data []byte) (string, bool) {
	if len(data) == 0 {
		return "", false
	}
	var out strings.Builder
	for i, b := range data {
		lo, hi := b&0xf, b>>4
		if lo > 9 {
			return "", false
		}
		out.WriteByte('0' + lo)
		if hi == 0xf && i == len(data)-1 {
			continue
		}
		if hi > 9 {
			return "", false
		}
		out.WriteByte('0' + hi)
	}
	if !slgDigits(out.String(), 1, 15) {
		return "", false
	}
	return out.String(), true
}
