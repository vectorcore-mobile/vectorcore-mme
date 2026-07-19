package s1ap

import (
	"errors"
	"time"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/asn1/aper"
	"github.com/vectorcore/mme/internal/metrics"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/s1ap/pdu"
	"github.com/vectorcore/mme/internal/uecontext"
)

const (
	maxPagingAttempts uint8         = 2
	t3413Duration     time.Duration = 6 * time.Second
)

// Sentinel errors returned by PageUE (also used as HTTP response bodies via Error()).
var (
	ErrUnknownIMSI      = errors.New("IMSI not found")
	ErrNotRegistered    = errors.New("UE not in EMM-REGISTERED state")
	ErrAlreadyConnected = errors.New("UE is already ECM-CONNECTED")
	ErrAlreadyPaging    = errors.New("paging already in progress")
	ErrNoPagingIdentity = errors.New("UE has no valid paging identity")
	ErrNoPagingTAI      = errors.New("UE has no valid paging TAI")
	ErrNoENB            = errors.New("no eNB available to page")
)

// PageUE implements api.Pager. It validates the UE state, selects target eNBs,
// sends S1AP Paging, and starts T3413 with retry logic.
func (s *Server) PageUE(imsi string) error {
	ue, ok := s.ueManager.GetByIMSI(imsi)
	if !ok {
		metrics.PagingTotal.WithLabelValues("unknown_imsi").Inc()
		return ErrUnknownIMSI
	}

	ue.Lock()
	emmState := ue.EMMState
	ecmState := ue.ECMState
	tai := ue.TAI
	guti := ue.GUTI
	ue.Unlock()

	if emmState != emm.StateRegistered {
		metrics.PagingTotal.WithLabelValues("not_registered").Inc()
		return ErrNotRegistered
	}
	if ecmState != emm.ECMIdle {
		metrics.PagingTotal.WithLabelValues("not_idle").Inc()
		return ErrAlreadyConnected
	}
	if guti == nil {
		metrics.PagingTotal.WithLabelValues("no_identity").Inc()
		return ErrNoPagingIdentity
	}
	if tai == nil {
		metrics.PagingTotal.WithLabelValues("no_tai").Inc()
		return ErrNoPagingTAI
	}

	ue.Lock()
	alreadyPaging := ue.PagingAttempts > 0
	ue.Unlock()
	if alreadyPaging {
		return ErrAlreadyPaging
	}

	targets := s.findENBsForTAI(tai)
	if len(targets) == 0 {
		metrics.PagingTotal.WithLabelValues("no_enb").Inc()
		return ErrNoENB
	}

	log := s.log.With(
		zap.String("imsi", imsi),
		zap.String("procedure", "Paging"),
	)
	if guti != nil {
		log = log.With(zap.Uint8("mmec", guti.MMEC), zap.Uint32("mtmsi", guti.MTMSI))
	}
	if tai != nil {
		log = log.With(zap.Uint16("tac", tai.TAC))
	}

	ue.Lock()
	ue.PagingAttempts = 1
	ue.Unlock()

	log.Info("s1ap: Paging UE", zap.Int("enb_count", len(targets)), zap.Uint8("attempt", 1))

	for _, addr := range targets {
		s.sendPaging(addr, ue, log)
	}
	metrics.PagingTotal.WithLabelValues("sent").Inc()

	s.startPagingTimer(ue, 1, log)
	return nil
}

// findENBsForTAI returns remote addresses of eNBs whose SupportedTAs include the given TAI.
// Falls back to all connected eNBs if no match is found.
func (s *Server) findENBsForTAI(tai *emm.TAI) []string {
	if tai == nil {
		return s.allENBAddrs()
	}

	var matched []string
	s.enbs.Range(func(key, val any) bool {
		enb := val.(*ENBContext)
		enb.mu.Lock()
		defer enb.mu.Unlock()
		for _, sta := range enb.SupportedTAs {
			if sta.TAC != tai.TAC {
				continue
			}
			for _, bp := range sta.BroadcastPLMNs {
				plmn, err := ies.EncodePLMN(bp.MCC, bp.MNC)
				if err != nil {
					continue
				}
				if len(plmn) == 3 && plmn[0] == tai.PLMN[0] && plmn[1] == tai.PLMN[1] && plmn[2] == tai.PLMN[2] {
					matched = append(matched, enb.RemoteAddr)
					return true // one match per eNB is enough
				}
			}
		}
		return true
	})

	if len(matched) == 0 {
		return s.allENBAddrs()
	}
	return matched
}

// allENBAddrs returns remote addresses of all connected eNBs.
func (s *Server) allENBAddrs() []string {
	var addrs []string
	s.enbs.Range(func(key, _ any) bool {
		addrs = append(addrs, key.(string))
		return true
	})
	return addrs
}

// sendPaging encodes and sends one S1AP Paging PDU to a single eNB.
func (s *Server) sendPaging(enbAddr string, ue *uecontext.Context, log *zap.Logger) {
	ue.Lock()
	imsi := ue.IMSI
	guti := ue.GUTI
	tai := ue.TAI
	ue.Unlock()

	// UEIdentityIndexValue: 10-bit BIT STRING, value = IMSI%1024
	idxValue := ies.EncodeUEIdentityIndexValue(imsi)

	// UE-PagingID: CHOICE s-TMSI (MMEC + M-TMSI from GUTI)
	pagingIDValue := ies.EncodeUEPagingIDSTMSI(guti.MMEC, guti.MTMSI)
	taiListValue := ies.EncodePagingTAIList([]emm.TAI{*tai})
	if taiListValue == nil {
		log.Warn("s1ap: paging skipped because TAI list encoding failed", zap.String("enb", enbAddr))
		return
	}

	ieList := []pdu.ProtocolIE{
		{ID: pdu.IEUEIdentityIndexValue, Criticality: aper.CriticalityReject, Value: idxValue},
		{ID: pdu.IEUEPagingID, Criticality: aper.CriticalityReject, Value: pagingIDValue},
		{ID: pdu.IECNDomain, Criticality: aper.CriticalityIgnore, Value: ies.EncodeCNDomain(0)},
		{ID: pdu.IEPagingTAIList, Criticality: aper.CriticalityIgnore, Value: taiListValue},
	}
	msg := pdu.BuildInitiatingMessage(pdu.ProcPaging, aper.CriticalityIgnore, ieList)

	s.sendToAddr(enbAddr, msg)
	log.Info("s1ap: Paging sent", zap.String("enb", enbAddr))
}

// startPagingTimer schedules T3413. On expiry it retries (if attempt < maxPagingAttempts)
// or records a timeout (UE stays EMM-REGISTERED/ECM-IDLE; no auto-detach).
func (s *Server) startPagingTimer(ue *uecontext.Context, attempt uint8, log *zap.Logger) {
	ue.Lock()
	ue.StartTimer(uecontext.TimerT3413, t3413Duration, func() {
		s.onPagingTimeout(ue, attempt, log)
	})
	ue.Unlock()
}

// onPagingTimeout is called when T3413 fires. Stale detection: if PagingAttempts != attempt
// the timer is from a superseded cycle (UE responded, or a new PageUE call was made), so no-op.
func (s *Server) onPagingTimeout(ue *uecontext.Context, attempt uint8, log *zap.Logger) {
	ue.Lock()
	current := ue.PagingAttempts
	ue.Unlock()

	if current != attempt {
		// Stale timer: UE responded (PagingAttempts=0) or a new paging cycle started.
		return
	}

	if attempt < maxPagingAttempts {
		// Retry paging.
		nextAttempt := attempt + 1

		ue.Lock()
		tai := ue.TAI
		ue.PagingAttempts = nextAttempt
		ue.Unlock()

		targets := s.findENBsForTAI(tai)
		log.Info("s1ap: Paging retry", zap.Uint8("attempt", nextAttempt), zap.Int("enb_count", len(targets)))

		for _, addr := range targets {
			s.sendPaging(addr, ue, log)
		}
		metrics.PagingTotal.WithLabelValues("retry").Inc()

		s.startPagingTimer(ue, nextAttempt, log)
		return
	}

	// All attempts exhausted — record timeout. UE stays EMM-REGISTERED/ECM-IDLE.
	ue.Lock()
	ue.PagingAttempts = 0
	ue.Unlock()

	metrics.PagingTotal.WithLabelValues("timeout").Inc()
	log.Warn("s1ap: Paging timeout — UE did not respond", zap.Uint8("max_attempts", maxPagingAttempts))
}
