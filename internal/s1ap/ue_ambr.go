package s1ap

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/uecontext"
)

type effectiveUEAMBRPDN struct {
	APN        string
	DefaultEBI uint8
	State      string
	Downlink   uint64
	Uplink     uint64
	Pending    bool
}

type effectiveUEAMBRResult struct {
	SubscribedDownlink uint64
	SubscribedUplink   uint64
	SumDownlink        uint64
	SumUplink          uint64
	Downlink           uint64
	Uplink             uint64
	PDNs               []effectiveUEAMBRPDN
	Fallback           string
}

// effectiveUEAMBR derives the S1AP aggregate bitrate from the PDNs currently
// participating in EPS service, plus any PDNs being established by the
// procedure under construction. All rates are bits/s.
func effectiveUEAMBR(ue *uecontext.Context, additional ...*uecontext.PDNContext) effectiveUEAMBRResult {
	result := effectiveUEAMBRResult{}
	if ue == nil {
		return result
	}
	ue.Lock()
	result.SubscribedDownlink = uint64(ue.UEAMBRDown)
	result.SubscribedUplink = uint64(ue.UEAMBRUp)
	seen := map[string]struct{}{}
	include := func(pdn *uecontext.PDNContext, pending bool) {
		if pdn == nil || !pdnCountsTowardUEAMBR(pdn.State) {
			return
		}
		key := fmt.Sprintf("%s|%d|%d", strings.ToLower(pdn.APN), pdn.DefaultEBI, pdn.LocalS11TEID)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		entry := effectiveUEAMBRPDN{APN: strings.ToLower(pdn.APN), DefaultEBI: pdn.DefaultEBI, State: pdn.State, Downlink: uint64(pdn.APNAMBRDown), Uplink: uint64(pdn.APNAMBRUp), Pending: pending}
		result.PDNs = append(result.PDNs, entry)
		result.SumDownlink = saturatingAdd(result.SumDownlink, entry.Downlink)
		result.SumUplink = saturatingAdd(result.SumUplink, entry.Uplink)
	}
	for _, pdn := range ue.PDNs {
		include(pdn, false)
	}
	include(ue.PendingPDN, true)
	for _, pdn := range additional {
		include(pdn, true)
	}
	ue.Unlock()

	sort.Slice(result.PDNs, func(i, j int) bool {
		if result.PDNs[i].APN == result.PDNs[j].APN {
			return result.PDNs[i].DefaultEBI < result.PDNs[j].DefaultEBI
		}
		return result.PDNs[i].APN < result.PDNs[j].APN
	})
	result.Downlink = effectiveUEAMBRDirection(result.SubscribedDownlink, result.SumDownlink)
	result.Uplink = effectiveUEAMBRDirection(result.SubscribedUplink, result.SumUplink)
	if result.SumDownlink == 0 && result.SumUplink == 0 {
		result.Fallback = "no-applicable-apn-ambr; subscribed-ue-ambr"
	} else if result.SubscribedDownlink == 0 || result.SubscribedUplink == 0 {
		result.Fallback = "missing-subscribed-direction; applicable-apn-ambr"
	} else {
		result.Fallback = "applicable-apn-ambr-capped-by-subscribed-ue-ambr"
	}
	return result
}

func pdnCountsTowardUEAMBR(state string) bool {
	state = strings.ToLower(state)
	for _, excluded := range []string{"delet", "disconnect", "failed", "rejected", "timeout", "cleanup"} {
		if strings.Contains(state, excluded) {
			return false
		}
	}
	return true
}

func effectiveUEAMBRDirection(subscribed, sum uint64) uint64 {
	if sum == 0 {
		return subscribed
	}
	if subscribed == 0 || sum < subscribed {
		return sum
	}
	return subscribed
}

func saturatingAdd(a, b uint64) uint64 {
	if math.MaxUint64-a < b {
		return math.MaxUint64
	}
	return a + b
}

func (s *Server) logEffectiveUEAMBR(ue *uecontext.Context, procedure string, additional ...*uecontext.PDNContext) effectiveUEAMBRResult {
	result := effectiveUEAMBR(ue, additional...)
	included := make([]string, 0, len(result.PDNs))
	for _, pdn := range result.PDNs {
		origin := "existing"
		if pdn.Pending {
			origin = "procedure-pending"
		}
		included = append(included, fmt.Sprintf("%s:ebi%d:%s:%s", pdn.APN, pdn.DefaultEBI, pdn.State, origin))
	}
	if s != nil && s.log != nil {
		s.log.Debug("s1ap: effective UE-AMBR calculated",
			zap.String("procedure", procedure),
			zap.Uint64("subscribed_dl", result.SubscribedDownlink),
			zap.Uint64("subscribed_ul", result.SubscribedUplink),
			zap.Strings("included_pdns", included),
			zap.Uint64("sum_apn_dl", result.SumDownlink),
			zap.Uint64("sum_apn_ul", result.SumUplink),
			zap.Uint64("effective_dl", result.Downlink),
			zap.Uint64("effective_ul", result.Uplink),
			zap.Bool("capped_dl", result.SubscribedDownlink != 0 && result.SumDownlink > result.SubscribedDownlink),
			zap.Bool("capped_ul", result.SubscribedUplink != 0 && result.SumUplink > result.SubscribedUplink),
			zap.String("fallback", result.Fallback))
	}
	return result
}
