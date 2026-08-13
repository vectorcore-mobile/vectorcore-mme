package s1ap

// S1 Setup topology helpers deliberately compare canonical MCC/MNC strings
// and TAC together.  S1AP PLMN identities and NAS PLMN values use different
// octet ordering, so routing/admission must not compare their raw bytes.

import (
	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/s1ap/ies"
)

func (s *Server) servesTAI(mcc, mnc string, tac uint16) bool {
	if len(s.nfCfg.TAIList) == 0 {
		// Older minimal configurations have no explicit served-TA list.  They
		// still must not accept an unrelated PLMN, but retain their historical
		// TAC-permissive behaviour until tai_list is configured.
		return mcc == s.nfCfg.MCC && mnc == s.nfCfg.MNC
	}
	for _, served := range s.nfCfg.TAIList {
		if served.MCC == mcc && served.MNC == mnc && served.TAC == tac {
			return true
		}
	}
	return false
}

// isNBIoTTAI reports whether the given TAI is configured as NB-IoT-designated
// (config.TAIItem.RAT == config.TAIRatNBIoT). Per TS 23.401, a Tracking Area
// never mixes WB-E-UTRAN and NB-IoT cells, so this is how the MME determines
// a UE's RAT from the TAI in its Initial UE Message — see
// applyS1APLocationToUELocked, which sets ue.IsNBIoT from this.
func (s *Server) isNBIoTTAI(mcc, mnc string, tac uint16) bool {
	for _, served := range s.nfCfg.TAIList {
		if served.MCC == mcc && served.MNC == mnc && served.TAC == tac {
			return served.RAT == config.TAIRatNBIoT
		}
	}
	return false
}

// acceptedSupportedTAs returns the served intersection without changing the
// eNB's advertised topology.  A network-sharing eNB can have a Global eNB ID
// PLMN different from a Broadcast PLMN; admission is therefore based only on
// Broadcast PLMN + TAC combinations.
func (s *Server) acceptedSupportedTAs(advertised []SupportedTA) []SupportedTA {
	accepted := make([]SupportedTA, 0, len(advertised))
	for _, ta := range advertised {
		out := SupportedTA{TAC: ta.TAC}
		for _, plmn := range ta.BroadcastPLMNs {
			if s.servesTAI(plmn.MCC, plmn.MNC, ta.TAC) {
				out.BroadcastPLMNs = append(out.BroadcastPLMNs, plmn)
			}
		}
		if len(out.BroadcastPLMNs) != 0 {
			accepted = append(accepted, out)
		}
	}
	return accepted
}

func supportsTAI(topology []SupportedTA, mcc, mnc string, tac uint16) bool {
	for _, ta := range topology {
		if ta.TAC != tac {
			continue
		}
		for _, plmn := range ta.BroadcastPLMNs {
			if plmn.MCC == mcc && plmn.MNC == mnc {
				return true
			}
		}
	}
	return false
}

// effectiveRoutingTAs is called while enb.mu is held.  Live S1 Setup always
// populates AcceptedTAs; the fallback is solely for pre-existing manually
// constructed contexts and preserves their historic test/administrative use.
func effectiveRoutingTAs(enb *ENBContext) []SupportedTA {
	if len(enb.AcceptedTAs) != 0 {
		return enb.AcceptedTAs
	}
	return enb.SupportedTAs
}

// validateInitialUETopology confirms that the received TAI and ECGI belong to
// both this MME's served topology and the particular eNB's accepted topology.
// The returned reason separates an unserved PLMN (CauseMisc unknown-PLMN) from
// a logical inconsistency with an otherwise served eNB association.
func (s *Server) validateInitialUETopology(remote string, tai *ies.TAI, ecgi *ies.ECGI) (served bool, ok bool) {
	if tai == nil || ecgi == nil {
		return false, false
	}
	value, found := s.enbs.Load(remote)
	if !found {
		// Normal dispatch rejects Initial UE Message before S1 Setup.  Keeping
		// this helper topology-neutral when invoked directly also avoids making
		// test-only handler calls look like a live association.
		return true, true
	}
	enb := value.(*ENBContext)
	enb.mu.Lock()
	setupComplete := enb.SetupComplete
	accepted := append([]SupportedTA(nil), enb.AcceptedTAs...)
	enb.mu.Unlock()
	if len(accepted) == 0 {
		// Only a successfully decoded S1 Setup populates AcceptedTAs. This
		// keeps direct unit-handler invocations from claiming a live topology.
		return true, true
	}
	if !s.servesTAI(tai.MCC, tai.MNC, tai.TAC) || !s.servesTAI(ecgi.MCC, ecgi.MNC, tai.TAC) {
		return false, false
	}
	return true, setupComplete && supportsTAI(accepted, tai.MCC, tai.MNC, tai.TAC) && supportsTAI(accepted, ecgi.MCC, ecgi.MNC, tai.TAC)
}

func topologySummary(tas []SupportedTA) []config.TAIItem {
	items := make([]config.TAIItem, 0)
	for _, ta := range tas {
		for _, plmn := range ta.BroadcastPLMNs {
			items = append(items, config.TAIItem{MCC: plmn.MCC, MNC: plmn.MNC, TAC: ta.TAC})
		}
	}
	return items
}
