package s1ap

import (
	"fmt"

	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/plmn"
	"github.com/vectorcore/mme/internal/roaming"
	"github.com/vectorcore/mme/internal/s1ap/ies"
	"github.com/vectorcore/mme/internal/uecontext"
)

type roamingAdmissionError struct {
	cause uint8
	err   error
}

func (e *roamingAdmissionError) Error() string { return e.err.Error() }

// classifyRoaming performs all fallible work from immutable snapshots before
// one locked assignment. No failed classification leaves partial UE state.
func (s *Server) classifyRoaming(ue *uecontext.Context, imsi string) error {
	// Preserve construction-only unit tests and legacy embeddings that have not
	// supplied the process-wide roaming configuration. Runtime cmd/mme always
	// calls SetRoamingConfig, including when roaming is disabled.
	if !s.roamingConfigured {
		return nil
	}
	ue.Lock()
	tai := ue.TAI
	if tai != nil {
		copyTAI := *tai
		tai = &copyTAI
	}
	serving := ue.Roaming.ServingPLMN
	ue.Unlock()
	if tai == nil || serving == (plmn.PLMN{}) {
		return &roamingAdmissionError{emm.CauseUEIdentityCannotBeDerived, fmt.Errorf("roaming: serving TAI unavailable")}
	}
	local, err := plmn.New(s.nfCfg.MCC, s.nfCfg.MNC)
	if err != nil {
		return &roamingAdmissionError{emm.CauseNetworkFailure, err}
	}
	hplmn, err := roaming.ResolveHPLMN(imsi, roaming.KnownPLMNs(local, s.roamingCfg))
	if err != nil {
		return &roamingAdmissionError{emm.CauseUEIdentityCannotBeDerived, err}
	}
	decision := roaming.Evaluate(hplmn, serving, s.roamingCfg)
	if !decision.Allowed {
		// The current roaming configuration is PLMN-wide: neither enabled nor
		// the HPLMN ACL expresses a TAC-specific restriction. TS 24.301 cause
		// #14 is therefore the correct result. Cause #13 is reserved for a
		// future policy that permits roaming in this VPLMN but denies this TAI.
		return &roamingAdmissionError{emm.CauseEPSServicesNotAllowedInPLMN, fmt.Errorf("roaming: denied by %s", decision.Source)}
	}
	state := uecontext.RoamingState{HPLMN: hplmn, ServingPLMN: serving, ServingTAI: tai, IsRoaming: decision.IsRoaming, RoamingAllowed: true, RoamingDecisionSource: string(decision.Source), LogicalPGWInterface: uecontext.LogicalPGWInterfaceS5}
	if decision.IsRoaming {
		dest, ok := roaming.PlanHSSDestination(hplmn, s.roamingCfg.HSSRoutes)
		if !ok {
			return &roamingAdmissionError{emm.CauseNetworkFailure, fmt.Errorf("roaming: no HSS route for %s", hplmn)}
		}
		state.SelectedHSSRealm, state.SelectedHSSHost = dest.Realm, dest.Host
		if dest.ExplicitRealm {
			state.HSSRealmSource = "configured"
		} else {
			state.HSSRealmSource = "generated"
		}
		state.LogicalPGWInterface = uecontext.LogicalPGWInterfaceS8
	} else {
		state.SelectedHSSRealm, state.HSSRealmSource = s.nfCfg.OriginRealm, "local"
	}
	ue.Lock()
	ue.Roaming = state
	ue.Unlock()
	return nil
}

func (s *Server) routedS6aRequest(ue *uecontext.Context) (roaming.S6aRequest, bool) {
	ue.Lock()
	defer ue.Unlock()
	r := ue.Roaming
	if r.HPLMN == (plmn.PLMN{}) || r.ServingPLMN == (plmn.PLMN{}) || r.SelectedHSSRealm == "" {
		return roaming.S6aRequest{}, false
	}
	return roaming.S6aRequest{SubscriberIMSI: ue.IMSI, VisitedPLMN: r.ServingPLMN, DestinationRealm: r.SelectedHSSRealm, DestinationHost: r.SelectedHSSHost}, true
}

type routedS6aClient interface {
	SendAIRToHSS(roaming.S6aRequest, uint32) error
	SendULRToHSS(roaming.S6aRequest, uint32) error
	SendPURToHSS(roaming.S6aRequest) error
}

func (s *Server) sendAIRForUE(ue *uecontext.Context) error {
	req, ok := s.routedS6aRequest(ue)
	ue.Lock()
	id, imsi := ue.MMEUES1APID, ue.IMSI
	ue.Unlock()
	if !s.roamingConfigured {
		encoded, err := ies.EncodePLMN(s.nfCfg.MCC, s.nfCfg.MNC)
		if err != nil {
			return err
		}
		var visited [3]byte
		copy(visited[:], encoded)
		return s.s6a.SendAIR(imsi, visited, id)
	}
	if routed, okRouted := s.s6a.(routedS6aClient); ok && okRouted {
		return routed.SendAIRToHSS(req, id)
	}
	if !ok {
		return fmt.Errorf("roaming: missing verified S6a destination")
	}
	// Compatibility for existing test doubles; runtime handlers implement routedS6aClient.
	encoded, err := ies.EncodePLMN(req.VisitedPLMN.MCC, req.VisitedPLMN.MNC)
	if err != nil {
		return err
	}
	var visited [3]byte
	copy(visited[:], encoded)
	return s.s6a.SendAIR(imsi, visited, id)
}

func (s *Server) sendULRForUE(ue *uecontext.Context) error {
	req, ok := s.routedS6aRequest(ue)
	ue.Lock()
	id, imsi := ue.MMEUES1APID, ue.IMSI
	ue.Unlock()
	if !s.roamingConfigured {
		encoded, err := ies.EncodePLMN(s.nfCfg.MCC, s.nfCfg.MNC)
		if err != nil {
			return err
		}
		var visited [3]byte
		copy(visited[:], encoded)
		return s.s6a.SendULR(imsi, visited, id)
	}
	if routed, okRouted := s.s6a.(routedS6aClient); ok && okRouted {
		return routed.SendULRToHSS(req, id)
	}
	if !ok {
		return fmt.Errorf("roaming: missing verified S6a destination")
	}
	encoded, err := ies.EncodePLMN(req.VisitedPLMN.MCC, req.VisitedPLMN.MNC)
	if err != nil {
		return err
	}
	var visited [3]byte
	copy(visited[:], encoded)
	return s.s6a.SendULR(imsi, visited, id)
}

func (s *Server) sendPURForUE(ue *uecontext.Context) {
	req, ok := s.routedS6aRequest(ue)
	if routed, okRouted := s.s6a.(routedS6aClient); okRouted && ok {
		go routed.SendPURToHSS(req)
		return
	}
	if ok {
		go s.s6a.SendPUR(req.SubscriberIMSI)
	}
}
