// Package roaming contains pure Phase 1 roaming foundation logic. It does not
// select Diameter peers or transmit S6a messages.
package roaming

import (
	"errors"
	"fmt"

	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/plmn"
)

var (
	ErrUnresolvedHPLMN = errors.New("roaming: unresolved HPLMN")
	ErrAmbiguousHPLMN  = errors.New("roaming: ambiguous HPLMN")
)

type DecisionSource string

const (
	DecisionHome          DecisionSource = "home"
	DecisionDisabled      DecisionSource = "disabled"
	DecisionExplicitAllow DecisionSource = "explicit-allow"
	DecisionExplicitDeny  DecisionSource = "explicit-deny"
	DecisionDefaultAllow  DecisionSource = "default-allow"
	DecisionDefaultDeny   DecisionSource = "default-deny"
)

// ResolveHPLMN resolves an IMSI only against supplied known PLMNs. Callers can
// append a future in-memory E.212 source to that set without changing policy.
func ResolveHPLMN(imsi string, known []plmn.PLMN) (plmn.PLMN, error) {
	if !plmn.IsIMSI(imsi) {
		return plmn.PLMN{}, fmt.Errorf("%w: invalid IMSI %q", ErrUnresolvedHPLMN, imsi)
	}
	var matches []plmn.PLMN
	seen := make(map[plmn.PLMN]struct{}, len(known))
	for _, candidate := range known {
		if candidate.Validate() != nil {
			continue
		}
		if _, duplicate := seen[candidate]; duplicate {
			continue
		}
		seen[candidate] = struct{}{}
		if len(imsi) >= len(candidate.IMSIPrefix()) && imsi[:len(candidate.IMSIPrefix())] == candidate.IMSIPrefix() {
			matches = append(matches, candidate)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return plmn.PLMN{}, fmt.Errorf("%w for IMSI %q", ErrUnresolvedHPLMN, imsi)
	default:
		return plmn.PLMN{}, fmt.Errorf("%w for IMSI %q: %v", ErrAmbiguousHPLMN, imsi, matches)
	}
}

// KnownPLMNs returns the Phase 1 configured HPLMN sources. Routes identify a
// destination only; including them here does not authorize roaming.
func KnownPLMNs(local plmn.PLMN, cfg config.RoamingConfig) []plmn.PLMN {
	known := []plmn.PLMN{local}
	for _, rule := range cfg.Policy.PLMNACL {
		known = append(known, rule.PLMN)
	}
	for _, route := range cfg.HSSRoutes {
		known = append(known, route.PLMN)
	}
	return known
}

type Decision struct {
	HPLMN          plmn.PLMN
	ServingPLMN    plmn.PLMN
	IsRoaming      bool
	Enabled        bool
	Allowed        bool
	Source         DecisionSource
	MatchedACLRule *config.RoamingPLMNACLRule
}

// Evaluate classifies a subscriber and applies ACL policy against the HPLMN.
func Evaluate(hplmn, serving plmn.PLMN, cfg config.RoamingConfig) Decision {
	d := Decision{HPLMN: hplmn, ServingPLMN: serving, Enabled: cfg.Enabled, IsRoaming: hplmn != serving}
	if !d.IsRoaming {
		d.Allowed, d.Source = true, DecisionHome
		return d
	}
	if !cfg.Enabled {
		d.Allowed, d.Source = false, DecisionDisabled
		return d
	}
	for _, rule := range cfg.Policy.PLMNACL {
		if rule.PLMN != hplmn {
			continue
		}
		match := rule // return a copy so evaluations cannot mutate configuration.
		d.MatchedACLRule = &match
		if rule.Action == config.RoamingActionAllow {
			d.Allowed, d.Source = true, DecisionExplicitAllow
		} else {
			d.Allowed, d.Source = false, DecisionExplicitDeny
		}
		return d
	}
	if cfg.Policy.DefaultAction == config.RoamingActionAllow {
		d.Allowed, d.Source = true, DecisionDefaultAllow
	} else {
		d.Allowed, d.Source = false, DecisionDefaultDeny
	}
	return d
}

type HSSDestination struct {
	HPLMN         plmn.PLMN
	Realm         string
	Host          string
	ExplicitRealm bool
}

// S6aRequest keeps the subscriber, serving PLMN, and HSS destination
// separate at the S6a boundary. The PLMN is typed until the Diameter builder
// encodes the Visited-PLMN-Id AVP.
type S6aRequest struct {
	SubscriberIMSI   string
	VisitedPLMN      plmn.PLMN
	DestinationRealm string
	DestinationHost  string
}

// PlanHSSDestination selects only an exact HPLMN route. It is deliberately
// separate from authorization and is not wired into AIR/ULR in Phase 1.
func PlanHSSDestination(hplmn plmn.PLMN, routes []config.HSSRouteConfig) (HSSDestination, bool) {
	for _, route := range routes {
		if route.PLMN != hplmn {
			continue
		}
		realm := route.Realm
		explicit := realm != ""
		if !explicit {
			realm = GeneratedRealm(hplmn)
		}
		return HSSDestination{HPLMN: hplmn, Realm: realm, Host: route.Host, ExplicitRealm: explicit}, true
	}
	return HSSDestination{}, false
}

func GeneratedRealm(p plmn.PLMN) string {
	mnc := p.MNC
	if len(mnc) == 2 {
		mnc = "0" + mnc
	}
	return fmt.Sprintf("epc.mnc%s.mcc%s.3gppnetwork.org", mnc, p.MCC)
}
