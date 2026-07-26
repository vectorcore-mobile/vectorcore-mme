package roaming

import (
	"errors"
	"sync"
	"testing"

	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/plmn"
)

func mustPLMN(t *testing.T, mcc, mnc string) plmn.PLMN {
	t.Helper()
	p, err := plmn.New(mcc, mnc)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestResolveHPLMN(t *testing.T) {
	local := mustPLMN(t, "311", "435")
	foreign := mustPLMN(t, "310", "260")
	twoDigit := mustPLMN(t, "001", "01")
	known := []plmn.PLMN{local, foreign, twoDigit}
	for _, tc := range []struct {
		imsi string
		want plmn.PLMN
	}{{"311435300070580", local}, {"310260123456789", foreign}, {"001010123456789", twoDigit}} {
		got, err := ResolveHPLMN(tc.imsi, known)
		if err != nil || got != tc.want {
			t.Fatalf("ResolveHPLMN(%q) = %v, %v; want %v", tc.imsi, got, err, tc.want)
		}
	}
	if _, err := ResolveHPLMN("999990123456789", known); !errors.Is(err, ErrUnresolvedHPLMN) {
		t.Fatalf("unresolved error = %v", err)
	}
	if _, err := ResolveHPLMN("001010123456789", []plmn.PLMN{twoDigit, mustPLMN(t, "001", "010")}); !errors.Is(err, ErrAmbiguousHPLMN) {
		t.Fatalf("ambiguous error = %v", err)
	}
}

func TestEvaluate(t *testing.T) {
	home := mustPLMN(t, "311", "435")
	foreign := mustPLMN(t, "310", "260")
	base := config.RoamingConfig{Policy: config.RoamingPolicyConfig{DefaultAction: config.RoamingActionDeny}}
	if d := Evaluate(home, home, base); !d.Allowed || d.Source != DecisionHome {
		t.Fatalf("home disabled = %+v", d)
	}
	if d := Evaluate(foreign, home, base); d.Allowed || d.Source != DecisionDisabled {
		t.Fatalf("foreign disabled = %+v", d)
	}
	base.Enabled = true
	base.Policy.PLMNACL = []config.RoamingPLMNACLRule{{PLMN: foreign, Action: config.RoamingActionAllow}}
	if d := Evaluate(foreign, home, base); !d.Allowed || d.Source != DecisionExplicitAllow || d.MatchedACLRule == nil {
		t.Fatalf("explicit allow = %+v", d)
	}
	base.Policy.DefaultAction = config.RoamingActionAllow
	base.Policy.PLMNACL[0].Action = config.RoamingActionDeny
	if d := Evaluate(foreign, home, base); d.Allowed || d.Source != DecisionExplicitDeny {
		t.Fatalf("explicit deny = %+v", d)
	}
	base.Policy.PLMNACL = nil
	if d := Evaluate(foreign, home, base); !d.Allowed || d.Source != DecisionDefaultAllow {
		t.Fatalf("default allow = %+v", d)
	}
	base.Policy.DefaultAction = config.RoamingActionDeny
	if d := Evaluate(foreign, home, base); d.Allowed || d.Source != DecisionDefaultDeny {
		t.Fatalf("default deny = %+v", d)
	}
}

func TestHSSRoutesDoNotAuthorizeAndPlan(t *testing.T) {
	p := mustPLMN(t, "001", "01")
	cfg := config.RoamingConfig{Enabled: true, Policy: config.RoamingPolicyConfig{DefaultAction: config.RoamingActionDeny}, HSSRoutes: []config.HSSRouteConfig{{PLMN: p, Host: "hss.example"}}}
	if d := Evaluate(p, mustPLMN(t, "311", "435"), cfg); d.Allowed {
		t.Fatalf("route authorized roaming: %+v", d)
	}
	d, ok := PlanHSSDestination(p, cfg.HSSRoutes)
	if !ok || d.Realm != "epc.mnc001.mcc001.3gppnetwork.org" || d.Host != "hss.example" || d.ExplicitRealm {
		t.Fatalf("generated route = %+v, %v", d, ok)
	}
	explicit := mustPLMN(t, "310", "260")
	d, ok = PlanHSSDestination(explicit, []config.HSSRouteConfig{{PLMN: explicit, Realm: "example.realm", Host: "hss.example"}})
	if !ok || d.Realm != "example.realm" || d.Host != "hss.example" || !d.ExplicitRealm {
		t.Fatalf("explicit route = %+v, %v", d, ok)
	}
	if got := GeneratedRealm(mustPLMN(t, "311", "435")); got != "epc.mnc435.mcc311.3gppnetwork.org" {
		t.Fatalf("realm = %q", got)
	}
}

func TestEvaluateIndependentAndRaceFree(t *testing.T) {
	home, foreign := mustPLMN(t, "311", "435"), mustPLMN(t, "310", "260")
	cfg := config.RoamingConfig{Enabled: true, Policy: config.RoamingPolicyConfig{DefaultAction: config.RoamingActionDeny, PLMNACL: []config.RoamingPLMNACLRule{{PLMN: foreign, Action: config.RoamingActionAllow}}}}
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := Evaluate(foreign, home, cfg)
			if !d.Allowed || d.MatchedACLRule == nil {
				t.Errorf("decision = %+v", d)
				return
			}
			d.MatchedACLRule.Action = config.RoamingActionDeny
		}()
	}
	wg.Wait()
	if cfg.Policy.PLMNACL[0].Action != config.RoamingActionAllow {
		t.Fatal("evaluation mutated config")
	}
}
