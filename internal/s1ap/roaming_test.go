package s1ap

import (
	"errors"
	"testing"

	"go.uber.org/zap"

	"github.com/vectorcore/mme/internal/config"
	"github.com/vectorcore/mme/internal/nas/emm"
	"github.com/vectorcore/mme/internal/plmn"
	"github.com/vectorcore/mme/internal/uecontext"
)

func roamingTAI(t *testing.T, mcc, mnc string) *emm.TAI {
	t.Helper()
	b, err := encodeNASPLMN(mcc, mnc)
	if err != nil {
		t.Fatal(err)
	}
	return &emm.TAI{PLMN: b, TAC: 1}
}

func TestClassifyRoamingAtomicAndRoutesHSS(t *testing.T) {
	s := &Server{nfCfg: config.NFConfig{MCC: "311", MNC: "435", OriginRealm: "epc.mnc435.mcc311.3gppnetwork.org"}, roamingConfigured: true, roamingCfg: config.RoamingConfig{Enabled: true, Policy: config.RoamingPolicyConfig{DefaultAction: config.RoamingActionDeny, PLMNACL: []config.RoamingPLMNACLRule{{PLMN: plmn.PLMN{MCC: "310", MNC: "260"}, Action: config.RoamingActionAllow}}}, HSSRoutes: []config.HSSRouteConfig{{PLMN: plmn.PLMN{MCC: "310", MNC: "260"}, Host: "hss01.example"}}}, log: zap.NewNop()}
	ue := uecontext.NewContext(1)
	ue.TAI = roamingTAI(t, "311", "435")
	ue.Roaming.ServingPLMN = plmn.PLMN{MCC: "311", MNC: "435"}
	if err := s.classifyRoaming(ue, "310260123456789"); err != nil {
		t.Fatal(err)
	}
	ue.Lock()
	got := ue.Roaming
	ue.Unlock()
	if !got.IsRoaming || !got.RoamingAllowed || got.HPLMN != (plmn.PLMN{MCC: "310", MNC: "260"}) || got.ServingPLMN != (plmn.PLMN{MCC: "311", MNC: "435"}) || got.SelectedHSSRealm != "epc.mnc260.mcc310.3gppnetwork.org" || got.SelectedHSSHost != "hss01.example" || got.HSSRealmSource != "generated" {
		t.Fatalf("state = %+v", got)
	}
	before := got
	if err := s.classifyRoaming(ue, "999990123456789"); err == nil {
		t.Fatal("unresolved HPLMN accepted")
	}
	ue.Lock()
	after := ue.Roaming
	ue.Unlock()
	if after != before {
		t.Fatalf("failed classification mutated state: before=%+v after=%+v", before, after)
	}
}

func TestClassifyRoamingRejectsDisabledForeignAndAllowsHome(t *testing.T) {
	s := &Server{nfCfg: config.NFConfig{MCC: "311", MNC: "435", OriginRealm: "local.realm"}, roamingConfigured: true, roamingCfg: config.RoamingConfig{Policy: config.RoamingPolicyConfig{DefaultAction: config.RoamingActionDeny}, HSSRoutes: []config.HSSRouteConfig{{PLMN: plmn.PLMN{MCC: "310", MNC: "260"}}}}}
	foreign := uecontext.NewContext(1)
	foreign.TAI = roamingTAI(t, "311", "435")
	foreign.Roaming.ServingPLMN = plmn.PLMN{MCC: "311", MNC: "435"}
	err := s.classifyRoaming(foreign, "310260123456789")
	var admission *roamingAdmissionError
	if !errors.As(err, &admission) || admission.cause != emm.CauseEPSServicesNotAllowedInPLMN {
		t.Fatalf("disabled foreign error = %v", err)
	}
	foreign.Lock()
	if foreign.Roaming.HPLMN != (plmn.PLMN{}) || foreign.Roaming.RoamingAllowed || foreign.Roaming.SelectedHSSRealm != "" {
		t.Fatalf("denial populated classification state: %+v", foreign.Roaming)
	}
	foreign.Unlock()
	home := uecontext.NewContext(2)
	home.TAI = roamingTAI(t, "311", "435")
	home.Roaming.ServingPLMN = plmn.PLMN{MCC: "311", MNC: "435"}
	if err := s.classifyRoaming(home, "311435123456789"); err != nil {
		t.Fatalf("home disabled = %v", err)
	}
}
