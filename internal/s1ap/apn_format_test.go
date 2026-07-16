package s1ap

import (
	"testing"

	"github.com/vectorcore/mme/internal/config"
)

func TestAPNForNASPreservesIMSServiceSelection(t *testing.T) {
	srv := &Server{nfCfg: config.NFConfig{MCC: "311", MNC: "435"}}
	if got, want := srv.apnForNAS("ims"), "ims"; got != want {
		t.Fatalf("apnForNAS() = %q, want %q", got, want)
	}
}

func TestAPNForNASPreservesQualifiedAPN(t *testing.T) {
	srv := &Server{nfCfg: config.NFConfig{MCC: "311", MNC: "435"}}
	if got, want := srv.apnForNAS("ims.mnc435.mcc311.gprs"), "ims.mnc435.mcc311.gprs"; got != want {
		t.Fatalf("apnForNAS() = %q, want %q", got, want)
	}
}

func TestAPNForNASPreservesServiceSelectionAPNs(t *testing.T) {
	srv := &Server{nfCfg: config.NFConfig{MCC: "311", MNC: "435"}}
	if got, want := srv.apnForNAS("internet"), "internet"; got != want {
		t.Fatalf("apnForNAS() = %q, want %q", got, want)
	}
}

func TestAPNForNASPreservesOriginalCase(t *testing.T) {
	srv := &Server{nfCfg: config.NFConfig{MCC: "311", MNC: "435"}}
	if got, want := srv.apnForNAS("IMS"), "IMS"; got != want {
		t.Fatalf("apnForNAS() = %q, want %q", got, want)
	}
}
