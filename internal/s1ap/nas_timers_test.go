package s1ap

import (
	"testing"

	"github.com/vectorcore/mme/internal/nas/timer"
)

func TestNasEMMTimers_UsesSubscribedT3412WhenNotRoaming(t *testing.T) {
	srv := newTestServer(nil)
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.SubscribedPeriodicRAUTAUTimer = 600
	ue.Unlock()

	t3412, _, _, err := srv.nasEMMTimers(ue)
	if err != nil {
		t.Fatalf("nasEMMTimers: %v", err)
	}
	if got := timer.DecodeGPRSTimer(t3412); got != 600 {
		t.Fatalf("T3412 got %d seconds, want 600 (subscribed value)", got)
	}
}

func TestNasEMMTimers_IgnoresSubscribedT3412WhenRoaming(t *testing.T) {
	srv := newTestServer(nil)
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.SubscribedPeriodicRAUTAUTimer = 600
	ue.Roaming.IsRoaming = true
	ue.Unlock()

	t3412, _, _, err := srv.nasEMMTimers(ue)
	if err != nil {
		t.Fatalf("nasEMMTimers: %v", err)
	}
	if got, want := timer.DecodeGPRSTimer(t3412), timer.DefaultT3412; got != want {
		t.Fatalf("T3412 got %d seconds, want %d (configured default, roaming UE)", got, want)
	}
}

func TestNasEMMTimers_FallsBackWhenSubscribedValueNotEncodable(t *testing.T) {
	srv := newTestServer(nil)
	ue := srv.ueManager.Allocate()
	ue.Lock()
	ue.SubscribedPeriodicRAUTAUTimer = 601 // not a multiple of any valid GPRS-timer granularity
	ue.Unlock()

	t3412, _, _, err := srv.nasEMMTimers(ue)
	if err != nil {
		t.Fatalf("nasEMMTimers: %v", err)
	}
	if got, want := timer.DecodeGPRSTimer(t3412), timer.DefaultT3412; got != want {
		t.Fatalf("T3412 got %d seconds, want %d (configured default, unencodable subscribed value)", got, want)
	}
}

func TestNasEMMTimers_UsesConfiguredDefaultWhenNoSubscribedValue(t *testing.T) {
	srv := newTestServer(nil)
	ue := srv.ueManager.Allocate()

	t3412, _, _, err := srv.nasEMMTimers(ue)
	if err != nil {
		t.Fatalf("nasEMMTimers: %v", err)
	}
	if got, want := timer.DecodeGPRSTimer(t3412), timer.DefaultT3412; got != want {
		t.Fatalf("T3412 got %d seconds, want %d (configured default)", got, want)
	}
}
