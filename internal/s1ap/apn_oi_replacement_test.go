package s1ap

import "testing"

func TestEffectiveAPNOIReplacement_PerAPNTakesPriority(t *testing.T) {
	got := effectiveAPNOIReplacement("per-apn.example.net", "ue-level.example.net")
	if got != "per-apn.example.net" {
		t.Fatalf("got %q, want %q", got, "per-apn.example.net")
	}
}

func TestEffectiveAPNOIReplacement_FallsBackToUELevel(t *testing.T) {
	got := effectiveAPNOIReplacement("", "ue-level.example.net")
	if got != "ue-level.example.net" {
		t.Fatalf("got %q, want %q", got, "ue-level.example.net")
	}
}

func TestEffectiveAPNOIReplacement_BothEmpty(t *testing.T) {
	got := effectiveAPNOIReplacement("", "")
	if got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}
