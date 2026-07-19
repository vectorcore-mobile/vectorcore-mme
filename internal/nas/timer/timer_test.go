package timer_test

import (
	"testing"

	nastimer "github.com/vectorcore/mme/internal/nas/timer"
)

func TestEncodeGPRSTimer(t *testing.T) {
	tests := []struct {
		name string
		sec  int
		want byte
	}{
		{name: "2 second unit", sec: 60, want: 0x1e},
		{name: "1 minute unit", sec: 720, want: 0x2c},
		{name: "6 minute unit", sec: 3240, want: 0x49},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := nastimer.EncodeGPRSTimer(tt.sec)
			if err != nil {
				t.Fatalf("EncodeGPRSTimer(%d) error = %v", tt.sec, err)
			}
			if got != tt.want {
				t.Fatalf("EncodeGPRSTimer(%d) = %#x, want %#x", tt.sec, got, tt.want)
			}
		})
	}
}

func TestEncodeGPRSTimerInvalid(t *testing.T) {
	if _, err := nastimer.EncodeGPRSTimer(61); err == nil {
		t.Fatal("EncodeGPRSTimer(61) expected error")
	}
}

func TestEncodeGPRSTimer3(t *testing.T) {
	got, err := nastimer.EncodeGPRSTimer3(720)
	if err != nil {
		t.Fatalf("EncodeGPRSTimer3(720) error = %v", err)
	}
	if got != 0x38 {
		t.Fatalf("EncodeGPRSTimer3(720) = %#x, want 0x38", got)
	}
}
