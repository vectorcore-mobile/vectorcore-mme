package ies

import "testing"

func TestDecodeS1APPLMNThreeDigitMNC(t *testing.T) {
	mcc, mnc, err := DecodePLMN([]byte{0x13, 0x41, 0x53})
	if err != nil || mcc != "311" || mnc != "435" {
		t.Fatalf("PLMN 134153 = %q/%q err=%v", mcc, mnc, err)
	}
	if _, _, err := DecodePLMN([]byte{0xfa, 0x41, 0x53}); err == nil {
		t.Fatal("invalid S1AP PLMN digit accepted")
	}
}

func TestCauseAPEREncodeDecodeRadioNetworkUserInactivity(t *testing.T) {
	encoded := EncodeCause(CauseGroupRadioNetwork, CauseRadioNetworkUserInactivity)
	group, value, err := DecodeCause(encoded)
	if err != nil {
		t.Fatalf("DecodeCause: %v", err)
	}
	if group != CauseGroupRadioNetwork || value != CauseRadioNetworkUserInactivity {
		t.Fatalf("cause: got group=%d value=%d encoded=%x", group, value, encoded)
	}
	if got := CauseName(group, value); got != "user-inactivity" {
		t.Fatalf("CauseName: got %q", got)
	}
}

func TestCauseDecodeShiftedSrsRANRadioNetworkValues(t *testing.T) {
	for _, tc := range []struct {
		raw  []byte
		want uint8
		name string
	}{
		{[]byte{0x00, 0xa0}, 20, "user-inactivity"},
		{[]byte{0x00, 0xe0}, 28, "interrat-redirection"},
	} {
		group, value, err := DecodeCause(tc.raw)
		if err != nil {
			t.Fatalf("DecodeCause(%x): %v", tc.raw, err)
		}
		if group != CauseGroupRadioNetwork || value != tc.want {
			t.Fatalf("DecodeCause(%x): got group=%d value=%d, want radioNetwork/%d", tc.raw, group, value, tc.want)
		}
		if got := CauseName(group, value); got != tc.name {
			t.Fatalf("CauseName(%x): got %q, want %q", tc.raw, got, tc.name)
		}
	}
}
