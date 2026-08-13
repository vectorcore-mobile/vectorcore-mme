package gateway

import "testing"

func TestAccessRestrictionData_LTEMNotAllowed(t *testing.T) {
	cases := []struct {
		name string
		ard  AccessRestrictionData
		want bool
	}{
		{"bit11 set", AccessRestrictLTEM, true},
		{"bit11 clear", AccessRestrictUTRAN, false},
		{"bit11 combined with unrelated bits", AccessRestrictUTRAN | AccessRestrictLTEM, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.ard.LTEMNotAllowed(); got != tc.want {
				t.Fatalf("LTEMNotAllowed() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAccessRestrictionData_WBEUTRANExceptLTEMNotAllowed(t *testing.T) {
	cases := []struct {
		name string
		ard  AccessRestrictionData
		want bool
	}{
		{"bit12 set", AccessRestrictWBEUTRANExceptLTEM, true},
		{"bit12 clear", AccessRestrictLTEM, false},
		{"bit12 combined with unrelated bits", AccessRestrictGERAN | AccessRestrictWBEUTRANExceptLTEM, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.ard.WBEUTRANExceptLTEMNotAllowed(); got != tc.want {
				t.Fatalf("WBEUTRANExceptLTEMNotAllowed() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAccessRestrictionData_NRIn5GSNotAllowed(t *testing.T) {
	if !AccessRestrictNRIn5GS.NRIn5GSNotAllowed() {
		t.Fatal("NRIn5GSNotAllowed() = false, want true for AccessRestrictNRIn5GS")
	}
	if AccessRestrictLTEM.NRIn5GSNotAllowed() {
		t.Fatal("NRIn5GSNotAllowed() = true, want false for unrelated bit")
	}
}

// TestAccessRestrictionData_BitPositionsMatchSpec pins the exact numeric
// values from TS 29.272 §7.3.31 so a future refactor can't silently shift a
// bit position.
func TestAccessRestrictionData_BitPositionsMatchSpec(t *testing.T) {
	cases := []struct {
		name string
		got  AccessRestrictionData
		want uint32
	}{
		{"NRIn5GS", AccessRestrictNRIn5GS, 0x00000400},
		{"LTEM", AccessRestrictLTEM, 0x00000800},
		{"WBEUTRANExceptLTEM", AccessRestrictWBEUTRANExceptLTEM, 0x00001000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if uint32(tc.got) != tc.want {
				t.Fatalf("%s = 0x%08x, want 0x%08x", tc.name, uint32(tc.got), tc.want)
			}
		})
	}
}
