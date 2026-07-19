package emm

import "testing"

func TestEncodeDecodeTAIListSamePLMNConsecutive(t *testing.T) {
	tais := []TAI{
		{PLMN: [3]byte{0x13, 0x51, 0x34}, TAC: 0x0102},
		{PLMN: [3]byte{0x13, 0x51, 0x34}, TAC: 0x0103},
		{PLMN: [3]byte{0x13, 0x51, 0x34}, TAC: 0x0104},
	}

	got := encodeTAIList(tais)
	if len(got) != 6 {
		t.Fatalf("encoded len got %d want 6", len(got))
	}
	if listType := got[0] >> 5; listType != taiListTypeOnePLMNConsecutive {
		t.Fatalf("list type got %d want %d", listType, taiListTypeOnePLMNConsecutive)
	}

	decoded, err := decodeTAIList(got)
	if err != nil {
		t.Fatalf("decodeTAIList: %v", err)
	}
	if len(decoded) != len(tais) {
		t.Fatalf("decoded len got %d want %d", len(decoded), len(tais))
	}
	for i := range tais {
		if decoded[i] != tais[i] {
			t.Fatalf("decoded[%d] got %+v want %+v", i, decoded[i], tais[i])
		}
	}
}

func TestEncodeDecodeTAIListMixedPLMNs(t *testing.T) {
	tais := []TAI{
		{PLMN: [3]byte{0x13, 0x51, 0x34}, TAC: 0x0102},
		{PLMN: [3]byte{0x13, 0x51, 0x34}, TAC: 0x0204},
		{PLMN: [3]byte{0x00, 0xF1, 0x10}, TAC: 0x0001},
		{PLMN: [3]byte{0x00, 0xF1, 0x10}, TAC: 0x0002},
		{PLMN: [3]byte{0x02, 0xF8, 0x39}, TAC: 0x1000},
	}

	got := encodeTAIList(tais)
	decoded, err := decodeTAIList(got)
	if err != nil {
		t.Fatalf("decodeTAIList: %v", err)
	}
	if len(decoded) != len(tais) {
		t.Fatalf("decoded len got %d want %d", len(decoded), len(tais))
	}
	for i := range tais {
		if decoded[i] != tais[i] {
			t.Fatalf("decoded[%d] got %+v want %+v", i, decoded[i], tais[i])
		}
	}
}

func TestDecodeTAIListTypeDifferentPLMNs(t *testing.T) {
	encoded := []byte{
		byte(taiListTypeDifferentPLMNs<<5) | 0x01,
		0x13, 0x51, 0x34, 0x01, 0x02,
		0x00, 0xF1, 0x10, 0x00, 0x01,
	}

	decoded, err := decodeTAIList(encoded)
	if err != nil {
		t.Fatalf("decodeTAIList: %v", err)
	}
	want := []TAI{
		{PLMN: [3]byte{0x13, 0x51, 0x34}, TAC: 0x0102},
		{PLMN: [3]byte{0x00, 0xF1, 0x10}, TAC: 0x0001},
	}
	if len(decoded) != len(want) {
		t.Fatalf("decoded len got %d want %d", len(decoded), len(want))
	}
	for i := range want {
		if decoded[i] != want[i] {
			t.Fatalf("decoded[%d] got %+v want %+v", i, decoded[i], want[i])
		}
	}
}
