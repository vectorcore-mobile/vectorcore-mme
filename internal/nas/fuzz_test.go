package nas

import "testing"

func addNASSeeds(f *testing.F) {
	f.Add([]byte{0x07, 0x41})          // plain EMM Attach Request header shape
	f.Add([]byte{0x27, 0x01, 0xd0})    // plain ESM header shape
	f.Add([]byte{0x17, 0, 0, 0, 0, 1}) // integrity-protected header with empty inner body
	f.Add([]byte{0x47, 0, 0, 0, 0, 1}) // ciphered header with empty inner body
}

func FuzzNASDecode(f *testing.F) {
	addNASSeeds(f)
	f.Fuzz(func(t *testing.T, raw []byte) {
		result, err := Decode(raw, 0, 0, nil, nil, 0)
		if err != nil {
			return
		}
		if result == nil {
			t.Fatal("Decode returned nil result without error")
		}
		if result.Plain == nil {
			t.Fatal("Decode returned nil Plain without error")
		}
	})
}
