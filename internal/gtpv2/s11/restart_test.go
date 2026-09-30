package s11

import "testing"

type memCounterStore struct {
	value uint8
	saved bool
	saves int
}

func (m *memCounterStore) LoadCounter() (uint8, bool, error) { return m.value, m.saved, nil }
func (m *memCounterStore) SaveCounter(v uint8) error {
	m.value, m.saved = v, true
	m.saves++
	return nil
}

func TestLoadRestartCounter(t *testing.T) {
	st := &memCounterStore{}
	// First start: the configured value is saved and used.
	if got, err := LoadRestartCounter(st, 7); err != nil || got != 7 || st.value != 7 {
		t.Fatalf("first start got %d (saved %d) err %v, want 7", got, st.value, err)
	}
	// Later starts keep the saved value, even if the config changes.
	for i := 0; i < 2; i++ {
		if got, err := LoadRestartCounter(st, 9); err != nil || got != 7 {
			t.Fatalf("restart got %d err %v, want 7 (kept)", got, err)
		}
	}
	if st.saves != 1 {
		t.Fatalf("counter saved %d times, want once", st.saves)
	}
}

func TestParseCounter(t *testing.T) {
	if v, ok, err := ParseCounter(" 255\n"); err != nil || !ok || v != 255 {
		t.Fatalf("ParseCounter(255) = %d %v %v", v, ok, err)
	}
	for _, bad := range []string{"256", "-1", "junk", ""} {
		if _, _, err := ParseCounter(bad); err == nil {
			t.Fatalf("ParseCounter(%q): want error", bad)
		}
	}
}

func TestInitialTEID(t *testing.T) {
	if got := InitialTEID(5); got != 5+teidSeedGap {
		t.Fatalf("InitialTEID(5) = %d, want %d", got, 5+teidSeedGap)
	}
	if got := InitialTEID(0xFFFFFFF0); got != teidSeedGap {
		t.Fatalf("InitialTEID near wrap = %#x, want %#x", got, teidSeedGap)
	}
	seen := map[uint32]bool{}
	for i := 0; i < 50; i++ {
		v := InitialTEID(0)
		if v == 0 || v > 0x7FFFFFFF {
			t.Fatalf("random seed %#x out of range", v)
		}
		seen[v] = true
	}
	if len(seen) < 45 {
		t.Fatalf("random seeds not random: %d distinct of 50", len(seen))
	}
}

func TestSeedTEIDAndAllocateSkipsZero(t *testing.T) {
	saved := localCounter.Load()
	defer localCounter.Store(saved)

	SeedTEID(0x10000)
	if got := AllocateTEID(); got != 0x10000 {
		t.Fatalf("first TEID after seed = %#x, want 0x10000", got)
	}
	SeedTEID(0xFFFFFFFF)
	if a, b := AllocateTEID(), AllocateTEID(); a != 0xFFFFFFFF || b != 1 {
		t.Fatalf("TEIDs across wrap = %#x, %#x, want 0xffffffff, 0x1", a, b)
	}
}
