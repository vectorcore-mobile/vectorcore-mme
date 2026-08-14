package uecontext

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sync/atomic"

	"github.com/vectorcore/mme/internal/nas/emm"
)

// GUTIAllocator assigns M-TMSIs from a pool.
// The PLMN, MMEGI, and MMEC are fixed at startup from config.
type GUTIAllocator struct {
	plmn  [3]byte
	mmegi uint16
	mmec  uint8
	next  atomic.Uint32 // next M-TMSI to allocate
}

// NewGUTIAllocator creates a new allocator. startMTMSI is the initial M-TMSI value.
func NewGUTIAllocator(mcc, mnc string, mmegi uint16, mmec uint8) (*GUTIAllocator, error) {
	plmn, err := encodePLMNBCD(mcc, mnc)
	if err != nil {
		return nil, err
	}
	a := &GUTIAllocator{
		mmegi: mmegi,
		mmec:  mmec,
	}
	copy(a.plmn[:], plmn)
	a.next.Store(0x00000001) // avoid M-TMSI = 0
	return a, nil
}

// Allocate returns a new GUTI with a unique M-TMSI.
func (a *GUTIAllocator) Allocate() *emm.GUTI {
	mtmsi := a.next.Add(1)
	if mtmsi == 0 {
		// Wrapped to zero — skip it
		mtmsi = a.next.Add(1)
	}
	return &emm.GUTI{
		PLMN:  a.plmn,
		MMEGI: a.mmegi,
		MMEC:  a.mmec,
		MTMSI: mtmsi,
	}
}

// AllocateUnique returns a GUTI whose full key is not reported as reserved.
// It uses cryptographic randomness first so M-TMSI allocation does not restart
// at the same low values after an MME process restart.
func (a *GUTIAllocator) AllocateUnique(reserved func(*emm.GUTI) bool) (*emm.GUTI, error) {
	for i := 0; i < 1024; i++ {
		g := a.allocateRandom()
		if g.MTMSI != 0 && (reserved == nil || !reserved(g)) {
			return g, nil
		}
	}
	for i := 0; i < 1024; i++ {
		g := a.Allocate()
		if g.MTMSI != 0 && (reserved == nil || !reserved(g)) {
			return g, nil
		}
	}
	return nil, fmt.Errorf("uecontext: exhausted GUTI allocation collision retries")
}

func (a *GUTIAllocator) allocateRandom() *emm.GUTI {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return a.Allocate()
	}
	mtmsi := binary.BigEndian.Uint32(b[:])
	if mtmsi == 0 {
		mtmsi = a.next.Add(1)
	}
	return &emm.GUTI{
		PLMN:  a.plmn,
		MMEGI: a.mmegi,
		MMEC:  a.mmec,
		MTMSI: mtmsi,
	}
}

// SerialiseGUTI returns a fixed-length hex string representation of a GUTI
// for use as a map key and database primary key.
func SerialiseGUTI(g *emm.GUTI) string {
	b := make([]byte, 10)
	copy(b[:3], g.PLMN[:])
	binary.BigEndian.PutUint16(b[3:], g.MMEGI)
	b[5] = g.MMEC
	binary.BigEndian.PutUint32(b[6:], g.MTMSI)
	return fmt.Sprintf("%X", b)
}

// DeserialiseGUTI parses the fixed-length hex string produced by
// SerialiseGUTI back into a *emm.GUTI. It round-trips the raw PLMN bytes
// directly rather than re-deriving them from decoded MCC/MNC, avoiding any
// 2-digit-vs-3-digit MNC ambiguity.
func DeserialiseGUTI(s string) (*emm.GUTI, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("uecontext: invalid GUTI hex %q: %w", s, err)
	}
	if len(b) != 10 {
		return nil, fmt.Errorf("uecontext: invalid GUTI length %d, want 10 bytes", len(b))
	}
	g := &emm.GUTI{
		MMEGI: binary.BigEndian.Uint16(b[3:5]),
		MMEC:  b[5],
		MTMSI: binary.BigEndian.Uint32(b[6:10]),
	}
	copy(g.PLMN[:], b[:3])
	return g, nil
}

func encodePLMNBCD(mcc, mnc string) ([]byte, error) {
	if len(mcc) != 3 {
		return nil, fmt.Errorf("uecontext: MCC must be 3 digits, got %q", mcc)
	}
	if len(mnc) != 2 && len(mnc) != 3 {
		return nil, fmt.Errorf("uecontext: MNC must be 2 or 3 digits, got %q", mnc)
	}
	d := func(s string, i int) byte { return s[i] - '0' }
	plmn := make([]byte, 3)
	plmn[0] = d(mcc, 1)<<4 | d(mcc, 0)
	if len(mnc) == 2 {
		plmn[1] = 0xF0 | d(mcc, 2)
		plmn[2] = d(mnc, 1)<<4 | d(mnc, 0)
	} else {
		plmn[1] = d(mnc, 2)<<4 | d(mcc, 2)
		plmn[2] = d(mnc, 1)<<4 | d(mnc, 0)
	}
	return plmn, nil
}
