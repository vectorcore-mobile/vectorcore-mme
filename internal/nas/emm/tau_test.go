package emm_test

import (
	"testing"

	"github.com/vectorcore/mme/internal/nas/emm"
)

// buildTAURequestBody constructs a minimal TAU Request body with a GUTI.
func buildTAURequestBody(updateType uint8, guti *emm.GUTI) []byte {
	b := make([]byte, 0, 32)

	// Byte 0: (eKSI=7)<<4 | (active=0)<<3 | updateType
	b = append(b, (0x07<<4)|updateType)

	// LV: mobile identity (GUTI)
	// GUTI wire format: [0xF6][PLMN(3)][MMEGI(2)][MMEC(1)][MTMSI(4)] = 11 bytes
	gutiBytes := guti.Encode() // returns LV: [0x0B, ...11 value bytes]
	b = append(b, gutiBytes...)

	// LV: UE network capability (length=2, EEA=0xE0, EIA=0xE0)
	b = append(b, 0x02, 0xE0, 0xE0)

	return b
}

// ── DecodeTAURequest ──────────────────────────────────────────────────────────

func TestDecodeTAURequest_PeriodicGUTI(t *testing.T) {
	guti := &emm.GUTI{
		PLMN:  [3]byte{0x00, 0xF1, 0x10},
		MMEGI: 1,
		MMEC:  1,
		MTMSI: 0xDEADBEEF,
	}
	body := buildTAURequestBody(emm.EPSUpdateTypePeriodic, guti)

	req, err := emm.DecodeTAURequest(body)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if req.EPSUpdateType != emm.EPSUpdateTypePeriodic {
		t.Errorf("EPSUpdateType: got %d, want %d (periodic)", req.EPSUpdateType, emm.EPSUpdateTypePeriodic)
	}
	if req.OldGUTI == nil {
		t.Fatal("OldGUTI should not be nil")
	}
	if req.OldGUTI.MTMSI != guti.MTMSI {
		t.Errorf("GUTI MTMSI: got %#x, want %#x", req.OldGUTI.MTMSI, guti.MTMSI)
	}
	if req.OldGUTI.MMEC != guti.MMEC {
		t.Errorf("GUTI MMEC: got %d, want %d", req.OldGUTI.MMEC, guti.MMEC)
	}
	if len(req.UENetworkCapability) != 2 {
		t.Errorf("UENetworkCapability length: got %d, want 2", len(req.UENetworkCapability))
	}
}

func TestDecodeTAURequest_NormalGUTI(t *testing.T) {
	guti := &emm.GUTI{
		PLMN:  [3]byte{0x02, 0xF8, 0x39},
		MMEGI: 42,
		MMEC:  7,
		MTMSI: 0x12345678,
	}
	body := buildTAURequestBody(emm.EPSUpdateTypeTA, guti)

	req, err := emm.DecodeTAURequest(body)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if req.EPSUpdateType != emm.EPSUpdateTypeTA {
		t.Errorf("EPSUpdateType: got %d, want %d (TA)", req.EPSUpdateType, emm.EPSUpdateTypeTA)
	}
	if req.OldGUTI == nil {
		t.Fatal("OldGUTI should not be nil")
	}
	if req.OldGUTI.MTMSI != 0x12345678 {
		t.Errorf("MTMSI: got %#x, want 0x12345678", req.OldGUTI.MTMSI)
	}
}

func TestDecodeTAURequest_TooShort(t *testing.T) {
	_, err := emm.DecodeTAURequest([]byte{0x03})
	if err == nil {
		t.Error("expected error for 1-byte body, got nil")
	}
}

// ── EncodeTAUAccept ───────────────────────────────────────────────────────────

func TestEncodeTAUAccept_NoGUTI(t *testing.T) {
	tai := emm.TAI{PLMN: [3]byte{0x00, 0xF1, 0x10}, TAC: 0x0001}
	b := emm.EncodeTAUAccept(0x00, 0x21, []emm.TAI{tai}, nil)

	if len(b) < 3 {
		t.Fatalf("output too short: %d bytes", len(b))
	}
	if b[0] != emm.PDEPSMobilityMgmt {
		t.Errorf("byte[0] PD: got %#x, want %#x", b[0], emm.PDEPSMobilityMgmt)
	}
	if b[1] != emm.MsgTrackingAreaUpdateAccept {
		t.Errorf("byte[1] msg type: got %#x, want %#x", b[1], emm.MsgTrackingAreaUpdateAccept)
	}
	if b[2] != 0x00 {
		t.Errorf("byte[2] EPS update result: got %#x, want 0x00", b[2])
	}
	// T3412 IEI should be present
	found := false
	for i := 3; i < len(b)-1; i++ {
		if b[i] == 0x5A {
			found = true
			if b[i+1] != 0x01 {
				t.Errorf("T3412 length: got %d, want 1", b[i+1])
			}
			if i+2 < len(b) && b[i+2] != 0x21 {
				t.Errorf("T3412 value: got %#x, want 0x21", b[i+2])
			}
			break
		}
	}
	if !found {
		t.Error("T3412 IEI 0x5A not found in TAU Accept")
	}
	// TAI list IEI should be present
	found = false
	for _, bb := range b[3:] {
		if bb == 0x54 {
			found = true
			break
		}
	}
	if !found {
		t.Error("TAI list IEI 0x54 not found in TAU Accept")
	}
	// GUTI IEI must NOT be present
	for _, bb := range b {
		if bb == 0x50 {
			t.Error("GUTI IEI 0x50 unexpectedly present in no-GUTI TAU Accept")
			break
		}
	}
}

func TestEncodeTAUAccept_WithGUTI(t *testing.T) {
	tai := emm.TAI{PLMN: [3]byte{0x00, 0xF1, 0x10}, TAC: 0x0007}
	guti := &emm.GUTI{PLMN: [3]byte{0x00, 0xF1, 0x10}, MMEGI: 1, MMEC: 1, MTMSI: 0xABCD1234}

	b := emm.EncodeTAUAccept(0x00, 0x21, []emm.TAI{tai}, guti)
	if len(b) < 20 {
		t.Fatalf("output too short with GUTI: %d bytes", len(b))
	}
	found := false
	for i, bb := range b {
		if bb == 0x50 {
			found = true
			// Next byte should be the GUTI LV length (0x0B = 11)
			if i+1 < len(b) && b[i+1] != 0x0B {
				t.Errorf("GUTI LV length: got %d, want 11", b[i+1])
			}
			break
		}
	}
	if !found {
		t.Error("GUTI IEI 0x50 not found in TAU Accept")
	}
}

// ── EncodeTAUReject ───────────────────────────────────────────────────────────

func TestEncodeTAUReject(t *testing.T) {
	const cause = emm.CauseImplicitlyDetached
	b := emm.EncodeTAUReject(cause)

	if len(b) != 3 {
		t.Fatalf("length: got %d, want 3", len(b))
	}
	if b[0] != emm.PDEPSMobilityMgmt {
		t.Errorf("byte[0] PD: got %#x, want %#x", b[0], emm.PDEPSMobilityMgmt)
	}
	if b[1] != emm.MsgTrackingAreaUpdateReject {
		t.Errorf("byte[1] msg type: got %#x, want %#x", b[1], emm.MsgTrackingAreaUpdateReject)
	}
	if b[2] != cause {
		t.Errorf("byte[2] cause: got %#x, want %#x", b[2], cause)
	}
}
